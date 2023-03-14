use core::{
    convert::Infallible,
    fmt,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};

use std::{
    collections::VecDeque,
    error,
    io::{self, Read, Write},
    net::SocketAddr,
    sync::Arc,
};

use futures_core::future::BoxFuture;
use http::Uri;
use rustls::{
    ClientConfig, ClientConnection, OwnedTrustAnchor, RootCertStore, ServerName, StreamOwned,
};
use tokio::{
    sync::{mpsc, oneshot},
    time,
};
use tracing::debug;
use webpki_roots::TLS_SERVER_ROOTS;
use xitca_io::{
    bytes::{Buf, BufInterest, BufWrite, BytesMut, WriteBuf},
    io::{AsyncIo, Interest, Ready},
    net::TcpStream,
};
use xitca_unsafe_collection::{
    bytes::read_buf,
    futures::{Select, SelectOutput},
};

use crate::{error::Error, proxy::udp::udp_resolve};

use super::Proxy;

type Msg = (Box<[u8]>, oneshot::Sender<Vec<u8>>);

pub struct TlsProxy {
    tx: mpsc::Sender<Msg>,
}

impl TlsProxy {
    pub async fn try_from_uri(uri: String, boot_strap_addr: SocketAddr) -> Result<Self, Error> {
        let mut root_certs = RootCertStore::empty();

        for cert in TLS_SERVER_ROOTS.0 {
            let cert = OwnedTrustAnchor::from_subject_spki_name_constraints(
                cert.subject,
                cert.spki,
                cert.name_constraints,
            );
            let certs = vec![cert].into_iter();
            root_certs.add_server_trust_anchors(certs);
        }

        let config = ClientConfig::builder()
            .with_safe_defaults()
            .with_root_certificates(root_certs)
            .with_no_client_auth();

        let cfg = Arc::new(config);

        let mut stream = connect(uri.as_str(), boot_strap_addr, &cfg).await?;

        let (tx, mut rx) = mpsc::channel(256);

        tokio::spawn(async move {
            while let Err(e) = pipeline_io(&mut stream, &mut rx).await {
                debug!("{:?} unexpected disconnect: {:?}", uri.as_str(), e);

                'inner: loop {
                    match connect(uri.as_str(), boot_strap_addr, &cfg).await {
                        Ok(s) => {
                            stream = s;
                            break 'inner;
                        }
                        Err(e) => {
                            debug!("{:?} connect error: {:?}", uri.as_str(), e);
                            time::sleep(Duration::from_secs(1)).await
                        }
                    }
                }
            }
        });

        Ok(Self { tx })
    }
}

async fn pipeline_io(stream: &mut TlsStream, rx: &mut mpsc::Receiver<Msg>) -> io::Result<()> {
    let mut ctx = TlsContext::new();

    loop {
        let interest = if ctx.buf_write.want_write_io() {
            Interest::READABLE | Interest::WRITABLE
        } else {
            Interest::READABLE
        };

        match rx.recv().select(stream.ready(interest)).await {
            // got new pipelined request. write to buffer and move on.
            SelectOutput::A(Some(msg)) => ctx.encode(msg),
            // tls stream is ready to be read/write.
            SelectOutput::B(res) => {
                let ready = res?;
                if ready.is_readable() {
                    try_read(stream, &mut ctx)?;
                }
                if ready.is_writable() && try_write(stream, &mut ctx).is_err() {
                    break;
                }
            }
            // proxy is dropped from app.
            SelectOutput::A(None) => break,
        }
    }

    loop {
        let want_read = !ctx.queue.is_empty();
        let want_write = ctx.buf_write.want_write_io();
        let interest = match (want_read, want_write) {
            (true, true) => Interest::READABLE | Interest::WRITABLE,
            (true, false) => Interest::READABLE,
            (false, true) => Interest::WRITABLE,
            (false, false) => break,
        };
        let ready = stream.ready(interest).await?;
        if ready.is_readable() {
            try_read(stream, &mut ctx)?;
        }
        if ready.is_writable() {
            let _ = try_write(stream, &mut ctx);
        }
    }

    Ok(())
}

fn try_read(stream: &mut TlsStream, ctx: &mut TlsContext) -> io::Result<()> {
    match read_buf(stream, &mut ctx.buf_read) {
        // remote closed read. treat as error.
        Ok(0) => return Err(io::ErrorKind::ConnectionAborted.into()),
        Ok(_) => ctx.decode(),
        Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
        Err(e) => return Err(e),
    }
    Ok(())
}

fn try_write(stream: &mut TlsStream, ctx: &mut TlsContext) -> io::Result<()> {
    ctx.buf_write.write_io(stream).map_err(|e| {
        ctx.buf_write.clear();
        e
    })
}

struct TlsContext {
    len: Option<usize>,
    buf_read: BytesMut,
    buf_write: WriteBuf,
    queue: VecDeque<oneshot::Sender<Vec<u8>>>,
}

impl TlsContext {
    fn new() -> Self {
        Self {
            len: None,
            buf_read: BytesMut::new(),
            buf_write: WriteBuf::new(),
            queue: VecDeque::new(),
        }
    }

    fn decode(&mut self) {
        loop {
            match self.len {
                Some(l) if self.buf_read.chunk().len() >= l => {
                    let buf = self.buf_read.split_to(l).to_vec();
                    let tx = self.queue.pop_front().unwrap();
                    let _ = tx.send(buf);
                    self.len = None;
                }
                None if self.buf_read.chunk().len() > 2 => {
                    let l = u16::from_be_bytes(self.buf_read.chunk()[..2].try_into().unwrap());
                    self.len = Some(l as usize);
                    self.buf_read.advance(2);
                }
                _ => return,
            }
        }
    }

    fn encode(&mut self, (buf, tx): (Box<[u8]>, oneshot::Sender<Vec<u8>>)) {
        let len = (buf.len() as u16).to_be_bytes();
        let _ = self.buf_write.write_buf(|b| {
            b.extend_from_slice(&len);
            b.extend_from_slice(&buf);
            Ok::<_, Infallible>(())
        });
        self.queue.push_back(tx);
    }
}

async fn connect(
    uri: &str,
    boot_strap_addr: SocketAddr,
    cfg: &Arc<ClientConfig>,
) -> Result<TlsStream, Error> {
    let uri = Uri::try_from(String::from(uri))?;

    let hostname = uri.host().ok_or_else(|| InvalidUri(uri.to_string()))?;
    let port = uri.port_u16().unwrap_or(853);

    let server_name = hostname.try_into()?;

    let addr = udp_resolve(boot_strap_addr, hostname, port).await?;

    let stream = crate::app::try_iter(addr.into_iter(), TcpStream::connect).await?;

    connect_tls(cfg.clone(), server_name, stream).await
}

impl Proxy for TlsProxy {
    fn proxy(&self, buf: Box<[u8]>) -> BoxFuture<'_, Result<Vec<u8>, Error>> {
        Box::pin(async move {
            let (tx, rx) = oneshot::channel();
            self.tx.send((buf, tx)).await?;
            Ok(rx.await?)
        })
    }
}

struct TlsStream {
    io: StreamOwned<ClientConnection, TcpStream>,
}

#[inline(never)]
async fn connect_tls(
    config: Arc<ClientConfig>,
    name: ServerName,
    mut io: TcpStream,
) -> Result<TlsStream, Error> {
    let mut conn = ClientConnection::new(config, name)?;

    loop {
        let interest = match conn.complete_io(&mut io) {
            Ok(_) => {
                return Ok(TlsStream {
                    io: StreamOwned::new(conn, io),
                })
            }
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                match (conn.wants_read(), conn.wants_write()) {
                    (true, true) => Interest::READABLE | Interest::WRITABLE,
                    (true, false) => Interest::READABLE,
                    (false, true) => Interest::WRITABLE,
                    (false, false) => unreachable!(),
                }
            }
            Err(e) => return Err(e.into()),
        };

        io.ready(interest).await?;
    }
}
impl AsyncIo for TlsStream {
    type Future<'f> = <TcpStream as AsyncIo>::Future<'f> where Self: 'f;

    #[inline]
    fn ready(&self, interest: Interest) -> Self::Future<'_> {
        self.io.get_ref().ready(interest)
    }

    #[inline]
    fn poll_ready(&self, interest: Interest, cx: &mut Context<'_>) -> Poll<io::Result<Ready>> {
        self.io.get_ref().poll_ready(interest, cx)
    }

    fn is_vectored_write(&self) -> bool {
        self.io.get_ref().is_vectored_write()
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        AsyncIo::poll_shutdown(Pin::new(self.get_mut().io.get_mut()), cx)
    }
}

impl Read for TlsStream {
    #[inline]
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        Read::read(&mut self.io, buf)
    }
}

impl Write for TlsStream {
    #[inline]
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        Write::write(&mut self.io, buf)
    }

    #[inline]
    fn write_vectored(&mut self, bufs: &[io::IoSlice<'_>]) -> io::Result<usize> {
        Write::write_vectored(&mut self.io, bufs)
    }

    #[inline]
    fn flush(&mut self) -> io::Result<()> {
        Write::flush(&mut self.io)
    }
}

#[derive(Debug)]
struct InvalidUri(String);

impl fmt::Display for InvalidUri {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} is not valid uri.", self.0)
    }
}

impl error::Error for InvalidUri {}
