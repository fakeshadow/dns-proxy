use core::{
    convert::Infallible,
    fmt,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};

use alloc::{collections::VecDeque, sync::Arc};

use std::{
    error,
    io::{self, Read, Write},
    net::SocketAddr,
};

use http::Uri;
use rustls::{
    ClientConfig, ClientConnection, OwnedTrustAnchor, RootCertStore, ServerName, StreamOwned,
};
use tokio::{
    sync::{mpsc, oneshot},
    time,
};
use tracing::{error, trace};
use xitca_io::{
    bytes::{Buf, BufInterest, BufWrite, BytesMut, WriteBuf},
    io::{AsyncIo, Interest, Ready},
    net::TcpStream,
};
use xitca_unsafe_collection::{
    bytes::read_buf,
    futures::{Select, SelectOutput},
};

use crate::{error::Error, proxy::udp::udp_resolve, util::BoxFuture};

use super::Proxy;

type Msg = (Box<[u8]>, oneshot::Sender<Vec<u8>>);

pub struct TlsProxy {
    tx: mpsc::Sender<Msg>,
}

impl TlsProxy {
    pub async fn try_from_uri(uri: String, boot_strap_addr: SocketAddr) -> Result<Self, Error> {
        let uri = Uri::try_from(uri)?;

        let hostname = uri.host().ok_or_else(|| InvalidUri(uri.to_string()))?;
        let port = uri.port_u16().unwrap_or(853);
        let server_name = hostname.try_into()?;

        let addrs = udp_resolve(boot_strap_addr, hostname, port).await?;

        let mut root_certs = RootCertStore::empty();
        root_certs.add_server_trust_anchors(webpki_roots::TLS_SERVER_ROOTS.0.iter().map(|cert| {
            OwnedTrustAnchor::from_subject_spki_name_constraints(
                cert.subject,
                cert.spki,
                cert.name_constraints,
            )
        }));

        let cfg = ClientConfig::builder()
            .with_safe_defaults()
            .with_root_certificates(root_certs)
            .with_no_client_auth();
        let cfg = Arc::new(cfg);

        let (tx, rx) = mpsc::channel(256);

        let mut ctx = TlsContext::new(rx);

        let hostname = hostname.to_string();
        tokio::spawn(async move {
            loop {
                match connect(&addrs, &cfg, &server_name).await {
                    Ok(stream) => {
                        let Err(e) = ctx.pipeline_io(stream).await else { return };
                        trace!("{hostname:?} unexpected disconnect: {e:?}");
                        if !ctx.wait_for_reconnect().await {
                            return;
                        }
                    }
                    Err(e) => {
                        error!("{hostname:?} connect error: {e:?}");
                        ctx.reset();
                        time::sleep(Duration::from_secs(1)).await;
                    }
                };
            }
        });

        Ok(Self { tx })
    }
}

struct TlsContext {
    len: Option<usize>,
    buf_read: BytesMut,
    buf_write: WriteBuf,
    queue: VecDeque<oneshot::Sender<Vec<u8>>>,
    rx: mpsc::Receiver<Msg>,
}

impl TlsContext {
    fn new(rx: mpsc::Receiver<Msg>) -> Self {
        Self {
            len: None,
            buf_read: BytesMut::new(),
            buf_write: WriteBuf::new(),
            queue: VecDeque::new(),
            rx,
        }
    }

    fn reset(&mut self) {
        self.len = None;
        self.buf_read.clear();
        self.buf_write.clear();
        self.queue.clear();
    }

    fn try_read(&mut self, stream: &mut TlsStream) -> io::Result<()> {
        loop {
            match read_buf(stream, &mut self.buf_read) {
                // remote closed read. treat as error.
                Ok(0) => return Err(io::ErrorKind::ConnectionAborted.into()),
                Ok(_) => self.decode(),
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => return Ok(()),
                Err(e) => return Err(e),
            }
        }
    }

    fn try_write(&mut self, stream: &mut TlsStream) -> io::Result<()> {
        self.buf_write.write_io(stream).map_err(|e| {
            self.buf_write.clear();
            e
        })
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

    async fn pipeline_io(&mut self, mut stream: TlsStream) -> io::Result<()> {
        loop {
            let interest = if self.buf_write.want_write_io() {
                Interest::READABLE | Interest::WRITABLE
            } else {
                Interest::READABLE
            };

            match self.rx.recv().select(stream.ready(interest)).await {
                // got new pipelined request. write to buffer and move on.
                SelectOutput::A(Some(msg)) => self.encode(msg),
                // tls stream is ready to be read/write.
                SelectOutput::B(res) => {
                    let ready = res?;
                    if ready.is_readable() {
                        self.try_read(&mut stream)?;
                    }
                    if ready.is_writable() && self.try_write(&mut stream).is_err() {
                        break;
                    }
                }
                // proxy is dropped from app.
                SelectOutput::A(None) => break,
            }
        }

        loop {
            let want_read = !self.queue.is_empty();
            let want_write = self.buf_write.want_write_io();
            let interest = match (want_read, want_write) {
                (true, true) => Interest::READABLE | Interest::WRITABLE,
                (true, false) => Interest::READABLE,
                (false, true) => Interest::WRITABLE,
                (false, false) => break,
            };
            let ready = stream.ready(interest).await?;
            if ready.is_readable() {
                self.try_read(&mut stream)?;
            }
            if ready.is_writable() {
                let _ = self.try_write(&mut stream);
            }
        }

        Ok(())
    }

    async fn wait_for_reconnect(&mut self) -> bool {
        self.reset();
        self.rx.recv().await.map(|msg| self.encode(msg)).is_some()
    }
}

async fn connect(
    addrs: &[SocketAddr],
    cfg: &Arc<ClientConfig>,
    server_name: &ServerName,
) -> Result<TlsStream, Error> {
    let stream = crate::app::try_iter(addrs.iter(), TcpStream::connect).await?;
    let _ = stream.set_nodelay(true);
    let conn = ClientConnection::new(cfg.clone(), server_name.clone())?;
    handshake(stream, conn).await
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
async fn handshake(mut io: TcpStream, mut conn: ClientConnection) -> Result<TlsStream, Error> {
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
