use core::{convert::Infallible, fmt, time::Duration};

use alloc::{collections::VecDeque, sync::Arc};

use std::{error, io, net::SocketAddr};

use http::Uri;
use rustls::{ClientConfig, ClientConnection, OwnedTrustAnchor, RootCertStore, ServerName};
use tokio::{
    sync::{mpsc, oneshot},
    time,
};
use tracing::{error, trace};
use xitca_io::{
    bytes::{Buf, BufInterest, BufRead, BufWrite, WriteBuf},
    io::{AsyncIo, Interest},
    net::TcpStream,
};
use xitca_unsafe_collection::futures::{Select, SelectOutput};

use crate::{error::Error, proxy::udp::udp_resolve, util::BoxFuture};

use super::Proxy;

type PagedBytesMut = xitca_io::bytes::PagedBytesMut<4096>;

type Msg = (Box<[u8]>, oneshot::Sender<Vec<u8>>);

type TlsStream = xitca_tls::rustls::TlsStream<ClientConnection, TcpStream>;

pub struct TlsProxy {
    tx: mpsc::Sender<Msg>,
}

impl TlsProxy {
    pub async fn try_from_uri(uri: String, boot_strap_addr: SocketAddr) -> Result<Self, Error> {
        let uri = Uri::try_from(uri)?;

        let host = match uri.host() {
            Some(host) => host,
            None => return Err(Error::from(InvalidUri(uri))),
        };
        let server_name = host.try_into()?;
        let port = uri.port_u16().unwrap_or(853);

        let addrs = udp_resolve(boot_strap_addr, host, port).await?;

        let mut root_certs = RootCertStore::empty();
        root_certs.add_trust_anchors(webpki_roots::TLS_SERVER_ROOTS.0.iter().map(|cert| {
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

        tokio::spawn(async move {
            let host = uri.host().unwrap();
            loop {
                match connect(&addrs, &cfg, &server_name).await {
                    Ok(stream) => {
                        let Err(e) = ctx.pipeline_io(stream).await else {
                            return;
                        };
                        trace!("{host} unexpected disconnect: {e}");
                        if !ctx.wait_for_reconnect().await {
                            return;
                        }
                    }
                    Err(e) => {
                        error!("{host} connect error: {e}");
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
    buf_read: PagedBytesMut,
    buf_write: WriteBuf,
    queue: VecDeque<oneshot::Sender<Vec<u8>>>,
    rx: mpsc::Receiver<Msg>,
}

impl TlsContext {
    fn new(rx: mpsc::Receiver<Msg>) -> Self {
        Self {
            len: None,
            buf_read: PagedBytesMut::new(),
            buf_write: WriteBuf::new(),
            queue: VecDeque::new(),
            rx,
        }
    }

    fn reset(&mut self) {
        self.len = None;
        self.buf_read.split();
        self.buf_write.clear();
        self.queue.clear();
    }

    fn try_read(&mut self, stream: &mut TlsStream) -> io::Result<()> {
        self.buf_read.do_io(stream).map(|_| self.decode())
    }

    fn try_write(&mut self, stream: &mut TlsStream) -> io::Result<()> {
        self.buf_write.do_io(stream).map_err(|e| {
            self.buf_write.clear();
            e
        })
    }

    fn decode(&mut self) {
        loop {
            match self.len {
                Some(l) if self.buf_read.chunk().len() >= l => {
                    let buf = self.buf_read.split_to(l).to_vec();
                    let _ = self.queue.pop_front().unwrap().send(buf);
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
    TlsStream::handshake(stream, conn).await.map_err(Into::into)
}

impl Proxy for TlsProxy {
    fn proxy(&self, buf: Box<[u8]>) -> BoxFuture<'_, Result<Vec<u8>, Error>> {
        Box::pin(async move {
            let (tx, rx) = oneshot::channel();
            self.tx.send((buf, tx)).await?;
            rx.await.map_err(Into::into)
        })
    }
}

#[derive(Debug)]
struct InvalidUri(Uri);

impl fmt::Display for InvalidUri {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} is not valid uri.", self.0)
    }
}

impl error::Error for InvalidUri {}
