use std::{
    collections::VecDeque,
    io::{self, Read, Write},
    net::SocketAddr,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use futures_core::future::BoxFuture;
use rustls::{
    ClientConfig, ClientConnection, OwnedTrustAnchor, RootCertStore, ServerName, StreamOwned,
};
use tokio::sync::{mpsc, oneshot};
use webpki_roots::TLS_SERVER_ROOTS;
use xitca_client::{
    error::{Error as XitcaClientError, InvalidUri},
    http::Uri,
};
use xitca_io::{
    bytes::{Buf, BytesMut},
    io::{AsyncIo, Interest, Ready},
    net::TcpStream,
};
use xitca_unsafe_collection::{
    bytes::read_buf,
    futures::{Select, SelectOutput},
};

use crate::{error::Error, proxy::udp::udp_resolve};

use super::Proxy;

pub struct TlsProxy {
    #[allow(dead_code)]
    config: Arc<ClientConfig>,
    tx: mpsc::Sender<(Box<[u8]>, oneshot::Sender<Vec<u8>>)>,
}

impl TlsProxy {
    pub async fn try_from_uri(uri: String, boot_strap_addr: SocketAddr) -> Result<Self, Error> {
        let uri = Uri::try_from(uri)?;

        let hostname = uri
            .host()
            .ok_or_else(|| XitcaClientError::from(InvalidUri::MissingHost))?;
        let port = uri.port_u16().unwrap_or(853);

        let server_name = hostname.try_into()?;

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

        let config = Arc::new(config);

        let addr = udp_resolve(boot_strap_addr, hostname, port).await?;

        let stream = crate::app::try_iter(addr.into_iter(), TcpStream::connect).await?;

        let mut stream = connect_tls(config.clone(), server_name, stream).await?;

        let (tx, mut rx) = mpsc::channel::<(Box<[u8]>, oneshot::Sender<Vec<u8>>)>(256);

        tokio::spawn(async move {
            let mut queue = VecDeque::<oneshot::Sender<Vec<u8>>>::new();

            let mut buf_r = BytesMut::new();
            let mut buf_w = BytesMut::new();

            let mut len = None;

            'out: loop {
                let interest = if buf_w.is_empty() {
                    Interest::READABLE
                } else {
                    Interest::READABLE | Interest::WRITABLE
                };

                match rx.recv().select(stream.ready(interest)).await {
                    SelectOutput::A(None) => break,
                    SelectOutput::A(Some((buf, tx))) => {
                        let len = (buf.len() as u16).to_be_bytes();
                        buf_w.extend_from_slice(&len);
                        buf_w.extend_from_slice(&buf);
                        queue.push_back(tx);
                    }
                    SelectOutput::B(Ok(ready)) => {
                        if ready.is_readable() {
                            match read_buf(&mut stream, &mut buf_r) {
                                Ok(0) => break,
                                Ok(_) => loop {
                                    match len {
                                        Some(l) if buf_r.chunk().len() >= l => {
                                            let buf = buf_r.split_to(l).to_vec();
                                            let tx = queue.pop_front().unwrap();
                                            let _ = tx.send(buf);
                                            len = None;
                                        }
                                        None if buf_r.chunk().len() > 2 => {
                                            let l = u16::from_be_bytes(
                                                buf_r.chunk()[..2].try_into().unwrap(),
                                            );
                                            len = Some(l as usize);
                                            buf_r.advance(2);
                                        }
                                        _ => continue 'out,
                                    }
                                },
                                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                                Err(_) => break,
                            }
                        }

                        if ready.is_writable() {
                            match stream.write(buf_w.chunk()) {
                                Ok(0) => break,
                                Ok(n) => buf_w.advance(n),
                                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                                Err(_) => break,
                            }
                        }
                    }
                    SelectOutput::B(Err(_)) => return,
                }
            }
        });

        Ok(Self { config, tx })
    }
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
    type ReadyFuture<'f> = <TcpStream as AsyncIo>::ReadyFuture<'f> where Self: 'f;

    #[inline]
    fn ready(&self, interest: Interest) -> Self::ReadyFuture<'_> {
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
