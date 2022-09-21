use std::{
    io::{self, Read, Write},
    net::SocketAddr,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use futures_core::future::BoxFuture;
use rustls::{ClientConfig, ClientConnection, PrivateKey, RootCertStore, ServerName, StreamOwned};
use tokio::sync::Mutex;
use xitca_io::{
    io::{AsyncIo, Interest, Ready},
    net::TcpStream,
};

use crate::error::Error;

use super::Proxy;

// TODO: the efficiency of TlsProxy is a big no.
// To improve one must use async pipelined feature to allow concurrent non blocking read/write
// of the tls stream.
pub struct TlsProxy {
    #[allow(dead_code)]
    config: Arc<ClientConfig>,
    stream: Mutex<TlsStream>,
}

impl TlsProxy {
    pub async fn try_from_addr(addr: SocketAddr) -> Result<Self, Error> {
        let config = ClientConfig::builder()
            .with_safe_default_cipher_suites()
            .with_safe_default_kx_groups()
            .with_safe_default_protocol_versions()?
            .with_root_certificates(RootCertStore::empty())
            .with_single_cert(vec![], PrivateKey(vec![]))?;

        let config = Arc::new(config);

        let stream = TcpStream::connect(addr).await?;

        let name = ServerName::IpAddress(addr.ip());
        let stream = connect_tls(config.clone(), name, stream).await?;

        Ok(Self {
            config,
            stream: Mutex::new(stream),
        })
    }
}

impl Proxy for TlsProxy {
    fn proxy(&self, buf: Box<[u8]>) -> BoxFuture<'_, Result<Vec<u8>, Error>> {
        Box::pin(async move {
            let mut stream = self.stream.lock().await;

            let mut n = 0;

            let head = (buf.len() as u16).to_be_bytes();
            while n < head.len() {
                match stream.write(&head[n..]) {
                    Ok(w) => n += w,
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                        stream.ready(Interest::WRITABLE).await?;
                    }
                    Err(e) => return Err(e.into()),
                }
            }

            n = 0;

            while n < buf.len() {
                match stream.write(&buf[n..]) {
                    Ok(w) => n += w,
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                        stream.ready(Interest::WRITABLE).await?;
                    }
                    Err(e) => return Err(e.into()),
                }
            }

            n = 0;

            let mut buf = vec![0; 512];
            let mut len = None;

            loop {
                match stream.read(&mut buf[n..]) {
                    Ok(r) => {
                        n += r;

                        match len {
                            Some(l) if n == l => {
                                let _ = buf.split_off(n);
                                return Ok(buf);
                            }
                            None if n > 2 => {
                                let remain = buf.split_off(2);
                                let l = u16::from_be_bytes(buf.try_into().unwrap());
                                len = Some(l as usize);
                                n -= 2;
                                buf = remain;
                            }
                            Some(l) if n > l => unreachable!(
                                "tls stream is locked between read and write. this can't be right"
                            ),
                            _ => continue,
                        }
                    }
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                        stream.ready(Interest::READABLE).await?;
                    }
                    Err(e) => return Err(e.into()),
                }
            }
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

impl io::Read for TlsStream {
    #[inline]
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        io::Read::read(&mut self.io, buf)
    }
}

impl io::Write for TlsStream {
    #[inline]
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        io::Write::write(&mut self.io, buf)
    }

    #[inline]
    fn write_vectored(&mut self, bufs: &[io::IoSlice<'_>]) -> io::Result<usize> {
        io::Write::write_vectored(&mut self.io, bufs)
    }

    #[inline]
    fn flush(&mut self) -> io::Result<()> {
        io::Write::flush(&mut self.io)
    }
}
