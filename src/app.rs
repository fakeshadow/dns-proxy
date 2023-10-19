use core::future::Future;

use std::{
    io,
    net::{SocketAddr, ToSocketAddrs},
};

use alloc::sync::Arc;

use tokio::net::UdpSocket;
use tracing::error;

use crate::{
    cache::Cache,
    config::{Config, UpstreamVariant},
    error::Error,
    proxy::{udp::UdpProxy, ProxyDyn},
};

pub struct App {
    listener: UdpSocket,
    cache: Cache,
    proxy: Box<dyn ProxyDyn>,
}

impl App {
    pub async fn run(cfg: Config) -> Result<(), Error> {
        let app = App::try_from_config(cfg).await?;

        let mut buf = [0; 512];

        loop {
            match app.listener.recv_from(&mut buf).await {
                Ok((len, addr)) => app.forward(&mut buf[..len], addr),
                Err(ref e) if connection_error(e) => continue,
                Err(e) => return Err(e.into()),
            }
        }
    }

    async fn try_from_config(cfg: Config) -> Result<Arc<Self>, Error> {
        let listener = try_iter(cfg.listen_addr.into_iter(), UdpSocket::bind).await?;

        let mut boot_strap = cfg.boot_strap_addr;
        let _boot_strap = boot_strap.pop().unwrap().to_socket_addrs()?.next().unwrap();
        let proxy = try_iter(cfg.upstream_addr.into_iter(), |addr| async move {
            match addr {
                UpstreamVariant::Udp(addr) => UdpProxy::try_from_addr(addr)
                    .await
                    .map(|p| Box::new(p) as _),
                #[cfg(feature = "tls")]
                UpstreamVariant::Tls(uri) => {
                    crate::proxy::tls::TlsProxy::try_from_uri(uri, _boot_strap)
                        .await
                        .map(|p| Box::new(p) as _)
                }
                #[cfg(feature = "https")]
                UpstreamVariant::Https(uri) => {
                    crate::proxy::https::HttpProxy::try_from_uri(uri, _boot_strap)
                        .await
                        .map(|p| Box::new(p) as _)
                }
            }
        })
        .await?;

        Ok(Arc::new(Self {
            listener,
            cache: Cache::new(),
            proxy,
        }))
    }

    fn forward(self: &Arc<Self>, buf: &mut [u8], addr: SocketAddr) {
        let either = match self.cache.get(buf) {
            Some(cache) => EitherBuf::Cache(cache),
            None => EitherBuf::Req((&*buf).into()),
        };

        let this = self.clone();
        tokio::spawn(async move {
            if let Err(e) = this._forward(either, addr).await {
                error!("forwarding dns lookup error: {e}")
            }
        });
    }

    async fn _forward(&self, either: EitherBuf, addr: SocketAddr) -> Result<(), Error> {
        let buf = match either {
            EitherBuf::Cache(cache) => cache,
            EitherBuf::Req(buf) => {
                let mut res = self.proxy.proxy_dyn(buf).await?;
                self.cache.set(&mut res);
                res
            }
        };
        self.listener.send_to(&buf, addr).await?;
        Ok(())
    }
}

enum EitherBuf {
    Cache(Vec<u8>),
    Req(Box<[u8]>),
}

#[cold]
#[inline(never)]
pub(crate) async fn try_iter<I, F, Fut, T, E>(addr: I, func: F) -> Result<T, E>
where
    I: Iterator,
    F: Fn(I::Item) -> Fut,
    Fut: Future<Output = Result<T, E>>,
{
    let mut err = None;

    for addr in addr {
        match func(addr).await {
            Ok(res) => return Ok(res),
            Err(e) => err = Some(e),
        }
    }

    Err(err.unwrap())
}

fn connection_error(e: &io::Error) -> bool {
    e.kind() == io::ErrorKind::ConnectionRefused
        || e.kind() == io::ErrorKind::ConnectionAborted
        || e.kind() == io::ErrorKind::ConnectionReset
}
