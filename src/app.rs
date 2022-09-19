use std::{
    future::Future,
    net::{SocketAddr, ToSocketAddrs},
    sync::Arc,
};

use tokio::net::UdpSocket;
use tracing::error;

use crate::{config::Config, error::Error, http::Client};

pub struct App {
    listener: UdpSocket,
    upstream: Client,
}

impl App {
    pub async fn run(cfg: Config) -> Result<(), Error> {
        let app = App::try_from_config(cfg).await?;

        let mut buf = [0; 512];

        loop {
            let (len, addr) = app.listener.recv_from(&mut buf).await?;

            let app = app.clone();
            let buf = Vec::from(&buf[..len]);
            tokio::spawn(async move {
                if let Err(e) = app.forward(buf, addr).await {
                    error!("forwarding dns lookup error: {}", e)
                }
            });
        }
    }

    async fn try_from_config(cfg: Config) -> Result<Arc<Self>, Error> {
        let listener = try_iter(cfg.listen_addr.into_iter(), UdpSocket::bind).await?;

        let mut boot_strap = cfg.boot_strap_addr;
        let boot_strap = boot_strap.pop().unwrap().to_socket_addrs()?.next().unwrap();
        let upstream = try_iter(cfg.upstream_addr.into_iter(), |addr| {
            Client::try_from_string(addr, boot_strap)
        })
        .await?;

        Ok(Arc::new(Self { listener, upstream }))
    }

    async fn forward(&self, buf: Vec<u8>, addr: SocketAddr) -> Result<(), Error> {
        let res = self.upstream.proxy_doh(buf).await?;
        self.listener.send_to(res.as_slice(), addr).await?;
        Ok(())
    }
}

#[cold]
#[inline(never)]
async fn try_iter<I, F, Fut, T, E>(addr: I, func: F) -> Result<T, E>
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
