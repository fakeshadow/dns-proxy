use std::net::SocketAddr;

use futures_core::future::BoxFuture;
use tokio::{net::UdpSocket, sync::Semaphore};

use crate::error::Error;

use super::Proxy;

// TODO: the efficiency of UdpProxy is a big no.
// To improve one must find a way to reuse a single UdpSocket for all dns look up. probably
// coupled with a dns cache to isolate the impact of out of order datagram received from upstream.
pub struct UdpProxy {
    addr: SocketAddr,
    permit: Semaphore,
}

impl UdpProxy {
    pub async fn try_from_addr(addr: SocketAddr) -> Result<Self, Error> {
        Ok(Self {
            addr,
            permit: Semaphore::new(64),
        })
    }
}

impl Proxy for UdpProxy {
    fn proxy(&self, mut buf: Vec<u8>) -> BoxFuture<'_, Result<Vec<u8>, Error>> {
        Box::pin(async move {
            let _permit = self.permit.acquire().await?;

            let socket = UdpSocket::bind("0.0.0.0:0").await?;
            socket.connect(self.addr).await?;

            buf.clear();
            let n = socket.recv(&mut buf).await?;

            let _ = buf.split_off(n);

            Ok(buf)
        })
    }
}
