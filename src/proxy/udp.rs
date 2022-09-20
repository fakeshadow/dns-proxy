use futures_core::future::BoxFuture;
use tokio::net::UdpSocket;

use crate::error::Error;

use super::Proxy;

pub struct UdpProxy {
    socket: UdpSocket,
}

impl Proxy for UdpProxy {
    fn proxy(&self, mut buf: Vec<u8>) -> BoxFuture<'_, Result<Vec<u8>, Error>> {
        Box::pin(async move {
            self.socket.send(&buf).await?;
            buf.clear();
            let n = self.socket.recv(&mut buf).await?;
            let _ = buf.split_off(n);
            Ok(buf)
        })
    }
}
