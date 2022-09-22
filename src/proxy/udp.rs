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
    fn proxy(&self, buf: Box<[u8]>) -> BoxFuture<'_, Result<Vec<u8>, Error>> {
        Box::pin(async move {
            let _permit = self.permit.acquire().await?;

            let socket = UdpSocket::bind("0.0.0.0:0").await?;
            socket.connect(self.addr).await?;

            socket.send(&buf).await?;

            let mut buf = vec![0; 512];

            let n = socket.recv(&mut buf).await?;

            let _ = buf.split_off(n);

            Ok(buf)
        })
    }
}

#[cfg(any(feature = "tls", feature = "https"))]
pub(super) async fn udp_resolve(
    boot_strap_addr: SocketAddr,
    hostname: &str,
    port: u16,
) -> std::io::Result<Vec<SocketAddr>> {
    use tracing::debug;

    use crate::dns::{DnsBuf, DnsPacket, DnsQuestion, DnsRecord, QueryType};

    debug!("resolving upstream host: {:?}", hostname);

    let mut buf = [0; 512];

    let mut dns_buf = DnsBuf::new(&mut buf);

    let mut dns_packet = DnsPacket::new();
    dns_packet
        .questions
        .push(DnsQuestion::new(String::from(hostname), QueryType::A));

    dns_packet.write(&mut dns_buf)?;

    let socket = UdpSocket::bind("0.0.0.0:0").await?;
    socket.connect(boot_strap_addr).await?;
    socket.send(dns_buf.as_slice()).await?;

    let len = socket.recv(&mut buf).await?;
    let mut dns_buf = DnsBuf::new(&mut buf[..len]);

    let mut dns_packet = DnsPacket::new();
    dns_packet.read(&mut dns_buf)?;

    let res = dns_packet
        .answers
        .into_iter()
        .filter_map(|answer| {
            debug!(
                "upstream host: {:?} resolved to dns record: {:?}",
                hostname, answer
            );
            match answer {
                DnsRecord::A { addr, .. } => Some((addr, port).into()),
                DnsRecord::AAAA { addr, .. } => Some((addr, port).into()),
                record => {
                    debug!("dns record: {:?} is not supported!", record);
                    None
                }
            }
        })
        .collect();

    Ok(res)
}
