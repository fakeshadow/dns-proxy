use core::net::SocketAddr;

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
    async fn proxy(&self, buf: Box<[u8]>) -> Result<Vec<u8>, Error> {
        let _permit = self.permit.acquire().await?;

        let socket = UdpSocket::bind("0.0.0.0:0").await?;
        socket.connect(self.addr).await?;

        socket.send(&buf).await?;

        let mut buf = vec![0; 512];

        let n = socket.recv(&mut buf).await?;

        buf.truncate(n);

        Ok(buf)
    }
}

#[cfg(any(feature = "tls", feature = "https"))]
pub(super) async fn udp_resolve(
    boot_strap_addr: SocketAddr,
    hostname: &str,
    port: u16,
) -> std::io::Result<Vec<SocketAddr>> {
    use tracing::debug;

    use core::time::Duration;

    use tokio::time::timeout;

    use crate::dns::{Buf, Packet, Query, Question, Record};

    debug!("resolving upstream host: {hostname}");

    let mut buf = [0; 512];

    let mut dns_buf = Buf::new(&mut buf);

    let mut dns_packet = Packet::new_ref();
    dns_packet
        .questions
        .push(Question::new(String::from(hostname), Query::A));

    dns_packet.write(&mut dns_buf)?;

    let socket = UdpSocket::bind("0.0.0.0:0").await?;
    socket.connect(boot_strap_addr).await?;

    let mut retry = 0;

    let send_buf = dns_buf.as_slice().to_vec();

    let len = loop {
        socket.send(send_buf.as_slice()).await?;

        match timeout(Duration::from_secs(2), socket.recv(&mut buf)).await {
            Ok(res) => break res?,
            Err(_) => {
                retry += 1;
                if retry > 10 {
                    return Err(std::io::ErrorKind::TimedOut.into());
                }
            }
        }
    };

    let mut dns_packet = Packet::new();
    dns_packet.read(&mut Buf::new(&mut buf[..len]))?;

    let res = dns_packet
        .answers
        .into_iter()
        .filter_map(|answer| {
            debug!("upstream host: {hostname} resolved to dns record: {answer:?}");
            match answer.record() {
                Record::A { addr, .. } => Some((*addr, port).into()),
                Record::AAAA { addr, .. } => Some((*addr, port).into()),
                record => {
                    debug!("dns record: {record:?} is not supported!");
                    None
                }
            }
        })
        .collect();

    Ok(res)
}
