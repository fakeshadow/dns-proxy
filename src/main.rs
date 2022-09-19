mod cfg;
mod packet;

use std::{future::Future, io, net::SocketAddr, sync::Arc};

use tokio::net::UdpSocket;
use tracing::{error, info};

use self::cfg::{parse_arg, Config};

fn main() {
    let cfg = parse_arg();

    tracing_subscriber::fmt()
        .with_max_level(cfg.log_level)
        .init();

    if let Err(e) = run(cfg) {
        error!("fatal error: {}", e);
    }
}

fn run(cfg: Config) -> io::Result<()> {
    info!("starting dns-proxy with configration: {:?}", cfg);

    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(_run(cfg))
}

async fn _run(cfg: Config) -> io::Result<()> {
    let listen = try_addrs(cfg.listen_addr, UdpSocket::bind).await?;
    let listen = Arc::new(listen);

    let upstream = try_addrs(cfg.upstream_addr, |addr| async move {
        let socket = UdpSocket::bind("0.0.0.0:0").await?;
        socket.connect(addr).await?;
        Ok(socket)
    })
    .await?;

    let upstream = Arc::new(upstream);

    let mut buf = [0; 512];

    loop {
        let (len, addr) = listen.recv_from(&mut buf).await?;

        let listen = listen.clone();
        let upstream = upstream.clone();
        tokio::spawn(async move {
            if let Err(e) = forward(&upstream, &listen, &mut buf, len, addr).await {
                error!("forwarding dns lookup error: {}", e)
            }
        });
    }
}

async fn forward(
    upstream: &UdpSocket,
    listen: &UdpSocket,
    buf: &mut [u8],
    len: usize,
    addr: SocketAddr,
) -> io::Result<()> {
    let len2 = upstream.send(&buf[..len]).await?;
    assert_eq!(len, len2);
    let len = upstream.recv(buf).await?;
    listen.send_to(&buf[..len], addr).await?;
    Ok(())
}

#[cold]
#[inline(never)]
async fn try_addrs<F, Fut, O>(addr: Vec<SocketAddr>, func: F) -> io::Result<O>
where
    F: Fn(SocketAddr) -> Fut,
    Fut: Future<Output = io::Result<O>>,
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
