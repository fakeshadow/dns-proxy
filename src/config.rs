/// Argument parsing.
use std::{
    net::{SocketAddr, ToSocketAddrs},
    str::FromStr,
    vec,
};

use bpaf::{construct, short, Parser};
use tracing::Level;

#[derive(Debug)]
pub struct Config {
    pub listen_addr: Vec<SocketAddr>,
    pub upstream_addr: Vec<UpstreamVariant>,
    pub boot_strap_addr: Vec<SocketAddr>,
    pub log_level: Level,
}

#[cold]
#[inline(never)]
pub fn parse_arg() -> Config {
    let listen_addr = short('l')
        .long("listen")
        .help("Local listening address for proxy")
        .argument("LISTEN")
        .parse(|addr| addr.to_socket_addrs().map(Vec::from_iter))
        .fallback("0.0.0.0:53".to_socket_addrs().unwrap().collect());

    let upstream_addr = short('u')
        .long("upstream")
        .help("Upstream server for dns look up")
        .argument("UPSTREAM")
        .some("--upstream argment must not be empty. At least one upstream dns server is needed")
        .parse(|addr| {
            let mut upstream = Vec::new();

            for addr in addr {
                let addr = addr.parse::<UpstreamVariant>()?;
                upstream.push(addr);
            }
            Ok::<_, <SocketAddr as FromStr>::Err>(upstream)
        });

    let boot_strap_addr = short('b')
        .long("bootstrap")
        .help("Bootstrap server for resolving DoH upstreams")
        .argument("BOOT_STRAP")
        .parse(|addr| addr.to_socket_addrs().map(Vec::from_iter))
        .fallback("1.1.1.1:53".to_socket_addrs().unwrap().collect());

    let log_level = short('L')
        .long("log-level")
        .help("Display level of logger: error,warn,info,debug,trace. number 1-5 can be used to represent level in the same order from error to trance")
        .argument("LOG_LEVEL")
        .parse(|level| level.parse())
        .fallback(Level::INFO);

    construct!(Config {
        listen_addr,
        upstream_addr,
        boot_strap_addr,
        log_level
    })
    .to_options()
    .run()
}

#[derive(Debug)]
pub enum UpstreamVariant {
    Https(String),
    Udp(SocketAddr),
    Tls(SocketAddr),
}

impl FromStr for UpstreamVariant {
    type Err = <SocketAddr as FromStr>::Err;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.trim();
        if s.starts_with("https://") {
            return Ok(Self::Https(String::from(s)));
        }
        if s.ends_with(":853") {
            return s.parse().map(Self::Tls);
        }
        s.parse().map(Self::Udp)
    }
}
