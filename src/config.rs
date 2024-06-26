/// Argument parsing.
use core::{net::SocketAddr, str::FromStr};

use std::net::ToSocketAddrs;

use bpaf::{construct, short, Parser};
use tracing::Level;

#[derive(Debug)]
pub struct Config {
    pub listen_addr: Vec<SocketAddr>,
    pub upstream_addr: Vec<UpstreamVariant>,
    pub boot_strap_addr: Vec<SocketAddr>,
    pub log_level: Level,
    pub thread_count: Option<usize>,
}

#[cold]
#[inline(never)]
pub fn parse_arg() -> Config {
    let thread_count = short('t')
        .long("thread")
        .help("OS thread count dns-proxy would spawn and opperate on in parallel")
        .argument::<usize>("THREAD")
        .optional();

    let listen_addr = short('l')
        .long("listen")
        .help("Local listening address for proxy")
        .argument::<String>("LISTEN")
        .fallback_with::<_, String>(|| Ok("0.0.0.0:53".to_owned()))
        .parse(|addr| addr.to_socket_addrs().map(Vec::from_iter));

    let upstream_addr = short('u')
        .long("upstream")
        .help("Upstream server for dns look up")
        .argument::<UpstreamVariant>("UPSTREAM")
        .some("--upstream argument must not be empty. At least one upstream dns server is needed");

    let boot_strap_addr = short('b')
        .long("bootstrap")
        .help("Bootstrap dns for resolving DoT/DoH upstreams")
        .argument::<String>("BOOT_STRAP")
        .fallback_with::<_, String>(|| Ok("1.1.1.1:53".to_owned()))
        .parse(|addr| addr.to_socket_addrs().map(Vec::from_iter));

    let log_level = short('L')
        .long("log-level")
        .help("Display level of logger: error,warn,info,debug,trace. number 1-5 can be used to represent level in the same order from error to trance")
        .argument::<Level>("LOG_LEVEL")
        .fallback(Level::INFO);

    construct!(Config {
        listen_addr,
        upstream_addr,
        boot_strap_addr,
        log_level,
        thread_count
    })
    .to_options()
    .run()
}

#[derive(Debug)]
pub enum UpstreamVariant {
    Udp(SocketAddr),
    #[cfg(feature = "tls")]
    Tls(String),
    #[cfg(feature = "https")]
    Https(String),
}

impl FromStr for UpstreamVariant {
    type Err = <SocketAddr as FromStr>::Err;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.trim();
        #[cfg(feature = "tls")]
        if s.starts_with("tls://") {
            return Ok(Self::Tls(String::from(s)));
        }

        #[cfg(feature = "https")]
        if s.starts_with("https://") {
            return Ok(Self::Https(String::from(s)));
        }

        s.parse().map(Self::Udp)
    }
}
