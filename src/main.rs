#![forbid(unsafe_code)]
#![feature(type_alias_impl_trait)]

mod app;
mod config;
#[cfg(any(feature = "tls", feature = "https"))]
mod dns;
mod error;
mod proxy;

use tracing::{error, info};

use self::{
    app::App,
    config::{parse_arg, Config},
    error::Error,
};

fn main() {
    let cfg = parse_arg();

    tracing_subscriber::fmt()
        .with_env_filter(format!("dns_proxy={}", cfg.log_level.as_str()))
        .init();

    if let Err(e) = run(cfg) {
        error!("fatal error: {}", e);
    }
}

fn run(cfg: Config) -> Result<(), Error> {
    info!("starting dns-proxy with configuration: {:?}", cfg);

    let mut rt = tokio::runtime::Builder::new_multi_thread();

    if let Some(count) = cfg.thread_count {
        rt.worker_threads(count);
    }

    rt.enable_all().build()?.block_on(App::run(cfg))
}
