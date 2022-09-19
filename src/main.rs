mod app;
mod config;
mod error;
mod http;
mod packet;

use tracing::{error, info};

use self::{
    app::App,
    config::{parse_arg, Config},
    error::Error,
};

fn main() {
    let cfg = parse_arg();

    tracing_subscriber::fmt()
        .with_max_level(cfg.log_level)
        .init();

    if let Err(e) = run(cfg) {
        error!("fatal error: {}", e);
    }
}

fn run(cfg: Config) -> Result<(), Error> {
    info!("starting dns-proxy with configration: {:?}", cfg);

    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?
        .block_on(App::run(cfg))
}
