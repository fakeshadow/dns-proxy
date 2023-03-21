#[cfg(feature = "https")]
pub mod https;
#[cfg(feature = "tls")]
pub mod tls;

pub mod udp;

use crate::{error::Error, util::BoxFuture};

pub trait Proxy: Send + Sync {
    fn proxy(&self, buf: Box<[u8]>) -> BoxFuture<'_, Result<Vec<u8>, Error>>;
}
