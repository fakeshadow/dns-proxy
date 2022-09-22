#[cfg(feature = "https")]
pub mod https;
#[cfg(feature = "tls")]
pub mod tls;

pub mod udp;

use futures_core::future::BoxFuture;

use crate::error::Error;

pub trait Proxy: Send + Sync {
    fn proxy(&self, buf: Box<[u8]>) -> BoxFuture<'_, Result<Vec<u8>, Error>>;
}
