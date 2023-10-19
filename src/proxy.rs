#[cfg(feature = "https")]
pub mod https;
#[cfg(feature = "tls")]
pub mod tls;

pub mod udp;

use core::future::Future;

use crate::{error::Error, util::BoxFuture};

/// general purpose trait for a dns proxy where it take in raw dns query bytes and output
/// raw dns response bytes.
pub trait Proxy: Send + Sync {
    fn proxy(&self, buf: Box<[u8]>) -> impl Future<Output = Result<Vec<u8>, Error>> + Send;
}

// helper trait making Proxy trait object safe.
pub(crate) trait ProxyDyn: Send + Sync {
    fn proxy_dyn(&self, buf: Box<[u8]>) -> BoxFuture<'_, Result<Vec<u8>, Error>>;
}

impl<P> ProxyDyn for P
where
    P: Proxy,
{
    #[inline]
    fn proxy_dyn(&self, buf: Box<[u8]>) -> BoxFuture<'_, Result<Vec<u8>, Error>> {
        Box::pin(self.proxy(buf))
    }
}
