use core::net::SocketAddr;

use tracing::debug;
use xitca_client::{
    http::{
        header::{HeaderMap, HeaderValue, ACCEPT, CONTENT_TYPE},
        Uri,
    },
    Connect, Service,
};

use crate::error::Error;

use super::{udp::udp_resolve, Proxy};

static DNS_MSG_HDR: HeaderValue = HeaderValue::from_static("application/dns-message");

pub struct HttpProxy {
    cli: xitca_client::Client,
    uri: Uri,
}

impl HttpProxy {
    pub async fn try_from_uri(uri: String, boot_strap_addr: SocketAddr) -> Result<Self, Error> {
        let uri = Uri::try_from(uri)?;

        let cli = xitca_client::Client::builder()
            .resolver(BootstrapResolver { boot_strap_addr })
            .rustls()
            .finish();

        Ok(Self { cli, uri })
    }
}

impl Proxy for HttpProxy {
    async fn proxy(&self, buf: Box<[u8]>) -> Result<Vec<u8>, Error> {
        let mut req = self.cli.post(self.uri.clone());

        req.headers_mut().insert(ACCEPT, DNS_MSG_HDR.clone());
        req.headers_mut().insert(CONTENT_TYPE, DNS_MSG_HDR.clone());

        let mut res = req.body(buf).send().await?;

        if res.status() != 200 {
            use std::{error, fmt};

            #[derive(Debug)]
            struct HttpError {
                uri: Uri,
                status: u16,
                headers: HeaderMap,
                body_string: String,
            }

            impl fmt::Display for HttpError {
                fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                    write!(
                        f,
                        "{:?} proxy error response {{ status: {:?}, headers: {:?}, body: {:?} }}",
                        &self.uri,
                        self.status,
                        &self.headers,
                        self.body_string.as_str()
                    )
                }
            }

            impl error::Error for HttpError {}

            let status = res.status().as_u16();
            let headers = std::mem::take(res.headers_mut());

            let body_string = res.string().await?;

            return Err(Box::new(HttpError {
                uri: self.uri.clone(),
                status,
                headers,
                body_string,
            }) as _);
        }

        debug!(
            "{:?} proxy response {{ status: {:?}, headers: {:?} }}",
            &self.uri,
            res.status(),
            res.headers()
        );

        res.body().await.map_err(Error::from)
    }
}

pub struct BootstrapResolver {
    boot_strap_addr: SocketAddr,
}

impl<'r, 'c> Service<&'r mut Connect<'c>> for BootstrapResolver {
    type Response = ();
    // possible error type when resolving failed.
    type Error = xitca_client::error::Error;

    async fn call(&self, connect: &'r mut Connect<'c>) -> Result<Self::Response, Self::Error> {
        let host = connect.hostname();
        let port = connect.port();
        let addrs = udp_resolve(self.boot_strap_addr, host, port).await?;
        connect.set_addrs(addrs);
        Ok(())
    }
}
