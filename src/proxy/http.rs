use std::{convert::TryFrom, net::SocketAddr};

use futures_core::future::BoxFuture;
use tokio::net::UdpSocket;
use tracing::debug;
use xitca_client::{
    http::{
        header::{HeaderMap, HeaderValue, ACCEPT, CONTENT_TYPE},
        Uri,
    },
    Resolve,
};

use crate::{
    dns::{DnsBuf, DnsPacket, DnsQuestion, DnsRecord, QueryType},
    error::Error,
};

use super::Proxy;

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
    fn proxy(&self, buf: Box<[u8]>) -> BoxFuture<'_, Result<Vec<u8>, Error>> {
        Box::pin(async move {
            let mut req = self.cli.post(self.uri.clone())?;

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
        })
    }
}

pub struct BootstrapResolver {
    boot_strap_addr: SocketAddr,
}

/// a custom self contained dns resolver in case proxy is used as the only dns resolver.
impl Resolve for BootstrapResolver {
    fn resolve<'s, 'h, 'f>(
        &'s self,
        hostname: &'h str,
        port: u16,
    ) -> BoxFuture<'f, Result<Vec<SocketAddr>, xitca_client::error::Error>>
    where
        's: 'f,
        'h: 'f,
    {
        Box::pin(async move {
            debug!("http-client resolving host: {}", hostname);

            let mut buf = [0; 512];

            let mut dns_buf = DnsBuf::new(&mut buf);

            let mut dns_packet = DnsPacket::new();
            dns_packet
                .questions
                .push(DnsQuestion::new(String::from(hostname), QueryType::A));

            dns_packet.write(&mut dns_buf)?;

            let socket = UdpSocket::bind("0.0.0.0:0").await?;
            socket.connect(self.boot_strap_addr).await?;
            socket.send(dns_buf.as_slice()).await?;

            let len = socket.recv(&mut buf).await?;
            let mut dns_buf = DnsBuf::new(&mut buf[..len]);

            let mut dns_packet = DnsPacket::new();
            dns_packet.read(&mut dns_buf)?;

            let res = dns_packet
                .answers
                .into_iter()
                .filter_map(|answer| {
                    debug!("http-client resolved to dns record: {:?}", answer);
                    match answer {
                        DnsRecord::A { addr, .. } => Some((addr, port).into()),
                        DnsRecord::AAAA { addr, .. } => Some((addr, port).into()),
                        record => {
                            debug!("dns record: {:?} is not supported!", record);
                            None
                        }
                    }
                })
                .collect();

            Ok(res)
        })
    }
}
