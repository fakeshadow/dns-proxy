use std::{convert::TryFrom, net::SocketAddr};

use futures_core::future::BoxFuture;
use tracing::debug;
use xitca_client::{
    http::{
        header::{HeaderValue, ACCEPT, CONTENT_TYPE},
        Uri,
    },
    Resolve,
};

use crate::{
    error::Error,
    packet::{DnsBufReader, DnsPacket, DnsQuestion, DnsRecord, QueryType},
};

static DNS_MSG_HDR: HeaderValue = HeaderValue::from_static("application/dns-message");

pub struct Client {
    cli: xitca_client::Client,
    upstream_uri: Uri,
}

impl Client {
    pub async fn try_from_string(
        upstream: String,
        boot_strap_addr: SocketAddr,
    ) -> Result<Self, Error> {
        let upstream_uri = Uri::try_from(upstream)?;
        let cli = xitca_client::Client::builder()
            .resolver(BootstrapResolver { boot_strap_addr })
            .rustls()
            .finish();

        Ok(Self { cli, upstream_uri })
    }

    pub async fn proxy_doh(&self, body: Vec<u8>) -> Result<Vec<u8>, Error> {
        let mut req = self.cli.post(self.upstream_uri.clone())?;

        req.headers_mut().insert(ACCEPT, DNS_MSG_HDR.clone());
        req.headers_mut().insert(CONTENT_TYPE, DNS_MSG_HDR.clone());

        let res = req.body(body).send().await?;

        debug!(
            "forward dns query outcome. status_code: {:?}, headers: {:?}",
            res.status(),
            res.headers()
        );

        if res.status() != 200 {
            use std::{error, fmt};
            #[derive(Debug)]
            struct ToDoError;

            impl fmt::Display for ToDoError {
                fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                    f.write_str("doh server return non 200 status")
                }
            }

            impl error::Error for ToDoError {}

            return Err(Box::new(ToDoError) as _);
        }

        res.body().await.map_err(Error::from)
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

            let mut reader = DnsBufReader::new(&mut buf);

            let mut dns_packet = DnsPacket::new();
            dns_packet
                .questions
                .push(DnsQuestion::new(String::from(hostname), QueryType::A));

            dns_packet.write(&mut reader)?;

            let socket = tokio::net::UdpSocket::bind("0.0.0.0:0").await?;
            socket.connect(self.boot_strap_addr).await?;
            socket.send(reader.as_slice()).await?;

            let len = socket.recv(&mut buf).await?;
            let mut reader = DnsBufReader::new(&mut buf[..len]);
            let dns_packet = DnsPacket::from_buffer(&mut reader)?;

            let mut res = Vec::new();

            for answer in dns_packet.answers {
                debug!("http-client resolved to dns record: {:?}", answer);
                match answer {
                    DnsRecord::A { addr, .. } => res.push((addr, port).into()),
                    DnsRecord::AAAA { addr, .. } => res.push((addr, port).into()),
                    record => debug!("dns record: {:?} is not supported!", record),
                }
            }

            Ok(res)
        })
    }
}
