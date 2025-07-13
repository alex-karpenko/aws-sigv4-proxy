use crate::{
    client::{HttpsClient, create_https_client},
    config::Config,
    credentials::CachedCredentials,
    signals::ShutdownReceiver,
    signer::ProxySigner,
};
use aws_sigv4::http_request::{SignableBody, SignableRequest};
use http::{
    Request, Response, Uri,
    request::Parts,
    uri::{Authority, PathAndQuery, Scheme},
};
use http_body_util::{BodyExt, Full};
use hyper::{
    body::{Bytes, Incoming},
    server::conn::http1,
    service::Service,
};
use hyper_util::rt::{TokioIo, TokioTimer};
use std::{pin::Pin, sync::Arc, time::Duration};
use tokio::{
    net::TcpListener,
    select,
    task::{self, JoinHandle},
    time,
};
use tokio_rustls::{
    TlsAcceptor,
    rustls::{
        self,
        pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject},
    },
};
use tracing::{debug, error, info, warn};

#[derive(Debug, Clone)]
pub struct ProxyHandler {
    signer: ProxySigner,
    target_scheme: Scheme,
    target_authority: Authority,
    client: HttpsClient,
}

impl ProxyHandler {
    pub fn new(config: &Config, credentials_provider: CachedCredentials) -> anyhow::Result<Self> {
        let signer = ProxySigner::new(config, credentials_provider);
        let forward_to = config.forward_to.clone();
        let client = create_https_client(config)?;

        Ok(Self {
            signer,
            target_scheme: forward_to.scheme().unwrap().clone(),
            target_authority: forward_to.authority().unwrap().clone(),
            client,
        })
    }

    async fn handle(self, parts: Parts, body: Bytes) -> anyhow::Result<Response<Incoming>> {
        let original_path_and_query = parts
            .uri
            .path_and_query()
            .unwrap_or(&PathAndQuery::from_static("/"))
            .clone();
        debug!(?original_path_and_query);

        let uri = Uri::builder()
            .scheme(self.target_scheme)
            .authority(self.target_authority)
            .path_and_query(original_path_and_query)
            .build()?;
        debug!(?uri);

        let headers = parts
            .headers
            .iter()
            .filter(|(n, _v)| *n != http::header::HOST)
            .collect::<Vec<_>>();
        debug!(?headers);

        let method = parts.method;
        let signable_request = SignableRequest::new(
            method.as_str(),
            uri.to_string(),
            headers
                .iter()
                .map(|(k, v)| (k.as_str(), std::str::from_utf8(v.as_bytes()).unwrap())),
            SignableBody::Bytes(&body),
        )?;
        debug!(?signable_request);

        // Sign and then apply the signature to the request.
        let signing_instructions = self.signer.sign(signable_request).await?;
        let mut signed_request = headers
            .iter()
            .fold(http::Request::builder(), |b, (n, v)| b.header(*n, *v))
            .uri(uri)
            .method(method)
            .body(Full::<Bytes>::from(body))?;

        signing_instructions.apply_to_request_http1x(&mut signed_request);
        debug!(?signed_request);

        Ok(self.client.request(signed_request).await?)
    }
}

impl Service<Request<Incoming>> for ProxyHandler {
    type Response = Response<Incoming>;
    type Error = anyhow::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn call(&self, req: Request<Incoming>) -> Self::Future {
        let handler = self.clone();
        let (parts, body) = req.into_parts();

        Box::pin(async move { handler.handle(parts, body.collect().await?.to_bytes()).await })
    }
}

pub async fn listener(
    cfg: &Config,
    credentials_provider: CachedCredentials,
    mut rx: ShutdownReceiver,
) -> anyhow::Result<JoinHandle<anyhow::Result<()>>> {
    let req_handler = Arc::new(ProxyHandler::new(cfg, credentials_provider)?);
    let cfg_timeout = Duration::from_secs(cfg.request_timeout);
    let tcp_listener = TcpListener::bind(cfg.listen_on).await?;
    let tls_acceptor = if let (Some(cert), Some(key)) = (cfg.cert.clone(), cfg.key.clone()) {
        let certs = CertificateDer::pem_file_iter(cert)?.collect::<Result<Vec<_>, _>>()?;
        let key = PrivateKeyDer::from_pem_file(key)?;
        let tls_config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)?;
        let acceptor = TlsAcceptor::from(Arc::new(tls_config));
        Some(acceptor)
    } else {
        None
    };

    let task = task::spawn(async move {
        let cloned_rx = rx.clone();
        info!("Proxy listener started");

        loop {
            select! {
                accepted = tcp_listener.accept() => {
                    let (stream, addr) = accepted?;
                    debug!(from=%addr, "accepted connection");

                    let handler = req_handler.clone();
                    let rx = cloned_rx.clone();

                    if let Some(tls_acceptor) = tls_acceptor.clone() {
                        let stream = tls_acceptor.accept(stream).await;
                        let stream = match stream {
                            Ok(stream) => stream,
                            Err(err) => {
                                warn!(error = ?err, "Error accepting TLS connection");
                                continue;
                            }
                        };

                        let io = TokioIo::new(stream);
                        task::spawn(async move {
                            let _shutdown_guard = rx.has_changed(); // Guard to wait on request completion after shutdown signal
                            match time::timeout(cfg_timeout, http1::Builder::new()
                                .timer(TokioTimer::new())
                                .serve_connection(io, handler))
                                .await {
                                    Ok(result) => {
                                        if let Err(err) = result {
                                            error!(error = ?err, "Error serving connection");
                                        }
                                    },
                                    Err(_) => {
                                        error!("Timeout serving connection");
                                    }
                                }
                        });
                    } else {
                        let io = TokioIo::new(stream);
                        task::spawn(async move {
                            let _shutdown_guard = rx.has_changed(); // Guard to wait on request completion after shutdown signal
                            match time::timeout(cfg_timeout, http1::Builder::new()
                                .timer(TokioTimer::new())
                                .serve_connection(io, handler))
                                .await {
                                    Ok(result) => {
                                        if let Err(err) = result {
                                            error!(error = ?err, "Error serving connection");
                                        }
                                    },
                                    Err(_) => {
                                        error!("Timeout serving connection");
                                    }
                                }
                        });
                    }
                }
                _ = rx.changed() => {
                    debug!("shutdown signal received");
                    drop(tcp_listener);
                    break;
                }
            }
        }

        Ok(())
    });

    Ok(task)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        config::{Config, DEFAULT_CONNECT_TIMEOUT, DEFAULT_REQUEST_TIMEOUT},
        tests::LocalStack,
    };
    use aws_config::SdkConfig;
    use aws_sdk_s3::primitives::{ByteStream, SdkBody};
    use http::Method;
    use tokio::sync::OnceCell;

    async fn init() {
        static INITED: OnceCell<()> = OnceCell::const_new();

        INITED
            .get_or_init(async || {
                tracing_subscriber::fmt::init();
            })
            .await;
    }

    async fn init_localstack() -> anyhow::Result<SdkConfig> {
        static INITED: OnceCell<LocalStack> = OnceCell::const_new();

        let stack = INITED
            .get_or_init(async || LocalStack::new("test", &["sts", "s3", "es"]).await.unwrap())
            .await;

        Ok(stack.get_aws_config().await)
    }

    fn get_raw_test_config(forward_to: impl Into<String>, service: Option<String>, region: Option<String>) -> Config {
        Config {
            forward_to: forward_to.into().parse().unwrap(),
            service,
            region,
            assume_role: None,
            listen_on: "127.0.0.1:8080".parse().unwrap(),
            request_timeout: DEFAULT_REQUEST_TIMEOUT,
            connect_timeout: DEFAULT_CONNECT_TIMEOUT,
            signature_lifetime: None,
            no_verify_ssl: false,
            ca: None,
            cert: None,
            key: None,
            utility_port: 9090,
        }
    }

    pub async fn get_test_local_config(
        service: Option<String>,
        region: Option<String>,
    ) -> anyhow::Result<(Config, SdkConfig)> {
        let aws_config = init_localstack().await?;
        let forward_to = aws_config.endpoint_url().unwrap().to_string();
        let config = get_raw_test_config(forward_to, service, region);
        let config = config.apply_aws_config(&aws_config).await?;

        Ok((config, aws_config))
    }

    async fn setup_test_s3(
        config: &SdkConfig,
        bucket_name: &str,
        key: &str,
        body: ByteStream,
    ) -> anyhow::Result<aws_sdk_s3::Client> {
        let s3_client_config: aws_sdk_s3::Config = aws_sdk_s3::Config::from(config)
            .to_builder()
            .force_path_style(true)
            .build();
        let client = aws_sdk_s3::Client::from_conf(s3_client_config);

        client.create_bucket().bucket(bucket_name).send().await?;
        client
            .put_object()
            .bucket(bucket_name)
            .key(key)
            .body(body)
            .send()
            .await?;

        Ok(client)
    }

    #[tokio::test]
    async fn test_s3_get_local() {
        const BUCKET_NAME: &str = "test-bucket";
        const FILE_NAME: &str = "some-file-name";

        init().await;

        let (config, aws_config) = get_test_local_config(Some("s3".to_string()), None).await.unwrap();
        let credentials_provider = CachedCredentials::new(&aws_config, &config.assume_role, None)
            .await
            .unwrap();
        let endpoint = aws_config.endpoint_url().unwrap();
        let body = ByteStream::new(SdkBody::from("test-body"));
        let _s3_client = setup_test_s3(&aws_config, BUCKET_NAME, FILE_NAME, body).await.unwrap();

        let (parts, body) = http::Request::builder()
            .uri(format!("{endpoint}/{BUCKET_NAME}/{FILE_NAME}"))
            .method(Method::GET)
            .body(Bytes::default())
            .unwrap()
            .into_parts();

        let proxy = ProxyHandler::new(&config, credentials_provider).unwrap();
        let resp = proxy.handle(parts, body).await.unwrap();
        assert_eq!(resp.status(), 200);

        let (parts, body) = resp.into_parts();
        assert_eq!(parts.status, 200);

        let bytes = body.collect().await.unwrap().to_bytes();
        assert!(!bytes.is_empty());

        assert_eq!(bytes, "test-body");
    }
}
