use crate::config::Config;
use http_body_util::Full;
use hyper::body::Bytes;
use hyper_rustls::HttpsConnectorBuilder;
use hyper_util::{
    client::legacy::{Client, connect::HttpConnector},
    rt::TokioExecutor,
};
use std::{path::PathBuf, sync::Arc, time::Duration};
use tokio_rustls::rustls::{
    self, ClientConfig, RootCertStore, SignatureScheme,
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    pki_types::{CertificateDer, pem::PemObject},
};
use tracing::{debug, warn};

pub type HttpsClient = Client<hyper_rustls::HttpsConnector<HttpConnector>, Full<Bytes>>;

pub fn create_https_client(config: &Config) -> anyhow::Result<HttpsClient> {
    let mut http_connector = HttpConnector::new();
    http_connector.enforce_http(false);
    http_connector.set_connect_timeout(Some(Duration::from_secs(config.connect_timeout)));

    let https_connector = {
        if config.no_verify_ssl {
            warn!("TLS verification disabled");
            HttpsConnectorBuilder::default().with_tls_config(get_dangerous_tls_config())
        } else if let Some(ca) = &config.ca {
            debug!("using custom CA certificates");
            HttpsConnectorBuilder::default().with_tls_config(get_custom_ca_tls_config(ca)?)
        } else if let Ok(connector) = HttpsConnectorBuilder::default().with_native_roots() {
            connector
        } else {
            HttpsConnectorBuilder::default().with_webpki_roots()
        }
    };

    let https_connector = https_connector
        .https_or_http()
        .enable_http1()
        .wrap_connector(http_connector);

    let https_client = Client::builder(TokioExecutor::default()).build(https_connector);
    Ok(https_client)
}

fn get_dangerous_tls_config() -> ClientConfig {
    let store = RootCertStore::empty();

    let mut config = ClientConfig::builder()
        .with_root_certificates(store)
        .with_no_client_auth();

    // this completely disables cert-verification
    let mut dangerous_config = ClientConfig::dangerous(&mut config);
    dangerous_config.set_certificate_verifier(Arc::new(NoCertificateVerification {}));

    config
}

fn get_custom_ca_tls_config(ca: &PathBuf) -> anyhow::Result<ClientConfig> {
    let ca = CertificateDer::pem_file_iter(ca)?.collect::<Result<Vec<_>, _>>()?;
    let mut store = RootCertStore::empty();
    for cert in ca {
        store.add(cert)?;
    }

    let config = ClientConfig::builder()
        .with_root_certificates(store)
        .with_no_client_auth();

    Ok(config)
}

#[derive(Debug)]
struct NoCertificateVerification {}

impl ServerCertVerifier for NoCertificateVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::RSA_PKCS1_SHA1,
            SignatureScheme::ECDSA_SHA1_Legacy,
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::ECDSA_NISTP521_SHA512,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::ED25519,
            SignatureScheme::ED448,
        ]
    }
}
