use crate::config::Config;
use aws_credential_types::provider::ProvideCredentials;
use aws_sigv4::{
    http_request::{PayloadChecksumKind, SignableRequest, SigningInstructions, SigningSettings, sign},
    sign::v4,
};
use aws_smithy_runtime_api::client::identity::Identity;
use std::{
    sync::Arc,
    time::{Duration, SystemTime},
};
use tracing::debug;

#[derive(Debug, Clone)]
pub struct ProxySigner {
    service: String,
    region: String,
    credentials_provider: Arc<Box<dyn ProvideCredentials>>,
    signing_settings: SigningSettings,
}

impl ProxySigner {
    pub fn new(config: &Config, credentials_provider: Box<dyn ProvideCredentials>) -> Self {
        let service = config.service.as_ref().unwrap().clone();
        let region = config.region.as_ref().unwrap().clone();
        let signature_lifetime = Duration::from_secs(config.signature_lifetime.unwrap_or(config.request_timeout));

        let mut signing_settings = SigningSettings::default();
        signing_settings.expires_in = Some(signature_lifetime);
        signing_settings.payload_checksum_kind = PayloadChecksumKind::XAmzSha256;

        Self {
            service,
            region,
            credentials_provider: Arc::new(credentials_provider),
            signing_settings,
        }
    }

    pub async fn sign(&self, req: SignableRequest<'_>) -> anyhow::Result<SigningInstructions> {
        let identity: Identity = self.credentials_provider.provide_credentials().await?.into();
        debug!(expiry = ?(identity.expiration().unwrap_or_else(SystemTime::now).duration_since(SystemTime::now())?));

        let params = v4::SigningParams::builder()
            .identity(&identity)
            .region(&self.region)
            .name(&self.service)
            .time(SystemTime::now())
            .settings(self.signing_settings.clone())
            .build()?
            .into();

        let (instructions, _) = sign(req, &params)?.into_parts();
        Ok(instructions)
    }
}
