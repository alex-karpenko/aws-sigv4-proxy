use crate::{config::Config, credentials::CachedCredentials};
use aws_credential_types::Credentials;
use aws_sigv4::{
    http_request::{PayloadChecksumKind, SignableRequest, SigningInstructions, SigningSettings, sign},
    sign::v4,
};
use std::{
    sync::Arc,
    time::{Duration, SystemTime},
};
use tracing::debug;

#[derive(Debug, Clone)]
pub struct ProxySigner {
    service: String,
    region: String,
    credentials_provider: Arc<CachedCredentials>,
    signing_settings: SigningSettings,
}

impl ProxySigner {
    pub fn new(config: &Config, credentials_provider: CachedCredentials) -> Self {
        let service = config.service.as_ref().unwrap().clone();
        let region = config.region.as_ref().unwrap().clone();
        let expiring_timeout = Duration::from_secs(config.signature_lifetime.unwrap_or(config.request_timeout));

        let mut signing_settings = SigningSettings::default();
        signing_settings.expires_in = Some(expiring_timeout);
        signing_settings.payload_checksum_kind = PayloadChecksumKind::XAmzSha256;

        Self {
            service,
            region,
            credentials_provider: Arc::new(credentials_provider),
            signing_settings,
        }
    }

    #[inline]
    async fn provide_credentials(&self) -> anyhow::Result<Credentials> {
        let creds = self.credentials_provider.provide_credentials().await?;
        debug!(expry = ?(creds.expiry().unwrap_or_else(SystemTime::now).duration_since(SystemTime::now()).unwrap()));
        Ok(creds)
    }

    #[inline]
    fn signing_settings(&self) -> SigningSettings {
        self.signing_settings.clone()
    }

    pub async fn sign(&self, req: SignableRequest<'_>) -> anyhow::Result<SigningInstructions> {
        let identity = self.provide_credentials().await?.into();
        let params = v4::SigningParams::builder()
            .identity(&identity)
            .region(&self.region)
            .name(&self.service)
            .time(SystemTime::now())
            .settings(self.signing_settings())
            .build()?
            .into();

        let (instructions, _) = sign(req, &params)?.into_parts();
        Ok(instructions)
    }
}
