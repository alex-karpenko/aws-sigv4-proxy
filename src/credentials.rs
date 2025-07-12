use aws_config::SdkConfig;
use aws_credential_types::{Credentials, provider::ProvideCredentials};
use std::{
    sync::atomic::{AtomicBool, Ordering},
    time::{Duration, SystemTime},
};
use tokio::sync::RwLock;
use tracing::{debug, warn};

const MINIMAL_REFRESH_WINDOW: Duration = Duration::from_secs(60); // 1 minute

#[derive(Debug)]
pub struct CachedCredentials {
    provider: Box<dyn ProvideCredentials>,
    cached: RwLock<Credentials>,
    next_refresh: RwLock<Option<SystemTime>>,
    refresh_window: Option<Duration>,
    in_refresh: AtomicBool,
}

impl CachedCredentials {
    pub async fn new(
        aws_config: &SdkConfig,
        assume_role: &Option<String>,
        signature_lifetime: Option<u64>,
    ) -> anyhow::Result<Self> {
        let provider: Box<dyn ProvideCredentials> = if let Some(role_arn) = assume_role {
            let provider = aws_config::sts::AssumeRoleProvider::builder(role_arn)
                .session_name(format!("{}-v{}", env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION")))
                .configure(aws_config)
                .build()
                .await;
            Box::new(provider)
        } else {
            let provider = aws_config.credentials_provider().unwrap();
            Box::new(provider)
        };

        let credentials = provider.provide_credentials().await?;
        let expiry = credentials.expiry();
        let credentials_lifetime = expiry.map(|e| e.duration_since(SystemTime::now()).unwrap());
        let signature_lifetime = signature_lifetime.map(Duration::from_secs);
        let refresh_window = Self::calc_refresh_window(signature_lifetime, credentials_lifetime);
        let next_refresh = RwLock::new(expiry.map(|e| e.checked_sub(refresh_window.unwrap()).unwrap()));

        debug!(?credentials, "credentials initialized");

        Ok(Self {
            provider,
            cached: RwLock::new(credentials),
            next_refresh,
            refresh_window,
            in_refresh: AtomicBool::new(false),
        })
    }

    fn calc_refresh_window(
        signature_lifetime: Option<Duration>,
        credentials_lifetime: Option<Duration>,
    ) -> Option<Duration> {
        debug!(?signature_lifetime, ?credentials_lifetime);

        let refresh_window = match (signature_lifetime, credentials_lifetime) {
            (_, None) => None,
            (None, Some(credentials_lifetime)) => Some(credentials_lifetime.checked_div(2).unwrap()),
            (Some(signature_lifetime), Some(credentials_lifetime)) => {
                if signature_lifetime < credentials_lifetime {
                    let delta = credentials_lifetime
                        .checked_sub(signature_lifetime)
                        .unwrap()
                        .checked_div(2)
                        .unwrap();
                    Some(signature_lifetime.checked_add(delta).unwrap())
                } else {
                    warn!(signature = ?signature_lifetime, credentials = ?credentials_lifetime, "Signature lifetime may be longer than credentials lifetime");
                    Some(
                        credentials_lifetime
                            .saturating_sub(MINIMAL_REFRESH_WINDOW)
                            .max(MINIMAL_REFRESH_WINDOW),
                    )
                }
            }
        };

        debug!(?refresh_window);
        refresh_window
    }

    pub async fn provide_credentials(&self) -> anyhow::Result<Credentials> {
        let to_refresh = if let Some(next_refresh) = self.next_refresh.read().await.as_ref()
            && next_refresh <= &SystemTime::now()
            && !self.in_refresh.fetch_or(true, Ordering::Acquire)
        {
            true
        } else {
            false
        };

        if to_refresh {
            // Refresh credentials
            debug!("refreshing credentials");
            let new_creads = self.provider.provide_credentials().await?;
            {
                *self.next_refresh.write().await = new_creads
                    .expiry()
                    .map(|e| e.checked_sub(self.refresh_window.unwrap()).unwrap());
                *self.cached.write().await = new_creads;
            }
            self.in_refresh.store(false, Ordering::Release);
        }

        Ok(self.cached.read().await.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    #[rstest]
    #[case(None, None, None)]
    #[case(Some(Duration::from_secs(3600)), None, None)]
    #[case(None, Some(Duration::from_secs(3600)), Some(Duration::from_secs(1800)))]
    #[case(
        Some(Duration::from_secs(1800)),
        Some(Duration::from_secs(3600)),
        Some(Duration::from_secs(2700))
    )]
    #[case(
        Some(Duration::from_secs(3600)),
        Some(Duration::from_secs(3600)),
        Some(Duration::from_secs(3540))
    )]
    fn test_calc_refresh_window(
        #[case] signature_lifetime: Option<Duration>,
        #[case] credentials_lifetime: Option<Duration>,
        #[case] expected: Option<Duration>,
    ) {
        let refresh_window = CachedCredentials::calc_refresh_window(signature_lifetime, credentials_lifetime);
        assert_eq!(refresh_window, expected);
    }
}
