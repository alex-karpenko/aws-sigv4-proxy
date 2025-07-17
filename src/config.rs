use anyhow::Error;
use aws_config::{AppName, BehaviorVersion, Region, SdkConfig};
use aws_credential_types::provider::ProvideCredentials;
use aws_smithy_runtime::client::identity::IdentityCache;
use clap::Parser;
use http::Uri;
use std::{
    net::{IpAddr, SocketAddr},
    path::PathBuf,
    time::Duration,
};

pub const DEFAULT_CONNECT_TIMEOUT: u64 = 10;
pub const DEFAULT_REQUEST_TIMEOUT: u64 = 30;
pub const DEFAULT_LISTEN_ON: &str = "0.0.0.0:8080";
pub const DEFAULT_UTILITY_PORT: u16 = 9090;

const DEFAULT_IDENTITY_CACHE_BUFFER_TIME: Duration = Duration::from_secs(60);

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
pub struct Config {
    /// URL of the AWS service to forward requests to
    #[arg(long, short = 'f')]
    pub forward_to: Uri,

    /// AWS signing service name (default is detected from the URL)
    #[arg(long, short = 's')]
    pub service: Option<String>,

    /// Override signing region (default is detected from the AWS config)
    #[arg(long, short = 'r')]
    pub region: Option<String>,

    /// Assume role ARN to use for signing requests
    #[arg(long, short = 'a')]
    pub assume_role: Option<String>,

    /// Port and optional IP address to listen on
    #[arg(long, short = 'l', default_value = DEFAULT_LISTEN_ON, value_parser = Config::parse_listen_on)]
    pub listen_on: SocketAddr,

    /// Port to respond on health checks and metrics requests
    #[arg(long, short = 'u', default_value_t = DEFAULT_UTILITY_PORT, value_parser = clap::value_parser!(u16).range(1..=65535))]
    pub utility_port: u16,

    /// Proxy connect timeout in seconds
    #[arg(long, default_value_t = DEFAULT_CONNECT_TIMEOUT, value_parser = clap::value_parser!(u64).range(1..=3600))]
    pub connect_timeout: u64,

    /// Proxy request timeout in seconds
    #[arg(long, default_value_t = DEFAULT_REQUEST_TIMEOUT, value_parser = clap::value_parser!(u64).range(1..=3600))]
    pub request_timeout: u64,

    /// Signature expiration timeout in seconds
    #[arg(long, value_parser = clap::value_parser!(u64).range(1..=3600))]
    pub signature_lifetime: Option<u64>,

    /// Path to a custom root CA bundle file (use a system bundle by default)
    #[arg(long)]
    pub ca: Option<PathBuf>,

    /// Skip SSL verification for outgoing connections
    #[arg(long, default_value = "false")]
    pub no_verify_ssl: bool,

    /// Path to a server certificates file bundle (enables TLS, disabled by default)
    #[arg(long, short = 'c', requires = "key")]
    pub cert: Option<PathBuf>,

    /// Path to certificate's private key file (enables TLS, disabled by default)
    #[arg(long, short = 'k', requires = "cert")]
    pub key: Option<PathBuf>,
}

impl Config {
    pub async fn load_default_aws_config(&self) -> anyhow::Result<SdkConfig> {
        let buffer_time = self
            .signature_lifetime
            .map(Duration::from_secs)
            .unwrap_or(Duration::ZERO)
            + DEFAULT_IDENTITY_CACHE_BUFFER_TIME;
        let identity_cache = IdentityCache::lazy().buffer_time(buffer_time).build();
        let aws_config = aws_config::defaults(BehaviorVersion::latest()).identity_cache(identity_cache);

        // Set region if provided
        let aws_config = if let Some(region) = &self.region {
            aws_config.region(Region::new(region.clone()))
        } else {
            aws_config
        };

        // Finish config
        Ok(aws_config.app_name(AppName::new(env!("CARGO_PKG_NAME"))?).load().await)
    }

    pub async fn get_credentials_provider(&self, aws_config: &SdkConfig) -> Box<dyn ProvideCredentials> {
        if let Some(role_arn) = self.assume_role.as_ref() {
            let provider = aws_config::sts::AssumeRoleProvider::builder(role_arn)
                .session_name(format!("{}-v{}", env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION")))
                .configure(aws_config)
                .build()
                .await;
            Box::new(provider)
        } else {
            let provider = aws_config.credentials_provider().unwrap();
            Box::new(provider)
        }
    }

    pub async fn apply_aws_config(self, aws_config: &SdkConfig) -> anyhow::Result<Self> {
        let region = self.region.clone().unwrap_or(aws_config.region().unwrap().to_string()); // TODO: Handle AWS config error
        Ok(Self {
            service: Some(self.get_service(&region)?),
            region: Some(region),
            ..self
        })
    }

    fn get_service(&self, region: &String) -> anyhow::Result<String> {
        if let Some(service) = &self.service {
            Ok(service.clone())
        } else if let Some(service) = self.resolve_service_from_url(region) {
            Ok(service)
        } else {
            Err(Error::msg("unable to determine service"))
        }
    }

    fn resolve_service_from_url(&self, region: &String) -> Option<String> {
        let host = self.forward_to.host()?;

        // parse aws endpoint
        // service-code.region-code.amazonaws.com
        let parts = host.split('.').collect::<Vec<&str>>();
        if parts.len() >= 4 && parts[parts.len() - 1] == "com" && parts[parts.len() - 2] == "amazonaws" {
            if parts[parts.len() - 3] == region {
                Some(parts[parts.len() - 4].to_string())
            } else if parts[parts.len() - 4] == region {
                Some(parts[parts.len() - 3].to_string())
            } else {
                None
            }
        } else {
            None
        }
    }

    fn parse_listen_on(s: &str) -> Result<SocketAddr, String> {
        let splitted = s.split(':').collect::<Vec<&str>>();
        if splitted.len() != 2 {
            return Err("invalid listen address".to_string());
        }
        let ip: IpAddr = if splitted[0].is_empty() {
            IpAddr::from([0, 0, 0, 0])
        } else {
            splitted[0].parse().map_err(|_| String::from("invalid IP address"))?
        };
        let port: u16 = splitted[1].parse().map_err(|_| String::from("invalid port"))?;

        if port == 0 {
            return Err("invalid port".to_string());
        }

        Ok(SocketAddr::new(ip, port))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    #[test]
    fn test_parse_listen_on() {
        assert_eq!(
            Config::parse_listen_on("127.0.0.1:8080"),
            Ok(SocketAddr::new("127.0.0.1".parse().unwrap(), 8080))
        );
        assert_eq!(
            Config::parse_listen_on("0.0.0.0:8080"),
            Ok(SocketAddr::new("0.0.0.0".parse().unwrap(), 8080))
        );
        assert_eq!(
            Config::parse_listen_on(":12345"),
            Ok(SocketAddr::new("0.0.0.0".parse().unwrap(), 12345))
        );
        assert_eq!(
            Config::parse_listen_on("127.0.0.1:0"),
            Err(String::from("invalid port"))
        );
        assert_eq!(Config::parse_listen_on("127.0.0.1:"), Err(String::from("invalid port")));
        assert_eq!(
            Config::parse_listen_on("127.0.0.1"),
            Err(String::from("invalid listen address"))
        );
        assert_eq!(
            Config::parse_listen_on("192.168.256.321.0.0.1:8080"),
            Err(String::from("invalid IP address"))
        );
        assert_eq!(
            Config::parse_listen_on("127.0.0.1:65536"),
            Err(String::from("invalid port"))
        );
        assert_eq!(
            Config::parse_listen_on("12345:12345"),
            Err(String::from("invalid IP address"))
        );
    }

    #[rstest]
    #[case("https://qqq.www.com", "eu-west-1", None, None)]
    #[case("https://ec2.eu-west-1.www.com", "eu-west-1", None, None)]
    #[case("https://ec2.eu-west-1.amazonaws.com", "eu-west-1", None, Some("ec2"))]
    #[case("https://eu-west-1.ec2.amazonaws.com", "eu-west-1", None, Some("ec2"))]
    #[case("https://ec2.eu-central-1.amazonaws.com", "eu-west-1", None, None)]
    #[case("https://qqq.www.com", "eu-west-1", Some("ecr"), Some("ecr"))]
    #[case("https://ec2.eu-west-1.www.com", "eu-west-1", Some("ecr"), Some("ecr"))]
    #[case("https://ec2.eu-west-1.amazonaws.com", "eu-west-1", Some("ecr"), Some("ecr"))]
    #[case("https://eu-west-1.ec2.amazonaws.com", "eu-west-1", Some("ecr"), Some("ecr"))]
    #[case("https://ec2.eu-central-1.amazonaws.com", "eu-west-1", Some("ecr"), Some("ecr"))]
    #[tokio::test]
    async fn test_get_service(
        #[case] forward_to: String,
        #[case] region: String,
        #[case] service: Option<&str>,
        #[case] expected: Option<&str>,
    ) {
        let config = Config {
            forward_to: forward_to.parse().unwrap(),
            service: service.map(|s| s.to_string()),
            region: Some(region.clone()),
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
        };

        let service = config.get_service(&region);
        if let Some(expected) = expected {
            assert_eq!(service.unwrap(), expected);
        } else {
            assert!(service.is_err());
        }
    }
}
