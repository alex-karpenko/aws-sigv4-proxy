pub mod client;
pub mod config;
pub mod credentials;
pub mod proxy;
pub mod signals;
pub mod signer;
pub mod utils;

#[cfg(test)]
mod tests {
    use aws_config::{BehaviorVersion, SdkConfig, meta::region::RegionProviderChain};
    use aws_credential_types::Credentials;
    use testcontainers::{
        ContainerAsync, Image, ImageExt,
        core::{Mount, WaitFor},
        runners::AsyncRunner,
    };
    use tokio::sync::OnceCell;

    const LOCALSTACK_IMAGE_NAME: &str = "localstack/localstack";
    const LOCALSTACK_IMAGE_TAG: &str = "4.6";
    const LOCALSTACK_IMAGE_DEFAULT_WAIT: u64 = 3000;
    const LOCALSTACK_DEFAULT_POSRT: u16 = 4566;

    #[derive(Default, Debug, Clone)]
    pub struct LocalStackImage {}

    impl Image for LocalStackImage {
        fn name(&self) -> &str {
            LOCALSTACK_IMAGE_NAME
        }

        fn tag(&self) -> &str {
            LOCALSTACK_IMAGE_TAG
        }

        fn ready_conditions(&self) -> Vec<WaitFor> {
            vec![
                WaitFor::message_on_stdout("Ready."),
                WaitFor::millis(LOCALSTACK_IMAGE_DEFAULT_WAIT),
            ]
        }
    }

    #[derive(Debug)]
    pub struct LocalStack {
        container: ContainerAsync<LocalStackImage>,
    }

    impl LocalStack {
        pub async fn new(name: &str, services: &[&str]) -> anyhow::Result<Self> {
            let with_lambda = services.contains(&"lambda");
            let services = services.join(",");

            let container = LocalStackImage::default()
                .with_env_var("SERVICES", services)
                .with_container_name(name);
            let container = if with_lambda {
                container.with_mount(Mount::bind_mount("/var/run/docker.sock", "/var/run/docker.sock"))
            } else {
                container
            };

            let container = container.start().await?;

            Ok(Self { container })
        }

        pub async fn get_port(&self) -> anyhow::Result<u16> {
            Ok(self.container.get_host_port_ipv4(LOCALSTACK_DEFAULT_POSRT).await?)
        }

        pub async fn get_host(&self) -> anyhow::Result<String> {
            Ok(self.container.get_host().await?.to_string())
        }

        #[allow(dead_code)]
        pub async fn remove(self) -> anyhow::Result<()> {
            self.container.stop().await?;
            Ok(self.container.rm().await?)
        }

        pub async fn get_aws_config(&self) -> SdkConfig {
            static INITED: OnceCell<SdkConfig> = OnceCell::const_new();

            let config = INITED
                .get_or_init(async || {
                    let credentials = Credentials::new("localstack", "localstack", None, None, "test");
                    let region_provider = RegionProviderChain::default_provider().or_else("us-east-1");

                    aws_config::defaults(BehaviorVersion::latest())
                        .region(region_provider)
                        .credentials_provider(credentials)
                        .endpoint_url(format!(
                            "http://{}:{}",
                            self.get_host().await.unwrap(),
                            self.get_port().await.unwrap()
                        ))
                        .load()
                        .await
                })
                .await;

            config.clone()
        }
    }
}
