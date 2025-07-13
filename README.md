# aws-sigv4-proxy

<p>
<a href="https://github.com/alex-karpenko/aws-sigv4-proxy/actions/workflows/ci.yaml" rel="nofollow"><img src="https://img.shields.io/github/actions/workflow/status/alex-karpenko/aws-sigv4-proxy/ci.yaml?label=ci" alt="CI status"></a>
<a href="https://github.com/alex-karpenko/aws-sigv4-proxy/actions/workflows/audit.yaml" rel="nofollow"><img src="https://img.shields.io/github/actions/workflow/status/alex-karpenko/aws-sigv4-proxy/audit.yaml?label=audit" alt="Audit status"></a>
<a href="https://github.com/alex-karpenko/aws-sigv4-proxy/actions/workflows/publish-image.yaml" rel="nofollow"><img src="https://img.shields.io/github/actions/workflow/status/alex-karpenko/aws-sigv4-proxy/publish-image.yaml?label=publish" alt="Docker image publishing status"></a>
<a href="https://app.codecov.io/github/alex-karpenko/aws-sigv4-proxy" rel="nofollow"><img src="https://img.shields.io/codecov/c/github/alex-karpenko/aws-sigv4-proxy" alt="License"></a>
<a href="https://github.com/alex-karpenko/aws-sigv4-proxy/blob/HEAD/LICENSE" rel="nofollow"><img src="https://img.shields.io/github/license/alex-karpenko/aws-sigv4-proxy" alt="License"></a>
</p>

**aws-sigv4-proxy** is a tiny proxy service that signs each request using [AWS SigV4](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_sigv.html)
and makes possible accessing AWS services with authentication from callers (services)
which are unable to authenticate themselves against AWS.

For now, this is just a pet project in development. It's not thoroughly tested yet, so patches will be here soon.

There are at least two other projects with the similar functionality, but unfortunately, with some minor issues:
- [aws-es-proxy](https://github.com/abutaha/aws-es-proxy) by [abutaha](https://github.com/abutaha) - isn't supported for more than 2 years;
- [aws-sigv4-proxy](https://github.com/awslabs/aws-sigv4-proxy) by [awslabs](https://github.com/awslabs) - has at least [one unresolved issue](https://github.com/awslabs/aws-sigv4-proxy/issues/67) which makes it unusable in some circumstances I encountered with.

## How to use

The easiest way to run `aws-sigv4-proxy` is to use [Docker image](#docker-image).
If you use Kubernetes to run workload, you can use [Helm chart](#helm-chart) to configure and deploy `aws-sigv4-proxy`.
The third way to run `aws-sigv4-proxy` is to [build native Rust binary](#build-your-own-binary) using Cargo utility and
run it.

### Docker image

Use the following command to get usage help, the same as running it with `--help` command line option:

```bash
docker run --rm alexkarpenko/aws-sigv4-proxy:latest
```

Typical output is:

```console
Proxy to apply AWS SigV4 to requests

Usage: aws-sigv4-proxy [OPTIONS] --forward-to <FORWARD_TO>

Options:
  -f, --forward-to <FORWARD_TO>
          URL of the AWS service to forward requests to
  -s, --service <SERVICE>
          AWS signing service name (default is detected from the URL)
  -r, --region <REGION>
          Override signing region (default is detected from the AWS config)
  -a, --assume-role <ASSUME_ROLE>
          Assume role ARN to use for signing requests
  -l, --listen-on <LISTEN_ON>
          Port and optional IP address to listen on [default: 0.0.0.0:8080]
  -u, --utility-port <UTILITY_PORT>
          Port to respond on health checks and metrics requests [default: 9090]
      --connect-timeout <CONNECT_TIMEOUT>
          Proxy connect timeout in seconds [default: 10]
      --request-timeout <REQUEST_TIMEOUT>
          Proxy request timeout in seconds [default: 30]
      --signature-lifetime <SIGNATURE_LIFETIME>
          Signature expiration timeout in seconds
      --ca <CA>
          Path to a custom root CA bundle file (use system bundle by default)
      --no-verify-ssl
          Skip SSL verification for outgoing connections
  -c, --cert <CERT>
          Path to a server certificates file bundle (enables TLS, disabled by default)
  -k, --key <KEY>
          Path to certificate's private key file (enables TLS, disabled by default)
  -h, --help
          Print help
  -V, --version
          Print version
```

### `--forward-to`
The only mandatory parameter is URL of the AWS service to forward signed requests to.
For example, URL of the OpenSearch VPC endpoint or S3 bucket root.

### `--service`, `--region`

By parsing forward-to URL, `aws-sigv4-proxy` tris to resolve service to sign requests for.
In case it's impossible to detect service, it should be implicitly specified using `--service` option.

The same is about service's region: `aws-sigv4-proxy` tries to determine a region from the current AWS config,
but it may be specified (or overridden) implicitly using `--region` option.

### `--assume-role`

It's possible to specify an IAM role ARN to use for signing requests.
In such a case current AWS IAM entity has to have permission to assume that role.

Another way to achieve this is to specify a role to assume in AWS config.

### `--listen-on`, `--utility-port`

By default, proxy accepts requests on all host's IP addresses and port 8080.
This may be overridden using `--listen-on` option.

Utility port is used to response on health checks on `/health` path
and to provide Prometheus metrics on `/metrics` path (isn't implemented yet).

### `--connect-timeout`, `--request-timeout`

Connect timeout (in seconds) defines maximum time from opening connection to the target service endpoint up to accepting it by remote.

Request timeout (in seconds) is a maximum time from accepting request by remote up to getting response.

### `--signature-lifetime`

Signature expiration time isn't limited by default. You can set it (in seconds) using this option.

_Be careful_: this time shouldn't exceed lifetime of the current credentials or maximum time of the assumed role token.

### `--ca`, `--no-verify-ssl`

By default, to verify target's SSL certificates `aws-sigv4-proxy` uses a system trusted root CA bundle
or Mozilla WebPKI bundle if system one is unavailable.
You may specify a path to file in PEM format with a custom root CA bundle.
It's useful when you operate in some kind of isolated environment with TLS inspecting firewall for outgoing connections.

Or you can use the second **_dangerous_** option to disable SSL verification completely.

### `--cert`, `--key`

By default, `aws-sigv4-proxy` accepts non-encrypted connection (without TLS).
To force using SSL for incoming connections, you should specify a path to valid SSL certificate and its private key,
both are in the PEM format.

File with SSL certificate may contain intermediate certificates (chain) as well.

### AWS Credentials

AWS credentials should be provided in any acceptable way [as AWS recommends](https://docs.aws.amazon.com/sdkref/latest/guide/creds-config-files.html):
- using shared config and credentials files in `~/.aws/` folder;
- via environment variables;
- IAM roles assumed using WebIdentity (EKS case);
- EC2 instance metadata;
- any other supported way.

Anyway, with security reason, there is no way to provide credentials directly to `aws-sigv4-proxy`.

### Helm chart

To add Helm repository:

```bash
helm repo add alex-karpenko https://alex-karpenko.github.io/helm-charts
helm repo update
```

To deploy Helm release,
create your own values file with overrides of the default values (or provide values via `--set` command line parameters)
and deploy it to your K8s cluster:

```bash
helm install aws-sigv4-proxy alex-karpenko/aws-sigv4-proxy -f my-values.yaml
```

Please explore the default chart's `values.yaml` file to get known about all possible parameters.

### Build your own binary

Since `aws-sigv4-proxy` is written in Rust, you can use standard Rust tools to build binary for any platform you need.
Of course, you have to have [Rust](https://rust-lang.org) tool-chain installed.

```bash
cargo build --release
```

And run it:

```bash
target/release/aws-sigv4-proxy --help
```

## TODO

- [ ] Improve errors handling.
- [ ] Add metrics.

## License

This project is licensed under the [MIT license](LICENSE).
