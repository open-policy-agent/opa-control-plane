# Docker Demo

The `docker-compose.yml` definition in this repository starts the following services:

1. OCP (edge image build, or env var `OCP_IMAGE`)
2. PostgreSQL
3. Prometheus
4. Localstack (S3), with an init service that creates be bucket "bundles"

## TLS

The OCP instance uses mTLS for its database connections. The certificate of OCP is provided via environment variables, `OCP_TLS_CERT` and `OCP_TLS_KEY`.
For convenience, you can generate and export them via

```sh
eval $(./init.sh)
```

This will generate the certs needed for the examples (via `tls/gencerts.sh`), and set the env vars for OCP accordingly.

> [!NOTE]
> The TLS setup needs to be prepared **first**, before calling `docker compose up`.
>

## Metrics

When it's running, you can go to http://127.0.0.1:9090 to examine the published Prometheus metrics.
Enter `ocp_` in the expression field to see completion options for the various metrics in the expression field to see completion options for the various metrics in the expression field to see completion options for the various metrics.

The OCP configuration already contains a bundle, pulling some rego from https://github.com/open-policy-agent/contrib, so that there are some metrics to explore.

> [!WARNING]
> Note that on startup, it will take a while until the system settles:
> The bucket needs to be created, and OCP needs to upload to it, OPA needs to download the bundle.
> Eventually, you should see `Bundle loaded and activated successfully.` in the OPA logs, indicating that all pieces played well together.
