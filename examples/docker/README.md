# Docker Demo

The `docker-compose.yml` definition in this repository starts the following services:

1. OCP (edge image build, or env var `OCP_IMAGE`)
2. PostgreSQL
3. Prometheus
4. Localstack (S3), with an init service that creates be bucket "bundles"

When it's running, you can go to http://127.0.0.1:9090 to examine the published Prometheus metrics.
Enter `ocp_` in the expression field to see completion options for the various metrics in the expression field to see completion options for the various metrics in the expression field to see completion options for the various metrics.

The OCP configuration already contains a bundle, pulling some rego from https://github.com/open-policy-agent/contrib, so that there are some metrics to explore.

> [!WARNING]
> Note that on startup, it will take a while until the system settles:
> The bucket needs to be created, and OCP needs to upload to it, OPA needs to download the bundle.
> Eventually, you should see `Bundle loaded and activated successfully.` in the OPA logs, indicating that all pieces played well together.
