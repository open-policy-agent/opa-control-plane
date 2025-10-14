# Docker Demo

The `docker-compose.yml` definition in this repository starts the following services:

1. OCP (edge image build, or env var `OCP_IMAGE`)
2. PostgreSQL
3. Prometheus

When it's running, you can go to http://127.0.0.1:9090 to examine the published Prometheus metrics.
Enter `ocp_` in the expression field to see completion options for the various metrics in the expression field to see completion options for the various metrics in the expression field to see completion options for the various metrics.

The OCP configuration already contains a bundle, pulling some rego from https://github.com/open-policy-agent/contrib, so that there are some metrics to explore.
