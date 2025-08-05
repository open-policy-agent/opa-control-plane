# OPA Control Plane (OCP)
<!-- TOC -->
- [OPA Control Plane (OCP)](#opa-control-plane-ocp)
  - [Introduction](#introduction)
  - [Guides](#guides)
    - [Kick the tires](#kick-the-tires)
    - [Deploy as a service to K8s/AWS/…](#deploy-as-a-service-to-k8sawsetc)
    - [API Access](#api-access)
  - [Concepts](#concepts)
    - [Bundles](#bundles)
    - [Sources](#sources)
    - [Stacks](#stacks)
    - [Secrets](#secrets)
    - [Configuration File Structure Concepts](#configuration-file-structure-concepts)
  - [Reference](#reference)
    - [Installation](#installation)
    - [Configuration Merging](#configuration-merging)
    - [Database Configuration](#database-configuration)
    - [Authentication and permissions](#authentication-and-permissions)
    - [API Reference](#api-reference)
      - [Overview](#overview)
      - [Bundle Management](#bundle-management)
      - [Source Management](#source-management)
      - [Source Data Management](#source-data-management)
      - [Stack Management](#stack-management)
      - [Error Responses](#error-responses)
      - [Configuration Examples](#configuration-examples)
      - [API Features](#api-features)
      - [Common HTTP Status Codes](#common-http-status-codes)
<!-- /TOC -->
# Introduction

OPA Control Plane (OCP) simplifies how you manage policies for your OPA deployments. It provides a centralized management system to control how OPAs receive the policies and data they need to make decisions. OCP provides:

* **Git-based Policy Management.** Build bundles based on Rego from multiple Git repositories and implement environment promotion strategies natively with Git.
* **External Datasources.** Fetch and bundle external data required by your policies build-time using HTTP push and pull datasources.
* **Highly-Available & Scalable Bundle Serving.** Distribute bundles to cloud object storage like AWS S3, Google Cloud Storage, or Azure Blob Storage and ensure your OPAs can quickly and reliably serve policy decisions.
* **Global and hierarchical policies.** Enforce organization-wide rules by defining global policies that get injected into bundles at build-time based on label selectors. Global policies can override other policies based on custom conflict resolution logic written in Rego.

# Guides

## Kick the tires

This section will guide you through setting up a minimal, self-contained example of OCP directly on your laptop. The goal is to provide a clear, step-by-step process that allows you to quickly get a working environment and observe OCP in action.

By following these instructions, you will be able to:

* Install OCP on your local machine.
* Define a basic bundle with a test policy.
* Use OCP to build the bundle
* Configure OPA to use the OCP build bundle
* Test the policy's enforcement and observe its effects.

This example is designed for rapid iteration and learning, making it ideal for new users who want to understand OCP's fundamental concepts and operational flow in a controlled, personal setting. We'll focus on simplicity and clarity, ensuring that each step is easy to follow and the outcomes are immediately visible.

#### Install binary

Install the opactl tool using one of the install methods [listed](#installation) below.

#### Define bundle

The bundle is defined by a configuration file normally in the `config.d` directory.  More details can be found in the [Concepts](#concepts) section, but for now lets use this configuration.  In your working directory add the following to `./config.d/hello.yaml`

```yaml
bundles:
  hello-world:
    object_storage:
      filesystem:
        path: bundles/hello-world/bundle.tar.gz
    requirements:
      - source: hello-world
sources:
  hello-world:
    directory: files/sources/hello-world
    paths:
      - rules/rules.rego
```

We also will want to define a simple policy for this bundle.  Add the following to `./files/sources/hello-world/rules/rules.rego`

```rego
package rules

import rego.v1

default allow := false
allow if {
  input.user == "alice"
}
```

#### Build the bundle

In your working directory run the `build` command:

`opactl build`

#### Configure OPA to use the bundle

You could set up a simple server to serve up the bundle, but for now we can just use OPA to watch the bundle.  Run this in your working directory:

```shell
opa run -s -w ./bundles/hello-world/bundle.tar.gz
```

#### Test the policy

You should now be able to test the policy running in OPA.  Using the following curl:

```shell
curl localhost:8181/v1/data/rules/allow -d \
'{"input":{"user":"alice"}}'
```

You can also try changing the policy in `./files/sources/hello-world/rules/rules.rego`.  After you make the change, rerun the build command from above to see the changes reflected in OPA.

## Deploy as a service to K8s/AWS/…

The preceding example provided a minimal local configuration. This next example significantly expands on that, illustrating a more comprehensive and realistic configuration.

This will showcase a practical, more complete server configuration and demonstrate its operational aspects.

**Key aspects to explore in this expanded configuration:**

* **Deployment Environment:**
  * Running the OCP server within Kubernetes
* **Database Integration:**
  * Connecting the OCP server to an external database.  For this example, we will set up a PostgreSQL database within the Kubernetes environment, but a more likely solution would be a managed SQL database.
* **Source control integration**:
  * This example will utilize git as the source of the policies
* **Advanced Bundle Management:**
  * Using an HTTP datasource to include data in multiple bundles that OCP manages.  Also, deploying the bundle to S3.
* **Configuration Management:**
  * Illustrating the dynamic pushing of configuration to the OCP server using `curl` commands. This will encompass updating configuration in real-time.

#### Prerequisites

* A Git repository and valid credentials to read from it
* Access and credentials to an S3 bucket
* A Kubernetes environment (a local environment with minikube or other tools is fine)

#### Complete manifest

The complete manifest can be found [here](k8s-manifests.yaml).

The rest of this section will just highlight portions of the full manifests to explain the concepts.

#### Database Integration

As mentioned we will use a PostgreSQL deployment/service for this example, but for a production install you will likely want to use an external/managed database.  Example configuration can be found in the [Database Configuration](#database-configuration) section below.

The configuration to connect to the database will be in a configuration file.  In our example it will look like this:

```yaml
database:
  sql:
    driver: postgres
    dsn: "postgres://opactl:password@postgres-service:5432/opactl?sslmode=disable"
```

#### OCP Server

The OCP server is fairly straightforward to setup, there is a docker [image](#docker-image) provided and you can configure it with one or more configuration files.  In this case we will use multiple configuration files in a configmap to do the configuration.  One important piece of configuration is the token setup for accessing the OCP API.  Details of this configuration can be found in the [Authorization and permissions](#authentication-and-permissions) section below, we will do a basic setup adds an admin and viewer API token:

```yaml
tokens:
  admin-user:
    api_key: "admin-api-key-change-me"
    scopes:
      - role: administrator
  viewer-user:
    api_key: "viewer-api-key-change-me"
    scopes:
      - role: viewer
```

Then the k8s manifest will look something like:

```yaml
containers:
- name: opactl
  image: openpolicyagent/opactl
  args:
  - "run"
  - "--addr=0.0.0.0:8282"
  - "--data-dir=/data"
  - "--config=/config.d/config.yaml"
  - "--config=/config.d/tokens.yaml"
  - "--config=/config.d/credentials.yaml"
  - "--config=/config.d/my-alpha-app.yaml"
  - "--config=/config.d/my-beta-app.yaml"
  - "--config=/config.d/my-shared-datasource.yaml"
  # - "--reset-persistence"                     # Not suitable for production, but useful for testing
  - "--log-level=debug"
```

`(other environment variables and mounts can be found in the complete manifest)`


#### Git Source setup

The normal setup for a system will be to get the policies from a git repository.  Full configuration for source is defined [below](#sources), but we will use a basic git config:

```yaml
sources:
  my-alpha-app:
    git:
      repo: https://github.com/your-org/my-alpha-app.git  # Change to your Git repository URL
      reference: refs/heads/main
      # path: path/to/rules                                       # Path within the Git repo
      excluded_files:
          - .*/*
      credentials: git-creds
```

Credentials can be [configured](#secrets) to be either ssh key or basic auth, we will use basic auth (getting the actual creds from env variables so they can be injected with secrets):

```yaml
secrets:
  git-creds:
    type: "basic_auth"
    username: "${GIT_USERNAME}"
    password: "${GIT_PASSWORD}"
```

#### S3 bundle deploy

OCP does not act as a bundle server so we need to put the bundle somewhere where OPA can retrieve it.  OCP can deploy [bundles](#bundle-configuration-fields) to cloud storage services, we will deploy to S3 in our example.  We will also include the source from our previously configured git repo and a yet to be configured datasource:

```yaml
bundles:
  my-alpha-app:
    object_storage:
      aws:
        bucket: my-aws-bucket-name                  # Change to your S3 bucket name
        key: bundles/my-alpha-app/bundle.tar.gz
        region: us-east-2                           # Change to your AWS region
    requirements:
      - source: my-alpha-app
      - source: my-shared-datasource
```

Note: the name `my-alpha-app` in the requirements is specifically referencing the name under sources (from the previous step).  You will oftentimes name the bundle with the same name to “link” them logically together, these will normally (but not required to) be configured together in their own configuration file.

You may notice that there are no credentials configured for the S3 bucket.  In this case they will be pulled from environment variables configured in the OCP deployment.

```yaml
env:
- name: AWS_ACCESS_KEY_ID
  valueFrom:
    secretKeyRef:
      name: aws-credentials
      key: AWS_ACCESS_KEY_ID
- name: AWS_SECRET_ACCESS_KEY
  valueFrom:
    secretKeyRef:
      name: aws-credentials
      key: AWS_SECRET_ACCESS_KEY
- name: AWS_REGION
  valueFrom:
    secretKeyRef:
      name: aws-credentials
      key: AWS_REGION
```

#### Shared Datasource

One of the powerful concepts in OCP is the ability to share policies and data across multiple bundles.  To do this we create another [source](#sources) for this and require it in the bundle.  We will set up a http datasouce to share, but you could just as easily do this for rego.  Full datasource configuration can be found [here](#sources), but for our purposes we will call out to httpbin using a bearer token (other authn can be found [here](#secrets)):

```yaml
sources:
  my-shared-datasource:
    datasources:
      - name: httpbin-json
        path: httpbin
        type: http
        config:
          url: https://httpbin.org/bearer
          credentials: httpbin-credentials

secrets:
 httpbin-credentials:
    type: "token_auth"
    token: "my-fake-token"
```

#### Deploy

This should now give you a configuration that is ready to deploy.  The full manifest also includes a second application that also uses the shared datasoure, it’s configured much like the previous example using the filesystem for rego and bundles.  Once OCP is up and running you should see bundles being automatically updated in S3 (or exec into the OCP container for the second app), sources are checked in a forever loop about every 30-60 seconds.  The manifest also includes an OPA configured for the `my-alpha-app` S3 bundle.  If you want to test through the OPA endpoints you can do a port forward:

```
kubectl port-forward svc/opa-service 8181:8181
```

#### API Access

All the configuration to this point has been done through the configuration files and this may be suitable for many (likely smaller) installs, but for larger installs this might not be efficient.  While OCP doesn’t have a UI it does have an [API](#api-reference) for doing configuration of [sources](#sources)/[bundles](#bundles)/[stacks](#stacks).

In order to use the api you will need to expose the opactl-server with whatever sort of ingress matches your infrastructure, but for testing you can use a simple port forward:

```shell
kubectl port-forward svc/opactl-service 8282:8282
```

To do a basic get of the bundles would look like this:

```shell
curl --request GET \
  --url http://localhost:8282/v1/bundles \
  --header 'Authorization: Bearer admin-api-key-change-me'
```

The output should look similar to this:

```json
{
	"result": [
		{
			"object_storage": {
				"aws": {
					"bucket": "my-aws-bucket-name",
					"key": "bundles/my-alpha-app/bundle.tar.gz",
					"region": "us-east-2"
				}
			},
			"requirements": [
				{
					"source": "my-alpha-app",
					"git": {}
				},
				{
					"source": "my-shared-datasource",
					"git": {}
				}
			]
		},
		{
			"object_storage": {
				"filesystem": {
					"path": "bundles/my-beta-app/bundle.tar.gz"
				}
			},
			"requirements": [
				{
					"source": "my-beta-app",
					"git": {}
				},
				{
					"source": "my-shared-datasource",
					"git": {}
				}
			]
		}
	]
}

```

If you want to add a new bundle you can upsert it with a PUT request:

```shell
curl --request PUT \
  --url http://localhost:8282/v1/bundles/my-alpha-app-no-shared \
  --header 'Authorization: Bearer admin-api-key-change-me' \
  --header 'Content-Type: application/json' \
  --data '{
	"object_storage": {
				"aws": {
					"bucket": "my-aws-bucket-name",
					"key": "bundles/my-alpha-app-no-shared/bundle.tar.gz",
					"region": "us-east-2"
				}
			},
			"requirements": [
				{
					"source": "my-alpha-app",
					"git": {}
				}
			]

}'

```

Then you can get that specific bundle like this:

```shell
curl --request GET \
  --url http://localhost:8282/v1/bundles/my-alpha-app-no-shared \
  --header 'Authorization: Bearer admin-api-key-change-me'
```

# Concepts

## Bundles

Bundles are the primary packaging and distribution unit in OCP. Each bundle contains Rego policies, data files, and is intended to be consumed by any number of OPA instances. The OCP configuration for the bundle specifies a set of **requirements** that list the sources (Rego, data, etc.) to include in the bundle.

OCP builds [OPA Bundles](https://openpolicyagent.org/docs/management-bundles) and pushes them to external object storage systems (e.g., S3, GCS, Azure Cloud Storage, File System). OPA instances are configured to download bundles directly from these storage systems. See the [OPA Configuration](https://www.openpolicyagent.org/docs/latest/configuration/) documentation for more information how to configure authentication and bundle downloads for different cloud providers

### Namespacing

In OCP, bundles must not require multiple sources with overlapping packages. When OCP builds bundles it checks that no two (distinct) sources being included in a bundle contain packages that are the same or prefix each other. This rule is applied transitively to all sources included in the bundle. If two sources contain overlapping packages OCP will report a build error:

`requirement "lib1" contains conflicting package x.y.z`
        `- package x.y from "system"`

In this example:

* lib1 is the name of a source that declares package x.y.z
* system is the name of another source that declares package x.y
* because x.y is a prefix of x.y.z, they overlap

If you are interested in seeing this restriction relaxed please leave a comment [here](https://github.com/StyraInc/opa-control-plane/issues/30) including any details you can share about your use case.

### Bundle Configuration Fields

* **object\_storage:**
  Configure the storage backend (S3, GCS, Azure Cloud Storage, or filesystem, etc.) for bundle distribution. OCP will write bundles to the object storage backend and the bundles will be served from there.
  * Filesystem:
    * Path: Path where the bundle will be created
      * Example: `bundles/prod-app.tar.gz`
  * Amazon S3 (aws):
    * Bucket: Name of the bucket
      * Example: `my-prod-bucket`
    * Key: Path and or name of the bundle to be built
      * Example: `prod/bundle.tar.gz`
    * Region: Aws region bucket was created in
    * Credentials: Reference a named Secret for authenticating with the target object store.
  * GCP Cloud Storage (gcp):
    * Project: GCP project the bucket is a part of
    * Bucket: Name of the bucket
    * Object: Name of the bundle, including the path
    * Credentials: Reference a named Secret for authenticating with the target object store.
  * Azure Blob Storage (azure):
    * Account URL: URL to the Azure account
    * Container: Name of the blob storage container
    * Path: Path and name of the bundle to be created
    * Credentials: Reference a named Secret for authenticating with the target object store.
* **labels:**
   Add metadata to bundles to describe environment, team, system-type, etc. Labels are used by Stacks (see below) for bundle selection and policy composition.
* **requirements:**
   Specify policies or data (from Sources) that must be included in the bundle.
* **Excluded\_files**: (optional)
  A list of files to be excluded from the bundle during build for example any hidden files

**Example:**

```yaml
bundles:
  prod-app:
    object_storage:
      aws:
        bucket: my-prod-bucket
        key: prod/bundle.tar.gz
        url: https://s3.amazonaws.com
        region: us-east-1
        credentials: s3-prod-creds
    labels:
      environment: prod
      team: payments
    requirements:
      - source: app-policy
```

## Sources

Sources define how OCP pulls Rego and data from external systems, local files, or built-in libraries to compose and build bundles.

### Types of Sources

* **git:** Pull policy code and data from a Git repository (HTTPS, with token/basicauth credentials).
  * Repo: Repository url either https or ssh
    * Example: `https://github.com/example/app-policy.git`
  * Reference (Optional): git reference
    * Example: `refs/head/main`
  * Commit (Optional): Commit sha of the commit you want the bundle built from
    * Example: `d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3`
  * Path (Optional): Git path to the files to be included in the policy
    * Example: `policies/authz`
  * Include Files (Optional): Files to explicitly include in the bundle
  * Excluded Files (Optional): Files to be explicitly excluded from the bundle
    * Example: `.*/*`
  * Credentials: Reference a named Secret for authenticating with the target git repository
* **datasources:** Configure HTTP(S) endpoints, APIs, or other external data services as data sources for policy evaluation.
  * Name
  * Path
  * Type
    * Http
    * S3
    * git
  * Transform Query
  * Config
  * Credentials
* **files:** Local embedded files provided to OCP at build time.
* **directory:** Local directories provided to OCP at build time
* **paths:** Paths to individual rego or datasource files to be used during bundle build
* **builtin:** Reference built-in policy or library modules shipped with OCP.
* **requirements:** Specify dependencies on other sources or builtins for composable policy development.
* **credentials:** Reference a named Secret for accessing Git/datasource endpoints.

**Example:**

```yaml
sources:
  app-policy:
    git:
      repo: https://github.com/example/app-policy.git
      reference: refs/heads/main
      excluded_files:
        - .*/*
      credentials: github-token
  global-data:
    files:
      data/common.json
```

## Stacks

Stacks enforce that certain policies are distributed to OPAs managed by OCP. When OCP builds bundles it identifies the applicable stacks (via [Selectors](#selectors)) and then adds the required sources (declared via `requirements`) to the bundle. Consider using stacks if:

* You have ephemeral OPA deployments that need to have a consistent set of policies  applied (e.g., CI/CD pipelines, Kubernetes clusters, etc.)
* You have global or hierarchical rules implementing organization-wide policies that you want to enforce automatically in many OPA deployments.

Let's look at an example:

* Your organization deploys microservices that use OPA to enforce API authorization rules
* Each microservice and bundle is owned by a separate team
* You want to enforce a global policy that blocks users contained in a blocklist

Stacks provide a convenient and scalable way of enforcing this policy. Instead of manually modifying the policy for each microservice or requiring that each team write policies that call into a common library, you can define this policy once and configure a stack to inject it into the bundles for each microservice.

Because Stacks inherently involve multiple policy decisions, *conflicts* can arise. See the [Conflict Resolution](#conflict-resolution) section for more information.

### Selectors

When OCP builds a bundle it includes all of the sources from all stacks that apply. A stack applies if both:

* The selector matches the bundle's labels AND EITHER
* The exclude selector DOES NOT match the bundle's labels OR
* The exclude selector is undefined

The selector and exclude selector are evaluated the same way. A selector matches if:

* It is empty

OR

* All of the keys in the selector exist in the labels

 AND EITHER

* At least one selector value matches the corresponding label value

 OR

* The selector value is empty (\[\])

A selector value matches the label value if:

* The selector value and the label value are the same OR
* The selector value contains a glob pattern (\*) that matches the label value.
  * OCP implements the same glob matching as [OPA's glob built-in functions](https://www.openpolicyagent.org/docs/policy-reference/builtins/glob).

### Conflict Resolution

If a stack policy and a bundle policy generate different decisions we refer to this as a *conflict*. Similarly, when multiple stacks are included in a bundle they may also generate conflicting decisions. Before returning the final decision to the application, the overall policy should resolve any potential conflicts by combining the different decisions. Below we provide examples of how to implement common conflict resolution patterns for different use cases. In general, conflict resolution involves:

* the bundle policy that produces a decision
* one or more stack policies that each produce a separate decision
* an **entrypoint** policy that produces by the final decision by composing all of the above

#### Pattern: stack deny overrides bundle allow

The following example shows how to implement a common pattern where:

* bundle owners define policies that generate allow decisions
* a single stack owner defines policies that generate deny decisions
* the final decision returned to the application should set allow to true IF
  * the bundle policy generates an allow (i.e., allow is true) AND
  * the stack policy does not generate a deny (i.e., deny is undefined or false)

To illustrate this pattern we will use a simple example with two bundle policies and a stack policy. The bundle policies allow access to microservice APIs (for a "petshop" service and a "notifications" service) and the stack policy will deny access based on a blocklist. Finally, there is an entrypoint policy that composes the bundle and stack policies to produce the final decision.

The petshop service will define a policy that allows:

* anyone to view pet profiles
* employees to update pet profiles

```rego
package service

allow if {	input.action == "view_pets"}

allow if {	input.action == "update_pets"
input.principal.is_employee}
```

The notifications service will define a policy that allows customers to subscribe to newsletters:

```rego
package service

allow if {	input.action == "subscribe_to_newsletter"	input.principal.is_customer}
```

The stack policy will deny users that are contained in the blocklist datasource.

```rego
package globalsecurity
deny if {	input.principal.username in data.blocklist}
```

Finally, the entrypoint policy will combine the service and stack policy to produce the final decision:

```rego
package main
main if {	data.service.allow
not data.globalsecurity.deny}
```

The configuration below illustrates how the bundles, sources, and stacks are tied together:

```yaml
bundles:
  petshop-svc:
    labels:
      environment: prod
    requirements:
      - source: petshop-svc
  notifications-svc:
    labels:
      environment: prod
    requirements:
      - source: notifications-svc

stacks:
  globalsecurity:
    selector:
      environment: prod
    requirements:
      - source: main
      - source: globalsecurity

sources:
  petshop-svc: ...
  notifications-svc: ...
  globalsecurity: ...
  main: ...
```

#### Pattern: unioning stack and bundle denies

The following example shows how to implement a common pattern where:

* bundle owners define a policy that generates a set of deny reasons
* stack owners also define policies that generate sets of deny reasons
* the final decision returned to the application should be the union of all the deny reasons

To illustrate this pattern we will use a simple example with a single bundle policy and two stack policies. The final decision will be generated by the entrypoint policy by unioning the bundle and stack decisions. For this example, we will assume that application querying OPA is a job running in a CI/CD pipeline that provides a set of build artifacts to deploy.

The bundle policy will deny deployments that contain artifacts that do not contain a "qa" attestation.

```rego
package pipeline
deny contains msg if {
some artifact in input.artifacts
"qa" in artifact.attestations
msg := sprintf("deployment contains untested artifact: %v", [artifact.name])
}
```

The first stack policy will block deployments that do not contain an SBOM:

```rego
package pipelines.stacks.sbom
deny contains "deployments must contain sbom" if {
not input.sbom
}
```

The second stack policy will block deployments if an artifact has critical CVEs:

```rego
package pipelines.stacks.cves
deny contains msg if {
	some artifact in input.artifacts
	some cve in data.cves[artifact.sha]
	cve.level == "critical"
msg := sprintf("artifact contains critical cve: %v", [cve.id])
}
```

The entrypoint policy will union all of the deny reasons to produce the final set. Since stacks are added to bundles dynamically at build-time, the entrypoint policy iterates over the `stacks` namespace. Only applicable stacks will be present in the bundle.

```rego
package pipelines
deny contains msg if {
	some msg in data.pipeline.deny
}

deny contains msg if {
some stackname	some msg in data.pipelines.stacks[stackname].deny}
```

The configuration below illustrates how the bundles, sources, and stacks are tied together:

```yaml
bundles:
  pipeline-a1234:
    labels:
      environment: prod
      type: pipeline
    requirements:
      - source: pipeline-a1234

stacks:
  sbom:
    selector:
      environment: [prod]
      type: [pipeline]
    requirements:
      - source: sbom
  cves:
    selector:
      environment: [prod]
      type: [pipeline]
    requirements:
      - source: cves
  pipelines:
    selector:
      type: [pipeline]
    requirements:
      - source: pipelines

sources:
  pipeline-a1234: ...
  sbom: ...
  cves: ...
  pipelines: ...
```

## Secrets

**Goal:**
 Secrets enable OCP to securely communicate with external systems (object storage, Git, datasources, etc.) without hardcoding credentials in configuration files.

### **Supported Secret Types**

* **aws\_auth:** For S3/MinIO storage (access key/secret key)
  * access\_key\_id:
  * secret\_access\_key:
  * session\_token:
* **basic\_auth:** For Git or HTTP(S) sources (username/password or token)
  * username:
  * password:
  * headers:
* **gcp\_auth:** For Google Cloud Storage
  * api\_key:
  * credentials: JSON credentials file
* **azure\_auth:** For Azure Blob Storage
  * account\_name:
  * account\_key:
* **github\_app\_auth:** For authentication as a GitHub App
  * integration\_id:
  * installation\_id:
  * Private\_key: Private key of the app as a PEM
* **ssh\_key:** For Authentication with an ssh key
  * key: Path to ssh key
  * passphrase:
  * Fingerprints: Optional ssh key fingerprints
* **token\_auth**: For authentication with a Bearer token or JWT token.
  * token:
* **password:** For password based authentication with datasource or the database
  * password:

**Example:**

```yaml
secrets:
  s3-prod-creds:
    type: aws_auth
    access_key_id: ${S3_ACCESS_KEY_ID}
    secret_access_key: ${S3_SECRET_ACCESS_KEY}
  github-token:
    type: basic_auth
    username: ${GITHUB_USERNAME}
    password: ${GITHUB_TOKEN}
```

# Configuration File Structure Concepts

OCP configuration files can be organized as a single file or split across multiple files and directories. For small or simple deployments, a single configuration file may be sufficient and easier to manage. When defining an "application," it is common practice to group related bundles and sources together in the same configuration file. This approach keeps the application's policy logic and its data sources tightly coupled, making updates and reviews straightforward.

Best practices suggest keeping secrets and environment-specific overrides in separate files or directories, while grouping each application's bundles and sources together. Use lexical naming and directory structure to avoid conflicts. For collaborative environments, version control each file and use directory-based organization to support team workflows and automated deployment pipelines. Choose the level of granularity that matches your operational complexity—favor modularity for larger teams and environments, but keep things simple for smaller setups.

# Reference

## Installation

Goal: show how users can obtain OCP

* binary
* docker image
* build from source

#### Download the OCP Binary

The OCP binary can be downloaded directly. After downloading, make the binary executable and verify it works by running the version command.

##### macOS \- Apple silicon (ARM)

```shell
curl -L -o opactl https://openpolicyagent.org/downloads/latest/opactl_darwin_arm64_static
chmod +x opactl
./opactl version
```

##### macOS \- Intel-based

```shell
curl -L -o opactl https://openpolicyagent.org/downloads/latest/opactl_darwin_amd64
chmod +x opactl
./opactl version
```

##### Linux/Unix \- amd64

```shell
curl -L -o opactl https://openpolicyagent.org/downloads/latest/opactl_linux_amd64
chmod +x opactl
./opactl version
```

##### Linux/Unix \- arm64

```shell
curl -L -o opactl https://openpolicyagent.org/downloads/latest/opactl_linux_arm64_static
chmod +x opactl
./opactl version
```

##### Windows \- via Powershell

```shell
Invoke-WebRequest -Uri "https://openpolicyagent.org/downloads/latest/opactl_windows_amd64.exe" -OutFile "opactl.exe"
.\opactl.exe version
```

##### Windows \- via Curl

```shell
curl -L -o opactl.exe https://openpolicyagent.org/downloads/latest/opactl_windows_amd64.exe
.\opactl.exe version
```

#### Docker image {#docker-image}

OCP Docker images are available on Docker Hub.

```shell
openpolicyagent/opactl
```

#### Adding opactl to PATH (Optional)

For easier usage, you can move the binary to a directory in your PATH:

**macOS/Linux:**
```shell
# Move to /usr/local/bin (requires sudo)
sudo mv opactl /usr/local/bin/

# Or move to a user directory (create if it doesn't exist)
mkdir -p ~/bin
mv opactl ~/bin/
export PATH="$HOME/bin:$PATH"  # Add to ~/.bashrc or ~/.zshrc for persistence
```

**Windows:**
```shell
# Move to a directory in your PATH or add current directory to PATH
move opactl.exe C:\Windows\System32\
```

After adding to PATH, you can run `opactl version` from anywhere.

#### Building OCP from source

To build the OCP binary locally run the following command from the root folder:

```shell
make build
```

The binary will be created in the form `opactl_<OS>_<ARCH>` (e.g., `opactl_darwin_amd64`, `opactl_linux_amd64`).

**Verify the build:**
```shell
# Example for macOS/Linux (adjust filename for your platform)
chmod +x ./opactl_darwin_amd64
./opactl_darwin_amd64 version
```

## **Configuration Merging**

OCP configuration can be split across multiple files on disk. When you execute OCP commands you specify the path to configuration files or directories with \-c/–config. The flag can point at individual files or directories. If a directory is provided, OCP will load the contents of the directory and all subdirectories (recursively) and merge them.

By default, OCP will merge object keys and override scalar values. Files are loaded in lexical order and the last file to set a scalar or list value wins. If the –merge-conflict-fail argument is specified, then scalar and list values are never overridden and an error will be returned if two files set the same field to a different value.

## Database Configuration

OCP uses a SQL-compatible database to store its internal state. By default, OCP runs with an in-memory SQLite3 database, which is ideal for development or testing. For production, you can configure it to use external databases such as PostgreSQL, MySQL, or Amazon RDS.

### Supported Database Backends

OCP supports the following database drivers:

* `sqlite3` (in-memory or file-based)
* `postgres`
* `mysql`
* `aws_rds` (PostgreSQL or MySQL)

### **Basic SQL Database Configuration**

To configure OCP to use a standard SQL database, create a `database.yaml` file in your config.d directory and specify the driver and DSN (Data Source Name):

```yaml
database:
  sql:
    driver: postgres
    dsn: postgres://user:password@db.example.com:5432/ocpdb?sslmode=disable
```

Replace:

* `driver` with `postgres`, `mysql`, or `sqlite3`
* `dsn` with your database connection string

**Example: SQLite3 (file-based)**

```
database:
  sql:
    driver: sqlite3
    dsn: /var/lib/ocp/ocp.db
```

### **Amazon RDS Configuration**

OCP supports direct configuration for Amazon RDS with optional high-availability setups. It also currently supports the postgres, pgx, or mysql drivers for AWS RDS.

```yaml
database:
  aws_rds:
    region: us-east-1
    endpoint: mydb.cluster-abcdefghijkl.us-east-1.rds.amazonaws.com:5432
    driver: postgres
    database_user: ocpuser
    database_name: ocpdb
    credentials:
      name: rds-credentials
    root_certificates: /etc/ssl/certs/rds-combined-ca-bundle.pem
```

**Key fields:**

* `region`: AWS region of the RDS instance
* `endpoint`: Hostname and port for your RDS cluster or instance
* `driver`: `postgres, pgx` or `mysql`
* `database_user`: Database user for OCP
* `database_name`: Database name for OCP
* `credentials`: Reference to a secret containing the password or AWS credentials
* `root_certificates`: Optional PEM-encoded root certificate bundle for TLS connections to RDS

### High Availability with AWS RDS

To run OCP with a highly available RDS setup:

1. **Use Multi-AZ Deployment**
   In the AWS Console or via Terraform/CloudFormation, enable Multi-AZ when creating your RDS instance or cluster. This provisions standby replicas in a different Availability Zone and enables automatic failover.
2. **Cluster Endpoints**
   Use the **RDS cluster endpoint** rather than an instance-specific endpoint. This ensures that OCP always connects to the primary writer node, even after a failover.
    Example:

```yaml
endpoint: mydb.cluster-abcdefghijkl.us-east-1.rds.amazonaws.com:5432
```

3. **Read Replicas for Scaling**
   If your OCP deployment requires read scaling, you can configure read replicas in RDS. This is generally not required for OCP itself, but can be useful for analytics or reporting workloads.
4. **TLS Encryption**
   Download the latest Amazon RDS CA bundle from: [https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/UsingWithRDS.SSL.html](https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/UsingWithRDS.SSL.html) Store it in your container or host, and reference it in `root_certificates`.
5. **Secrets Management**
   Store the database password as well as AWS credentials in an OCP secret, such as:

```yaml
secrets:
  rds-credentials:
    password: ${RDS_PASSWORD}
```

**Additional References:**

* [Amazon RDS Multi-AZ Deployments](https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/Concepts.MultiAZ.html)

* [Amazon RDS Cluster Endpoints](https://docs.aws.amazon.com/AmazonRDS/latest/AuroraUserGuide/Aurora.Overview.Endpoints.html)

* [Amazon RDS SSL Support](https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/UsingWithRDS.SSL.html)

## Authentication and permissions {#authentication-and-permissions}

OPA Control Plane includes Role Based Access Control (RBAC) to govern access to the API, several roles are predefined and can be assigned to a user, these are;

* administrator \- All operations allowed on all resources
* viewer \- read operations allowed on all resources
* owner \-All operations for all resources they own
* stack\_owner \- All operations for stacks they own

Authorized users are identified to the API through bearer tokens, the tokens are opaque and can be generated using any acceptable methodology:

Example:

```shell
cat /dev/urandom | head -c 32 | base64
```

Tokens are tied to a principal and assigned a role from the above list or roles using yaml configuration, see the example below;

Example:

```yaml
tokens:
    admin:
        api-key: 7lPLBKKpmiljMa0J9GwyYWLDJKEVFXEO6ZGAjmDf5eQ=
        scopes:
            - role: administrator
```

## API Reference {#api-reference}

## Overview

The OPA Control Plane Server exposes a REST API for managing OPA bundles, sources, stacks, and data. All API endpoints except `/health` require Bearer token authentication.

## Authentication

- **Method**: Bearer token authentication
- **Header**: `Authorization: Bearer <api-key>`
- **Middleware**: All `/v1/*` endpoints require valid API key
- **Unauthorized Response**: HTTP 401 with "Unauthorized" message

### Example Authentication Header

```yaml
Authorization: Bearer admin-api-key-change-me
```

## Base URL Structure

- **Health Check**: `/health`
- **API Endpoints**: `/v1/*`

---

## Health Check Endpoint

### GET /health

**Description**: Health check endpoint to verify server readiness

**Authentication**: None required

**Response**:

- **200 OK**: Server is healthy and ready
- **500 Internal Server Error**: Server is not ready

**Example Response**:

```json
{}
```

---

## Bundle Management

Bundles are collections of policies and data that can be distributed to OPA instances.

### GET /v1/bundles

**Description**: List all bundles with pagination support

**Query Parameters**:

- `limit` (optional): Number of results to return (max 100, default 100\)
- `cursor` (optional): Pagination cursor for next page
- `pretty` (optional): Pretty-print JSON response (default true if param present with no value)

**Example Response**:

```json
{
  "result": [
    {
      "labels": {
        "env": "production",
        "team": "platform"
      },
      "object_storage": {
        "aws": {
          "bucket": "my-policy-bundles",
          "key": "bundles/my-app/bundle.tar.gz",
          "region": "us-east-1",
          "credentials": "aws-creds"
        }
      },
      "requirements": [
        {
          "source": "my-app-policies"
        },
        {
          "source": "shared-policies"
        }
      ],
      "excluded_files": [
        "*.test.rego",
        ".git/*"
      ]
    }
  ],
  "next_cursor": "eyJpZCI6IjEyMyIsInRzIjoxNjkwMjM0NTY3fQ=="
}
```

### GET /v1/bundles/{bundle}

**Description**: Get a specific bundle by name

**Path Parameters**:

- `bundle`: URL-encoded bundle name

**Example Response**:

```json
{
  "result": {
    "labels": {
      "env": "production",
      "version": "1.0.0"
    },
    "object_storage": {
      "filesystem": {
        "path": "/bundles/my-app/bundle.tar.gz"
      }
    },
    "requirements": [
      {
        "source": "my-app-policies"
      },
      {
        "git": {
          "commit": "abc123def456"
        }
      }
    ],
    "excluded_files": [
      "*.md",
      "docs/*"
    ]
  }
}
```

### PUT /v1/bundles/{bundle}

**Description**: Create or update a bundle

**Path Parameters**:

- `bundle`: URL-encoded bundle name

**Validation**:

- Bundle name in path must match name in body (if provided)
- If no name in body, path name is used

**Example Request**:

```json
{
  "labels": {
    "env": "staging",
    "team": "security"
  },
  "object_storage": {
    "aws": {
      "bucket": "policy-bundles-staging",
      "key": "bundles/auth-service/bundle.tar.gz",
      "region": "us-west-2",
      "credentials": "aws-staging-creds"
    }
  },
  "requirements": [
    {
      "source": "auth-policies"
    },
    {
      "source": "common-utils"
    }
  ],
  "excluded_files": [
    "*.test.rego",
    "examples/*"
  ]
}
```

**Example Response**:

```json
{}
```

---

## Source Management

Sources define where policies and data come from (Git repositories, local files, HTTP endpoints, etc.).

### GET /v1/sources

**Description**: List all sources with pagination support

**Query Parameters**: Same as bundles endpoint

**Example Response**:

```json
{
  "result": [
    {
      "git": {
        "repo": "https://github.com/myorg/policies.git",
        "reference": "refs/heads/main",
        "path": "src/policies",
        "included_files": ["*.rego"],
        "excluded_files": ["*.test.rego"],
        "credentials": "github-creds"
      },
      "requirements": [
        {
          "source": "base-policies"
        }
      ]
    },
    {
      "directory": "/local/policies",
      "paths": [
        "authz.rego",
        "utils.rego"
      ],
      "datasources": [
        {
          "name": "user-data",
          "path": "external/users",
          "type": "http",
          "config": {
            "url": "https://api.example.com/users"
          },
          "credentials": "api-creds"
        }
      ]
    }
  ],
  "next_cursor": null
}
```

### GET /v1/sources/{source}

**Description**: Get a specific source by name

**Path Parameters**:

- `source`: URL-encoded source name

**Example Response**:

```json
{
  "result": {
    "builtin": "styra.entitlements.v1",
    "requirements": [
      {
        "source": "foundation-policies"
      }
    ]
  }
}
```

### PUT /v1/sources/{source}

**Description**: Create or update a source

**Path Parameters**:

- `source`: URL-encoded source name

**Example Request (Git Source)**:

```json
{
  "git": {
    "repo": "https://github.com/myorg/security-policies.git",
    "reference": "refs/heads/production",
    "commit": "abc123def456789",
    "path": "policies",
    "included_files": ["*.rego"],
    "excluded_files": ["*.test.rego", "examples/*"],
    "credentials": "github-readonly"
  },
  "requirements": [
    {
      "source": "shared-utilities"
    }
  ]
}
```

**Example Request (Directory Source)**:

```json
{
  "directory": "/local/policies",
  "paths": [
    "main.rego",
    "utils.rego"
  ],
  "datasources": [
    {
      "name": "user-directory",
      "path": "external/users",
      "type": "http",
      "config": {
        "url": "https://api.company.com/users",
        "headers": {
          "Accept": "application/json",
          "User-Agent": "OPA-Control-Plane/1.0"
        }
      },
      "credentials": "api-credentials",
      "transform_query": "users[user.id] = user { user := input.users[_] }"
    }
  ]
}
```

**Example Response**:

```json
{}
```

---

## Source Data Management

Manage runtime data that gets injected into policy bundles.

### GET /v1/sources/{source}/data/{path}

**Description**: Retrieve data from a source at a specific path

**Path Parameters**:

- `source`: URL-encoded source name
- `path`: Data path (automatically appends `/data.json`)

**Example Response**:

```json
{
  "result": {
    "users": [
      {
        "id": "user123",
        "name": "John Doe",
        "roles": ["admin", "user"]
      },
      {
        "id": "user456",
        "name": "Jane Smith",
        "roles": ["user"]
      }
    ],
    "last_updated": "2025-08-07T10:30:00Z"
  }
}
```

### POST|PUT /v1/sources/{source}/data/{path}

**Description**: Upload data to a source at a specific path

**Path Parameters**:

- `source`: URL-encoded source name
- `path`: Data path (automatically appends `/data.json`)

**Example Request**:

```json
{
  "permissions": {
    "read": ["admin", "user"],
    "write": ["admin"],
    "delete": ["admin"]
  },
  "resources": [
    {
      "id": "resource1",
      "type": "document",
      "owner": "user123"
    }
  ]
}
```

**Example Response**:

```json
{}
```

### DELETE /v1/sources/{source}/data/{path}

**Description**: Delete data from a source at a specific path

**Path Parameters**:

- `source`: URL-encoded source name
- `path`: Data path (automatically appends `/data.json`)

**Example Response**:

```json
{}
```

---

## Stack Management

Stacks define how bundles are distributed to different environments or services based on selectors.

### GET /v1/stacks

**Description**: List all stacks with pagination support

**Query Parameters**: Same as bundles endpoint

**Example Response**:

```json
{
  "result": [
    {
      "selector": {
        "environment": ["production"],
        "service": ["auth-service", "api-gateway"]
      },
      "exclude_selector": {
        "region": ["us-west-1"]
      },
      "requirements": [
        {
          "source": "production-policies"
        },
        {
          "source": "security-baseline"
        }
      ]
    }
  ],
  "next_cursor": "eyJpZCI6IjQ1NiIsInRzIjoxNjkwMjM0NTY3fQ=="
}
```

### GET /v1/stacks/{stack}

**Description**: Get a specific stack by name

**Path Parameters**:

- `stack`: URL-encoded stack name

**Example Response**:

```json
{
  "result": {
    "selector": {
      "team": ["platform", "security"],
      "environment": ["staging", "production"]
    },
    "requirements": [
      {
        "source": "team-policies"
      },
      {
        "source": "compliance-rules"
      }
    ]
  }
}
```

### PUT /v1/stacks/{stack}

**Description**: Create or update a stack

**Path Parameters**:

- `stack`: URL-encoded stack name

**Example Request**:

```json
{
  "selector": {
    "environment": ["development"],
    "team": ["backend"]
  },
  "exclude_selector": {
    "deprecated": ["true"]
  },
  "requirements": [
    {
      "source": "dev-policies"
    },
    {
      "source": "testing-utils"
    }
  ]
}
```

**Example Response**:

```json
{}
```

---

## Error Responses

### Standard Error Format

```json
{
  "code": "error_code",
  "message": "error description"
}
```

### Error Codes and Examples

#### 400 Bad Request

```json
{
  "code": "invalid_parameter",
  "message": "bundle name must match path"
}
```

#### 401 Unauthorized

```
HTTP/1.1 401 Unauthorized
Content-Type: text/plain

Unauthorized
```

#### 403 Forbidden

```json
{
  "code": "not_authorized",
  "message": "user does not have permission to access this resource"
}
```

#### 404 Not Found

```json
{
  "code": "not_found",
  "message": "bundle 'my-bundle' not found"
}
```

#### 500 Internal Server Error

```json
{
  "code": "internal_error",
  "message": "database connection failed"
}
```

---

## Configuration Examples

### Object Storage Types

#### AWS S3 Storage

```json
{
  "object_storage": {
    "aws": {
      "bucket": "my-policy-bundles",
      "key": "bundles/my-app/bundle.tar.gz",
      "region": "us-east-1",
      "credentials": "aws-credentials",
      "url": "https://custom-s3-endpoint.com"
    }
  }
}
```

#### Filesystem Storage

```json
{
  "object_storage": {
    "filesystem": {
      "path": "/local/bundles/my-app/bundle.tar.gz"
    }
  }
}
```

#### GCP Cloud Storage

```json
{
  "object_storage": {
    "gcp": {
      "project": "my-gcp-project",
      "bucket": "policy-bundles",
      "object": "bundles/my-app/bundle.tar.gz",
      "credentials": "gcp-service-account"
    }
  }
}
```

#### Azure Blob Storage

```json
{
  "object_storage": {
    "azure": {
      "account": "mystorageaccount",
      "container": "policy-bundles",
      "key": "bundles/my-app/bundle.tar.gz",
      "credentials": "azure-credentials"
    }
  }
}
```

### Git Configuration Examples

#### Basic Git Source

```json
{
  "git": {
    "repo": "https://github.com/myorg/policies.git",
    "reference": "refs/heads/main",
    "credentials": "github-token"
  }
}
```

#### Git with Path and File Filtering

```json
{
  "git": {
    "repo": "git@github.com:myorg/monorepo.git",
    "reference": "refs/heads/production",
    "commit": "abc123def456789",
    "path": "services/auth/policies",
    "included_files": ["*.rego", "*.json"],
    "excluded_files": ["*.test.rego", "examples/*"],
    "credentials": "ssh-key"
  }
}
```

### Datasource Examples

#### HTTP Datasource

```json
{
  "datasources": [
    {
      "name": "user-directory",
      "path": "external/users",
      "type": "http",
      "config": {
        "url": "https://api.company.com/users",
        "headers": {
          "Accept": "application/json",
          "User-Agent": "OPA-Control-Plane/1.0"
        }
      },
      "credentials": "api-credentials",
      "transform_query": "users[user.id] = user { user := input.users[_] }"
    }
  ]
}
```

---

## API Features

### Pagination

- All list endpoints support pagination
- `limit`: Max 100 items per page (default 100\)
- `cursor`: Opaque cursor for next page
- `next_cursor` in response indicates more data available

### Pretty Printing

- Add `?pretty` or `?pretty=true` to format JSON responses
- Default is pretty-printed if `pretty` parameter is present without value

### URL Encoding

- All path parameters support URL encoding for special characters
- Names with spaces, slashes, etc. should be URL-encoded

### Content Type

- All API endpoints expect and return `application/json`
- Request bodies must be valid JSON for PUT/POST operations

---

## Common HTTP Status Codes

- **200**: Success
- **400**: Bad Request (invalid parameters)
- **401**: Unauthorized (missing/invalid API key)
- **403**: Forbidden (not authorized for resource)
- **404**: Not Found (resource doesn't exist)
- **500**: Internal Server Error

---
