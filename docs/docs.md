
# OPA Control Plane Documentation

Table of Contents

 1. [Introduction](#1-introduction)
 1. [Feature Comparison: Styra DAS vs OPA Control Plane](#2-feature-comparison-styra-das-vs-opa-control-plane) 
1. [Migration Overview & Preparation](#3-migration-overview--preparation)
   1. [What You’ll Need](#31-what-youll-need)
   1. [Recommended Workflow](#32-recommended-workflow)
1. [Migration Preparation](#4-migration-preparation)
1. [Migration Steps (Updated for Latest Workflow)](#5-migration-steps-updated-for-latest-workflow)
   1. [Set Up Authentication](#51-set-up-authentication)
   1. [Run the Migration Command](#52-run-the-migration-command)
   1. [Review the Output](#53-review-the-output)
   1. [Update Configs as Needed](#54-update-configs-as-needed)
   1. [Run OPA Control Plane](#55-run-opa-control-plane)
   1. [Backtest the Bundle](#56-backtest-the-bundle)
   1. [Finalize and Test End-to-End](#57-finalize-and-test-end-to-end)
1. [Running OPA Control Plane](#6-running-opa-control-plane)
   1. [Discovery Bundles & Multi-Bundle Support](#61-discovery-bundles--multi-bundle-support)
   1. [Disabling DAS Decision Logging](#62-disabling-das-decision-logging)
1. [Backtesting OPA Control Plane Bundles](#7-backtesting-opa-control-plane-bundles)
   1. [Understanding Backtest Output](#71-understanding-backtest-output)
   1. [Comparing Bundles](#72-comparing-bundles)
1. [Testing Policy Changes via Git](#8-testing-policy-changes-via-git)
1. [System-Type Migration Guides](#9-system-type-migration-guides)
   1. [Custom System Type](#91-custom-system-type)
   1. [Kubernetes System Type](#92-kubernetes-system-type)
   1. [Envoy System Type](#93-envoy-system-type)
   1. [Istio System Type](#94-istio-system-type)
   1. [Terraform System Type](#95-terraform-system-type)
   1. [Entz System Type](#96-entz-system-type)
   1. [Other System Types](#97-other-system-types)
1. [Bundle and Policy Promotion](#10-bundle-and-policy-promotion)
   1. [Overview: Promotion in DAS vs OPA Control Plane](#101-overview-promotion-in-das-vs-opa-control-plane)
   1. [Why This Matters: Real-World Promotion Nuances](#102-why-this-matters-real-world-promotion-nuances)
   1. [Recommended Promotion Patterns in OPA Control Plane](#103-recommended-promotion-patterns-in-opa-control-plane)
   1. [Best Practices](#104-best-practices)
   1. [Promotion Comparison Table](#105-promotion-comparison-table)
1. [Datasources: Migration Guidance](#11-datasources-migration-guidance)
   1. [Overview](#111-overview)
   1. [What’s Supported in OPA Control Plane](#112-whats-supported-in-opa-control-plane)
   1. [Migration Recommendations](#113-migration-recommendations)
1. [Appendix: Troubleshooting & FAQs](#12-appendix-troubleshooting--faqs)

---

## 1. Introduction

**What is OPA Control Plane?**  
 OPA Control Plane is an open-source control plane for policy management. Its core capabilities include:

* Managing policy as code: Policies are stored and versioned in a Git repository.

* Dependency consolidation: Dependencies are defined as requirements in the configuration, and OPA Control Plane resolves and builds them as part of the policy bundle.

* Bundle creation and distribution: OPA Control Plane builds OPA policy bundles and pushes them to an S3-compatible storage solution.

* OPA integration: OPA can be configured to pull bundles directly from S3 storage, enabling automated and secure policy enforcement.

**Why migrate?**  
 OPA Control Plane provides a streamlined, open alternative to Styra DAS, making it easier to manage, version, and distribute your policies using standard tools and processes.

---

## 2. Feature Comparison: Styra DAS vs OPA Control Plane

| Feature Category | Styra DAS | OPA Control Plane | Notes & Migration Considerations |
| ----- | ----- | ----- | ----- |
| Policy Authoring | \- UI-based policy authoring- Policy-as-Code (Git)- In-browser Rego editor | \- Policy-as-Code (Git)- Recommended: IDE (e.g., VSCode) with Regal/OPA linter | Use VSCode (or another IDE) with [Regal](https://github.com/StyraInc/regal) for linting. No UI-based authoring in OPA Control Plane. |
| Policy Impact Analysis | \- Built-in impact analysis- Decision log-based backtesting | \- PR-based unit testing- Temporary backtesting command | Backtesting requires DAS decision logs. Long-term: use test-driven dev and unit testing. Decision log management is external. |
| Distribution | \- Integrated bundle distribution via DAS- HA via SLP | \- Bundle pushed to object storage; OPA pulls from there | No SLP. OPA configured to pull from object storage. |
| Monitoring & Logging | \- OPA health/metrics/logs in UI | \- Not included; must be configured externally | Use OPA’s Prometheus endpoint and external log storage. |
| Enterprise Readiness | \- SSO, RBAC, multi-tenant, multi-cloud | \- No built-in SSO/RBAC- Multi-system/cloud via config | SSO/RBAC can be added in OSS. Managed via config. |
| System Types | \- Predefined: Kubernetes, Envoy, Terraform, Kong, etc. | \- Same system types supported- Conflict/monitoring logic open source | Users can build/customize system types from libraries. |
| Policy Promotion | \- Manual/automatic promotion via UI/API | \- Promotion via Git workflow or bundle copy | No UI/manual mode; promotion is artifact-based. |
| Stacks & Libraries | \- Managed in UI | \- Managed via Git, reusable in config | Managed through code/PRs instead of UI. |
| Decision Logs | \- Centralized storage/search | \- No built-in storage/UI | OPA must be configured to push logs externally. |
| UI & UX | \- Comprehensive UI | \- CLI/Git workflows only | Management is code-based. |

---

## 3. Migration Overview \& Preparation

### 3.1. What Youll Need

* **DAS API token:** Workspace Viewer or higher

* **OPA Control Plane CLI:** Installed locally

* **S3/MinIO/GCS/Azure Storage bucket:** For bundle storage

* **Git repo:** For policy source-of-truth (use HTTPS and personal access tokens\!)

* **GitHub/MinIO credentials:** For secrets config

* (Optional) DAS decision logs for backtesting

  ### 3.2. Recommended Workflow

* **Migrate** DAS system(s) one at a time, or all systems using `ocp migrate`

* **Organize configs** in `config.d/<system-id>/` per system for easier management

* **Update configs:** S3/MinIO bucket, git repo, secrets

* **Run OPA Control Plane** and backtest before production

* **Finalize OPA deployment** and policy promotion flow

---

## 4. Migration Preparation

### **Prerequisites** {#prerequisites}

* **Styra DAS Token:** API token with at least Workspace Viewer permission.

* **OPA Control Plane CLI:** Installed locally.

* **Styra DAS Tenant URL:** e.g., [https://expo.styra.com](https://expo.styra.com/)

* **Git Repository:** For storing and versioning policies.

* **S3-Compatible Storage:** AWS S3, GCP, Azure Storage, or MinIO bucket, with credentials.

---

## 5. Migration Steps (Updated for Latest Workflow)

### 5.1. Set Up Authentication

Export your Styra DAS token:

```shell
export STYRA_TOKEN=<your_token>
```

The token must have at least **Workspace Viewer** permissions.

---

### 5.2. Run the Migration Command

Run OPA Control Plane migrate for a system, with S3 and datasources options:

```shell
./ocp migrate \
  --url https://expo.styra.com \
  --system-id "<your system id>" \ 
  --s3-bucket-name <your bucket name> \
  --s3-bucket-region us-east-1 \
  --prune \
  --datasources \
  --embed-files
```

#### Key Flags and When to Use Them:

* `--system-id` — Migrate a specific system.

* `--url` — Styra DAS tenant URL.

* `--s3-bucket-name` / `--s3-bucket-region` — **Set placeholders** for bundle destinations (required\!).

* `--datasources` — Pulls down push datasources not in git (recommended for systems using external data).

* `--embed-files` — Creates a config file with embedded files (datasources, etc.), under `config.d/<system-id>`.

* `--prune` — Cleans up unused resources in the migration.

* `--stdout` — Output config to stdout, but **default is to write config files to `config.d/<system-id>`** for organization.

#### Note:

* If your DAS system uses git with SSH, *update the generated config to use HTTPS and tokens*. SSH is not supported by OPA Control Plane at this time.

* Each DAS system gets its own subfolder, making multi-system management much simpler.

---

### 5.3. Review the Output

After running the migration, you’ll have a directory structure like:

```
config.d/
  config-bundles.yaml
  config-secrets.yaml
  config-sources.yaml
  <test-files.yaml> // Optional if running with --embed-files
```

**Note**: If you run with the `--system-id` option, an additional system-id folder will be created under config.d, containing the system's configuration.

**Note:** If you have files that are in DAS but not included in git then they will be placed in a folder called files. It is recommended to then move these files into the same git repository as the rest of the policies or data.

**Action:**

* Open each file in the system folder.

* Remove or update any references to SSH (for git sources).

* Update `config-bundles.yaml` to use your correct S3 bucket/path.

* Update `config-secrets.yaml` to use correct Github/MinIO credentials.

* Check `config-sources.yaml`—update git repo URLs if needed (HTTPS only).

* Review embedded files config (`test-files.yaml`) for any non-git files/DAS push datasources.

---

### 5.4. Update Configs as Needed

* **Git Sources:**

  * Use HTTPS URLs and access tokens (not SSH).

  * One repo per system/environment (separation), or one repo with directories/branches/tags per environment.

  * *See Git Policy Organization Patterns below.*

* **Secrets:**

  * Only HTTP Basic Auth (username/personal access token) is supported for Git.


  Secrets define the configuration for secrets/tokens used by OPA Control Plane for Git synchronization, datasources, etc.

  Each secret is stored as a map of key-value pairs, where the keys and values are strings. Secret type is also declared in the config.

  For example, a secret for basic HTTP authentication might look like this (in YAML):

```
My_secret:
type: basic_auth
username: myuser
password: mypassword
```

  Secrets may also refer to environment variables using the ${VAR\_NAME} syntax. For example:

```
My_secret:
type: aws_auth
access_key_id: ${AWS_ACCESS_KEY_ID}
secret_access_key: ${AWS_SECRET_ACCESS_KEY}
session_token: ${AWS_SESSION_TOKEN}

```


In this case, the actual values for username and password will be read from the environment variables `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY,`and `AWS_SESSION_TOKEN`.

Currently the following secret types are supported:

* "aws\_auth" for AWS authentication. Values for keys "access\_key\_id", "secret\_access\_key", and optional "session\_token" are expected.  
* "azure\_auth" for Azure authentication. Values for keys "account\_name" and "account\_key" are expected.  
* "basic\_auth" for HTTP basic authentication. Values for keys "username" and "password" are expected.  
*  "headers" (string array) is optional and can be used to set additional headers for the HTTP requests (currently only supported for git).  
* "gcp\_auth" for Google Cloud authentication. Value for a key "api\_key" or "credentials" is expected.  
*  "github\_app\_auth" for GitHub App authentication. Values for keys "integration\_id", "installation\_id", and "private\_key" are expected.  
* "ssh\_key" for SSH private key authentication. Value for key "key" (private key) is expected. "fingerprints" (string array) and "passphrase" are optional.  
* "token\_auth" for HTTP bearer token authentication. Value for a key "token" is expected.


* .**Bundles:**

  * Set `bucket` and `key` in `config-bundles.yaml` to reflect your S3/MinIO layout.

* **Sources:**

  * Point to the right directory or branch/tag as needed.

* **Stacks:**

  * Selector-based, not policy-based: A stack references a library and applies it to all bundles matching the selector (label-based).

---

### 5.5. Run OPA Control Plane

With your configs ready (in `config.d/`), run OPA Control Plane:

```shell
./ocp run -c config.d
```

*   
  By default, this merges all configs in the folder and starts the server.

* Use `--once` for one-time build/test.

* Use `--log-level debug` for troubleshooting.

---

### 5.6. Backtest the Bundle

Backtest against DAS historical decisions:

```shell
./ocp backtest --config config.d --url http://expo.styra.com
```

*   
  Shows differences in policy outcomes and timing.

* **Failures may be caused by:**

  * Missing datasources (`--datasources`/`--embed-files` not used).

  * Policy differences (true/false diff).

  * Slow evaluation (\>100% longer than DAS).

#### Example Output Explanation

* `reason: "bundle decision took over 100% longer"`: Performance regression.

* `reason: "--- Expected\n+++ Found ..."`: Policy result changed (usually missing input data or policies).  
  Note: One thing to check is that policies are fully up to date before running the migration. If you use Manual bundle deployments for Styra DAS it is possible that the bundle that is currently deployed to your OPA’s may be different then the policy that is in git that OPA Control Plane will use to build the bundle. If you do experience policy issues it is important to review the reason as it will give you an indicator as to why the decision result was different.

---

### 5.7. Finalize and Test End-to-End

* Update your OPA config to point to the correct S3/MinIO bucket.

* Push a policy change in Github.

* Confirm OPA Control Plane sees the change, builds a new bundle, and pushes it to object storage.

* Watch OPA logs (or enable decision printing) to verify new policy is loaded and applied.

---

### Git Policy Organization Patterns

* **One repo per system/environment:**

  * Clean separation, easier to manage access but can lead to duplication.

* **One repo with directories:**

  * Organize by subdirectory per system/environment.

  * Config points to directory in repo.

* **Branches/tags per environment:**

  * **Recommended for promotion\!**

  * Each branch/tag is mapped to a bundle in S3/MinIO (e.g., `dev`, `staging`, `prod`).

* **GitHub App:**

  * Advanced: Not documented here—see future updates.

---

### Troubleshooting Tips

* If OPA cannot pull bundle:

  * Check S3/MinIO key, bucket, and permissions.

  * Confirm credentials in secrets.

* Decision mismatches:

  * Ensure all files and datasources are migrated and referenced.

  * Validate that the correct directories/branches are being used.

* SSH repo URLs:

  * Switch to HTTPS and use personal access tokens.

---

## Additions & Changes Based on Your Experience

* You must include `--datasources` and `--embed-files` for systems with push datasources (not in git), otherwise policy/data may be missing and backtests will fail.

* Config is now folder-based (per system), not a single file.

* Terms are shifting: **bundles**, **sources**, and **stacks**—*not* “systems” and “libraries.”

* Backtesting output can now report timing and functional differences; review details for remediation.

---

## 6\. Running OPA Control Plane

OPA Control Plane **does not serve bundles** itself. It pushes them to your configured object storage (e.g., S3).  
 Configure OPA (or other agents) to pull bundles from storage.

**Usage:**

```shell
ocp run --config config.d
```

**Common Flags:**

* `-a, --addr string`: Listening address (default: localhost:8282)

* `-c, --config strings`: Path to config file (default: config.yaml)

* `-d, --data-dir string`: Persistence directory (default: data)

* `--merge-conflict-fail`: Fail on config merge conflicts

* `--once`: Build bundles once, then exit (for CI/CD/testing)

* `--reset-persistence`: Reset data directory (development use)

**Typical Workflow:**

* Development/Test: Use `--once`

* Production: Run as a long-lived service (watches for git changes)

**Example:**

```shell
ocp run --config config.yaml --once
```

### 6.1. Discovery Bundles & Multi-Bundle Support

Styra DAS supports a “discovery bundle,” allowing OPA to download additional policy/data bundles dynamically. OPA Control Plane does **not** generate a discovery bundle by default.

* If you wish to preserve this pattern, use OPA’s multiple bundle support and specify multiple bundles in your `opa.yaml`.

* Migration step: **Remove** DAS discovery bundle references from your OPA config and explicitly list all bundles OPA should download.

### 6.2. Disabling DAS Decision Logging

After migration, disable decision logging to DAS and ensure OPA is configured only to pull bundles from S3 (or other object storage).

* This avoids double logging and unexpected bundle updates.

---

## 7. Backtesting OPA Control Plane Bundles

**What is Backtesting?**  
 Validate policy parity after migration: replays past decisions (logs exported from DAS) against your OPA Control Plane-generated bundle.

**Usage:**

```shell
ocp backtest --config config.d --url https://your-tenant.styra.com
```

**Common Flags:**

* `-c, --config strings`: Path to config file

* `-u, --url string`: DAS tenant URL to fetch decision logs

* `-n, --decisions int`: Number of decisions to backtest (default: 100\)

* `--policy-type string`: Filter by policy type (validating, mutating, etc.)

* `--max-eval-time-inflation int`: Max allowed increase in decision eval time (%)

**Example:**

```shell
ocp backtest --config config.yaml --url https://john.styra.com --decisions 200 --policy-type validating
```

**Note:** Backtesting is most useful during initial migration. After switching to OPA Control Plane, new DAS decision logs will not be available unless you continue running DAS in parallel.

### 7.1. Understanding Backtest Output

* Backtest compares policy decisions from OPA Control Plane vs. historical decisions from DAS.

* Mismatches can indicate:

  * Policy drift (git vs deployed bundle)

  * Differences in input data shape or resource data (esp. with kube-mgmt)

  * Library/stack mismatches

  * File encoding errors

* **Tips:**

  * Start small (`--decisions 10`)

  * Use backtest results to spot policies/data needing correction.

### 7.2. Comparing Bundles

If no decision logs are available, use the `OPA Control Plane compare` command to diff the OPA Control Plane-generated bundle against the bundle currently served by DAS:

sh

CopyEdit

`ocp compare --config config.yaml --url https://your-tenant.styra.com`

* Compares files, libraries, and dependencies.

* Useful for verifying parity before cutover.

* Flags: `-c`, `-u`, `--merge-conflict-fail`, etc.

---

## 8. Testing Policy Changes via Git

* **Edit Policy:** Make a change in your git repo.

* **Push Changes:** Commit and push to the tracked branch.

* **Bundle Update:** OPA Control Plane rebuilds and pushes to your storage (e.g., S3).

* **Validate:** Optionally, re-run backtest or manually verify OPA picks up the new bundle.

**Tip:**  
 Align git branches to S3 bundle paths (dev, staging, prod) for clarity.  
 Promotion \= merge to branch or bundle artifact copy.

**Promotion via Git or S3**

* Use Git branches/tags to promote between dev/staging/prod.

* Map each environment to a unique S3 key (e.g., `dev/bundle.tar.gz`, `prod/bundle.tar.gz`).

* No UI/manual promotion: the artifact (bundle) is the promotion event.

---

## 9. System-Type Migration Guides

### 9.1. Custom System Type

**(Covered by general migration steps above; reference as needed.)**

---

### 9.2. Kubernetes System Type

#### Overview

* DAS → OPA Control Plane: OPA Control Plane replaces centralized policy management & bundle delivery.

* SLP → kube-mgmt: SLP is not open source; use [kube-mgmt](https://github.com/open-policy-agent/kube-mgmt) instead.

* All config/code-based—no UI.

#### Migration Steps

**1\. Inventory & Preparation**

* List all systems, stacks, and libraries.

* Gather k8s resource types referenced in Rego.

* Access to DAS, S3, Git, and K8s cluster.

**2\. Export Config from DAS**

```shell
export STYRA_TOKEN=<your_token>
ocp migrate -u https://your-tenant.styra.com --system-id <system_id> > config.yaml
```

*   
  Output includes system labels/selectors, stacks/libraries, base64-encoded files.

**3\. Update OPA Control Plane Config**

* Set up `object_storage`, `git`, `secrets`, `files`, `stacks`, `libraries`.

**4\. Deploy OPA Control Plane and Build Bundles**

```shell
ocp run -c config.yaml
```

**5\. Prepare OPA and kube-mgmt for New Bundle**

*OPA Config Example (S3 bundle):*

```
apiVersion: v1
kind: ConfigMap
metadata:
  name: opa-config
  namespace: opa-system
data:
  opa.yaml: |
    services:
      - name: s3
        url: s3://<your-bucket-name>
    bundles:
      kubernetes:
        service: s3
        resource: bundle.tar.gz
    labels:
      system-type: "kubernetes:v2"
```

**OPA S3 Credentials Example (env in Deployment YAML):**

```
env:
  - name: AWS_ACCESS_KEY_ID
    valueFrom:
      secretKeyRef:
        name: opa-s3-creds
        key: access_key_id
  - name: AWS_SECRET_ACCESS_KEY
    valueFrom:
      secretKeyRef:
        name: opa-s3-creds
        key: secret_access_key
```

See [OPA S3 Bundle Management Docs](https://www.openpolicyagent.org/docs/management-bundles#amazon-s3) for advanced config.

**6\. Configure kube-mgmt**

* List each resource kind needed by your policies as `--replicate` or `--replicate-cluster` args.

* Example:

```
--replicate-cluster=v1/namespaces
--replicate=apps/v1/deployments
--replicate=v1/pods
```

**7\. Test & Troubleshoot**

* Verify OPA pulls bundle from S3.

* Ensure kube-mgmt data available (`/v1/data/kubernetes`).

* Validate webhooks (admission registration).

* Check for missing data/resources.

---

### 9.3. Envoy System Type

#### **Overview** {#overview-1}

* OPA deployed as ext\_authz for Envoy.

* No SLP required in OPA Control Plane.

* No UI/snippets—just git, config, S3.

#### Migration Steps

* Export policies/config via `ocp migrate`.

* Set `object_storage` and `git` in config.yaml.

* Update OPA deployment to remove SLP dependencies.

* OPA config example:

```
apiVersion: v1
kind: ConfigMap
metadata:
  name: opa-envoy-config
  namespace: opa-system
data:
  opa.yaml: |
    services:
      - name: s3bundle
        url: https://s3.amazonaws.com
    bundles:
      envoy:
        service: s3bundle
        resource: /my-envoy-bundles/prod/envoy-bundle.tar.gz
        persist: true
    labels:
      app: envoy
```

---

### 9.4. Istio System Type

*(To be completed; follow pattern above. Note differences from Envoy in system type and webhook integration.)*

---

### 9.5. Terraform System Type

*(To be completed; describe bundle flow for Terraform policy enforcement.)*

---

### 9.6. Entz System Type

**Note:**  
 Entz system-type migration not yet tested/complete.  
 Document will be updated as support is finalized.

---

### 9.7. Other System Types

* Follow general workflow.

* Reference [OPA Docs](https://www.openpolicyagent.org/docs/latest/) for custom integrations.

---

Great catch\! Yes, some context from your earlier *brain dump* and detailed reasoning around the nuances of **policy promotion and bundle lifecycle** in DAS versus OPA Control Plane got shortened in the last version to keep the doc more reference-style and concise. The details about manual mode, stack propagation risks, and how promotion in DAS can cause git/policy divergence—those are critical *for understanding why OPA Control Plane does things differently*.

If you want the **Bundle and Policy Promotion** section to stand alone for someone who hasn’t read the rest, it’s worth bringing back some of that context. Here’s a revised, more detailed section, bringing together the key points you outlined, while keeping the reference style clear:

---

## 10. Bundle and Policy Promotion

### 10.1. Overview: Promotion in DAS vs. OPA Control Plane

**Styra DAS**

* Supports both git-based and manual bundle promotion.

* Most teams use separate systems for dev, staging, and prod.

* Each system typically references a branch, tag, or commit—but DAS also allows “manual mode” for bundles (so policies only go live when a bundle is explicitly promoted).

* DAS can promote (copy) bundles between systems (dev → stage → prod) via UI or API.

* Stack policies can affect multiple systems at once—sometimes unintentionally, as a stack update may propagate to all systems referencing it.

**OPA Control Plane**

* **No UI/manual promotion:** There’s no UI or API “promote bundle” button.

* **Git and object storage are the source of truth:** Promotion is controlled by merging to a branch or copying a bundle artifact between storage locations.

* Stack changes propagate per how your git and bundle build process are structured—no hidden updates.

### 10.2. Why This Matters: Real-World Promotion Nuances

**In DAS:**

* Manual bundle promotion was commonly used to tightly control when a policy actually reached prod.

* “Manual mode” disables automatic bundle updates—someone must click "promote" or use the API, ensuring only tested bundles reach prod.

* This can introduce a risk: if stack policies change, they can propagate into a bundle without the user realizing, especially if stack content isn’t versioned or pinned.

* Sometimes the actual policies in a deployed bundle may diverge from what’s in git or in the UI, leading to confusion—because DAS doesn’t extract policies from bundles for display after a manual promotion.

**In OPA Control Plane:**

* There is no “manual mode” or UI-based promotion.

* All policy updates flow from git or by copying bundle artifacts in storage.

* **Promotion \== artifact movement:** Either merge to a branch (which triggers a new bundle build to a prod S3 key), or copy a tested bundle artifact to a new environment key in storage.

* This *simplifies visibility*—the policies in your git are what end up in the bundle, and your storage layout controls which environment sees which version.

### 10.3. Recommended Promotion Patterns in OPA Control Plane

* **Git-Driven Promotion:**

  * Use dev, stage, and prod branches in git, each mapped to their own bundle path (e.g., `dev/bundle.tar.gz`, `prod/bundle.tar.gz`).

  * Merge PRs to promote tested policies.

* **Artifact-Based Promotion:**

  * After testing a bundle, copy it (e.g., in S3) from dev to prod. (Use tools like `aws s3 cp`.)

* **Stack/Library Caution:**

  * Since stack/library changes propagate wherever they are referenced, use tags, versions, or branch pinning if you want more control.

  * Always review changes in shared logic before promotion.

### 10.4. Best Practices

* Keep all policies and stack content in git for traceability.

* Use code reviews/CI to gate promotions and catch dependency changes.

* Separate bundle paths in object storage by environment for clarity.

* Treat bundle artifact copy (in storage) as a promotion event—track it in your CI/CD or deployment pipeline.

* For organizations with compliance needs, ensure auditability via git logs and S3 access logs.

### 10.5. Promotion Comparison Table

| Aspect | Styra DAS | OPA Control Plane |
| ----- | ----- | ----- |
| Manual mode | Yes (UI/API; bundle promotion) | No; promotion is git/CI/storage action |
| Stack policy effects | Can ripple to many systems | Explicit via git structure |
| Policy visibility | May diverge in UI after promotion | Git is always the source |
| Audit trail | UI logs, API actions | Git history, S3 access logs |
| Workflow | UI- and API-driven | Git- and artifact-driven |

---

## 11. Datasources: Migration Guidance

### 11.1. Overview

Styra DAS supports a wide variety of datasources—including Kubernetes state, S3, GCS, Git, HTTPS, LDAP, and Okta—to enhance policy decisions with external data. In OPA Control Plane, datasource support is intentionally simplified and config-driven. This section describes what’s supported in OPA Control Plane, how to migrate your existing datasources, and recommended approaches for the most common scenarios.

---

### 11.2. What’s Supported in OPA Control Plane

* **Kubernetes Datasource**

  * **DAS:** Provided a live JSON view of Kubernetes cluster state for use in policy and compliance.

  * **OPA Control Plane:** *Not supported directly as a datasource.*

    * **Migration recommendation:**

      * Use [kube-mgmt](https://github.com/open-policy-agent/kube-mgmt) alongside OPA to load Kubernetes resources into OPA’s `data.kubernetes` document.

      * Explicitly list all resource types needed in your kube-mgmt deployment.

      * See the Kubernetes migration guide for a detailed workflow.

* **Other Datasources (S3, GCS, Git, HTTPS, LDAP, Okta, JSON, etc.)**

  * **DAS:** Allowed pulling data from a wide range of external systems for policy use.

  * **OPA Control Plane:**

    * **Git:** Supported for policy-as-code (not as a dynamic datasource).

    * **HTTP:** Not yet available (future OPA Control Plane releases will address this).

    * **Other types (S3, GCS, LDAP, Okta, etc.):** Not supported directly.

      * **Migration recommendation:**

        * Move static or infrequently changing data into your Git repository as versioned files. OPA Control Plane will include them in the policy bundle delivered to OPA.

        * For dynamic data requirements, build external jobs or sidecars to fetch and inject data into OPA at runtime, or plan to use HTTP datasources when supported in future releases.

---

### 11.3. Migration Recommendations

* **Move static data to Git:**  
   Place reference data (e.g., allow-lists, configuration, mappings) as JSON/YAML in your Git repo, then include in your bundle.

* **For dynamic/API-driven data:**  
   Use external automation to fetch data and load into OPA (as files, bundles, or via the OPA REST API). Monitor OPA Control Plane releases for HTTP datasource support.

* **Kubernetes resource data:**  
   Rely on kube-mgmt to inject all required Kubernetes objects into OPA.

---

**Summary:**  
 OPA Control Plane does not support the full range of datasources found in Styra DAS. Audit your current DAS systems for datasource dependencies and refactor as needed:

* Use Git for static data.

* Use kube-mgmt for Kubernetes data.

* Use external processes for other dynamic data needs.

---

## 12. Appendix: Troubleshooting & FAQs

* Check for missing required sections (object\_storage, secrets).

* Confirm all referenced policy files exist and are correctly encoded.

* If OPA cannot pull bundle: check S3 permissions, key names, and bucket policy.

* Decision logs: set up external log storage (e.g., Loki, Elasticsearch, cloud logging).

* Webhook errors: verify TLS/certs, webhook config, and OPA health endpoints.

---

**\[End of Guide\]**

### 

