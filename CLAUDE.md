# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

OPA Control Plane (OCP) is a centralized management system for Open Policy Agent (OPA) deployments. It provides Git-based policy management, external datasources, highly-available bundle serving, and support for global/hierarchical policies with custom conflict resolution.

The binary is called `opactl` and can be used to build bundles locally or run as a service.

## Common Commands

### Build

```bash
# Build all bundles defined in config files
make build

# Or build using the binary directly
./opactl_darwin_arm64 build -c config.d/

# Build specific bundles only
./opactl_darwin_arm64 build -c config.d/ --bundle hello-world

# Build with non-interactive mode (CI/CD)
./opactl_darwin_arm64 build -c config.d/ --noninteractive
```

### Testing

```bash
# Run all tests (includes unit tests, benchmarks, library tests, and authz tests)
make test

# Run only Go unit tests
make go-test

# Run benchmarks
make go-bench

# Run library tests
make library-test

# Run authz tests (OPA policy tests for internal/authz)
make authz-test

# Run e2e migration tests
make go-e2e-migrate-test
```

### Development

```bash
# Generate code (run before building if generated files changed)
make generate

# Run linter (requires Docker)
make check

# Clean build artifacts
make clean
```

### Running as a Service

```bash
# Run the OCP service (starts HTTP API server on localhost:8282)
./opactl_darwin_arm64 run -c config.d/

# Run on custom address
./opactl_darwin_arm64 run -c config.d/ --addr 0.0.0.0:8080

# Reset persistence directory (development only)
./opactl_darwin_arm64 run -c config.d/ --reset-persistence
```

## Architecture

### Core Components

**Service Layer** (`internal/service/`): The main orchestration layer that manages bundle workers, handles configuration loading, and coordinates the build pipeline. Each bundle gets its own `BundleWorker` that runs independently and continuously rebuilds when source changes are detected.

**Builder** (`internal/builder/`): Compiles OPA bundles from multiple sources. It validates package namespacing (no overlapping packages allowed), merges filesystems from different sources, and uses OPA's native compiler to produce optimized bundles.

**Database** (`internal/database/`): SQL-based storage (SQLite/PostgreSQL/MySQL) for all OCP configuration and state. Stores bundles, sources, stacks, tokens, secrets, and source data. Implements RBAC authorization checks for all operations.

**Synchronizers**: Pull source code and data from external systems before building:
- **GitSync** (`internal/gitsync/`): Clones/pulls Git repositories with authentication support
- **HTTPSync** (`internal/httpsync/`): Fetches data from HTTP endpoints
- **SQLSync** (`internal/sqlsync/`): Retrieves source data from the database
- **BuiltinSync** (`internal/builtinsync/`): Copies built-in policy libraries from embedded FS

**Storage** (`internal/s3/`): Abstracts cloud object storage for bundle distribution. Supports AWS S3, Google Cloud Storage, Azure Blob Storage, and local filesystem.

**Server** (`internal/server/`): HTTP REST API for managing bundles, sources, and stacks. Authenticated via Bearer tokens. Runs on port 8282 by default when using `opactl run`.

### Configuration System

OCP uses a hierarchical configuration model with three main resource types:

1. **Bundles**: Define what gets built and where it's pushed. Each bundle specifies:
   - Object storage destination (S3/GCS/Azure/filesystem)
   - Labels for stack selection
   - Requirements (sources to include)

2. **Sources**: Define where policies and data come from:
   - Git repositories (with commit pinning)
   - HTTP datasources
   - Embedded files
   - Built-in libraries
   - Local directories/files

3. **Stacks**: Inject policies into bundles based on label selectors. Enable organization-wide policies and hierarchical policy composition.

Configuration files are YAML or JSON, can be split across multiple files/directories (loaded in lexical order), and support environment variable substitution for secrets.

### Build Pipeline

1. Service loads configuration from files into database
2. For each bundle, service creates a BundleWorker
3. Worker determines applicable stacks based on label selectors
4. Worker resolves dependency graph of sources (fails on cycles or conflicts)
5. Synchronizers pull latest source code/data
6. Builder validates namespace isolation (no overlapping packages)
7. Builder compiles sources into OPA bundle using merged filesystem
8. Bundle is pushed to object storage
9. Process repeats every 15 seconds or on configuration change

### Key Design Patterns

**Worker Pool**: `internal/pool/` provides a goroutine pool (default 10 workers) to build multiple bundles concurrently.

**Namespace Isolation**: Bundles cannot include sources with overlapping package paths (e.g., `x.y` and `x.y.z` conflict). This is validated during the build phase.

**Conflict Resolution**: When multiple policies (from bundle + stacks) produce different decisions, the final policy must implement conflict resolution logic. Common patterns documented in `docs/concepts.md`.

**Persistence Directory Structure**:
```
data/
├── {md5(bundle.Name)}/
│   └── sources/
│       └── {source.Name}/
│           ├── builtin/     # Built-in library files
│           ├── database/    # Source files from SQL database
│           ├── datasources/ # HTTP datasource data
│           └── repo/        # Git repository
└── sqlite.db  # Default SQLite database (when using 'run' command)
```

## Libraries

The `libraries/` directory contains built-in policy libraries that can be referenced in source configurations using the `builtin` field:
- `entitlements-v1`
- `envoy-v2.0`, `envoy-v2.1`
- `kong-gateway-v1`
- `kubernetes-v2`
- `terraform-v2.0`

Each library has its own Makefile with tests.

## Database Migrations

OCP handles database schema initialization automatically on startup. The migration system is in `internal/database/schema.go`.

## Important Notes

- The `build` command uses in-memory SQLite by default; `run` command uses persistent SQLite by default
- Configuration merging: last file wins for scalars/lists unless `--merge-conflict-fail` is set
- Bundle builds are idempotent - running build multiple times with same config produces same result
- Git sync supports SSH keys, basic auth, GitHub App auth, and token auth
- Stack selectors support glob patterns for matching label values
- OPA instances pull bundles directly from object storage, not from OCP server