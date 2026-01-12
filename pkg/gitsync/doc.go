// Package gitsync provides git repository synchronization for OPA bundle building.
//
// This package implements secure git clone, fetch, and checkout operations with
// support for multiple authentication methods:
//   - GitHub App (short-lived installation tokens)
//   - Personal Access Tokens (PAT)
//   - SSH keys with fingerprint validation
//   - Basic HTTP authentication
//   - OIDC Client Credentials
//
// The primary type is Synchronizer, which manages the lifecycle of a git repository
// clone and keeps it synchronized with the remote repository.
//
// Example usage:
//
//	import "github.com/open-policy-agent/opa-control-plane/pkg/gitsync"
//	import "github.com/open-policy-agent/opa-control-plane/internal/config"
//
//	gitConfig := config.Git{
//	    Repo:      "https://github.com/myorg/policies.git",
//	    Reference: ptr("main"),
//	    Credentials: &config.SecretRef{
//	        Name: "github-token",
//	        // ... credential configuration
//	    },
//	}
//
//	syncer := gitsync.New("/path/to/clone", gitConfig, "my-source")
//	err := syncer.Execute(ctx)
//	if err != nil {
//	    log.Fatal(err)
//	}
//	defer syncer.Close(ctx)
//
// Thread Safety: Synchronizer instances are NOT thread-safe. Each instance should
// be used by a single goroutine. Create separate instances for concurrent operations.
package gitsync
