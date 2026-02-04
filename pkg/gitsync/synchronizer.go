package gitsync

import (
	"context"
	"errors"

	"github.com/open-policy-agent/opa-control-plane/internal/config"
	"github.com/open-policy-agent/opa-control-plane/internal/gitsync"
)

// Synchronizer defines the interface for git repository synchronization.
// It provides a contract for maintaining local filesystem copies of git repositories.
//
// The synchronizer is not thread-safe. Callers should handle concurrency.
type Synchronizer interface {
	// Execute performs the synchronization of the configured Git repository.
	// If the repository does not exist on disk, it will be cloned.
	// If it exists, it will fetch the latest changes and checkout the configured reference/commit.
	//
	// Returns an error if synchronization fails.
	Execute(ctx context.Context) error

	// Close releases any resources held by the synchronizer.
	// It should be called when the synchronizer is no longer needed.
	Close(ctx context.Context)
}

// NewFromGitConfig creates a new Synchronizer for external users using a git configuration map.
// This is the recommended constructor for external projects integrating with this package.
//
// The gitConfig map should contain the following fields:
//   - "repo" (string, required): Git repository URL
//   - "reference" (string, optional): Git branch or tag name (mutually exclusive with "commit")
//   - "commit" (string, optional): Specific commit SHA to checkout (mutually exclusive with "reference")
//   - "credential" (string, optional): Name of the credential to use for authentication
//
// The secretProvider is required if credentials are needed. The provider will be called
// with the credential name to retrieve the actual credentials.
//
// Example usage:
//
//	gitConfig := map[string]any{
//	    "repo":       "https://github.com/myorg/policies.git",
//	    "reference":  "main",
//	    "credential": "github-token",
//	}
//	provider := myorg.NewVaultSecretProvider(vaultClient)
//	syncer, err := gitsync.NewFromGitConfig("/path/to/clone", gitConfig, "my-source", provider)
//	if err != nil {
//	    log.Fatal(err)
//	}
//	err = syncer.Execute(ctx)
func NewFromGitConfig(path string, gitConfig map[string]any, sourceName string, provider SecretProvider) (Synchronizer, error) {
	// Extract required field: repo
	repo, ok := gitConfig["repo"].(string)
	if !ok || repo == "" {
		return nil, errors.New("git config: 'repo' field is required")
	}

	cfg := config.Git{
		Repo: repo,
	}

	// Extract optional reference
	if ref, ok := gitConfig["reference"].(string); ok && ref != "" {
		cfg.Reference = &ref
	}

	// Extract optional commit
	if commit, ok := gitConfig["commit"].(string); ok && commit != "" {
		cfg.Commit = &commit
	}

	// Extract optional credential name
	if credName, ok := gitConfig["credential"].(string); ok && credName != "" {
		cfg.Credentials = &config.SecretRef{
			Name: credName,
		}
	}

	return gitsync.NewWithProvider(path, cfg, sourceName, provider), nil
}
