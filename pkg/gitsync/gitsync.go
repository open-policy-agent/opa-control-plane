// gitsync package implements Git synchronization. It maintains a local filesystem copy for each configured
// git reference. This package implements no threadpooling, it is expected that the caller will handle
// concurrency and parallelism. The Synchronizer is not thread-safe.
package gitsync

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/go-git/go-git/v5"
	gitconfig "github.com/go-git/go-git/v5/config"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/protocol/packp/capability"
	"github.com/go-git/go-git/v5/plumbing/transport"

	"github.com/open-policy-agent/opa-control-plane/internal/config"
	"github.com/open-policy-agent/opa-control-plane/internal/metrics"
)

// configFile is an internal config file used to track if a git repository
// can be re-used or needs to be wiped.
// NB(sr): If this is called '*.yaml', or '*.json', it'll be picked up by the
// bundle builder.
const configFile = "ocpconfig"

func init() {
	// For Azure DevOps compatibility. More details: https://github.com/go-git/go-git/issues/64
	transport.UnsupportedCapabilities = []capability.Capability{
		capability.ThinPack,
	}
}

// Synchronizer manages the synchronization of a Git repository to the local filesystem.
// It handles cloning, fetching, and checking out specific references or commits.
type Synchronizer struct {
	path       string
	config     config.Git
	gh         github
	sourceName string
}

// New creates a new Synchronizer instance. It is expected the threadpooling is outside of this package.
// The synchronizer does not validate the path holds the same repository as the config. Therefore, the caller
// should guarantee that the path is unique for each repository and that the path is not used by multiple
// Synchronizer instances. If the path does not exist, it will be created.
func New(path string, config config.Git, sourceName string) *Synchronizer {
	return &Synchronizer{path: path, config: config, sourceName: sourceName}
}

// Execute performs the synchronization of the configured Git repository. If the repository does not exist
// on disk, clone it. If it does exist, pull the latest changes and rebase the local branch onto the remote branch.
func (s *Synchronizer) Execute(ctx context.Context) error {
	startTime := time.Now()

	done, err := s.execute(ctx)
	if err != nil {
		metrics.GitSyncFailed(s.sourceName, s.config.Repo)
		return fmt.Errorf("source %q: git synchronizer: %v: %w", s.sourceName, s.config.Repo, err)
	}
	if done {
		metrics.GitSyncSucceeded(s.sourceName, s.config.Repo, startTime)
	}
	return nil
}

func (s *Synchronizer) execute(ctx context.Context) (bool, error) {
	var repository *git.Repository
	var fetched bool
	if s.config.Commit == nil && s.config.Reference == nil {
		return false, errors.New("either reference or commit must be set in git configuration")
	}

	var referenceName plumbing.ReferenceName
	if s.config.Reference != nil {
		referenceName = plumbing.ReferenceName(*s.config.Reference)
	}

	// A configuration change may necessitate wiping an earlier clone: in particular, re-cloning
	// is the easiest option if the repository URL has changed. For simplicity, follow the same
	// logic with any config change EXCEPT for credentials. That's because it's harder to do, the
	// resolved file alone won't have the secrets, only their names.

	if data, err := os.ReadFile(filepath.Join(s.path, ".git", configFile)); err == nil {
		config := config.Git{
			Credentials: s.config.Credentials,
		}
		if err := json.Unmarshal(data, &config); err != nil || !config.Equal(&s.config) {
			if err := os.RemoveAll(s.path); err != nil {
				return false, err
			}
		}
	} else if !os.IsNotExist(err) {
		return false, err
	}

	var authMethod transport.AuthMethod

	repository, err := git.PlainOpen(s.path)
	if errors.Is(err, git.ErrRepositoryNotExists) { // does not exist? clone it
		authMethod, err = s.auth(ctx)
		if err != nil {
			return false, err
		}

		fetched = true
		repository, err = git.PlainCloneContext(ctx, s.path, false, &git.CloneOptions{
			URL:               s.config.Repo,
			Auth:              authMethod,
			RecurseSubmodules: git.DefaultSubmoduleRecursionDepth,
			ReferenceName:     referenceName,
			SingleBranch:      true,
			NoCheckout:        true, // We will checkout later
		})
		if err != nil {
			return false, err
		}

		data, err := json.Marshal(s.config)
		if err != nil {
			return false, err
		}
		if err := os.WriteFile(filepath.Join(s.path, ".git", configFile), data, 0644); err != nil {
			return false, err
		}
	} else if err != nil { // other errors are bubbled up
		return false, err
	}

	w, err := repository.Worktree()
	if err != nil {
		return false, err
	}

	if s.config.Commit != nil {
		opts := &git.CheckoutOptions{
			Force: true,
			Hash:  plumbing.NewHash(*s.config.Commit),
		}
		if w.Checkout(opts) == nil { // success! nothing further to do
			return fetched, nil
		}
	}

	// If we couldn't check out the hash, we're using a branch or tag reference,
	// or we have not checked out anything yet. Either way, we'll need to fetch
	// and checkout.

	if authMethod == nil {
		authMethod, err = s.auth(ctx)
		if err != nil {
			return false, err
		}
	}

	remote := "origin"
	fetched = true
	if err := repository.FetchContext(ctx, &git.FetchOptions{
		RemoteName: remote,
		Auth:       authMethod,
		Force:      true,
		RefSpecs: []gitconfig.RefSpec{
			gitconfig.RefSpec(fmt.Sprintf("+refs/heads/*:refs/remotes/%s/refs/heads/*", remote)),
			gitconfig.RefSpec(fmt.Sprintf("+refs/tags/*:refs/remotes/%s/refs/tags/*", remote)),
		},
	}); err != nil && err != git.NoErrAlreadyUpToDate {
		return false, err
	}

	opts := &git.CheckoutOptions{
		Force: true, // Discard any local changes
	}
	switch {
	case s.config.Reference != nil:
		ref := fmt.Sprintf("refs/remotes/%s/%s", remote, *s.config.Reference)
		opts.Branch = plumbing.ReferenceName(ref)
	case s.config.Commit != nil:
		opts.Hash = plumbing.NewHash(*s.config.Commit)
	}

	return fetched, w.Checkout(opts)
}

// Close closes the synchronizer and releases any resources.
func (*Synchronizer) Close(context.Context) {
	// No resources to close.
}
