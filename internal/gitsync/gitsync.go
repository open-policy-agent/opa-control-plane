// gitsync package implements Git synchronization. It maintains a local filesystem copy for each configured
// git reference. This package implements no threadpooling, it is expected that the caller will handle
// concurrency and parallelism. The Synchronizer is not thread-safe.
package gitsync

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	gohttp "net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/bradleyfalzon/ghinstallation/v2"
	"github.com/go-git/go-git/v5"
	gitconfig "github.com/go-git/go-git/v5/config"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/protocol/packp/capability"
	"github.com/go-git/go-git/v5/plumbing/transport"
	"github.com/go-git/go-git/v5/plumbing/transport/http"
	gitssh "github.com/go-git/go-git/v5/plumbing/transport/ssh"
	pkgsync "github.com/open-policy-agent/opa-control-plane/pkg/sync"

	"golang.org/x/crypto/ssh"

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

// SecretProvider abstracts the source of secrets, allowing external projects
// to integrate with their own secret management backends (Vault, AWS Secrets Manager,
// HashiCorp Vault, etc.).
//
// The GetSecret method returns a map containing the secret data. The map MUST include
// a "type" field to indicate the credential type, and additional fields based on the type.
//
// Supported credential types and their required fields:
//
// Type: "basic_auth"
//   - username (string, optional)
//   - password (string, required)
//   - headers ([]string, optional) - format: "Header-Name: value"
//
// Type: "github_app"
//   - integration_id (int64, required)
//   - installation_id (int64, required)
//   - private_key (string, required) - path to PEM file
//
// Type: "ssh_key"
//   - key (string, required) - SSH private key in PEM format
//   - passphrase (string, optional)
//   - fingerprints ([]string, required) - SHA256 fingerprints
//
// Type: "bearer_token"
//   - token (string, required)
//
// Type: "oidc_client_credentials"
//   - issuer (string, required if token_url not provided)
//   - token_url (string, required if issuer not provided)
//   - client_id (string, required)
//   - client_secret (string, required)
//   - scopes ([]string, optional)
//
// Example:
//
//	// GitHub App credentials
//	return map[string]any{
//	    "type":            "github_app",
//	    "integration_id":  int64(12345),
//	    "installation_id": int64(67890),
//	    "private_key":     "/path/to/key.pem",
//	}, nil
//
// This interface enables:
//   - Centralize secret management
//   - Enforce security policies
//   - Rotate credentials without config changes
//   - Audit secret access
//   - Integrate with enterprise secret management systems
//
// SecretProvider is an alias to pkg/sync.SecretProvider for backward compatibility.
// See pkg/sync package for interface documentation and supported credential types.
type SecretProvider = pkgsync.SecretProvider

type Synchronizer struct {
	path           string
	config         config.Git
	gh             github
	sourceName     string
	secretProvider SecretProvider
}

// New creates a new Synchronizer instance. It is expected the threadpooling is outside of this package.
// The synchronizer does not validate the path holds the same repository as the config. Therefore, the caller
// should guarantee that the path is unique for each repository and that the path is not used by multiple
// Synchronizer instances. If the path does not exist, it will be created.
func New(path string, config config.Git, sourceName string) *Synchronizer {
	return &Synchronizer{path: path, config: config, sourceName: sourceName}
}

// WithSecretProvider configures the synchronizer to use an external SecretProvider for authentication.
// This allows external projects to integrate their own secret management systems (e.g., Whisper, Vault).
//
// If provider is nil, credentials will be resolved from the config file.
//
// Example:
//
//	s := gitsync.New(path, config, sourceName).
//	    WithSecretProvider(myProvider)
func (s *Synchronizer) WithSecretProvider(provider SecretProvider) *Synchronizer {
	s.secretProvider = provider
	return s
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

func (*Synchronizer) Close(context.Context) {
	// No resources to close.
}

func (s *Synchronizer) auth(ctx context.Context) (transport.AuthMethod, error) {
	if s.config.Credentials == nil {
		return nil, nil
	}

	var typed any

	// Resolve credentials to typed value
	if s.secretProvider != nil {
		// External SecretProvider integration
		credMap, err := s.secretProvider.GetSecret(ctx, s.config.Credentials.Name)
		if err != nil {
			return nil, err
		}
		// Convert map to typed credential
		secret := &config.Secret{
			Name:  s.config.Credentials.Name,
			Value: credMap,
		}
		typed, err = secret.Typed(ctx)
		if err != nil {
			return nil, err
		}
	} else {
		// Legacy config-based credentials
		var err error
		typed, err = s.config.Credentials.Resolve(ctx)
		if err != nil {
			return nil, err
		}
	}

	// Common path: convert typed credential to AuthMethod
	return authFromTyped(ctx, &s.gh, typed)
}

// authFromTyped converts a typed config credential to transport.AuthMethod
func authFromTyped(ctx context.Context, gh *github, value any) (transport.AuthMethod, error) {
	switch value := value.(type) {
	case *config.SecretBasicAuth:
		return &basicAuth{
			Username: value.Username,
			Password: value.Password,
			Headers:  value.Headers,
		}, nil

	case config.SecretGitHubApp:
		token, err := gh.Token(ctx, value.IntegrationID, value.InstallationID, value.PrivateKey)
		if err != nil {
			return nil, err
		}
		return &http.BasicAuth{Username: "x-access-token", Password: token}, nil

	case config.SecretSSHKey:
		return newSSHAuth(value.Key, value.Passphrase, value.Fingerprints)

	case *config.SecretOIDCClientCredentials:
		// Use the TokenSecret interface for OAuth2 token-based authentication
		return &tokenAuth{
			tokenSecret: value,
			name:        "oidc-client-credentials",
		}, nil

	case *config.SecretTokenAuth:
		// Use the TokenSecret interface for static token-based authentication
		return &tokenAuth{
			tokenSecret: value,
			name:        "bearer-token",
		}, nil

	default:
		return nil, fmt.Errorf("unsupported authentication type for git: %T", value)
	}
}

type github struct {
	integrationID  int64
	installationID int64
	privateKey     []byte
	tr             *ghinstallation.Transport
	mu             sync.Mutex
}

func (gh *github) Token(ctx context.Context, integrationID, installationID int64, privateKeyFile string) (string, error) {
	privateKey, err := os.ReadFile(privateKeyFile)
	if err != nil {
		return "", err
	}

	tr, err := gh.transport(integrationID, installationID, privateKey)
	if err != nil {
		return "", err
	}

	token, err := tr.Token(ctx)
	if err != nil {
		return "", err
	}

	return token, nil
}

func (gh *github) transport(integrationID, installationID int64, privateKey []byte) (*ghinstallation.Transport, error) {
	gh.mu.Lock()
	defer gh.mu.Unlock()

	if gh.tr == nil || gh.integrationID != integrationID || gh.installationID != installationID || !bytes.Equal(gh.privateKey, privateKey) {
		tr, err := ghinstallation.New(gohttp.DefaultTransport, integrationID, installationID, privateKey)
		if err != nil {
			return nil, err
		}

		gh.integrationID = integrationID
		gh.installationID = installationID
		gh.privateKey = privateKey
		gh.tr = tr
	}

	return gh.tr, nil
}

func newSSHAuth(key string, passphrase string, fingerprints []string) (gitssh.AuthMethod, error) {
	var signer ssh.Signer
	var err error
	if passphrase != "" {
		signer, err = ssh.ParsePrivateKeyWithPassphrase([]byte(key), []byte(passphrase))
		if err != nil {
			return nil, err
		}
	} else {
		signer, err = ssh.ParsePrivateKey([]byte(key))
		if err != nil {
			return nil, err
		}
	}

	if len(fingerprints) == 0 {
		return nil, errors.New("ssh: at least one fingerprint is required when using ssh_key authentication")
	}

	return &gitssh.PublicKeys{
		User:   "git",
		Signer: signer,
		HostKeyCallbackHelper: gitssh.HostKeyCallbackHelper{
			HostKeyCallback: newCheckFingerprints(fingerprints),
		},
	}, nil
}

func newCheckFingerprints(fingerprints []string) ssh.HostKeyCallback {
	m := make(map[string]bool, len(fingerprints))
	for _, fp := range fingerprints {
		m[fp] = true
	}

	return func(hostname string, _ net.Addr, key ssh.PublicKey) error {
		fingerprint := ssh.FingerprintSHA256(key)
		if _, ok := m[fingerprint]; !ok {
			return fmt.Errorf("ssh: unknown fingerprint (%s) for %s", fingerprint, hostname)
		}
		return nil
	}
}

// basicAuth provides HTTP basic authentication but in addition can set
// extra headers required for authentication.
type basicAuth struct {
	Username string
	Password string
	Headers  []string
}

func (a *basicAuth) String() string {
	masked := "*******"
	if a.Password == "" {
		masked = "<empty>"
	}
	return fmt.Sprintf("%s - %s:%s [%s]", a.Name(), a.Username, masked, strings.Join(a.Headers, ", "))
}

func (*basicAuth) Name() string {
	return "http-basic-auth-extra"
}

func (a *basicAuth) SetAuth(r *gohttp.Request) {
	r.SetBasicAuth(a.Username, a.Password)
	for _, header := range a.Headers {
		name, value, found := strings.Cut(header, ":")
		if found {
			r.Header.Set(strings.TrimSpace(name), strings.TrimSpace(value))
		}
	}
}

// tokenAuth provides HTTP bearer token authentication using any TokenSecret.
// It works with both static tokens and dynamic tokens (like OIDC client credentials).
type tokenAuth struct {
	tokenSecret config.TokenSecret
	name        string
}

func (a *tokenAuth) String() string {
	return a.Name() + " - token-based"
}

func (a *tokenAuth) Name() string {
	return "http-" + a.name
}

func (a *tokenAuth) SetAuth(r *gohttp.Request) {
	// Get a token using the TokenSecret interface
	token, err := a.tokenSecret.Token(r.Context())
	if err != nil {
		// If we can't get a token, we can't set auth
		// This will likely result in an authentication error downstream
		return
	}

	r.Header.Set("Authorization", "Bearer "+token)
}
