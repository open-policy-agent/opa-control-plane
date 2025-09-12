// gitsync package implements Git synchronization. It maintains a local filesystem copy for each configured
// git reference. This package implements no threadpooling, it is expected that the caller will handle
// concurrency and parallelism. The Synchronizer is not thread-safe.
package gitsync

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	gohttp "net/http"
	"os"
	"strings"
	"sync"

	"github.com/bradleyfalzon/ghinstallation/v2"
	"github.com/go-git/go-git/v5"
	gitconfig "github.com/go-git/go-git/v5/config"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/protocol/packp/capability"
	"github.com/go-git/go-git/v5/plumbing/transport"
	"github.com/go-git/go-git/v5/plumbing/transport/http"
	gitssh "github.com/go-git/go-git/v5/plumbing/transport/ssh"
	"github.com/styrainc/opa-control-plane/internal/config"
	"golang.org/x/crypto/ssh"
)

func init() {
	// For Azure DevOps compatibility. More details: https://github.com/go-git/go-git/issues/64
	transport.UnsupportedCapabilities = []capability.Capability{
		capability.ThinPack,
	}
}

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
	if err := s.execute(ctx); err != nil {
		return fmt.Errorf("source %q: git synchronizer: %v: %w", s.sourceName, s.config.Repo, err)
	}
	return nil
}

func (s *Synchronizer) execute(ctx context.Context) error {
	var repository *git.Repository

	authMethod, err := s.auth(ctx)
	if err != nil {
		return err
	}

	var referenceName plumbing.ReferenceName
	if s.config.Reference != nil {
		referenceName = plumbing.ReferenceName(*s.config.Reference)
	}

	if _, err := os.Stat(s.path); os.IsNotExist(err) {
		repository, err = git.PlainClone(s.path, false, &git.CloneOptions{
			URL:               s.config.Repo,
			Auth:              authMethod,
			RecurseSubmodules: git.DefaultSubmoduleRecursionDepth,
			ReferenceName:     referenceName,
			SingleBranch:      true,
			NoCheckout:        true, // We will checkout later
		})
		if err != nil {
			return err
		}
	} else {
		repository, err = git.PlainOpen(s.path)
		if err != nil {
			return err
		}
	}

	remote := "origin"

	err = repository.FetchContext(ctx, &git.FetchOptions{
		RemoteName: remote,
		Auth:       authMethod,
		Force:      true,
		RefSpecs: []gitconfig.RefSpec{
			gitconfig.RefSpec(fmt.Sprintf("+refs/heads/*:refs/remotes/%s/refs/heads/*", remote)),
			gitconfig.RefSpec(fmt.Sprintf("+refs/tags/*:refs/remotes/%s/refs/tags/*", remote)),
		},
	})
	if err != nil && err != git.NoErrAlreadyUpToDate {
		return err
	}

	w, err := repository.Worktree()
	if err != nil {
		return err
	}

	var checkoutOpts *git.CheckoutOptions

	if s.config.Commit != nil {
		checkoutOpts = &git.CheckoutOptions{
			Force: true, // Discard any local changes
			Hash:  plumbing.NewHash(*s.config.Commit),
		}
	} else if s.config.Reference != nil {
		ref := fmt.Sprintf("refs/remotes/%s/%s", remote, *s.config.Reference)
		checkoutOpts = &git.CheckoutOptions{
			Force:  true, // Discard any local changes
			Branch: plumbing.ReferenceName(ref),
		}
	} else {
		return errors.New("either reference or commit must be set in git configuration")
	}

	return w.Checkout(checkoutOpts)
}

func (*Synchronizer) Close(_ context.Context) {
	// No resources to close.
}

func (s *Synchronizer) auth(ctx context.Context) (transport.AuthMethod, error) {

	if s.config.Credentials == nil {
		return nil, nil
	}

	value, err := s.config.Credentials.Resolve(ctx)
	if err != nil {
		return nil, err
	}

	switch value := value.(type) {
	case config.SecretBasicAuth:
		return &basicAuth{
			Username: value.Username,
			Password: value.Password,
			Headers:  value.Headers,
		}, nil

	case config.SecretGitHubApp:
		token, err := s.gh.Token(ctx, value.IntegrationID, value.InstallationID, value.PrivateKey)
		if err != nil {
			return nil, err
		}

		return &http.BasicAuth{Username: "x-access-token", Password: token}, nil

	case config.SecretSSHKey:
		return newSSHAuth(value.Key, value.Passphrase, value.Fingerprints)
	}

	return nil, fmt.Errorf("unsupported authentication type: %T", value)
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
