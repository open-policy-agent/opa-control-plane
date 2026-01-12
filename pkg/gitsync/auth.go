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
	"github.com/go-git/go-git/v5/plumbing/transport"
	"github.com/go-git/go-git/v5/plumbing/transport/http"
	gitssh "github.com/go-git/go-git/v5/plumbing/transport/ssh"
	"golang.org/x/crypto/ssh"

	"github.com/open-policy-agent/opa-control-plane/internal/config"
)

// auth returns the appropriate authentication method for the configured credentials.
func (s *Synchronizer) auth(ctx context.Context) (transport.AuthMethod, error) {

	if s.config.Credentials == nil {
		return nil, nil
	}

	value, err := s.config.Credentials.Resolve(ctx)
	if err != nil {
		return nil, err
	}

	switch value := value.(type) {
	case *config.SecretBasicAuth:
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
	}

	return nil, fmt.Errorf("unsupported authentication type: %T", value)
}

// github handles GitHub App authentication by managing installation tokens.
type github struct {
	integrationID  int64
	installationID int64
	privateKey     []byte
	tr             *ghinstallation.Transport
	mu             sync.Mutex
}

// Token retrieves a GitHub App installation token for authentication.
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

// transport returns a cached GitHub App transport or creates a new one if the configuration has changed.
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

// newSSHAuth creates an SSH authentication method with fingerprint validation.
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

// newCheckFingerprints creates an SSH host key callback that validates against known fingerprints.
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
