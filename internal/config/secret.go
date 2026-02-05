package config

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"reflect"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/go-viper/mapstructure/v2"
	"github.com/goccy/go-yaml"
	"golang.org/x/oauth2/clientcredentials"
)

// ClientSecret is the shared type of those secrets that can become effective by
// returning a properly set-up *http.Client.
// Note that this is not used everywhere yet, only for a those supported in the
// HTTP datasource.
type ClientSecret interface {
	Client(context.Context) (*http.Client, error)
}

// TokenSecret is the shared type of those secrets that can become effective by
// returning a bearer token string. This is used for token-based authentication
// in various contexts like git repositories and HTTP requests.
type TokenSecret interface {
	Token(context.Context) (string, error)
}

var wellknownFingerprints = []string{
	"SHA256:uNiVztksCsDhcc0u9e8BujQXVUpKZIDTMczCvj3tD2s", // github.com https://docs.github.com/en/github/authenticating-to-github/githubs-ssh-key-fingerprints
	"SHA256:p2QAMXNIC1TJYWeIOttrVc98/R1BUFWu3/LiyKgUfQM", // github.com
	"SHA256:+DiY3wvvV6TuJJhbpZisF/zLDA0zPMSvHdkr4UvCOqU", // github.com
	"SHA256:zzXQOXSRBEiUtuE8AikJYKwbHaxvSc0ojez9YXaGp1A", // bitbucket.org https://support.atlassian.com/bitbucket-cloud/docs/configure-ssh-and-two-step-verification/
	"SHA256:ohD8VZEXGWo6Ez8GSEJQ9WpafgLFsOfLOtGGQCQo6Og", // dev.azure.com https://github.com/MicrosoftDocs/azure-devops-docs/issues/7726 (also available through user settings after signing in)
}

// Secret defines the configuration for secrets/tokens used by OPA Control Plane
// for Git synchronization, datasources, etc.
//
// Each secret is stored as a map of key-value pairs, where the keys and values are strings. Secret type is also declared in the config.
// For example, a secret for basic HTTP authentication might look like this (in YAML):
//
// my_secret:
//
//	type: basic_auth
//	username: myuser
//	password: mypassword
//
// Secrets may also refer to environment variables using the ${VAR_NAME} syntax. For example:
//
// my_secret:
//
//	type: aws_auth
//	access_key_id: ${AWS_ACCESS_KEY_ID}
//	secret_access_key: ${AWS_SECRET_ACCESS_KEY}
//	session_token: ${AWS_SESSION_TOKEN}
//
// In this case, the actual values for username and password will be read from the environment variables AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY,
// and AWS_SESSION_TOKEN.
//
// Currently the following secret types are supported:
//
//   - "aws_auth" for AWS authentication. Values for keys "access_key_id", "secret_access_key", and optional "session_token" are expected.
//   - "azure_auth" for Azure authentication. Values for keys "account_name" and "account_key" are expected.
//   - "basic_auth" for HTTP basic authentication. Values for keys "username" and "password" are expected.
//     "headers" (string array) is optional and can be used to set additional headers for the HTTP requests (currently only supported for git).
//   - "oidc_client_credentials" for OIDC Client Credentials flow. Values for either `issuer` OR `token_url`, and `client_id`, and `client_secret` are expected, `scopes` are optional (currently only supported for HTTP datasource).
//   - "gcp_auth" for Google Cloud authentication. Value for a key "api_key" or "credentials" is expected.
//   - "github_app_auth" for GitHub App authentication. Values for keys "integration_id", "installation_id", and "private_key" are expected.
//   - "password" for password authentication. Value for key "password" is expected.
//   - "ssh_key" for SSH private key authentication. Value for key "key" (private key) is expected. "fingerprints" (string array) and "passphrase" are optional.
//   - "token_auth" for HTTP bearer token authentication. Value for a key "token" is expected.
type Secret struct {
	Name  string         `json:"-"`
	Value map[string]any `json:"-"`
}

func (s *Secret) Ref() *SecretRef {
	return &SecretRef{Name: s.Name, value: s}
}

func (s *Secret) MarshalYAML() (any, error) {
	if len(s.Value) == 0 {
		return map[string]any{}, nil
	}
	return s.Value, nil
}

func (s *Secret) MarshalJSON() ([]byte, error) {
	v, err := s.MarshalYAML()
	if err != nil {
		return nil, err
	}

	return json.Marshal(v)
}

func (s *Secret) UnmarshalYAML(bs []byte) error {
	if err := yaml.Unmarshal(bs, &s.Value); err != nil {
		return fmt.Errorf("expected mapping node: %w", err)
	}
	return nil
}

func (s *Secret) UnmarshalJSON(bs []byte) error {
	return json.Unmarshal(bs, &s.Value)
}

func (s *Secret) Equal(other *Secret) bool {
	return fastEqual(s, other, func(s, other *Secret) bool {
		return s.Name == other.Name &&
			reflect.DeepEqual(s.Value, other.Value)
	})
}

// get retrieves the values from any external source as necessary.
// NB(sr): "external sources" (plural) is aspirational: we support env vars only, so far.
func (s *Secret) get() (map[string]any, error) {
	value := make(map[string]any, len(s.Value))

	for k, v := range s.Value {
		switch v := v.(type) {
		case string:
			value[k] = os.ExpandEnv(v)
		default: // Keep non-string values as is
			value[k] = v
		}
	}

	return value, nil
}

func (s *Secret) Typed(context.Context) (any, error) {
	m, err := s.get() // Ensure values are resolved
	if err != nil {
		return nil, err
	}

	if len(m) == 0 {
		return nil, fmt.Errorf("secret %q is not configured", s.Name)
	}

	switch m["type"] {
	case "aws_auth":
		var value SecretAWS

		if err := decode(m, &value); err != nil {
			return nil, err
		} else if value.AccessKeyID == "" || value.SecretAccessKey == "" {
			return nil, errors.New("missing access_key_id or secret_access_key in AWS secret")
		}

		return &value, nil

	case "azure_auth":
		var value SecretAzure

		if err := decode(m, &value); err != nil {
			return nil, err
		} else if value.AccountName == "" || value.AccountKey == "" {
			return nil, errors.New("missing account_name or account_key in Azure secret")
		}

		return value, nil

	case "gcp_auth":
		var value SecretGCP

		if err := decode(m, &value); err != nil {
			return nil, err
		} else if value.APIKey == "" && value.Credentials == "" {
			return nil, errors.New("missing api_key or credentials in GCP secret")
		}

		return value, nil

	case "github_app_auth":
		var value SecretGitHubApp

		if err := decode(m, &value); err != nil {
			return nil, err
		}

		return value, nil

	case "ssh_key":
		var value SecretSSHKey
		if err := decode(m, &value); err != nil {
			return nil, err
		} else if value.Key == "" {
			return nil, errors.New("missing key in SSH secret")
		}

		// If no fingerprints are provided, use well-known ones for popular services.
		if len(value.Fingerprints) == 0 {
			value.Fingerprints = wellknownFingerprints
		}

		return value, nil

	case "basic_auth":
		var value SecretBasicAuth
		if err := decode(m, &value); err != nil {
			return nil, err
		}

		return &value, nil

	case "token_auth":
		var value SecretTokenAuth
		if err := decode(m, &value); err != nil {
			return nil, err
		}

		return &value, nil

	case "oidc_client_credentials":
		var value SecretOIDCClientCredentials
		if err := decode(m, &value); err != nil {
			return nil, err
		}

		return &value, nil

	case "password":
		var value SecretPassword
		if err := decode(m, &value); err != nil {
			return nil, err
		}

		return value, nil

	case "tls_cert":
		var value SecretTLSCert
		if err := decode(m, &value); err != nil {
			return nil, err
		}

		return value, nil

	default:
		return nil, fmt.Errorf("unknown secret type %q", s.Value["type"])
	}
}

type SecretAWS struct {
	AccessKeyID     string `json:"access_key_id"`
	SecretAccessKey string `json:"secret_access_key"`
	SessionToken    string `json:"session_token"`
}

type SecretGCP struct {
	APIKey      string `json:"api_key"`
	Credentials string `json:"credentials"` // Credentials file as JSON.
}

type SecretAzure struct {
	AccountName string `json:"account_name"`
	AccountKey  string `json:"account_key"`
}

type SecretGitHubApp struct {
	IntegrationID  int64  `json:"integration_id"`
	InstallationID int64  `json:"installation_id"`
	PrivateKey     string `json:"private_key"` // Private key filepath as PEM.
}

type SecretSSHKey struct {
	Key          string   `json:"key"`                    // Private key as PEM.
	Passphrase   string   `json:"passphrase,omitempty"`   // Optional passphrase for the private key.
	Fingerprints []string `json:"fingerprints,omitempty"` // Optional SSH key fingerprints.
}

type SecretBasicAuth struct {
	Username string   `json:"username"`
	Password string   `json:"password"`
	Headers  []string `json:"headers,omitempty"` // Optional additional headers for HTTP requests.
}

var _ ClientSecret = (*SecretBasicAuth)(nil)

func (s *SecretBasicAuth) Client(context.Context) (*http.Client, error) {
	return wrappedClient(func(r *http.Request) *http.Request {
		r.SetBasicAuth(s.Username, s.Password)
		return r
	}), nil
}

// SecretOIDCClientCredentials represents OIDC Client Credentials flow configuration.
// It supports both explicit token endpoint configuration and automatic discovery via issuer.
type SecretOIDCClientCredentials struct {
	Issuer       string   `json:"issuer"`           // OIDC issuer URL for automatic discovery (required if TokenURL is not provided)
	TokenURL     string   `json:"token_endpoint"`   // Explicit token endpoint URL (optional if Issuer is provided)
	ClientID     string   `json:"client_id"`        // OAuth2 client ID (required)
	ClientSecret string   `json:"client_secret"`    // OAuth2 client secret (required)
	Scopes       []string `json:"scopes,omitempty"` // Optional OAuth2 scopes
}

// validate performs upfront validation of the OIDC credentials configuration.
// This helps catch configuration errors early and provides clear error messages.
func (value *SecretOIDCClientCredentials) validate() error {
	if value.ClientID == "" {
		return errors.New("client_id is required")
	}
	if value.ClientSecret == "" {
		return errors.New("client_secret is required")
	}
	if value.TokenURL == "" && value.Issuer == "" {
		return errors.New("either issuer or token_endpoint must be provided")
	}
	return nil
}

// getClientCredentialsConfig creates and returns a properly configured clientcredentials.Config.
// This method handles token URL discovery if needed and centralizes the configuration logic.
func (value *SecretOIDCClientCredentials) getClientCredentialsConfig(ctx context.Context) (*clientcredentials.Config, error) {
	if err := value.validate(); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	tokenURL := value.TokenURL

	if tokenURL == "" {
		provider, err := oidc.NewProvider(ctx, value.Issuer)
		if err != nil {
			return nil, fmt.Errorf("discovery failed for issuer %q: %w", value.Issuer, err)
		}

		endpoint := provider.Endpoint()
		tokenURL = endpoint.TokenURL

		if tokenURL == "" {
			return nil, fmt.Errorf("discovery did not return a token endpoint for issuer %q", value.Issuer)
		}
	}

	return &clientcredentials.Config{
		ClientID:     value.ClientID,
		ClientSecret: value.ClientSecret,
		Scopes:       value.Scopes,
		TokenURL:     tokenURL,
	}, nil
}

// Client returns an HTTP client configured with OIDC Client Credentials flow authentication.
// The returned client automatically handles token acquisition and refresh.
func (value *SecretOIDCClientCredentials) Client(ctx context.Context) (*http.Client, error) {
	config, err := value.getClientCredentialsConfig(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to configure client: %w", err)
	}

	return config.Client(ctx), nil
}

// Token obtains and returns an access token using OIDC Client Credentials flow.
// This method is useful when you need just the token string rather than a configured HTTP client.
func (value *SecretOIDCClientCredentials) Token(ctx context.Context) (string, error) {
	config, err := value.getClientCredentialsConfig(ctx)
	if err != nil {
		return "", fmt.Errorf("failed to configure client: %w", err)
	}

	tokenSource := config.TokenSource(ctx)
	token, err := tokenSource.Token()
	if err != nil {
		return "", fmt.Errorf("failed to acquire access token: %w", err)
	}

	if token.AccessToken == "" {
		return "", errors.New("received empty access token from provider")
	}

	return token.AccessToken, nil
}

var _ ClientSecret = (*SecretOIDCClientCredentials)(nil)
var _ TokenSecret = (*SecretOIDCClientCredentials)(nil)

type SecretTokenAuth struct {
	BearerToken string `json:"token"` // Bearer token for HTTP authentication.
}

func (s *SecretTokenAuth) Client(context.Context) (*http.Client, error) {
	return wrappedClient(func(r *http.Request) *http.Request {
		r.Header.Set("Authorization", "Bearer "+s.BearerToken)
		return r
	}), nil
}

func (s *SecretTokenAuth) Token(context.Context) (string, error) {
	return s.BearerToken, nil
}

var _ ClientSecret = (*SecretTokenAuth)(nil)
var _ TokenSecret = (*SecretTokenAuth)(nil)

type SecretPassword struct {
	Password string `json:"password"` // Password for authentication.
}

type SecretTLSCert struct {
	RootCA  string `json:"root_ca"`  // Root CA certificate (PEM encoded)
	TLSCert string `json:"tls_cert"` // TLS certificate (PEM encoded)
	TLSKey  string `json:"tls_key"`  // TLS key (PEM encoded)
}

func (value *SecretTLSCert) ToConfig(ctx context.Context) (*tls.Config, error) {
	tlsCfg := &tls.Config{}

	// Root CA
	if value.RootCA != "" {
		rootCAs := x509.NewCertPool()
		ok := rootCAs.AppendCertsFromPEM([]byte(value.RootCA))
		if !ok {
			return nil, errors.New("failed to append root CA certificate")
		}
		tlsCfg.RootCAs = rootCAs
	}

	// Client Certificate and Key
	if value.TLSCert != "" && value.TLSKey != "" {
		cert, err := tls.X509KeyPair([]byte(value.TLSCert), []byte(value.TLSKey))
		if err != nil {
			return nil, err
		}

		tlsCfg.Certificates = []tls.Certificate{cert}
	}

	// Enforce TLS 1.2 or higher
	tlsCfg.MinVersion = tls.VersionTLS12

	return tlsCfg, nil
}

// we use this one so we don't need duplicate tags on every struct
func decode(input any, output any) error {
	config := &mapstructure.DecoderConfig{
		TagName:  "json",
		Metadata: nil,
		Result:   output,
	}

	decoder, err := mapstructure.NewDecoder(config)
	if err != nil {
		return err
	}

	return decoder.Decode(input)
}

func wrappedClient(f func(*http.Request) *http.Request) *http.Client {
	return &http.Client{
		Transport: &crt{f: f, w: http.DefaultTransport.(*http.Transport).Clone()},
	}
}

type crt struct {
	f func(*http.Request) *http.Request
	w http.RoundTripper
}

func (c *crt) RoundTrip(req *http.Request) (*http.Response, error) {
	return c.w.RoundTrip(c.f(req))
}
