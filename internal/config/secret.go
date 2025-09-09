package config

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"reflect"

	"github.com/go-viper/mapstructure/v2"
	"github.com/swaggest/jsonschema-go"
	"gopkg.in/yaml.v3"
)

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
//   - "gcp_auth" for Google Cloud authentication. Value for a key "api_key" or "credentials" is expected.
//   - "github_app_auth" for GitHub App authentication. Values for keys "integration_id", "installation_id", and "private_key" are expected.
//   - "password" for password authentication. Value for key "password" is expected.
//   - "ssh_key" for SSH private key authentication. Value for key "key" (private key) is expected. "fingerprints" (string array) and "passphrase" are optional.
//   - "token_auth" for HTTP bearer token authentication. Value for a key "token" is expected.
type Secret struct {
	Name  string                 `json:"-" yaml:"-"`
	Value map[string]interface{} `json:"-" yaml:"-"`
}

func (s *Secret) Ref() *SecretRef {
	return &SecretRef{Name: s.Name, value: s}
}

func (*Secret) PrepareJSONSchema(schema *jsonschema.Schema) error {
	schema.Type = nil
	schema.AddType(jsonschema.Object)
	return nil
}

func (s *Secret) MarshalYAML() (interface{}, error) {
	if len(s.Value) == 0 {
		return map[string]interface{}{}, nil
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

func (s *Secret) UnmarshalYAML(n *yaml.Node) error {
	if n.Kind == yaml.MappingNode {
		return n.Decode(&s.Value)
	}
	return fmt.Errorf("expected mapping node, got %v", n.Kind)
}

func (s *Secret) UnmarshalJSON(bs []byte) error {
	return json.Unmarshal(bs, &s.Value)
}

func (s *Secret) Equal(other *Secret) bool {
	return fastEqual(s, other, func() bool {
		return s.Name == other.Name && reflect.DeepEqual(s.Value, other.Value)
	})
}

// get retrieves the values from any external source as necessary.
func (s *Secret) get() (map[string]interface{}, error) {
	value := make(map[string]interface{}, len(s.Value))

	for k, v := range s.Value {
		if str, ok := v.(string); ok && str != "" {
			value[k] = os.ExpandEnv(str)
		} else {
			value[k] = v // Keep non-string values as is
		}
	}

	return value, nil
}

func (s *Secret) Typed(ctx context.Context) (interface{}, error) {
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

		if err := mapstructure.Decode(m, &value); err != nil {
			return nil, err
		} else if value.AccessKeyID == "" || value.SecretAccessKey == "" {
			return nil, errors.New("missing access_key_id or secret_access_key in AWS secret")
		}

		return value, nil

	case "azure_auth":
		var value SecretAzure

		if err := mapstructure.Decode(m, &value); err != nil {
			return nil, err
		} else if value.AccountName == "" || value.AccountKey == "" {
			return nil, errors.New("missing account_name or account_key in Azure secret")
		}

		return value, nil

	case "gcp_auth":
		var value SecretGCP

		if err := mapstructure.Decode(m, &value); err != nil {
			return nil, err
		} else if value.APIKey == "" && value.Credentials == "" {
			return nil, errors.New("missing api_key or credentials in GCP secret")
		}

		return value, nil

	case "github_app_auth":
		var value SecretGitHubApp

		if err := mapstructure.Decode(m, &value); err != nil {
			return nil, err
		}

		return value, nil

	case "ssh_key":
		var value SecretSSHKey
		if err := mapstructure.Decode(m, &value); err != nil {
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
		if err := mapstructure.Decode(m, &value); err != nil {
			return nil, err
		}

		return value, nil

	case "token_auth":
		var value SecretTokenAuth
		if err := mapstructure.Decode(m, &value); err != nil {
			return nil, err
		}

		return value, nil

	case "password":
		var value SecretPassword
		if err := mapstructure.Decode(m, &value); err != nil {
			return nil, err
		}

		return value, nil

	default:
		return nil, fmt.Errorf("unknown secret type %q", s.Value["type"])
	}
}

type SecretAWS struct {
        AccessKeyID     string `json:"access_key_id" yaml:"access_key_id" mapstructure:"access_key_id"`
        SecretAccessKey string `json:"secret_access_key" yaml:"secret_access_key" mapstructure:"secret_access_key"`
        SessionToken    string `json:"session_token" yaml:"session_token" mapstructure:"session_token"`
}

type SecretGCP struct {
        APIKey      string `json:"api_key" yaml:"api_key" mapstructure:"api_key"`
        Credentials string `json:"credentials" yaml:"credentials" mapstructure:"credentials"` // Credentials file as JSON.
}

type SecretAzure struct {
        AccountName string `json:"account_name" yaml:"account_name" mapstructure:"account_name"`
        AccountKey  string `json:"account_key" yaml:"account_key" mapstructure:"account_key"`
}

type SecretGitHubApp struct {
        IntegrationID  int64  `json:"integration_id" yaml:"integration_id" mapstructure:"integration_id"`
        InstallationID int64  `json:"installation_id" yaml:"installation_id" mapstructure:"installation_id"`
        PrivateKey     string `json:"private_key" yaml:"private_key" mapstructure:"private_key"` // Private key as PEM.
}

type SecretSSHKey struct {
        Key          string   `json:"key" yaml:"key" mapstructure:"key"`                                                          // Private key as PEM.
        Passphrase   string   `json:"passphrase,omitempty" yaml:"passphrase,omitempty" mapstructure:"passphrase,omitempty"`       // Optional passphrase for the private key.
        Fingerprints []string `json:"fingerprints,omitempty" yaml:"fingerprints,omitempty" mapstructure:"fingerprints,omitempty"` // Optional SSH key fingerprints.
}

type SecretBasicAuth struct {
        Username string   `json:"username" yaml:"username" mapstructure:"username"`
        Password string   `json:"password" yaml:"password" mapstructure:"password"`
        Headers  []string `json:"headers,omitempty" yaml:"headers,omitempty" mapstructure:"headers,omitempty"` // Optional additional headers for HTTP requests.
}

type SecretTokenAuth struct {
        Token string `json:"token" yaml:"token" mapstructure:"token"` // Bearer token for HTTP authentication.
}

type SecretPassword struct {
        Password string `json:"password" yaml:"password" mapstructure:"password"` // Password for authentication.
}


