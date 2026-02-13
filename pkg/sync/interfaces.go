// Package sync provides common interfaces for synchronization operations.
//
// This package defines the core contracts used by both git and HTTP synchronizers,
// enabling external projects to integrate with their own secret management systems
// and implement custom synchronization logic.
package sync

import "context"

// Synchronizer defines the interface for data synchronization operations.
// Implementations may synchronize git repositories, HTTP endpoints, SQL databases, etc.
//
// The synchronizer is not thread-safe. Callers should handle concurrency.
type Synchronizer interface {
	// Execute performs the synchronization operation.
	// The exact behavior depends on the implementation (git clone/fetch, HTTP GET, etc.).
	//
	// Returns an error if synchronization fails.
	Execute(ctx context.Context) error

	// Close releases any resources held by the synchronizer.
	// It should be called when the synchronizer is no longer needed.
	Close(ctx context.Context)
}

// SecretProvider defines the interface for retrieving secrets from external systems.
// External projects (e.g., OMA with Whisper, enterprises with Vault) implement this
// interface to integrate their own secret management systems.
//
// This interface is used by both git and HTTP synchronizers to fetch credentials
// without hardcoding secret storage logic.
type SecretProvider interface {
	// GetSecret retrieves a secret by name and returns a map with credential data.
	// The map must include a "type" field and other fields as required by the credential type.
	//
	// The type strings and fields must match OCP's internal config package conventions.
	// Supported credential types:
	//
	// Git Synchronization (gitsync):
	//   - GitHub App ("github_app_auth"):
	//     {
	//       "type": "github_app_auth",
	//       "integration_id": 12345,
	//       "installation_id": 67890,
	//       "private_key": "-----BEGIN RSA PRIVATE KEY-----\n..."
	//     }
	//   - Personal Access Token ("token_auth"):
	//     {
	//       "type": "token_auth",
	//       "token": "ghp_abc123..."
	//     }
	//   - SSH Key ("ssh_key"):
	//     {
	//       "type": "ssh_key",
	//       "key": "-----BEGIN OPENSSH PRIVATE KEY-----\n...",
	//       "passphrase": "optional-passphrase",
	//       "fingerprints": ["SHA256:..."]  // optional
	//     }
	//   - Basic Auth ("basic_auth"):
	//     {
	//       "type": "basic_auth",
	//       "username": "user",
	//       "password": "pass"
	//     }
	//   - OIDC Client Credentials ("oidc_client_credentials"):
	//     {
	//       "type": "oidc_client_credentials",
	//       "issuer": "https://issuer.example.com",
	//       "client_id": "client-id",
	//       "client_secret": "client-secret",
	//       "scopes": ["openid"]  // optional
	//     }
	//
	// HTTP Synchronization (httpsync):
	//   - Bearer Token ("token_auth"):
	//     {
	//       "type": "token_auth",
	//       "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
	//     }
	//   - Basic Auth ("basic_auth"):
	//     {
	//       "type": "basic_auth",
	//       "username": "user",
	//       "password": "pass"
	//     }
	//   - mTLS ("tls_cert"):
	//     {
	//       "type": "tls_cert",
	//       "root_ca": "-----BEGIN CERTIFICATE-----\n...",  // PEM encoded (optional)
	//       "tls_cert": "-----BEGIN CERTIFICATE-----\n...", // PEM encoded
	//       "tls_key": "-----BEGIN PRIVATE KEY-----\n..."   // PEM encoded
	//     }
	//   - API Key ("api_key"):
	//     {
	//       "type": "api_key",
	//       "key": "X-API-Key",        // header name or query param name
	//       "value": "secret-value",
	//       "in": "header"             // "header" or "query" (default: "header")
	//     }
	//
	// Returns an error if the secret cannot be retrieved or does not exist.
	GetSecret(ctx context.Context, name string) (map[string]any, error)
}
