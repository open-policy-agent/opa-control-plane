package httpsync

import pkgsync "github.com/open-policy-agent/opa-control-plane/pkg/sync"

// SecretProvider is re-exported from pkg/sync for external use.
// See pkg/sync package for interface documentation and supported credential types.
type SecretProvider = pkgsync.SecretProvider
