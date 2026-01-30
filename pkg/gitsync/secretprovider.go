package gitsync

import internalgitsync "github.com/open-policy-agent/opa-control-plane/internal/gitsync"

// SecretProvider is re-exported from internal/gitsync for external use.
// See internal/gitsync package for interface documentation and supported credential types.
type SecretProvider = internalgitsync.SecretProvider
