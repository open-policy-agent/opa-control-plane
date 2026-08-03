package service

import (
	"cmp"
	"context"

	"github.com/open-policy-agent/opa-control-plane/internal/config"
	"github.com/open-policy-agent/opa-control-plane/internal/gitsync"
	"github.com/open-policy-agent/opa-control-plane/internal/httpsync"
	"github.com/open-policy-agent/opa-control-plane/internal/syncerr"
	pkgsync "github.com/open-policy-agent/opa-control-plane/pkg/sync"
)

// BindingType identifies the kind of binding a BindingAccessResult reports on.
type BindingType string

const (
	BindingTypeGit  BindingType = "git"
	BindingTypeHTTP BindingType = "http"
	BindingTypeS3   BindingType = "s3"
)

// Error is a JSON-serializable description of why a binding's access check
// failed. A Go error doesn't marshal to anything useful on its own, so
// BindingAccessResult reports failures through this type instead.
type Error struct {
	Message string `json:"message"`
	// UserError is true when the failure is caused by misconfiguration
	// (invalid credentials, an unreachable repository/URL, a 4xx
	// response, ...) rather than a transient or internal failure. Callers
	// can use this to decide whether Message is safe to surface to the
	// end user as-is.
	UserError bool `json:"user_error"`
}

func newError(err error) *Error {
	if err == nil {
		return nil
	}
	return &Error{Message: err.Error(), UserError: syncerr.IsUserError(err)}
}

// BindingAccessResult reports the outcome of checking one git or datasource
// binding within a Source for reachability and credential validity.
type BindingAccessResult struct {
	Type BindingType `json:"type"`
	// Name is the datasource name, or "" for the source's git binding.
	Name string `json:"name,omitempty"`
	// Err is nil if the binding was successfully verified.
	Err *Error `json:"error,omitempty"`
}

type accessChecker interface {
	CheckAccess(ctx context.Context) error
	Close(ctx context.Context)
}

// ValidateSourceAccess checks whether each of src's git and datasource
// bindings is reachable and its credentials, if any, are valid, without
// performing a full clone or download. provider resolves named credentials
// referenced by src's bindings; pass nil if none of them reference secrets.
//
// Unlike Service.Run, this does not require Init or a database connection,
// so it can be called directly against a Source before (or without) it ever
// being persisted.
func ValidateSourceAccess(ctx context.Context, src *config.Source, provider pkgsync.SecretProvider) []BindingAccessResult {
	var results []BindingAccessResult

	if checker := gitAccessChecker(src, provider); checker != nil {
		defer checker.Close(ctx)
		err := checker.CheckAccess(ctx)
		results = append(results, BindingAccessResult{Type: BindingTypeGit, Err: newError(err)})
	}

	for _, ds := range src.Datasources {
		checker := datasourceAccessChecker(ds, provider)
		if checker == nil {
			continue
		}
		defer checker.Close(ctx)
		err := checker.CheckAccess(ctx)
		results = append(results, BindingAccessResult{Type: BindingType(ds.Type), Name: ds.Name, Err: newError(err)})
	}

	return results
}

func gitAccessChecker(src *config.Source, provider pkgsync.SecretProvider) accessChecker {
	if src.Git.Repo == "" {
		return nil
	}
	return gitsync.New("", src.Git, src.Name).WithSecretProvider(provider)
}

func datasourceAccessChecker(ds config.Datasource, provider pkgsync.SecretProvider) accessChecker {
	switch ds.Type {
	case "http":
		url, _ := ds.Config["url"].(string)
		method, _ := ds.Config["method"].(string)
		method = cmp.Or(method, "GET")
		body, _ := ds.Config["body"].(string)
		headers, _ := ds.Config["headers"].(map[string]any)
		return httpsync.New("", url, method, body, headers, ds.Credentials).WithSecretProvider(provider)
	case "s3":
		bucket, _ := ds.Config["bucket"].(string)
		key, _ := ds.Config["key"].(string)
		region, _ := ds.Config["region"].(string)
		endpoint, _ := ds.Config["endpoint"].(string)
		region = cmp.Or(region, "us-east-1")

		var url string
		if endpoint != "" {
			url = endpoint + "/" + bucket + "/" + key
		} else {
			url = "https://" + bucket + ".s3." + region + ".amazonaws.com/" + key
		}
		return httpsync.NewS3("", url, region, endpoint, ds.Credentials)
	default:
		return nil
	}
}
