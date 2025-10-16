package types

import (
	"encoding/json"

	"github.com/open-policy-agent/opa-control-plane/internal/config"
	"github.com/open-policy-agent/opa-control-plane/internal/jsonpatch"
)

const (
	CodeInternal         = "internal_error"
	CodeNotAuthorized    = "not_authorized"
	CodeNotFound         = "not_found"
	CodeInvalidParameter = "invalid_parameter"
)

const (
	ParamPrettyV1 = "pretty"
)

type HealthResponse struct {
}

type SourcesPatchDataRequestV1 = jsonpatch.Patch

type SourcesPatchDataResponseV1 struct{}

type SourcesGetDataResponseV1 struct {
	Result *any `json:"result,omitempty"`
}

type SourcesListResponseV1 struct {
	Result     []*config.Source `json:"result,omitempty"`
	NextCursor string           `json:"next_cursor,omitempty"`
}

type BundlesListResponseV1 struct {
	Result     []*config.Bundle `json:"result,omitempty"`
	NextCursor string           `json:"next_cursor,omitempty"`
}

type BundlesGetResponseV1 struct {
	Result *config.Bundle `json:"result,omitempty"`
}

type BundlesPutResponseV1 struct{}

type BundlesDeleteResponseV1 struct{}

type SourcesGetResponseV1 struct {
	Result *config.Source `json:"result,omitempty"`
}

type SourcesPutResponseV1 struct{}

type SourcesDeleteResponseV1 struct{}

type SourcesDeleteDataResponseV1 struct{}

type SourcesPutDataResponseV1 struct{}

type StacksListResponseV1 struct {
	Result     []*config.Stack `json:"result"`
	NextCursor string          `json:"next_cursor,omitempty"`
}

type StacksGetResponseV1 struct {
	Result *config.Stack `json:"result"`
}

type StacksPutResponseV1 struct{}

type StacksDeleteResponseV1 struct{}

type SecretsListResponseV1 struct {
	Result     []*config.SecretRef `json:"result"`
	NextCursor string              `json:"next_cursor,omitempty"`
}

type SecretsGetResponseV1 struct {
	Result *config.SecretRef `json:"result"`
}

type SecretsPutResponseV1 struct{}

type SecretsDeleteResponseV1 struct{}

type ErrorV1 struct {
	Code    string  `json:"code"`
	Message string  `json:"message"`
	Errors  []error `json:"errors,omitempty"`
}

func NewErrorV1(code, f string) *ErrorV1 {
	return &ErrorV1{
		Code:    code,
		Message: f,
	}
}

func (e *ErrorV1) Bytes() []byte {
	bs, _ := json.MarshalIndent(e, "", "  ")
	return bs
}
