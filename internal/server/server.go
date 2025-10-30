package server

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"path"
	"strconv"
	"strings"

	"github.com/open-policy-agent/opa/v1/server/writer"

	"github.com/open-policy-agent/opa-control-plane/internal/config"
	"github.com/open-policy-agent/opa-control-plane/internal/database"
	"github.com/open-policy-agent/opa-control-plane/internal/jsonpatch"
	"github.com/open-policy-agent/opa-control-plane/internal/metrics"
	"github.com/open-policy-agent/opa-control-plane/internal/server/chain"
	"github.com/open-policy-agent/opa-control-plane/internal/server/types"
)

type Server struct {
	router    *http.ServeMux
	db        *database.Database
	readyFn   func(context.Context) error
	apiPrefix string
}

func New() *Server {
	return &Server{}
}

func (s *Server) Init() *Server {
	if s.router == nil {
		s.router = http.NewServeMux()
	}

	apiPrefix := s.apiPrefix

	s.router.Handle(apiPrefix+"/metrics", metrics.Handler())
	s.router.HandleFunc("GET "+apiPrefix+"/health", s.health)

	base := chain.New(authenticationMiddleware(s.db))
	setup := func(method, pattern string, hndl http.HandlerFunc) {
		s.router.Handle(method+" "+apiPrefix+pattern, append(base, metrics.InstrumentHandler(apiPrefix+pattern)).ThenFunc(hndl))
	}

	setup("GET", "/v1/sources/{source}/data/{path...}", s.v1SourcesDataGet)
	setup("POST", "/v1/sources/{source}/data/{path...}", s.v1SourcesDataPut)
	setup("PUT", "/v1/sources/{source}/data/{path...}", s.v1SourcesDataPut)
	setup("DELETE", "/v1/sources/{source}/data/{path...}", s.v1SourcesDataDelete)
	setup("PATCH", "/v1/sources/{source}/data/{path...}", s.v1SourcesDataPatch)

	setup("GET", "/v1/sources", s.v1SourcesList)
	setup("GET", "/v1/sources/{source}", s.v1SourcesGet)
	setup("PUT", "/v1/sources/{source}", s.v1SourcesPut)
	setup("DELETE", "/v1/sources/{source}", s.v1SourcesDelete)

	setup("GET", "/v1/bundles", s.v1BundlesList)
	setup("GET", "/v1/bundles/{bundle}", s.v1BundlesGet)
	setup("PUT", "/v1/bundles/{bundle}", s.v1BundlesPut)
	setup("DELETE", "/v1/bundles/{bundle}", s.v1BundlesDelete)

	setup("GET", "/v1/stacks", s.v1StacksList)
	setup("GET", "/v1/stacks/{stack}", s.v1StacksGet)
	setup("PUT", "/v1/stacks/{stack}", s.v1StacksPut)
	setup("DELETE", "/v1/stacks/{stack}", s.v1StacksDelete)

	setup("GET", "/v1/secrets", s.v1SecretsList)
	setup("GET", "/v1/secrets/{secret}", s.v1SecretsGet)
	setup("PUT", "/v1/secrets/{secret}", s.v1SecretsPut)
	setup("DELETE", "/v1/secrets/{secret}", s.v1SecretsDelete)

	return s
}

func (s *Server) WithRouter(router *http.ServeMux) *Server {
	s.router = router
	return s
}

func (s *Server) WithDatabase(db *database.Database) *Server {
	s.db = db
	return s
}

func (s *Server) WithReadiness(fn func(context.Context) error) *Server {
	s.readyFn = fn
	return s
}

func (s *Server) ListenAndServe(addr string) error {
	return http.ListenAndServe(addr, s.router)
}

func (s *Server) WithConfig(config *config.Service) *Server {
	if config != nil {
		s.apiPrefix = config.ApiPrefix
	}
	return s
}

func (s *Server) health(w http.ResponseWriter, r *http.Request) {

	err := s.readyFn(r.Context())
	if err != nil {
		errorAuto(w, err)
		return
	}

	resp := types.HealthResponse{}
	JSONOK(w, resp, false)
}

func (s *Server) v1BundlesList(w http.ResponseWriter, r *http.Request) {

	ctx := r.Context()
	opts := s.listOptions(r)
	bundles, nextCursor, err := s.db.ListBundles(ctx, s.auth(r), opts)
	if err != nil {
		errorAuto(w, err)
		return
	}

	resp := types.BundlesListResponseV1{Result: bundles, NextCursor: nextCursor}
	JSONOK(w, resp, pretty(r))
}

func (s *Server) v1BundlesPut(w http.ResponseWriter, r *http.Request) {

	ctx := r.Context()

	name, err := url.PathUnescape(r.PathValue("bundle"))
	if err != nil {
		ErrorString(w, http.StatusBadRequest, types.CodeInvalidParameter, err)
		return
	}

	var b config.Bundle
	if err := newJSONDecoder(r.Body).Decode(&b); err != nil {
		writer.ErrorString(w, http.StatusBadRequest, types.CodeInvalidParameter, err)
		return
	}

	if b.Name == "" {
		b.Name = name
	} else if b.Name != name {
		writer.ErrorString(w, http.StatusBadRequest, types.CodeInvalidParameter, errors.New("bundle name must match path"))
		return
	}

	if err := s.db.UpsertBundle(ctx, s.auth(r), &b); err != nil {
		errorAuto(w, err)
		return
	}

	resp := types.BundlesPutResponseV1{}
	JSONOK(w, resp, pretty(r))
}

func (s *Server) v1BundlesGet(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	name, err := url.PathUnescape(r.PathValue("bundle"))
	if err != nil {
		ErrorString(w, http.StatusBadRequest, types.CodeInvalidParameter, err)
		return
	}

	b, err := s.db.GetBundle(ctx, s.auth(r), name)
	if err != nil {
		errorAuto(w, err)
		return
	}

	resp := types.BundlesGetResponseV1{Result: b}
	JSONOK(w, resp, pretty(r))
}

func (s *Server) v1BundlesDelete(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	name, err := url.PathUnescape(r.PathValue("bundle"))
	if err != nil {
		ErrorString(w, http.StatusBadRequest, types.CodeInvalidParameter, err)
		return
	}

	if err := s.db.DeleteBundle(ctx, s.auth(r), name); err != nil {
		errorAuto(w, err)
		return
	}

	resp := types.SourcesDeleteResponseV1{}
	JSONOK(w, resp, pretty(r))
}

func (s *Server) v1SourcesList(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	opts := s.listOptions(r)
	sources, nextCursor, err := s.db.ListSources(ctx, s.auth(r), opts)
	if err != nil {
		errorAuto(w, err)
		return
	}

	resp := types.SourcesListResponseV1{Result: sources, NextCursor: nextCursor}
	JSONOK(w, resp, pretty(r))
}

func (s *Server) v1SourcesPut(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	name, err := url.PathUnescape(r.PathValue("source"))
	if err != nil {
		ErrorString(w, http.StatusBadRequest, types.CodeInvalidParameter, err)
		return
	}

	var src config.Source
	if err := newJSONDecoder(r.Body).Decode(&src); err != nil {
		writer.ErrorString(w, http.StatusBadRequest, types.CodeInvalidParameter, err)
		return
	}

	if src.Name == "" {
		src.Name = name
	} else if src.Name != name {
		writer.ErrorString(w, http.StatusBadRequest, types.CodeInvalidParameter, errors.New("source name must match path"))
		return
	}

	if err := s.db.UpsertSource(ctx, s.auth(r), &src); err != nil {
		errorAuto(w, err)
		return
	}

	resp := types.SourcesPutResponseV1{}
	JSONOK(w, resp, pretty(r))
}

func (s *Server) v1SourcesGet(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	name, err := url.PathUnescape(r.PathValue("source"))
	if err != nil {
		ErrorString(w, http.StatusBadRequest, types.CodeInvalidParameter, err)
		return
	}

	src, err := s.db.GetSource(ctx, s.auth(r), name)
	if err != nil {
		errorAuto(w, err)
		return
	}

	resp := types.SourcesGetResponseV1{Result: src}
	JSONOK(w, resp, pretty(r))
}

func (s *Server) v1SourcesDelete(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	name, err := url.PathUnescape(r.PathValue("source"))
	if err != nil {
		ErrorString(w, http.StatusBadRequest, types.CodeInvalidParameter, err)
		return
	}

	if err := s.db.DeleteSource(ctx, s.auth(r), name); err != nil {
		errorAuto(w, err)
		return
	}

	resp := types.SourcesDeleteResponseV1{}
	JSONOK(w, resp, pretty(r))
}

// v1SourcesDataGet handles GET requests to retrieve data from a source.
func (s *Server) v1SourcesDataGet(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	name, err := url.PathUnescape(r.PathValue("source"))
	if err != nil {
		ErrorString(w, http.StatusBadRequest, types.CodeInvalidParameter, err)
		return
	}

	data, ok, err := s.db.SourcesDataGet(ctx, name, path.Join(r.PathValue("path"), "data.json"), s.auth(r))
	if err != nil {
		errorAuto(w, err)
		return
	}

	resp := types.SourcesGetDataResponseV1{}

	if ok {
		resp.Result = &data
	}

	JSONOK(w, resp, pretty(r))
}

// v1SourcesDataPut handles PUT and POST requests to upload data to a source.
func (s *Server) v1SourcesDataPut(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	name, err := url.PathUnescape(r.PathValue("source"))
	if err != nil {
		ErrorString(w, http.StatusBadRequest, types.CodeInvalidParameter, err)
		return
	}

	var value any
	if err := newJSONDecoder(r.Body).Decode(&value); err != nil {
		writer.ErrorString(w, http.StatusBadRequest, types.CodeInvalidParameter, err)
		return
	}

	err = s.db.SourcesDataPut(ctx, name, path.Join(r.PathValue("path"), "data.json"), value, s.auth(r))
	if err != nil {
		errorAuto(w, err)
		return
	}

	resp := types.SourcesPutDataResponseV1{}
	JSONOK(w, resp, pretty(r))
}

func (s *Server) v1SourcesDataPatch(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	name, err := url.PathUnescape(r.PathValue("source"))
	if err != nil {
		ErrorString(w, http.StatusBadRequest, types.CodeInvalidParameter, err)
		return
	}

	var patch types.SourcesPatchDataRequestV1
	if err := newJSONDecoder(r.Body).Decode(&patch); err != nil {
		writer.ErrorString(w, http.StatusBadRequest, types.CodeInvalidParameter, err)
		return
	}

	if err := s.db.SourcesDataPatch(ctx, name, path.Join(r.PathValue("path"), "data.json"), s.auth(r), patch); err != nil {
		if pe := (&jsonpatch.PatchError{}); errors.As(err, &pe) {
			writer.ErrorString(w, http.StatusBadRequest, types.CodeInvalidParameter, err)
		} else {
			errorAuto(w, err)
		}
		return
	}

	resp := types.SourcesPatchDataResponseV1{}
	JSONOK(w, resp, pretty(r))
}

// v1SourcesDataDelete handles DELETE requests to remove data from a source.
func (s *Server) v1SourcesDataDelete(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	name, err := url.PathUnescape(r.PathValue("source"))
	if err != nil {
		ErrorString(w, http.StatusBadRequest, types.CodeInvalidParameter, err)
		return
	}

	err = s.db.SourcesDataDelete(ctx, name, path.Join(r.PathValue("path"), "data.json"), s.auth(r))
	if err != nil {
		errorAuto(w, err)
		return
	}

	resp := types.SourcesDeleteDataResponseV1{}
	JSONOK(w, resp, pretty(r))
}

// v1StacksList handles GET /v1/stacks
func (s *Server) v1StacksList(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	opts := s.listOptions(r)
	stacks, nextCursor, err := s.db.ListStacks(ctx, s.auth(r), opts)
	if err != nil {
		errorAuto(w, err)
		return
	}

	resp := types.StacksListResponseV1{Result: stacks, NextCursor: nextCursor}
	JSONOK(w, resp, pretty(r))
}

// v1StacksGet handles GET /v1/stacks/{stack}
func (s *Server) v1StacksGet(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	name, err := url.PathUnescape(r.PathValue("stack"))
	if err != nil {
		ErrorString(w, http.StatusBadRequest, types.CodeInvalidParameter, err)
		return
	}

	stack, err := s.db.GetStack(ctx, s.auth(r), name)
	if err != nil {
		errorAuto(w, err)
		return
	}

	resp := types.StacksGetResponseV1{Result: stack}
	JSONOK(w, resp, pretty(r))
}

func (s *Server) v1StacksDelete(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	name, err := url.PathUnescape(r.PathValue("stack"))
	if err != nil {
		ErrorString(w, http.StatusBadRequest, types.CodeInvalidParameter, err)
		return
	}

	if err := s.db.DeleteStack(ctx, s.auth(r), name); err != nil {
		errorAuto(w, err)
		return
	}

	resp := types.StacksDeleteResponseV1{}
	JSONOK(w, resp, pretty(r))
}

// v1StacksPut handles PUT /v1/stacks/{stack}
func (s *Server) v1StacksPut(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	name, err := url.PathUnescape(r.PathValue("stack"))
	if err != nil {
		ErrorString(w, http.StatusBadRequest, types.CodeInvalidParameter, err)
		return
	}

	var stack config.Stack
	if err := newJSONDecoder(r.Body).Decode(&stack); err != nil {
		writer.ErrorString(w, http.StatusBadRequest, types.CodeInvalidParameter, err)
		return
	}

	if stack.Name == "" {
		stack.Name = name
	} else if stack.Name != name {
		writer.ErrorString(w, http.StatusBadRequest, types.CodeInvalidParameter, errors.New("stack name must match path"))
		return
	}

	if err := s.db.UpsertStack(ctx, s.auth(r), &stack); err != nil {
		errorAuto(w, err)
		return
	}

	resp := types.StacksPutResponseV1{}
	JSONOK(w, resp, pretty(r))
}

func (s *Server) v1SecretsList(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	opts := s.listOptions(r)
	secrets, nextCursor, err := s.db.ListSecrets(ctx, s.auth(r), opts)
	if err != nil {
		errorAuto(w, err)
		return
	}

	resp := types.SecretsListResponseV1{Result: secrets, NextCursor: nextCursor}
	JSONOK(w, resp, pretty(r))
}

func (s *Server) v1SecretsGet(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	name, err := url.PathUnescape(r.PathValue("secret"))
	if err != nil {
		ErrorString(w, http.StatusBadRequest, types.CodeInvalidParameter, err)
		return
	}

	secret, err := s.db.GetSecret(ctx, s.auth(r), name)
	if err != nil {
		errorAuto(w, err)
		return
	}

	resp := types.SecretsGetResponseV1{Result: secret}
	JSONOK(w, resp, pretty(r))
}

func (s *Server) v1SecretsDelete(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	name, err := url.PathUnescape(r.PathValue("secret"))
	if err != nil {
		ErrorString(w, http.StatusBadRequest, types.CodeInvalidParameter, err)
		return
	}

	if err := s.db.DeleteSecret(ctx, s.auth(r), name); err != nil {
		errorAuto(w, err)
		return
	}

	resp := types.SecretsDeleteResponseV1{}
	JSONOK(w, resp, pretty(r))
}

func (s *Server) v1SecretsPut(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	name, err := url.PathUnescape(r.PathValue("secret"))
	if err != nil {
		ErrorString(w, http.StatusBadRequest, types.CodeInvalidParameter, err)
		return
	}

	var secret config.Secret
	if err := newJSONDecoder(r.Body).Decode(&secret); err != nil {
		writer.ErrorString(w, http.StatusBadRequest, types.CodeInvalidParameter, err)
		return
	}

	if secret.Name == "" {
		secret.Name = name
	} else if secret.Name != name {
		writer.ErrorString(w, http.StatusBadRequest, types.CodeInvalidParameter, errors.New("secret name must match path"))
		return
	}

	if err := s.db.UpsertSecret(ctx, s.auth(r), &secret); err != nil {
		errorAuto(w, err)
		return
	}

	resp := types.SecretsPutResponseV1{}
	JSONOK(w, resp, pretty(r))
}

func (*Server) auth(r *http.Request) string {
	p := r.Context().Value(principalKey{})
	if p == nil {
		// NOTE(tsandall): this should never be reached because the
		// authentication middleware will reject requests that do not contain a
		// valid API key. If this panic occurs it indicates an logical error in
		// the server that must be fixed.
		panic("unreachable")
	}
	return p.(string)
}

const pageLimitMax = 100

func (*Server) listOptions(r *http.Request) database.ListOptions {
	var opts database.ListOptions
	q := r.URL.Query()
	limit := q.Get("limit")
	if n, err := strconv.Atoi(limit); err == nil {
		if n <= pageLimitMax {
			opts.Limit = n
		}
	}
	if opts.Limit == 0 {
		opts.Limit = pageLimitMax
	}
	opts.Cursor = q.Get("cursor")
	return opts
}

func errorAuto(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, database.ErrNotAuthorized):
		ErrorString(w, http.StatusForbidden, types.CodeNotAuthorized, err)
	case errors.Is(err, database.ErrNotFound):
		ErrorString(w, http.StatusNotFound, types.CodeNotFound, err)
	case errors.Is(err, database.ErrDataConflict):
		ErrorString(w, http.StatusBadRequest, types.CodeDataConflict, err)
	default:
		ErrorString(w, http.StatusInternalServerError, types.CodeInternal, err)
	}
}

func ErrorString(w http.ResponseWriter, status int, code string, err error) {
	Error(w, status, types.NewErrorV1(code, err.Error()))
}

func Error(w http.ResponseWriter, status int, err *types.ErrorV1) {
	headers := w.Header()
	headers.Add("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(append(err.Bytes(), byte('\n')))
}

func JSON(w http.ResponseWriter, code int, v any, pretty bool) {
	enc := json.NewEncoder(w)
	if pretty {
		enc.SetIndent("", "  ")
	}

	w.Header().Add("Content-Type", "application/json")
	w.WriteHeader(code)

	if err := enc.Encode(v); err != nil {
		errorAuto(w, err)
	}
}

func JSONOK(w http.ResponseWriter, v any, pretty bool) {
	JSON(w, http.StatusOK, v, pretty)
}

func getBoolParam(url *url.URL, name string, ifEmpty bool) bool {
	p, ok := url.Query()[name]
	if !ok {
		return false
	}

	if len(p) == 1 && p[0] == "" {
		return ifEmpty
	}

	for _, x := range p {
		if strings.EqualFold(x, "true") {
			return true
		}
	}

	return false
}

func pretty(r *http.Request) bool {
	return getBoolParam(r.URL, types.ParamPrettyV1, true)
}

func newJSONDecoder(r io.Reader) *json.Decoder {
	decoder := json.NewDecoder(r)
	decoder.UseNumber()
	return decoder
}

func authenticationMiddleware(db *database.Database) func(http.Handler) http.Handler {
	return func(inner http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			apiKey, err := extractBearerToken(r)
			if err != nil {
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}

			principalId, err := db.GetPrincipalID(r.Context(), apiKey)
			if err != nil {
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}

			inner.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), principalKey{}, principalId)))
		})
	}
}

type principalKey struct{}

func extractBearerToken(r *http.Request) (string, error) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return "", errors.New("authorization header is missing")
	}

	parts := strings.SplitN(authHeader, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "bearer") {
		return "", errors.New("invalid authorization header format")
	}

	return parts[1], nil
}
