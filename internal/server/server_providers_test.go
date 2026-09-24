package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	prom "github.com/prometheus/client_golang/prometheus"
	"github.com/testcontainers/testcontainers-go"

	"github.com/open-policy-agent/opa-control-plane/internal/config"
	"github.com/open-policy-agent/opa-control-plane/internal/test/dbs"
	pkgsync "github.com/open-policy-agent/opa-control-plane/pkg/sync"
)

// paramProvider requires {"param1": "<non-empty string>"}.
type paramProvider struct{}

func (paramProvider) Type() string                  { return "example.custom-source" }
func (paramProvider) ConfigSchema() json.RawMessage { return json.RawMessage(`{}`) }
func (paramProvider) New(context.Context, pkgsync.ProviderParams) (pkgsync.Synchronizer, error) {
	return nil, nil
}

func (paramProvider) Parse(raw json.RawMessage) (any, error) {
	var cfg struct {
		Param1 string `json:"param1"`
	}
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return nil, err
	}
	if cfg.Param1 == "" {
		return nil, errors.New("param1 is required")
	}
	return cfg, nil
}

func TestServerSourcesPutValidatesProviders(t *testing.T) {
	ctx := t.Context()
	const adminKey = "test-admin-apikey"

	for databaseType, databaseConfig := range dbs.Configs(t) {
		t.Run(databaseType, func(t *testing.T) {
			t.Parallel()
			var ctr testcontainers.Container
			if databaseConfig.Setup != nil {
				ctr = databaseConfig.Setup(t)
				t.Cleanup(databaseConfig.Cleanup(t, ctr))
			}

			db := initTestDB(t, databaseConfig.Database(t, ctr).Database)
			if err := db.UpsertPrincipal(ctx, principal); err != nil {
				t.Fatal(err)
			}
			if err := db.UpsertToken(ctx, "internal", "default", &config.Token{Name: "admin", APIKey: adminKey, Scopes: []config.Scope{{Role: "administrator"}}}); err != nil {
				t.Fatal(err)
			}

			reg := pkgsync.NewSourceProviderRegistry()
			if err := reg.Register(paramProvider{}); err != nil {
				t.Fatal(err)
			}

			// Requests are served through the router directly; no listener needed.
			router := http.NewServeMux()
			New().WithDatabase(db).WithRouter(router).WithPrometheusRegisterer(prom.NewRegistry()).
				WithSourceProviders(reg).Init()
			put := func(body string) *httptest.ResponseRecorder {
				req := httptest.NewRequest(http.MethodPut, "/v1/sources/app", bytes.NewBufferString(body))
				req.Header.Add("authorization", "Bearer "+adminKey)
				w := httptest.NewRecorder()
				router.ServeHTTP(w, req)
				return w
			}

			for _, tc := range []struct {
				note, body string
				status     int
				exp        string // substring of the response body
			}{
				{
					note:   "valid",
					body:   `{"providers": [{"name": "users", "type": "example.custom-source", "param1": "x"}]}`,
					status: http.StatusOK,
				},
				{
					note:   "unknown type",
					body:   `{"providers": [{"name": "users", "type": "nope"}]}`,
					status: http.StatusBadRequest,
					exp:    `source \"app\": provider \"users\": unknown type \"nope\"`,
				},
				{
					note:   "parse error",
					body:   `{"providers": [{"name": "users", "type": "example.custom-source"}]}`,
					status: http.StatusBadRequest,
					exp:    `param1 is required`,
				},
				{
					note:   "missing name",
					body:   `{"providers": [{"type": "example.custom-source", "param1": "x"}]}`,
					status: http.StatusBadRequest,
					exp:    `provider #1: name is required`,
				},
			} {
				t.Run(tc.note, func(t *testing.T) {
					w := put(tc.body)
					if w.Code != tc.status {
						t.Fatalf("expected status %d, got %d: %s", tc.status, w.Code, w.Body)
					}
					if tc.exp != "" && !strings.Contains(w.Body.String(), tc.exp) {
						t.Errorf("expected body containing %q, got %s", tc.exp, w.Body)
					}
				})
			}

			// Only the valid request was stored.
			src, err := db.GetSource(ctx, "internal", "default", "app")
			if err != nil {
				t.Fatal(err)
			}
			if len(src.Providers) != 1 || src.Providers[0].Config["param1"] != "x" {
				t.Errorf("unexpected stored providers: %+v", src.Providers)
			}
		})
	}
}
