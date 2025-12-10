package server

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/open-policy-agent/opa/v1/util"
	"github.com/testcontainers/testcontainers-go"

	"github.com/open-policy-agent/opa-control-plane/internal/config"
	"github.com/open-policy-agent/opa-control-plane/internal/database"
	"github.com/open-policy-agent/opa-control-plane/internal/migrations"
	"github.com/open-policy-agent/opa-control-plane/internal/server/types"
	"github.com/open-policy-agent/opa-control-plane/internal/test/dbs"
)

const tenant = "default"

var principal = database.Principal{
	Id:     "internal",
	Role:   "administrator",
	Tenant: tenant,
}

func TestServerSourcesData(t *testing.T) {
	ctx := t.Context()
	for databaseType, databaseConfig := range dbs.Configs(t) {
		t.Run(databaseType, func(t *testing.T) {
			t.Parallel()
			var ctr testcontainers.Container
			if databaseConfig.Setup != nil {
				ctr = databaseConfig.Setup(t)
				t.Cleanup(databaseConfig.Cleanup(t, ctr))
			}

			db := initTestDB(t, databaseConfig.Database(t, ctr).Database)
			ts := initTestServer(t, db)
			defer ts.Close()

			if err := db.UpsertPrincipal(ctx, principal); err != nil {
				t.Fatal(err)
			}

			const adminKey = "test-admin-apikey"

			if err := db.UpsertToken(ctx, "internal", "default", &config.Token{Name: "admin", APIKey: adminKey, Scopes: []config.Scope{{Role: "administrator"}}}); err != nil {
				t.Fatal(err)
			}

			tests := []struct {
				name       string
				method     string
				path       string
				body       string
				apikey     string
				statusCode int
				result     any
			}{
				{
					name:       "Create source",
					method:     "PUT",
					path:       "/v1/sources/system1",
					body:       `{}`,
					apikey:     adminKey,
					statusCode: 200,
					result:     map[string]any{},
				},
				{
					name:       "GET",
					method:     "GET",
					path:       "/v1/sources/system1/data/foo",
					body:       "",
					apikey:     adminKey,
					statusCode: 200,
					result:     map[string]any{},
				},
				{
					name:       "PUT",
					method:     "PUT",
					path:       "/v1/sources/system1/data/foo",
					body:       `{"key": "value"}`,
					apikey:     adminKey,
					statusCode: 200,
					result:     map[string]any{},
				},
				{
					name:       "GET after PUT",
					method:     "GET",
					path:       "/v1/sources/system1/data/foo",
					body:       "",
					apikey:     adminKey,
					statusCode: 200,
					result:     map[string]any{"result": map[string]any{"key": "value"}},
				},
				{
					name:       "POST",
					method:     "POST",
					path:       "/v1/sources/system1/data/foo",
					body:       `{"key": "value2"}`,
					apikey:     adminKey,
					statusCode: 200,
					result:     map[string]any{},
				},
				{
					name:       "GET after POST",
					method:     "GET",
					path:       "/v1/sources/system1/data/foo",
					body:       "",
					apikey:     adminKey,
					statusCode: 200,
					result:     map[string]any{"result": map[string]any{"key": "value2"}},
				},
				{
					name:       "PATCH new key",
					method:     "PATCH",
					path:       "/v1/sources/system1/data/foo",
					body:       `[{"op":"add","path":"/key2","value":"value4"}]`,
					apikey:     adminKey,
					statusCode: 200,
					result:     map[string]any{},
				},
				{
					name:       "GET after PATCH new key",
					method:     "GET",
					path:       "/v1/sources/system1/data/foo",
					body:       "",
					apikey:     adminKey,
					statusCode: 200,
					result: map[string]any{"result": map[string]any{
						"key":  "value2",
						"key2": "value4",
					}},
				},
				{
					name:       "PATCH replace key, add some array",
					method:     "PATCH",
					path:       "/v1/sources/system1/data/foo",
					body:       `[{"op":"replace","path":"/key2","value":"value3"},{"op":"add","path":"/arr","value":["one"]}]`,
					apikey:     adminKey,
					statusCode: 200,
					result:     map[string]any{},
				},
				{
					name:       "GET after PATCH new key",
					method:     "GET",
					path:       "/v1/sources/system1/data/foo",
					body:       "",
					apikey:     adminKey,
					statusCode: 200,
					result: map[string]any{"result": map[string]any{
						"arr":  []any{"one"},
						"key":  "value2",
						"key2": "value3",
					}},
				},
				{
					name:       "PATCH remove key2, append to array",
					method:     "PATCH",
					path:       "/v1/sources/system1/data/foo",
					body:       `[{"op":"remove","path":"/key2"},{"op":"add","path":"/arr/-","value":"two"}]`,
					apikey:     adminKey,
					statusCode: 200,
					result:     map[string]any{},
				},
				{
					name:       "GET after PATCH remove key2, add to array",
					method:     "GET",
					path:       "/v1/sources/system1/data/foo",
					body:       "",
					apikey:     adminKey,
					statusCode: 200,
					result: map[string]any{"result": map[string]any{
						"arr": []any{"one", "two"},
						"key": "value2",
					}},
				},
				{
					name:       "PATCH add deeply nested key",
					method:     "PATCH",
					path:       "/v1/sources/system1/data/foo",
					body:       `[{"op":"add","path":"/a/b/c/d","value": "D"}]`,
					apikey:     adminKey,
					statusCode: 200,
					result:     map[string]any{},
				},
				{
					name:       "PATCH remove nonexistant key",
					method:     "PATCH",
					path:       "/v1/sources/system1/data/foo",
					body:       `[{"op":"remove","path":"/x/y/z"}]`,
					apikey:     adminKey,
					statusCode: 200,
					result:     map[string]any{},
				},
				{
					name:       "GET after PATCH deeply nested key",
					method:     "GET",
					path:       "/v1/sources/system1/data/foo",
					body:       "",
					apikey:     adminKey,
					statusCode: 200,
					result: map[string]any{"result": map[string]any{
						"arr": []any{"one", "two"},
						"a":   map[string]any{"b": map[string]any{"c": map[string]any{"d": "D"}}},
						"key": "value2",
					}},
				},
				{
					name:       "DELETE",
					method:     "DELETE",
					path:       "/v1/sources/system1/data/foo",
					body:       "",
					apikey:     adminKey,
					statusCode: 200,
					result:     map[string]any{},
				},
				{
					name:       "GET after DELETE",
					method:     "GET",
					path:       "/v1/sources/system1/data/foo",
					body:       "",
					apikey:     adminKey,
					statusCode: 200,
					result:     map[string]any{},
				},
				{
					name:       "PATCH with op=test",
					method:     "PATCH",
					path:       "/v1/sources/system1/data/foo",
					body:       `[{"op":"test","path":"/key2","value":"value4"}]`,
					apikey:     adminKey,
					statusCode: 400,
					result: map[string]any{
						"code":    "invalid_parameter",
						"message": `unsupported patch operation "test", must be one of "replace", "add", "remove"`,
					},
				},
				{
					name:       "PATCH with op=move",
					method:     "PATCH",
					path:       "/v1/sources/system1/data/foo",
					body:       `[{"op":"move","path":"/key2","from":"/key1"}]`,
					apikey:     adminKey,
					statusCode: 400,
					result: map[string]any{
						"code":    "invalid_parameter",
						"message": `unsupported patch operation "move", must be one of "replace", "add", "remove"`,
					},
				},
				{
					name:       "PATCH with op=copy",
					method:     "PATCH",
					path:       "/v1/sources/system1/data/foo",
					body:       `[{"op":"copy","path":"/key2","from":"/key1"}]`,
					apikey:     adminKey,
					statusCode: 400,
					result: map[string]any{
						"code":    "invalid_parameter",
						"message": `unsupported patch operation "copy", must be one of "replace", "add", "remove"`,
					},
				},
				{
					name:       "PATCH with non-patch payload",
					method:     "PATCH",
					path:       "/v1/sources/system1/data/foo",
					body:       `[{}]`,
					apikey:     adminKey,
					statusCode: 400,
					result: map[string]any{
						"code":    "invalid_parameter",
						"message": `unsupported patch operation "unknown", must be one of "replace", "add", "remove"`,
					},
				},
				{
					name:       "PATCH with non-patch payload",
					method:     "PATCH",
					path:       "/v1/sources/system1/data/foo",
					body:       `{}`,
					apikey:     adminKey,
					statusCode: 400,
					result: map[string]any{
						"code":    "invalid_parameter",
						"message": `json: cannot unmarshal object into Go value of type jsonpatch.Patch`,
					},
				},
			}
			for _, test := range tests {
				t.Run(test.name, func(t *testing.T) {
					tr := ts.Request(test.method, test.path, test.body, test.apikey).ExpectStatus(test.statusCode)

					exp, act := test.result, tr.BodyDecoded()
					if diff := cmp.Diff(exp, act); diff != "" {
						t.Fatal("unexpected body (-want, +got)", diff)
					}
				})
			}
		})
	}
}

func TestServerSecretsOwners(t *testing.T) {
	ctx := t.Context()

	for databaseType, databaseConfig := range dbs.Configs(t) {
		t.Run(databaseType, func(t *testing.T) {
			t.Parallel()
			var ctr testcontainers.Container
			if databaseConfig.Setup != nil {
				ctr = databaseConfig.Setup(t)
				t.Cleanup(databaseConfig.Cleanup(t, ctr))
			}

			db := initTestDB(t, databaseConfig.Database(t, ctr).Database)
			ts := initTestServer(t, db)
			defer ts.Close()

			if err := db.UpsertPrincipal(ctx, principal); err != nil {
				t.Fatal(err)
			}

			const ownerKey = "test-owner-key"
			const ownerKey2 = "test-owner-key2"

			if err := db.UpsertToken(ctx, "internal", "default", &config.Token{Name: "testowner", APIKey: ownerKey, Scopes: []config.Scope{{Role: "owner"}}}); err != nil {
				t.Fatal(err)
			}

			if err := db.UpsertToken(ctx, "internal", "default", &config.Token{Name: "testowner2", APIKey: ownerKey2, Scopes: []config.Scope{{Role: "owner"}}}); err != nil {
				t.Fatal(err)
			}

			ts.Request("PUT", "/v1/secrets/test", `{"value":{"type":"token_auth","token":"yadda"}}`, ownerKey).ExpectStatus(200)
			exp := &config.SecretRef{
				Name: "test",
			}

			{
				var secret types.SecretsGetResponseV1
				ts.Request("GET", "/v1/secrets/test", "", ownerKey).ExpectStatus(200).ExpectBody(&secret)
				act := secret.Result
				if diff := cmp.Diff(exp, act); diff != "" {
					t.Fatal("unexpected response (-want,+got)", diff)
				}
			}

			{
				var ownerList types.SecretsListResponseV1
				ts.Request("GET", "/v1/secrets", "", ownerKey).ExpectStatus(200).ExpectBody(&ownerList)
				if len(ownerList.Result) != 1 {
					t.Fatal("expected exactly one secret")
				}
				act := ownerList.Result[0]
				if diff := cmp.Diff(exp, act); diff != "" {
					t.Fatal("unexpected response (-want,+got)", diff)
				}
			}

			{
				var ownerList2 types.SecretsListResponseV1
				ts.Request("GET", "/v1/secrets", "", ownerKey2).ExpectStatus(200).ExpectBody(&ownerList2)
				if len(ownerList2.Result) != 0 {
					t.Fatal("did not expect to see secret")
				}
			}

			{ // compared to using ownerKey2
				ts.Request("PUT", "/v1/secrets/test", "{}", ownerKey2).ExpectStatus(403)
				ts.Request("GET", "/v1/secrets/test", "", ownerKey2).ExpectStatus(404)
				ts.Request("PUT", "/v1/secrets/test", "{}", ownerKey).ExpectStatus(200)
			}
			{ // deleting as not-the-owner
				ts.Request("DELETE", "/v1/secrets/guessname", "", ownerKey2).ExpectStatus(403)
				ts.Request("DELETE", "/v1/secrets/test", "", ownerKey2).ExpectStatus(403)
			}
			{ // deleting as owner
				ts.Request("DELETE", "/v1/secrets/test", "", ownerKey).ExpectStatus(200)
				var ownerList types.SecretsListResponseV1
				ts.Request("GET", "/v1/secrets", "", ownerKey).ExpectStatus(200).ExpectBody(&ownerList)
				if len(ownerList.Result) != 0 {
					t.Fatal("did not expect to see secret")
				}
			}
		})
	}
}

func TestServerBundleOwners(t *testing.T) {
	ctx := t.Context()

	for databaseType, databaseConfig := range dbs.Configs(t) {
		t.Run(databaseType, func(t *testing.T) {
			t.Parallel()
			var ctr testcontainers.Container
			if databaseConfig.Setup != nil {
				ctr = databaseConfig.Setup(t)
				t.Cleanup(databaseConfig.Cleanup(t, ctr))
			}

			db := initTestDB(t, databaseConfig.Database(t, ctr).Database)
			ts := initTestServer(t, db)
			defer ts.Close()

			if err := db.UpsertPrincipal(ctx, principal); err != nil {
				t.Fatal(err)
			}

			const ownerKey = "test-owner-key"
			const ownerKey2 = "test-owner-key2"

			if err := db.UpsertToken(ctx, "internal", "default", &config.Token{Name: "testowner", APIKey: ownerKey, Scopes: []config.Scope{{Role: "owner"}}}); err != nil {
				t.Fatal(err)
			}

			if err := db.UpsertToken(ctx, "internal", "default", &config.Token{Name: "testowner2", APIKey: ownerKey2, Scopes: []config.Scope{{Role: "owner"}}}); err != nil {
				t.Fatal(err)
			}

			ts.Request("PUT", "/v1/bundles/testbundle", `{
		"object_storage": {
			"aws": {
				"region": "us-east-1",
				"bucket": "test-bucket",
				"key": "test-key"
			}
		},
		"rebuild_interval": "10m30s"
	}`, ownerKey).ExpectStatus(200)

			ivl, _ := time.ParseDuration("10m30s")
			exp := &config.Bundle{
				Name: "testbundle",
				ObjectStorage: config.ObjectStorage{
					AmazonS3: &config.AmazonS3{
						Region: "us-east-1",
						Bucket: "test-bucket",
						Key:    "test-key",
					},
				},
				Interval: config.Duration(ivl),
			}

			{
				var ownerList types.BundlesListResponseV1
				ts.Request("GET", "/v1/bundles", "", ownerKey).ExpectStatus(200).ExpectBody(&ownerList)
				if len(ownerList.Result) != 1 {
					t.Fatal("expected exactly one bundle")
				}
				act := ownerList.Result[0]
				if diff := cmp.Diff(exp, act); diff != "" {
					t.Fatal("unexpected response (-want,+got)", diff)
				}
			}

			{
				var bundle types.BundlesGetResponseV1
				ts.Request("GET", "/v1/bundles/testbundle", "", ownerKey).ExpectStatus(200).ExpectBody(&bundle)
				act := bundle.Result
				if diff := cmp.Diff(exp, act); diff != "" {
					t.Fatal("unexpected response (-want,+got)", diff)
				}
			}

			{
				var ownerList2 types.SourcesListResponseV1
				ts.Request("GET", "/v1/bundles", "", ownerKey2).ExpectStatus(200).ExpectBody(&ownerList2)
				if len(ownerList2.Result) != 0 {
					t.Fatal("did not expect to see bundle")
				}
			}

			{ // compared to using ownerKey2
				ts.Request("PUT", "/v1/bundles/testbundle", "{}", ownerKey2).ExpectStatus(403)
				ts.Request("GET", "/v1/bundles/testbundle", "", ownerKey2).ExpectStatus(404)
				ts.Request("PUT", "/v1/bundles/testbundle", "{}", ownerKey).ExpectStatus(200)
			}
			{ // deleting as not-the-owner
				ts.Request("DELETE", "/v1/bundles/guessname", "", ownerKey2).ExpectStatus(403)
				ts.Request("DELETE", "/v1/bundles/testbundle", "", ownerKey2).ExpectStatus(403)
			}
			{ // deleting as owner
				ts.Request("DELETE", "/v1/bundles/testbundle", "", ownerKey).ExpectStatus(200)
				var ownerList types.BundlesListResponseV1
				ts.Request("GET", "/v1/bundles", "", ownerKey).ExpectStatus(200).ExpectBody(&ownerList)
				if len(ownerList.Result) != 0 {
					t.Fatal("did not expect to see bundle")
				}
			}
		})
	}
}

func TestServerSourceOwners(t *testing.T) {
	ctx := t.Context()
	for databaseType, databaseConfig := range dbs.Configs(t) {
		t.Run(databaseType, func(t *testing.T) {
			t.Parallel()
			var ctr testcontainers.Container
			if databaseConfig.Setup != nil {
				ctr = databaseConfig.Setup(t)
				t.Cleanup(databaseConfig.Cleanup(t, ctr))
			}

			db := initTestDB(t, databaseConfig.Database(t, ctr).Database)
			ts := initTestServer(t, db)
			defer ts.Close()

			if err := db.UpsertPrincipal(ctx, principal); err != nil {
				t.Fatal(err)
			}

			const ownerKey = "test-owner-key"
			const ownerKey2 = "test-owner-key2"

			if err := db.UpsertToken(ctx, "internal", "default", &config.Token{Name: "testowner", APIKey: ownerKey, Scopes: []config.Scope{{Role: "owner"}}}); err != nil {
				t.Fatal(err)
			}

			if err := db.UpsertToken(ctx, "internal", "default", &config.Token{Name: "testowner2", APIKey: ownerKey2, Scopes: []config.Scope{{Role: "owner"}}}); err != nil {
				t.Fatal(err)
			}

			ts.Request("PUT", "/v1/sources/required", `{}`, ownerKey).ExpectStatus(200)
			ts.Request("PUT", "/v1/sources/testsrc", `{"datasources": [{"name": "ds"}], "requirements": [{"source": "required", "automount": false}]}`, ownerKey).ExpectStatus(200)

			{
				var ownerList types.SourcesListResponseV1
				ts.Request("GET", "/v1/sources", "", ownerKey).ExpectStatus(200).ExpectBody(&ownerList)
				if len(ownerList.Result) != 2 {
					t.Fatal("expected exactly one source")
				}
				src, f := "required", false
				exp := &config.Source{
					Name: "testsrc",
					Datasources: []config.Datasource{
						{Name: "ds"},
					},
					Requirements: []config.Requirement{
						{
							Source:    &src,
							AutoMount: &f,
						},
					},
				}
				if !ownerList.Result[1].Equal(exp) {
					t.Fatalf("unexpected response, expected %v, got %v", exp, ownerList.Result[0])
				}
			}

			{
				var src types.SourcesGetResponseV1
				ts.Request("GET", "/v1/sources/testsrc", "", ownerKey).ExpectStatus(200).ExpectBody(&src)
				srcN, f := "required", false
				exp := &config.Source{
					Name: "testsrc",
					Datasources: []config.Datasource{
						{Name: "ds"},
					},
					Requirements: []config.Requirement{
						{
							Source:    &srcN,
							AutoMount: &f,
						},
					},
				}
				act := src.Result
				if diff := cmp.Diff(exp, act); diff != "" {
					t.Fatal("unexpected source (-want,+got)", diff)
				}
			}

			{
				var ownerList2 types.SourcesListResponseV1
				ts.Request("GET", "/v1/sources", "", ownerKey2).ExpectStatus(200).ExpectBody(&ownerList2)
				if len(ownerList2.Result) != 0 {
					t.Fatal("did not expect to see source")
				}
			}

			{ // compared to using ownerKey2
				ts.Request("PUT", "/v1/sources/testsrc", "{}", ownerKey2).ExpectStatus(403)
				ts.Request("GET", "/v1/sources/testsrc", "", ownerKey2).ExpectStatus(404)
				ts.Request("PUT", "/v1/sources/testsrc", "{}", ownerKey).ExpectStatus(200)
			}
			{ // deleting as not-the-owner
				ts.Request("DELETE", "/v1/sources/guessname", "", ownerKey2).ExpectStatus(403)
				ts.Request("DELETE", "/v1/sources/testsrc", "", ownerKey2).ExpectStatus(403)
			}
			{ // deleting as owner
				ts.Request("DELETE", "/v1/sources/testsrc", "", ownerKey).ExpectStatus(200)
				ts.Request("DELETE", "/v1/sources/required", "", ownerKey).ExpectStatus(200)
				var ownerList types.SourcesListResponseV1
				ts.Request("GET", "/v1/sources", "", ownerKey).ExpectStatus(200).ExpectBody(&ownerList)
				if len(ownerList.Result) != 0 {
					t.Fatal("did not expect to see source")
				}
			}
		})
	}
}

func TestSourcesDatasourcesSecrets(t *testing.T) {
	ctx := t.Context()
	for databaseType, databaseConfig := range dbs.Configs(t) {
		t.Run(databaseType, func(t *testing.T) {
			t.Parallel()
			var ctr testcontainers.Container
			if databaseConfig.Setup != nil {
				ctr = databaseConfig.Setup(t)
				t.Cleanup(databaseConfig.Cleanup(t, ctr))
			}

			db := initTestDB(t, databaseConfig.Database(t, ctr).Database)
			ts := initTestServer(t, db)
			defer ts.Close()

			if err := db.UpsertPrincipal(ctx, principal); err != nil {
				t.Fatal(err)
			}

			if err := db.UpsertSecret(ctx, "internal", "default", &config.Secret{
				Name:  "creds-for-api",
				Value: map[string]any{"type": "token_auth", "token": "box"},
			}); err != nil {
				t.Fatal(err)
			}

			const ownerKey = "test-owner-key"

			if err := db.UpsertToken(ctx, "internal", "default", &config.Token{Name: "testowner", APIKey: ownerKey, Scopes: []config.Scope{{Role: "owner"}}}); err != nil {
				t.Fatal(err)
			}

			src := map[string]any{
				"datasources": []any{
					map[string]any{
						"name":            "testds",
						"path":            "ds",
						"transform_query": "input",
						"type":            "http",
						"config": map[string]any{
							"url": "https://api.ipa.pai/pia",
						},
						"credentials": "creds-for-api",
					},
				},
			}
			payload := util.MustMarshalJSON(src)
			ts.Request("PUT", "/v1/sources/testsrc", string(payload), ownerKey).ExpectStatus(200)

			exp := &config.Source{
				Name: "testsrc",
				Datasources: []config.Datasource{
					{
						Name:           "testds",
						Path:           "ds",
						Type:           "http",
						TransformQuery: "input",
						Config: map[string]any{
							"url": "https://api.ipa.pai/pia",
						},
						Credentials: &config.SecretRef{Name: "creds-for-api"},
					},
				},
			}

			{ // GET /v1/sources
				var ownerList types.SourcesListResponseV1
				ts.Request("GET", "/v1/sources", "", ownerKey).ExpectStatus(200).ExpectBody(&ownerList)
				if exp, act := 1, len(ownerList.Result); exp != act {
					t.Fatalf("expected %d sources, got %d", exp, act)
				}
				act := ownerList.Result[0]
				if diff := cmp.Diff(exp, act); diff != "" {
					t.Fatal("unexpected response, (-want, +got)", diff)
				}
			}

			{ // GET /v1/sources/testsrc
				var src types.SourcesGetResponseV1
				ts.Request("GET", "/v1/sources/testsrc", "", ownerKey).ExpectStatus(200).ExpectBody(&src)
				act := src.Result
				if diff := cmp.Diff(exp, act); diff != "" {
					t.Fatal("unexpected source (-want,+got)", diff)
				}
			}

			{ // PUT source with datasource w/o credentials (ensure it's optional)
				src := map[string]any{
					"datasources": []any{
						map[string]any{
							"name": "testds",
							"path": "ds",
							"type": "http",
							"config": map[string]any{
								"url": "https://api.ipa.pai/pia",
							},
						},
					},
				}
				payload := util.MustMarshalJSON(src)
				ts.Request("PUT", "/v1/sources/testsrc", string(payload), ownerKey).ExpectStatus(200)
			}

			{ // GET /v1/sources/testsource (ensure the credential ref is gone)
				var src types.SourcesGetResponseV1
				ts.Request("GET", "/v1/sources/testsrc", "", ownerKey).ExpectStatus(200).ExpectBody(&src)
				act := src.Result
				exp := &config.Source{
					Name: "testsrc",
					Datasources: []config.Datasource{
						{
							Name: "testds",
							Path: "ds",
							Type: "http",
							Config: map[string]any{
								"url": "https://api.ipa.pai/pia",
							},
						},
					},
				}
				if diff := cmp.Diff(exp, act); diff != "" {
					t.Fatal("unexpected source (-want,+got)", diff)
				}
			}
		})
	}
}

func TestServerStackOwners(t *testing.T) {
	ctx := t.Context()

	for databaseType, databaseConfig := range dbs.Configs(t) {
		t.Run(databaseType, func(t *testing.T) {
			t.Parallel()
			var ctr testcontainers.Container
			if databaseConfig.Setup != nil {
				ctr = databaseConfig.Setup(t)
				t.Cleanup(databaseConfig.Cleanup(t, ctr))
			}

			db := initTestDB(t, databaseConfig.Database(t, ctr).Database)
			ts := initTestServer(t, db)
			defer ts.Close()

			if err := db.UpsertPrincipal(ctx, principal); err != nil {
				t.Fatal(err)
			}

			const ownerKey = "test-stack-owner-key"
			const ownerKey2 = "test-stack-owner-key2"

			if err := db.UpsertToken(ctx, "internal", "default", &config.Token{Name: "teststackowner", APIKey: ownerKey, Scopes: []config.Scope{{Role: "stack_owner"}}}); err != nil {
				t.Fatal(err)
			}

			if err := db.UpsertToken(ctx, "internal", "default", &config.Token{Name: "teststackowner2", APIKey: ownerKey2, Scopes: []config.Scope{{Role: "stack_owner"}}}); err != nil {
				t.Fatal(err)
			}

			ts.Request("PUT", "/v1/stacks/teststack", `{}`, ownerKey).ExpectStatus(200)

			{
				var ownerList types.StacksListResponseV1
				ts.Request("GET", "/v1/stacks", "", ownerKey).ExpectStatus(200).ExpectBody(&ownerList)
				if len(ownerList.Result) != 1 {
					t.Fatal("expected exactly one stack")
				}
				act := ownerList.Result[0]
				exp := &config.Stack{
					Name:     "teststack",
					Selector: config.MustNewSelector(nil),
				}
				if diff := cmp.Diff(exp, act); diff != "" {
					t.Fatal("unexpected stack (-want,+got)", diff)
				}
			}

			{
				var ownerGetOne types.StacksGetResponseV1
				ts.Request("GET", "/v1/stacks/teststack", "", ownerKey).ExpectStatus(200).ExpectBody(&ownerGetOne)
				act := ownerGetOne.Result
				exp := &config.Stack{
					Name:     "teststack",
					Selector: config.MustNewSelector(nil),
				}
				if diff := cmp.Diff(exp, act); diff != "" {
					t.Fatal("unexpected stack (-want,+got)", diff)
				}
			}

			{
				var ownerList2 types.StacksListResponseV1
				ts.Request("GET", "/v1/stacks", "", ownerKey2).ExpectStatus(200).ExpectBody(&ownerList2)
				if len(ownerList2.Result) != 0 {
					t.Fatal("did not expect to see stack")
				}
			}

			{ // compared to using ownerKey2
				ts.Request("PUT", "/v1/stacks/teststack", `{}`, ownerKey2).ExpectStatus(403)
				ts.Request("GET", "/v1/stacks/teststack", "", ownerKey2).ExpectStatus(404)
				ts.Request("PUT", "/v1/stacks/teststack", `{}`, ownerKey).ExpectStatus(200)
			}
			{ // deleting as not-the-owner
				ts.Request("DELETE", "/v1/stacks/guessname", "", ownerKey2).ExpectStatus(403)
				ts.Request("DELETE", "/v1/stacks/teststack", "", ownerKey2).ExpectStatus(403)
			}
			{ // deleting as owner
				ts.Request("DELETE", "/v1/stacks/teststack", "", ownerKey).ExpectStatus(200)
				var ownerList types.StacksListResponseV1
				ts.Request("GET", "/v1/stacks", "", ownerKey).ExpectStatus(200).ExpectBody(&ownerList)
				if len(ownerList.Result) != 0 {
					t.Fatal("did not expect to see stack")
				}
			}
		})
	}
}

func TestServerSourcePagination(t *testing.T) {
	ctx := t.Context()

	for databaseType, databaseConfig := range dbs.Configs(t) {
		t.Run(databaseType, func(t *testing.T) {
			t.Parallel()
			var ctr testcontainers.Container
			if databaseConfig.Setup != nil {
				ctr = databaseConfig.Setup(t)
				t.Cleanup(databaseConfig.Cleanup(t, ctr))
			}

			db := initTestDB(t, databaseConfig.Database(t, ctr).Database)
			ts := initTestServer(t, db)
			defer ts.Close()

			if err := db.UpsertPrincipal(ctx, principal); err != nil {
				t.Fatal(err)
			}

			const ownerKey = "test-owner-key"

			if err := db.UpsertToken(ctx, "internal", "default", &config.Token{Name: "testowner", APIKey: ownerKey, Scopes: []config.Scope{{Role: "owner"}}}); err != nil {
				t.Fatal(err)
			}

			const ownerKey2 = "test-owner-key2"

			if err := db.UpsertToken(ctx, "internal", "default", &config.Token{Name: "testowner2", APIKey: ownerKey2, Scopes: []config.Scope{{Role: "owner"}}}); err != nil {
				t.Fatal(err)
			}

			for i := range 200 {
				ts.Request("PUT", "/v1/sources/testsrc"+strconv.Itoa(i), "{}", ownerKey).ExpectStatus(200)
			}

			// Create a source for another owner that must not be seen during pagination.
			ts.Request("PUT", "/v1/sources/othersource", "{}", ownerKey2).ExpectStatus(200)

			var (
				allSources []*config.Source
				cursor     string
				pageCount  int
			)

			for {
				url := "/v1/sources?limit=10"
				if cursor != "" {
					url += "&cursor=" + cursor
				}
				var resp types.SourcesListResponseV1
				ts.Request("GET", url, "", ownerKey).ExpectStatus(200).ExpectBody(&resp)

				allSources = append(allSources, resp.Result...)
				if resp.NextCursor == "" {
					break
				}
				cursor = resp.NextCursor
				pageCount++
			}

			if len(allSources) != 200 {
				t.Fatalf("expected 200 sources, got %d", len(allSources))
			}
			if pageCount != 20 {
				t.Fatalf("expected pagination to require multiple pages, got %d", pageCount)
			}
		})
	}
}

func TestServerHealthEndpoint(t *testing.T) {

	ts := initTestServer(t, nil)
	defer ts.Close()

	notReady := func(context.Context) error { return errors.New("not ready") }
	ready := func(context.Context) error { return nil }

	ts.srv.readyFn = notReady

	resp := ts.Request("GET", "/health", "", "")
	resp.ExpectStatus(500)

	ts.srv.readyFn = ready

	resp = ts.Request("GET", "/health", "", "")
	resp.ExpectStatus(200)

}

// TestServerTenancy checks that names only need to unique within a tenant.
func TestServerTenancy(t *testing.T) {
	ctx := t.Context()

	for databaseType, databaseConfig := range dbs.Configs(t) {
		t.Run(databaseType, func(t *testing.T) {
			t.Parallel()
			var ctr testcontainers.Container
			if databaseConfig.Setup != nil {
				ctr = databaseConfig.Setup(t)
				if databaseConfig.Cleanup != nil {
					t.Cleanup(databaseConfig.Cleanup(t, ctr))
				}
			}

			db := initTestDB(t, databaseConfig.Database(t, ctr).Database)
			ts := initTestServer(t, db)
			defer ts.Close()

			if err := db.UpsertPrincipal(ctx, principal); err != nil {
				t.Fatal(err)
			}

			const otherPrincipal = "other-internal"
			const otherTenant = "other-tenant"
			if _, err := db.DB().ExecContext(ctx, "INSERT INTO tenants (name) VALUES ('"+otherTenant+"')"); err != nil {
				t.Fatal(err)
			}
			p2 := principal
			p2.Id = otherPrincipal
			p2.Tenant = otherTenant
			if err := db.UpsertPrincipal(ctx, p2); err != nil {
				t.Fatal(err)
			}

			{ // put bundle/stack/source/secret with same name in another tenant
				if err := db.UpsertBundle(ctx, "other-internal", otherTenant, &config.Bundle{Name: "foobundle"}); err != nil {
					t.Fatal(err)
				}
				if err := db.UpsertSource(ctx, "other-internal", otherTenant, &config.Source{Name: "foosource"}); err != nil {
					t.Fatal(err)
				}
				if err := db.UpsertSecret(ctx, "other-internal", otherTenant, &config.Secret{Name: "foosecret"}); err != nil {
					t.Fatal(err)
				}
				if err := db.UpsertStack(ctx, "other-internal", otherTenant, &config.Stack{Name: "foostack"}); err != nil {
					t.Fatal(err)
				}
			}

			const ownerKey, stackOwnerKey = "test-owner-key", "test-stack-owner-key"
			if err := db.UpsertToken(ctx, "internal", "default", &config.Token{Name: "testowner", APIKey: ownerKey, Scopes: []config.Scope{{Role: "owner"}}}); err != nil {
				t.Fatal(err)
			}
			if err := db.UpsertToken(ctx, "internal", "default", &config.Token{Name: "teststackowner", APIKey: stackOwnerKey, Scopes: []config.Scope{{Role: "stack_owner"}}}); err != nil {
				t.Fatal(err)
			}

			t.Run("bundle", func(t *testing.T) {
				ts.Request("PUT", "/v1/bundles/foobundle", `{
		"object_storage": {
			"aws": {
				"region": "us-east-1",
				"bucket": "test-bucket",
				"key": "test-key"
			}
		},
		"rebuild_interval": "10m30s"
	}`, ownerKey).ExpectStatus(200)

				ivl, _ := time.ParseDuration("10m30s")
				exp := &config.Bundle{
					Name: "foobundle",
					ObjectStorage: config.ObjectStorage{
						AmazonS3: &config.AmazonS3{
							Region: "us-east-1",
							Bucket: "test-bucket",
							Key:    "test-key",
						},
					},
					Interval: config.Duration(ivl),
				}

				var ownerList types.BundlesListResponseV1
				ts.Request("GET", "/v1/bundles", "", ownerKey).ExpectStatus(200).ExpectBody(&ownerList)
				if len(ownerList.Result) != 1 {
					t.Fatal("expected exactly one bundle")
				}
				act := ownerList.Result[0]
				if diff := cmp.Diff(exp, act); diff != "" {
					t.Fatal("unexpected response (-want,+got)", diff)
				}
			})

			t.Run("secret", func(t *testing.T) {
				ts.Request("PUT", "/v1/secrets/foosecret", `{"value":{"type":"token_auth","token":"yadda"}}`, ownerKey).ExpectStatus(200)
				exp := &config.SecretRef{
					Name: "foosecret",
				}

				var secret types.SecretsGetResponseV1
				ts.Request("GET", "/v1/secrets/foosecret", "", ownerKey).ExpectStatus(200).ExpectBody(&secret)
				act := secret.Result
				if diff := cmp.Diff(exp, act); diff != "" {
					t.Fatal("unexpected response (-want,+got)", diff)
				}

				var ownerList types.SecretsListResponseV1
				ts.Request("GET", "/v1/secrets", "", ownerKey).ExpectStatus(200).ExpectBody(&ownerList)
				if len(ownerList.Result) != 1 {
					t.Fatal("expected exactly one secret")
				}
				if diff := cmp.Diff(exp, ownerList.Result[0]); diff != "" {
					t.Fatal("unexpected response (-want,+got)", diff)
				}
			})

			t.Run("stack", func(t *testing.T) {
				ts.Request("PUT", "/v1/stacks/foostack", `{}`, stackOwnerKey).ExpectStatus(200)

				var ownerList types.StacksListResponseV1
				ts.Request("GET", "/v1/stacks", "", stackOwnerKey).ExpectStatus(200).ExpectBody(&ownerList)
				if len(ownerList.Result) != 1 {
					t.Fatal("expected exactly one stack")
				}
				act := ownerList.Result[0]
				exp := &config.Stack{
					Name:     "foostack",
					Selector: config.MustNewSelector(nil),
				}
				if diff := cmp.Diff(exp, act); diff != "" {
					t.Fatal("unexpected stack (-want,+got)", diff)
				}
				var ownerGetOne types.StacksGetResponseV1
				ts.Request("GET", "/v1/stacks/foostack", "", stackOwnerKey).ExpectStatus(200).ExpectBody(&ownerGetOne)
				if diff := cmp.Diff(exp, ownerGetOne.Result); diff != "" {
					t.Fatal("unexpected stack (-want,+got)", diff)
				}
			})

			t.Run("source", func(t *testing.T) {
				ts.Request("PUT", "/v1/sources/foosource", `{"datasources": [{"name": "ds"}]}`, ownerKey).ExpectStatus(200)

				var ownerList types.SourcesListResponseV1
				ts.Request("GET", "/v1/sources", "", ownerKey).ExpectStatus(200).ExpectBody(&ownerList)
				if len(ownerList.Result) != 1 {
					t.Fatal("expected exactly one source")
				}
				exp := &config.Source{
					Name: "foosource",
					Datasources: []config.Datasource{
						{Name: "ds"},
					},
				}
				if !ownerList.Result[0].Equal(exp) {
					t.Fatalf("unexpected response, expected %v, got %v", exp, ownerList.Result[0])
				}

				var src types.SourcesGetResponseV1
				ts.Request("GET", "/v1/sources/foosource", "", ownerKey).ExpectStatus(200).ExpectBody(&src)
				act := src.Result
				if diff := cmp.Diff(exp, act); diff != "" {
					t.Fatal("unexpected source (-want,+got)", diff)
				}
			})
		})
	}
}

func initTestDB(t *testing.T, config *config.Database) *database.Database {
	t.Helper()
	db, err := migrations.New().
		WithConfig(config).
		WithMigrate(true).
		Run(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	return db
}

type testServer struct {
	t      *testing.T
	srv    *Server
	router *http.ServeMux
	s      *httptest.Server
}

func initTestServer(t *testing.T, db *database.Database) *testServer {
	var ts testServer
	ts.t = t
	ts.router = http.NewServeMux()
	ts.srv = New().WithDatabase(db).WithRouter(ts.router)
	ts.srv.Init()
	ts.s = httptest.NewServer(ts.router)
	return &ts
}

func (ts *testServer) Close() {
	ts.s.Close()
}

func (ts *testServer) Request(method, path string, body string, apikey string) *testResponse {
	var buf io.Reader
	if body != "" {
		buf = bytes.NewBufferString(body)
	}
	req := httptest.NewRequest(method, ts.s.URL+path, buf)
	if apikey != "" {
		req.Header.Add("authorization", "Bearer "+apikey)
	}
	w := httptest.NewRecorder()
	ts.router.ServeHTTP(w, req)
	return &testResponse{ts: ts, w: w}
}

type testResponse struct {
	ts *testServer
	w  *httptest.ResponseRecorder
}

func (tr *testResponse) Body() *bytes.Buffer {
	return tr.w.Body
}

func (tr *testResponse) BodyDecoded() any {
	var v any
	if err := newJSONDecoder(tr.w.Body).Decode(&v); err != nil {
		panic(err)
	}
	return v
}

func (tr *testResponse) ExpectStatus(code int) *testResponse {
	tr.ts.t.Helper()
	if tr.w.Code != code {
		tr.ts.t.Log("body:", tr.w.Body.String())
		tr.ts.t.Fatalf("expected status %v but got %v", code, tr.w.Code)
	}
	return tr
}

func (tr *testResponse) ExpectBody(x any) *testResponse {

	tr.ts.t.Helper()
	if err := newJSONDecoder(tr.w.Body).Decode(x); err != nil {
		tr.ts.t.Log("body:", tr.w.Body.String())
		tr.ts.t.Fatal(err)
	}
	return tr
}
