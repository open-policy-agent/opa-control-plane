package server

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/gorilla/mux"
	"github.com/testcontainers/testcontainers-go"

	"github.com/styrainc/opa-control-plane/internal/config"
	"github.com/styrainc/opa-control-plane/internal/database"
	"github.com/styrainc/opa-control-plane/internal/server/types"
	"github.com/styrainc/opa-control-plane/internal/test/dbs"
)

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

			db := (&database.Database{}).WithConfig(databaseConfig.Database(t, ctr).Database)
			db = initTestDB(t, db)
			ts := initTestServer(t, db)
			defer ts.Close()

			if err := db.UpsertPrincipal(ctx, database.Principal{Id: "internaladmin", Role: "administrator"}); err != nil {
				t.Fatal(err)
			}

			const adminKey = "test-admin-apikey"

			if err := db.UpsertToken(ctx, "internaladmin", &config.Token{Name: "admin", APIKey: adminKey, Scopes: []config.Scope{{Role: "administrator"}}}); err != nil {
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

			db := (&database.Database{}).WithConfig(databaseConfig.Database(t, ctr).Database)
			db = initTestDB(t, db)
			ts := initTestServer(t, db)
			defer ts.Close()

			if err := db.UpsertPrincipal(ctx, database.Principal{Id: "internal", Role: "administrator"}); err != nil {
				t.Fatal(err)
			}

			const ownerKey = "test-owner-key"
			const ownerKey2 = "test-owner-key2"

			if err := db.UpsertToken(ctx, "internal", &config.Token{Name: "testowner", APIKey: ownerKey, Scopes: []config.Scope{{Role: "owner"}}}); err != nil {
				t.Fatal(err)
			}

			if err := db.UpsertToken(ctx, "internal", &config.Token{Name: "testowner2", APIKey: ownerKey2, Scopes: []config.Scope{{Role: "owner"}}}); err != nil {
				t.Fatal(err)
			}

			ts.Request("PUT", "/v1/bundles/testbundle", `{
		"object_storage": {
			"aws": {
				"region": "us-east-1",
				"bucket": "test-bucket",
				"key": "test-key"
			}
		}
	}`, ownerKey).ExpectStatus(200)

			exp := &config.Bundle{
				Name: "testbundle",
				ObjectStorage: config.ObjectStorage{
					AmazonS3: &config.AmazonS3{
						Region: "us-east-1",
						Bucket: "test-bucket",
						Key:    "test-key",
					},
				},
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

			ts.Request("PUT", "/v1/bundles/testbundle", "{}", ownerKey2).ExpectStatus(403)
			ts.Request("GET", "/v1/bundles/testbundle", "", ownerKey2).ExpectStatus(404)
			ts.Request("PUT", "/v1/bundles/testbundle", "{}", ownerKey).ExpectStatus(200)
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

			db := (&database.Database{}).WithConfig(databaseConfig.Database(t, ctr).Database)
			db = initTestDB(t, db)

			ts := initTestServer(t, db)
			defer ts.Close()

			if err := db.UpsertPrincipal(ctx, database.Principal{Id: "internal", Role: "administrator"}); err != nil {
				t.Fatal(err)
			}

			const ownerKey = "test-owner-key"
			const ownerKey2 = "test-owner-key2"

			if err := db.UpsertToken(ctx, "internal", &config.Token{Name: "testowner", APIKey: ownerKey, Scopes: []config.Scope{{Role: "owner"}}}); err != nil {
				t.Fatal(err)
			}

			if err := db.UpsertToken(ctx, "internal", &config.Token{Name: "testowner2", APIKey: ownerKey2, Scopes: []config.Scope{{Role: "owner"}}}); err != nil {
				t.Fatal(err)
			}

			ts.Request("PUT", "/v1/sources/testsrc", `{"datasources": [{"name": "ds"}]}`, ownerKey).ExpectStatus(200)

			{
				var ownerList types.SourcesListResponseV1
				ts.Request("GET", "/v1/sources", "", ownerKey).ExpectStatus(200).ExpectBody(&ownerList)
				if len(ownerList.Result) != 1 {
					t.Fatal("expected exactly one source")
				}
				exp := &config.Source{
					Name: "testsrc",
					Datasources: []config.Datasource{
						{Name: "ds"},
					},
				}
				if !ownerList.Result[0].Equal(exp) {
					t.Fatalf("unexpected response, expected %v, got %v", exp, ownerList.Result[0])
				}
			}

			{
				var src types.SourcesGetResponseV1
				ts.Request("GET", "/v1/sources/testsrc", "", ownerKey).ExpectStatus(200).ExpectBody(&src)
				exp := &config.Source{
					Name: "testsrc",
					Datasources: []config.Datasource{
						{Name: "ds"},
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

			ts.Request("PUT", "/v1/sources/testsrc", "{}", ownerKey2).ExpectStatus(403)
			ts.Request("GET", "/v1/sources/testsrc", "", ownerKey2).ExpectStatus(404)
			ts.Request("PUT", "/v1/sources/testsrc", "{}", ownerKey).ExpectStatus(200)
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

			db := (&database.Database{}).WithConfig(databaseConfig.Database(t, ctr).Database)
			db = initTestDB(t, db)
			ts := initTestServer(t, db)
			defer ts.Close()

			if err := db.UpsertPrincipal(ctx, database.Principal{Id: "internal", Role: "administrator"}); err != nil {
				t.Fatal(err)
			}

			const ownerKey = "test-stack-owner-key"
			const ownerKey2 = "test-stack-owner-key2"

			if err := db.UpsertToken(ctx, "internal", &config.Token{Name: "teststackowner", APIKey: ownerKey, Scopes: []config.Scope{{Role: "stack_owner"}}}); err != nil {
				t.Fatal(err)
			}

			if err := db.UpsertToken(ctx, "internal", &config.Token{Name: "teststackowner2", APIKey: ownerKey2, Scopes: []config.Scope{{Role: "stack_owner"}}}); err != nil {
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
			ts.Request("PUT", "/v1/stacks/teststack", `{}`, ownerKey2).ExpectStatus(403)
			ts.Request("GET", "/v1/stacks/teststack", "", ownerKey2).ExpectStatus(404)
			ts.Request("PUT", "/v1/stacks/teststack", `{}`, ownerKey).ExpectStatus(200)
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

			db := (&database.Database{}).WithConfig(databaseConfig.Database(t, ctr).Database)
			db = initTestDB(t, db)

			ts := initTestServer(t, db)
			defer ts.Close()

			if err := db.UpsertPrincipal(ctx, database.Principal{Id: "internal", Role: "administrator"}); err != nil {
				t.Fatal(err)
			}

			const ownerKey = "test-owner-key"

			if err := db.UpsertToken(ctx, "internal", &config.Token{Name: "testowner", APIKey: ownerKey, Scopes: []config.Scope{{Role: "owner"}}}); err != nil {
				t.Fatal(err)
			}

			const ownerKey2 = "test-owner-key2"

			if err := db.UpsertToken(ctx, "internal", &config.Token{Name: "testowner2", APIKey: ownerKey2, Scopes: []config.Scope{{Role: "owner"}}}); err != nil {
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

func initTestDB(t *testing.T, db *database.Database) *database.Database {
	t.Helper()
	if db == nil {
		db = &database.Database{}
	}
	if err := db.InitDB(t.Context()); err != nil {
		t.Fatal(err)
	}
	return db
}

type testServer struct {
	t      *testing.T
	srv    *Server
	router *mux.Router
	s      *httptest.Server
}

func initTestServer(t *testing.T, db *database.Database) *testServer {
	var ts testServer
	ts.t = t
	ts.router = mux.NewRouter()
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
