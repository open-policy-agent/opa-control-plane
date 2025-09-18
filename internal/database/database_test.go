package database_test

import (
	"context"
	"reflect"
	"testing"

	"github.com/styrainc/opa-control-plane/internal/config"
	"github.com/styrainc/opa-control-plane/internal/database"
	"github.com/styrainc/opa-control-plane/internal/service"
	"github.com/styrainc/opa-control-plane/internal/test/dbs"
	"github.com/testcontainers/testcontainers-go"
)

func TestDatabase(t *testing.T) {

	ctx := t.Context()

	for databaseType, databaseConfig := range dbs.Configs(t) {
		t.Run(databaseType, func(t *testing.T) {
			t.Parallel()
			var ctr testcontainers.Container
			if databaseConfig.Setup != nil {
				ctr = databaseConfig.Setup(t)
				t.Cleanup(databaseConfig.Cleanup(t, ctr))
			}

			db := service.New().WithConfig(databaseConfig.Database(t, ctr)).Database()
			err := db.InitDB(ctx)
			if err != nil {
				t.Fatalf("expected no error, got %v", err)
			}

			defer db.CloseDB()

			if err := db.UpsertPrincipal(ctx, database.Principal{Id: "admin", Role: "administrator"}); err != nil {
				t.Fatal(err)
			}

			data1 := map[string]any{"key": "value1"}
			data2 := map[string]any{"key": "value2"}

			root := config.Root{
				Bundles: map[string]*config.Bundle{
					"system1": {
						Name: "system1",
						Labels: config.Labels{
							"env": "test1",
						},
						ObjectStorage: config.ObjectStorage{
							FileSystemStorage: &config.FileSystemStorage{
								Path: "/path/to/bundle",
							},
						},
						Requirements: config.Requirements{
							config.Requirement{Source: newString("system1")},
						},
						ExcludedFiles: config.StringSet{"excluded-file1.txt", "excluded-file2.txt"},
					},

					"system2": {
						Name: "system2",
						Labels: config.Labels{
							"env": "test2",
						},
						ObjectStorage: config.ObjectStorage{
							AmazonS3: &config.AmazonS3{
								Region:      "us-west-2",
								Key:         "/path/bundle.tgz",
								Bucket:      "my-bucket",
								Credentials: &config.SecretRef{Name: "secret1"},
							},
						},
						Requirements: config.Requirements{
							config.Requirement{Source: newString("system2")},
						},
					},
					"system3": {
						Name: "system3",
						Labels: config.Labels{
							"env": "test3",
						},
						ObjectStorage: config.ObjectStorage{
							FileSystemStorage: &config.FileSystemStorage{
								Path: "/path/to/bundle",
							},
						},
						Requirements: config.Requirements{
							config.Requirement{Source: newString("system3")},
						},
					},
					"system4": {
						Name: "system4",
						Labels: config.Labels{
							"env": "test4",
						},
						ObjectStorage: config.ObjectStorage{
							GCPCloudStorage: &config.GCPCloudStorage{
								Project:     "gcp-project",
								Bucket:      "gcp-bucket",
								Object:      "path/to/bundle.tgz",
								Credentials: &config.SecretRef{Name: "secret1"},
							},
						},
						Requirements: config.Requirements{
							config.Requirement{Source: newString("system3")},
						},
					},
					"system5": {
						Name: "system5",
						Labels: config.Labels{
							"env": "test5",
						},
						ObjectStorage: config.ObjectStorage{
							AzureBlobStorage: &config.AzureBlobStorage{
								AccountURL:  "https://myaccount.blob.core.windows.net",
								Container:   "azure-container",
								Path:        "path/to/bundle.tgz",
								Credentials: &config.SecretRef{Name: "secret1"},
							},
						},
						Requirements: config.Requirements{
							config.Requirement{Source: newString("system3")},
						},
					},
				},
				Stacks: map[string]*config.Stack{
					"stack1": {
						Name: "stack1",
						Selector: config.MustNewSelector(map[string]config.StringSet{
							"env": {"test1"},
						}),
						Requirements: config.Requirements{
							config.Requirement{Source: newString("system1")},
							config.Requirement{Source: newString("system2")},
						},
					},
				},
				Sources: map[string]*config.Source{
					"system1": {
						Name:         "system1",
						Requirements: config.Requirements{},
					},
					"system2": {
						Name:         "system2",
						Requirements: config.Requirements{},
					},
					"system3": {
						Name:         "system3",
						Requirements: config.Requirements{},
					},
					"system4": {
						Name: "system4",
						Requirements: config.Requirements{
							config.Requirement{Source: newString("system5")},
						},
					},
					"system5": {
						Name:         "system5",
						Requirements: config.Requirements{},
					},
				},
				Secrets: map[string]*config.Secret{
					"secret1": {
						Name: "secret1",
						Value: map[string]any{
							"type":     "password",
							"password": "value",
						},
					},
				},
				Database: &config.Database{
					SQL: &config.SQLDatabase{
						Driver: "sqlite3",
						DSN:    database.SQLiteMemoryOnlyDSN,
					},
				},
			}
			if err := root.Unmarshal(); err != nil {
				t.Fatalf("failed to unmarshal config: %v", err)
			}

			tests := []*testCase{
				// bootstrap operations:
				newTestCase("load config").LoadConfig(root),

				// source operations:
				newTestCase("list sources").ListSources([]*config.Source{root.Sources["system1"], root.Sources["system2"], root.Sources["system3"], root.Sources["system5"], root.Sources["system4"]}),
				newTestCase("get source system1").GetSource("system1", root.Sources["system1"]),

				// stack operations:
				newTestCase("list stacks").ListStacks([]*config.Stack{root.Stacks["stack1"]}),
				newTestCase("get stack stack1").GetStack("stack1", root.Stacks["stack1"]),

				// source data operations:
				newTestCase("source/get non-existing  data").SourcesGetData("system1", "foo", nil),
				newTestCase("source/put source data").SourcesPutData("system1", "foo", data1).SourcesGetData("system1", "foo", data1),
				newTestCase("source/update data foo").SourcesPutData("system1", "foo", data2).SourcesGetData("system1", "foo", data2),
				newTestCase("source/update data bar").SourcesPutData("system1", "bar", data1).SourcesGetData("system1", "bar", data1),
				newTestCase("source/query data").SourcesQueryData("system1", map[string][]byte{
					"bar": []byte(`{"key":"value1"}`),
					"foo": []byte(`{"key":"value2"}`),
				}),
				newTestCase("source/delete data").SourcesDeleteData("system1", "foo").SourcesGetData("system1", "foo", nil),
				newTestCase("source/put requirements").SourcesPutRequirements("system1", config.Requirements{
					config.Requirement{Source: newString("system2")},
					config.Requirement{Source: newString("system3")},
				}).GetSource("system1", &config.Source{
					Name: "system1",
					Requirements: config.Requirements{
						config.Requirement{Source: newString("system2")},
						config.Requirement{Source: newString("system3")},
					},
				}),
				newTestCase("source/put requirements overrides").SourcesPutRequirements("system1", config.Requirements{
					config.Requirement{Source: newString("system3")},
					config.Requirement{Source: newString("system4")},
				}).GetSource("system1", &config.Source{
					Name: "system1",
					Requirements: config.Requirements{
						config.Requirement{Source: newString("system3")},
						config.Requirement{Source: newString("system4")},
					},
				}),
				newTestCase("source/put nil requirements").SourcesPutRequirements("system1", nil).GetSource("system1", &config.Source{
					Name: "system1",
					Requirements: config.Requirements{
						config.Requirement{Source: newString("system3")},
						config.Requirement{Source: newString("system4")},
					},
				}),
				newTestCase("source/put delete requirements").SourcesPutRequirements("system1", config.Requirements{}).GetSource("system1", &config.Source{
					Name:         "system1",
					Requirements: config.Requirements{},
				}),

				// bundle operations:
				newTestCase("list bundles").ListBundles([]*config.Bundle{
					root.Bundles["system1"], root.Bundles["system2"], root.Bundles["system3"],
					root.Bundles["system4"], root.Bundles["system5"],
				}),
				newTestCase("get bundle system1").GetBundle("system1", root.Bundles["system1"]),
				newTestCase("put bundle requirements").BundlesPutRequirements("system6", config.Requirements{
					config.Requirement{Source: newString("system1")},
					config.Requirement{Source: newString("system2")},
				}).GetBundle("system6", &config.Bundle{
					Name: "system6",
					Requirements: config.Requirements{
						config.Requirement{Source: newString("system1")},
						config.Requirement{Source: newString("system2")},
					},
				}),
				newTestCase("put bundle requirements overrides").BundlesPutRequirements("system6", config.Requirements{
					config.Requirement{Source: newString("system1")},
					config.Requirement{Source: newString("system3")},
				}).GetBundle("system6", &config.Bundle{
					Name: "system6",
					Requirements: config.Requirements{
						config.Requirement{Source: newString("system1")},
						config.Requirement{Source: newString("system3")},
					},
				}),
				newTestCase("put bundle ignores nil requirements").BundlesPutRequirements("system6", nil).GetBundle("system6", &config.Bundle{
					Name: "system6",
					Requirements: config.Requirements{
						config.Requirement{Source: newString("system1")},
						config.Requirement{Source: newString("system3")},
					},
				}),
				newTestCase("put bundle deletes requirements").BundlesPutRequirements("system6", config.Requirements{}).GetBundle("system6", &config.Bundle{
					Name:         "system6",
					Requirements: config.Requirements{},
				}),
			}

			for _, test := range tests {
				t.Run(test.note, func(t *testing.T) {
					for _, op := range test.operations {
						op(ctx, t, db)
					}
				})
			}
		})
	}
}

type testCase struct {
	note       string
	operations []func(ctx context.Context, t *testing.T, db *database.Database)
}

func newTestCase(note string) *testCase {
	return &testCase{
		note:       note,
		operations: nil,
	}
}

func (tc *testCase) SourcesGetData(srcID, dataID string, expected any) *testCase {
	tc.operations = append(tc.operations, func(ctx context.Context, t *testing.T, db *database.Database) {
		data, found, err := db.SourcesDataGet(ctx, srcID, dataID, "admin")
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}

		switch {
		case found && expected == nil:
			t.Fatal("expected no data to be found")
		case !found && expected != nil:
			t.Fatal("expected data to be found")
		case !found && expected == nil:
			// OK
		case found && expected != nil:
			if !reflect.DeepEqual(expected, data) {
				t.Fatalf("expected data not found, got %v", data)
			}
		}
	})
	return tc
}

func (tc *testCase) SourcesQueryData(srcID string, expected map[string][]byte) *testCase {
	tc.operations = append(tc.operations, func(ctx context.Context, t *testing.T, db *database.Database) {
		cursor, err := db.QuerySourceData(ctx, srcID)
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}

		data := make(map[string][]byte)

		for cursor.Next() {
			value, err := cursor.Value()
			if err != nil {
				t.Fatalf("expected no error, got %v", err)
			}
			data[value.Path] = value.Data
		}

		if !reflect.DeepEqual(expected, data) {
			t.Fatalf("expected data not found, got %v", data)
		}
	})
	return tc
}

func (tc *testCase) SourcesPutData(srcID, dataID string, data any) *testCase {
	tc.operations = append(tc.operations, func(ctx context.Context, t *testing.T, db *database.Database) {
		if err := db.SourcesDataPut(ctx, srcID, dataID, data, "admin"); err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
	})
	return tc
}

func (tc *testCase) SourcesDeleteData(srcID, dataID string) *testCase {
	tc.operations = append(tc.operations, func(ctx context.Context, t *testing.T, db *database.Database) {
		if err := db.SourcesDataDelete(ctx, srcID, dataID, "admin"); err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
	})
	return tc
}

func (tc *testCase) SourcesPutRequirements(id string, requirements config.Requirements) *testCase {
	tc.operations = append(tc.operations, func(ctx context.Context, t *testing.T, db *database.Database) {
		if err := db.UpsertSource(ctx, "admin", &config.Source{
			Name:         id,
			Requirements: requirements,
		}); err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
	})
	return tc
}

func (tc *testCase) LoadConfig(root config.Root) *testCase {
	tc.operations = append(tc.operations, func(ctx context.Context, t *testing.T, db *database.Database) {
		if err := db.LoadConfig(ctx, nil, "admin", &root); err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
	})
	return tc
}

func (tc *testCase) ListBundles(expected []*config.Bundle) *testCase {
	tc.operations = append(tc.operations, func(ctx context.Context, t *testing.T, db *database.Database) {
		cursor := ""
		var listed []*config.Bundle

		for {
			var bundles []*config.Bundle
			var err error
			limit := 2
			bundles, cursor, err = db.ListBundles(ctx, "admin", database.ListOptions{Limit: limit, Cursor: cursor})
			if err != nil {
				t.Fatalf("expected no error, got %v", err)
			}

			listed = append(listed, bundles...)

			if len(bundles) < limit {
				break

			}
		}

		if len(expected) != len(listed) {
			t.Fatalf("expected %d bundles but got %d", len(expected), len(listed))
		}

		for i := range expected {
			if !listed[i].Equal(expected[i]) {
				t.Fatalf("expected bundle %q to be equal.", expected[i].Name)
			}
		}

	})

	return tc
}

func (tc *testCase) BundlesPutRequirements(id string, requirements config.Requirements) *testCase {
	tc.operations = append(tc.operations, func(ctx context.Context, t *testing.T, db *database.Database) {
		if err := db.UpsertBundle(ctx, "admin", &config.Bundle{
			Name:         id,
			Requirements: requirements,
		}); err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
	})
	return tc
}

func (tc *testCase) GetBundle(id string, expected *config.Bundle) *testCase {
	tc.operations = append(tc.operations, func(ctx context.Context, t *testing.T, db *database.Database) {
		bundle, err := db.GetBundle(ctx, "admin", id)
		if err != nil && err != database.ErrNotFound {
			t.Fatalf("expected no error, got %v", err)
		}

		switch {
		case bundle != nil && expected == nil:
			t.Fatal("expected no bundle to be found")
		case bundle == nil && expected != nil:
			t.Fatal("expected bundle to be found")
		case bundle == nil && expected == nil:
			// OK
		case bundle != nil && expected != nil:
			if !bundle.Equal(expected) {
				t.Fatalf("expected bundle not found, got %v", bundle)
			}
		}
	})

	return tc
}

func (tc *testCase) ListSources(expected []*config.Source) *testCase {
	tc.operations = append(tc.operations, func(ctx context.Context, t *testing.T, db *database.Database) {
		cursor := ""
		var listed []*config.Source

		for {
			var sources []*config.Source
			var err error
			limit := 2
			sources, cursor, err = db.ListSources(ctx, "admin", database.ListOptions{Limit: limit, Cursor: cursor})
			if err != nil {
				t.Fatalf("expected no error, got %v", err)
			}

			listed = append(listed, sources...)

			if len(sources) < limit {
				break

			}
		}

		if len(expected) != len(listed) {
			t.Fatalf("expected %d sources but got %d", len(expected), len(listed))
		}

		for i := range expected {
			if !listed[i].Equal(expected[i]) {
				t.Fatalf("expected source %q to be equal.", expected[i].Name)
			}
		}

	})

	return tc
}

func (tc *testCase) GetSource(id string, expected *config.Source) *testCase {
	tc.operations = append(tc.operations, func(ctx context.Context, t *testing.T, db *database.Database) {
		source, err := db.GetSource(ctx, "admin", id)
		if err != nil && err != database.ErrNotFound {
			t.Fatalf("expected no error, got %v", err)
		}

		switch {
		case source != nil && expected == nil:
			t.Fatal("expected no source to be found")
		case source == nil && expected != nil:
			t.Fatal("expected source to be found")
		case source == nil && expected == nil:
			// OK
		case source != nil && expected != nil:
			if !source.Equal(expected) {
				t.Fatalf("expected source not found, got %v", source)
			}
		}
	})

	return tc
}

func (tc *testCase) ListStacks(expected []*config.Stack) *testCase {
	tc.operations = append(tc.operations, func(ctx context.Context, t *testing.T, db *database.Database) {
		cursor := ""
		var listed []*config.Stack

		for {
			var stacks []*config.Stack
			var err error
			limit := 2
			stacks, cursor, err = db.ListStacks(ctx, "admin", database.ListOptions{Limit: limit, Cursor: cursor})
			if err != nil {
				t.Fatalf("expected no error, got %v", err)
			}

			listed = append(listed, stacks...)

			if len(stacks) < limit {
				break

			}
		}

		if len(expected) != len(listed) {
			t.Fatalf("expected %d stacks but got %d", len(expected), len(listed))
		}

		for i := range expected {
			if !listed[i].Equal(expected[i]) {
				t.Fatalf("expected stack %q to be equal.", expected[i].Name)
			}
		}

	})

	return tc
}

func (tc *testCase) GetStack(id string, expected *config.Stack) *testCase {
	tc.operations = append(tc.operations, func(ctx context.Context, t *testing.T, db *database.Database) {
		stack, err := db.GetStack(ctx, "admin", id)
		if err != nil && err != database.ErrNotFound {
			t.Fatalf("expected no error, got %v", err)
		}

		switch {
		case stack != nil && expected == nil:
			t.Fatal("expected no stack to be found")
		case stack == nil && expected != nil:
			t.Fatal("expected stack to be found")
		case stack == nil && expected == nil:
			// OK
		case stack != nil && expected != nil:
			if !stack.Equal(expected) {
				t.Fatalf("expected stack not found, got %v", stack)
			}
		}
	})

	return tc
}

func newString(s string) *string {
	return &s
}
