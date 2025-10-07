//go:build migration_e2e

package e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"io/ioutil"
	"log"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"testing"
	"text/template"
	"time"

	"github.com/johannesboyne/gofakes3"
	"github.com/johannesboyne/gofakes3/backend/s3mem"
	"github.com/open-policy-agent/opa-control-plane/cmd/backtest"
	"github.com/open-policy-agent/opa-control-plane/cmd/migrate"
	"github.com/open-policy-agent/opa-control-plane/internal/config"
	"github.com/open-policy-agent/opa-control-plane/internal/logging"
	"github.com/open-policy-agent/opa-control-plane/internal/s3"
	"github.com/open-policy-agent/opa-control-plane/internal/service"
	"github.com/open-policy-agent/opa-control-plane/internal/test/tempfs"
	"github.com/open-policy-agent/opa-control-plane/internal/util"
	"github.com/open-policy-agent/opa-control-plane/libraries"
	"github.com/open-policy-agent/opa/bundle"
	"github.com/open-policy-agent/opa/rego"
	"golang.org/x/sync/errgroup"
)

func TestMigration(t *testing.T) {

	// Set mock AWS credentials to avoid IMDS errors.
	os.Setenv("AWS_ACCESS_KEY_ID", "mock-access-key")
	os.Setenv("AWS_SECRET_ACCESS_KEY", "mock-secret-key")
	os.Setenv("AWS_REGION", "us-east-1")

	cases := []struct {
		name              string
		styraURL          string
		systemId          string
		limitStacks       bool
		styraTokenEnvName string // default STYRA_TOKEN
		bundleName        string
		extraConfigs      map[string]string
		policyType        string   // used to filter decisions for backtest
		datasources       bool     // indicates whether to include datasource content in migration
		skipBacktest      bool     // indicates backtest should be skipped
		queries           []string // queries to execute after migrating and building
		inputs            []string // inputs to provide to test queries
		decisions         []string // decisions to expect from test queries
	}{
		{
			name:       "envoy21",
			styraURL:   "https://expo.styra.com",
			systemId:   "f89b1de32c4a4252ac19db97c007f8d4",
			bundleName: "envoy_app",
			extraConfigs: map[string]string{
				"config.d/1-secrets.yaml": `{
					secrets: {
						libraries_envoy_git: {
							type: basic_auth,
							password: $GITHUB_PASSWORD,
							username: $GITHUB_USERNAME,
						},
					},
				}`,
				"config.d/2-storage.yaml": `{
					bundles: {
						envoy_app: {
							object_storage: {
								aws: {
									url: {{ .URL }},
									bucket: test,
									region: mock-region,
									key: bundle.tar.gz,
								},
							},
						},
					},
				}`,
			},
		},
		{
			name:              "envoy1",
			styraURL:          "https://kurt.styra.com",
			systemId:          "cbbf33aeb9ce44349bc3faad43060ae0",
			bundleName:        "envoy-v1-e2e-test",
			styraTokenEnvName: "STYRA_TOKEN_3",
			skipBacktest:      true,
			queries: []string{
				`data.policy["com.styra.envoy"].resolver.main`,
				`data.policy["com.styra.envoy"].resolver.main`,
			},
			inputs: []string{
				readFileString("testdata/migrate_e2e/envoy1-allow.json"),
				readFileString("testdata/migrate_e2e/envoy1-deny.json"),
			},
			decisions: []string{
				readFileString("testdata/migrate_e2e/envoy1-allow-decision.json"),
				readFileString("testdata/migrate_e2e/envoy1-deny-decision.json"),
			},
			extraConfigs: map[string]string{
				"config.d/2-storage.yaml": `{
					bundles: {
						envoy-v1-e2e-test: {
							object_storage: {
								aws: {
									url: {{ .URL }},
									bucket: test,
									region: mock-region,
									key: bundle.tar.gz,
								},
							},
						},
					},
				}`,
			},
		},
		{
			name:              "kubernetes1",
			styraURL:          "https://test.styra.com",
			systemId:          "ace44151df234247ab59e9177d02c9cc",
			styraTokenEnvName: "STYRA_TOKEN_2",
			bundleName:        "torin-k8s-v1-test",
			skipBacktest:      true,
			queries:           []string{"data.main.main", "data.main.main"},
			inputs: []string{
				readFileString("testdata/migrate_e2e/kubernetes1-allow.json"),
				readFileString("testdata/migrate_e2e/kubernetes1-deny.json"),
			},
			decisions: []string{
				readFileString("testdata/migrate_e2e/kubernetes1-allow-decision.json"),
				readFileString("testdata/migrate_e2e/kubernetes1-deny-decision.json"),
			},
			extraConfigs: map[string]string{
				"config.d/2-storage.yaml": `{
					bundles: {
						torin-k8s-v1-test: {
							object_storage: {
								aws: {
									url: {{ .URL }},
									bucket: test,
									region: mock-region,
									key: bundle.tar.gz,
								},
							},
						},
					},
				}`,
			},
		},
		{
			name:       "kubernetes2-validating",
			styraURL:   "https://expo.styra.com",
			systemId:   "b470325746e3417e86301b564113b29b",
			bundleName: "banteng_cluster",
			extraConfigs: map[string]string{
				"config.d/1-secrets.yaml": `{
					secrets: {
						libraries_test_git: {
							type: basic_auth,
							password: $GITHUB_PASSWORD,
							username: $GITHUB_USERNAME,
						},
					},
				}`,
				"config.d/2-storage.yaml": `{
					bundles: {
						banteng_cluster: {
							object_storage: {
								aws: {
									url: {{ .URL }},
									bucket: test,
									region: mock-region,
									key: bundle.tar.gz,
								},
							},
						},
					},
				}`,
			},
			policyType: "validating",
		},
		{
			name:       "kubernetes2-mutating",
			styraURL:   "https://expo.styra.com",
			systemId:   "b470325746e3417e86301b564113b29b",
			bundleName: "banteng_cluster",
			extraConfigs: map[string]string{
				"config.d/1-secrets.yaml": `{
					secrets: {
						libraries_test_git: {
							type: basic_auth,
							password: $GITHUB_PASSWORD,
							username: $GITHUB_USERNAME,
						},
					},
				}`,
				"config.d/2-storage.yaml": `{
					bundles: {
						banteng_cluster: {
							object_storage: {
								aws: {
									url: {{ .URL }},
									bucket: test,
									region: mock-region,
									key: bundle.tar.gz,
								},
							},
						},
					},
				}`,
			},
			policyType: "mutating",
		},
		{
			name:       "custom system with push datasource",
			styraURL:   "https://expo.styra.com",
			systemId:   "a8318943a5814712a69adcb2d9f76976",
			bundleName: "custom_app",
			extraConfigs: map[string]string{
				"config.d/1-secrets.yaml": `{
					secrets: {
						libraries_custom_snippets_git: {
							type: basic_auth,
							password: $GITHUB_PASSWORD,
							username: $GITHUB_USERNAME,
						},
						systems_a8318943a5814712a69adcb2d9f76976_git: {
							type: basic_auth,
							password: $GITHUB_PASSWORD,
							username: $GITHUB_USERNAME,
						},
					},
				}`,
				"config.d/2-storage.yaml": `{
					bundles: {
						custom_app: {
							object_storage: {
								aws: {
									url: {{ .URL }},
									bucket: test,
									region: mock-region,
									key: bundle.tar.gz,
								},
							},
						},
					},
				}`,
			},
			datasources: true,
		},
		{
			name:       "istio10",
			styraURL:   "https://expo.styra.com",
			systemId:   "a3dd4c8155ae43a794b6e5b7a53cdd60",
			bundleName: "istio_app",
			extraConfigs: map[string]string{
				"config.d/2-storage.yaml": `{
					bundles: {
						istio_app: {
							object_storage: {
								aws: {
									url: {{ .URL }},
									bucket: test,
									region: mock-region,
									key: bundle.tar.gz,
								},
							},
						},
					},
				}`,
			},
		},
		{
			name:       "kuma10",
			styraURL:   "https://expo.styra.com",
			systemId:   "d1c66f8ca33749b9b27b2d2ac1151bc1",
			bundleName: "kuma",
			extraConfigs: map[string]string{
				"config.d/2-storage.yaml": `{
					bundles: {
						kuma: {
							object_storage: {
								aws: {
									url: {{ .URL }},
									bucket: test,
									region: mock-region,
									key: bundle.tar.gz,
								},
							},
						},
					},
				}`,
			},
		},
		{
			// NOTE(tsandall): policies depend on two datasources however system
			// does not have any decisions that exercise that part of the
			// policy, so we are not enabling datasource content migration here.
			name:       "kong-gateway10",
			styraURL:   "https://expo.styra.com",
			systemId:   "ef6321e7461a4035b8638f73951fa0c4",
			bundleName: "kong_gateway_-_prod",
			extraConfigs: map[string]string{
				"config.d/2-storage.yaml": `{
					bundles: {
						kong_gateway_-_prod: {
							object_storage: {
								aws: {
									url: {{ .URL }},
									bucket: test,
									region: mock-region,
									key: bundle.tar.gz,
								},
							},
						},
					},
				}`,
			},
		},
		{
			name:       "terraform20",
			styraURL:   "https://expo.styra.com",
			systemId:   "c600dddb333c48b7b67616564e7b8726",
			bundleName: "terraform_-_gcp",
			extraConfigs: map[string]string{
				"config.d/2-storage.yaml": `{
					bundles: {
						terraform_-_gcp: {
							object_storage: {
								aws: {
									url: {{ .URL }},
									bucket: test,
									region: mock-region,
									key: bundle.tar.gz,
								},
							},
						},
					},
				}`,
			},
			datasources: true,
		},
		{
			name:              "http pull datasources",
			styraURL:          "https://test.styra.com",
			styraTokenEnvName: "STYRA_TOKEN_2",
			systemId:          "c765ce3ea0e14751b88e3530f9d3c8ac",
			bundleName:        "torin-pull-test-2",
			skipBacktest:      true,
			queries:           []string{`data.main.main.allowed`, `data.main.main.allowed`},
			inputs:            []string{`{"foo": "bar"}`, `{"foo": "baz"}`},
			decisions:         []string{"false", "true"},
			extraConfigs: map[string]string{
				"config.d/2-storage.yaml": `{
					bundles: {
						"torin-pull-test-2": {
							object_storage: {
								aws: {
									url: {{ .URL }},
									bucket: test,
									region: mock-region,
									key: bundle.tar.gz,
								},
							},
						},
					},
				}`,
			},
		},
		{
			name:              "library without rego",
			styraURL:          "https://test.styra.com",
			styraTokenEnvName: "STYRA_TOKEN_2",
			systemId:          "d11309cff921437cab7a25ed87c927cb",
			bundleName:        "e2e-system-with-data-lib-dep",
			skipBacktest:      true,
			datasources:       true,
			queries:           []string{`data.rules.main`},
			inputs:            []string{`{"foo": "bar"}`},
			decisions:         []string{"true"},
			extraConfigs: map[string]string{
				"config.d/2-storage.yaml": `{
					bundles: {
						"e2e-system-with-data-lib-dep": {
							object_storage: {
								aws: {
									url: {{ .URL }},
									bucket: test,
									region: mock-region,
									key: bundle.tar.gz,
								},
							},
						},
					},
				}`,
			},
		},
		{
			name:              "v1-policies with subpackages",
			styraURL:          "https://expo.styra.com",
			styraTokenEnvName: "STYRA_TOKEN",
			systemId:          "a7f6d187ada24f628a417bed3a90a99f",
			bundleName:        "policy_builder",
			extraConfigs: map[string]string{
				"config.d/2-storage.yaml": `{
					bundles: {
						"policy_builder": {
							object_storage: {
								aws: {
									url: {{ .URL }},
									bucket: test,
									region: mock-region,
									key: bundle.tar.gz,
								},
							},
						},
					},
				}`,
			},
		},
		{
			name:              "manual deployment pinning",
			styraURL:          "https://test.styra.com",
			styraTokenEnvName: "STYRA_TOKEN_2",
			systemId:          "d024548afa144aef9539a604ec96fd81",
			bundleName:        "opactl-manual-deploy-e2e-system",
			skipBacktest:      true,
			queries:           []string{`data.main.main.allowed`, `data.main.main.allowed`},
			inputs:            []string{`{"foo": "bar"}`, `{}`},
			decisions:         []string{"true", "false"},
			extraConfigs: map[string]string{
				"config.d/2-storage.yaml": `{
					bundles: {
						"opactl-manual-deploy-e2e-system": {
							object_storage: {
								aws: {
									url: {{ .URL }},
									bucket: test,
									region: mock-region,
									key: bundle.tar.gz,
								},
							},
						},
					},
				}`,
				"config.d/1-secrets.yaml": `{
					secrets: {
						stacks_f7a9564f6b174382816c8373b7f9bcee_git: {
							type: basic_auth,
							password: $GITHUB_PASSWORD,
							username: $GITHUB_USERNAME,
						},
					},
				}`,
			},
		},
		{
			name:              "limit stacks parameter",
			styraURL:          "https://test.styra.com",
			styraTokenEnvName: "STYRA_TOKEN_2",
			systemId:          "d024548afa144aef9539a604ec96fd81",
			limitStacks:       true,
			bundleName:        "opactl-limit-stacks-flag",
			skipBacktest:      true,
			queries:           []string{`data.main.main.allowed`, `data.main.main.allowed`},
			inputs:            []string{`{"foo": "bar"}`, `{}`},
			decisions:         []string{"true", "false"},
			extraConfigs: map[string]string{
				"config.d/2-storage.yaml": `{
					bundles: {
						"opactl-manual-deploy-e2e-system": {
							object_storage: {
								aws: {
									url: {{ .URL }},
									bucket: test,
									region: mock-region,
									key: bundle.tar.gz,
								},
							},
						},
					},
				}`,
				"config.d/1-secrets.yaml": `{
					secrets: {
						stacks_f7a9564f6b174382816c8373b7f9bcee_git: {
							type: basic_auth,
							password: $GITHUB_PASSWORD,
							username: $GITHUB_USERNAME,
						},
					},
				}`,
			},
		},
	}

	type templateParams struct {
		URL string
	}

	for _, tc := range cases {

		t.Run(tc.name, func(t *testing.T) {

			if tc.styraTokenEnvName == "" {
				tc.styraTokenEnvName = "STYRA_TOKEN"
			}

			styraToken := os.Getenv(tc.styraTokenEnvName)
			if styraToken == "" {
				t.Fatalf("%v environment variable is not set", tc.styraTokenEnvName)
			}

			mock, s3TS := testS3Service(t, "test")

			files := make(map[string]string)
			var params templateParams
			params.URL = s3TS.URL

			for name, content := range tc.extraConfigs {
				tmpl, err := template.New(name).Parse(content)
				if err != nil {
					t.Fatal(err)
				}

				buf := bytes.NewBuffer(nil)
				if err := tmpl.Execute(buf, params); err != nil {
					t.Fatal(err)
				}

				files[name] = buf.String()
			}

			tempfs.WithTempFS(t, files, func(t *testing.T, dir string) {

				t.Logf("Root directory: %v", dir)

				if err := os.MkdirAll(filepath.Join(dir, "config.d"), 0755); err != nil {
					t.Fatal(err)
				}

				f, err := os.Create(filepath.Join(dir, "config.d", "0-config.yaml"))
				if err != nil {
					t.Fatal(err)
				}

				err = migrate.Run(migrate.Options{
					URL:            tc.styraURL,
					Token:          styraToken,
					SystemId:       tc.systemId,
					LimitStacks:    tc.limitStacks,
					Prune:          true,
					Datasources:    tc.datasources,
					EmbedFiles:     true,
					Output:         f,
					Noninteractive: true,
				})
				if err != nil {
					t.Fatal(err)
				}

				merged, err := config.Merge([]string{filepath.Join(dir, "config.d")}, true)
				if err != nil {
					t.Fatal(err)
				}

				config, err := config.Parse(bytes.NewBuffer(merged))
				if err != nil {
					log.Fatalf("configuration error: %v", err)
				}

				svc := service.New().
					WithBuiltinFS(util.NewEscapeFS(libraries.FS)).
					WithConfig(config).
					WithPersistenceDir(filepath.Join(dir, "data")).
					WithLogger(logging.NewLogger(logging.Config{Level: logging.LevelDebug}))

				var g errgroup.Group
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()

				stopped := make(chan struct{})
				g.Go(func() error {
					defer close(stopped)
					return svc.Run(ctx)
				})

				func() {
					time.Sleep(time.Millisecond * 100)
					var obj *gofakes3.Object
					var err error
					for obj == nil && (err == nil || gofakes3.HasErrorCode(err, gofakes3.ErrNoSuchKey)) {
						obj, err = mock.GetObject("test", "bundle.tar.gz", nil)
						time.Sleep(time.Millisecond)
					}
					if err != nil {
						t.Fatal(err)
					}
				}()

				buf := bytes.NewBuffer(nil)

				if !tc.skipBacktest {

					maxEvalTimeInflation := 100
					if v := os.Getenv("BACKTEST_MAX_EVAL_TIME_INFLATION"); v != "" {
						n, err := strconv.Atoi(v)
						if err != nil {
							t.Fatal(err)
						}
						maxEvalTimeInflation = n
					}

					if err := backtest.Run(backtest.Options{
						ConfigFile:           []string{filepath.Join(dir, "config.d")},
						URL:                  tc.styraURL,
						Token:                styraToken,
						NumDecisions:         100,
						PolicyType:           tc.policyType,
						MaxEvalTimeInflation: maxEvalTimeInflation,
						Output:               buf,
						Noninteractive:       true,
						Format:               backtest.OutputFormatJSON,
					}); err != nil {
						t.Fatal(err)
					}

					cancel()
					<-stopped

					var r backtest.Report
					if err := json.Unmarshal(buf.Bytes(), &r); err != nil {
						t.Fatal(err)
					}

					if r.Bundles[tc.bundleName].Status != backtest.ReportStatusPassed {
						t.Logf("Dumping output:\n%v", buf.String())
						t.Fatalf("expected %q to be successful", tc.bundleName)
					}
				}

				if len(tc.queries) > 0 {

					s, err := s3.New(ctx, config.Bundles[tc.bundleName].ObjectStorage)
					if err != nil {
						t.Fatal(err)
					}

					r, err := s.Download(ctx)
					if err != nil {
						t.Fatal(err)
					}

					bs, err := ioutil.ReadAll(r)
					if err != nil {
						t.Fatal(err)
					}

					a, err := bundle.NewReader(bytes.NewReader(bs)).Read()
					if err != nil {
						t.Fatal(err)
					}

					for i := range tc.queries {
						input := decodeJSONUseNumber(tc.inputs[i])
						decision := decodeJSONUseNumber(tc.decisions[i])
						rs, err := rego.New(
							rego.ParsedBundle("bundle.tar.gz", &a),
							rego.Query(tc.queries[i]),
							rego.Input(input),
						).Eval(ctx)
						if err != nil {
							t.Fatal(err)
						}
						if !reflect.DeepEqual(rs[0].Expressions[0].Value, decision) {
							t.Fatalf("unexpected decision:\ngot: %v\nexp: %v", rs[0].Expressions[0].Value, decision)
						}
					}
				}

			})
		})
	}
}

func testS3Service(t *testing.T, bucket string) (*s3mem.Backend, *httptest.Server) {
	mock := s3mem.New()
	mock.CreateBucket(bucket)
	ts := httptest.NewServer(gofakes3.New(mock).Server())
	t.Cleanup(ts.Close)
	return mock, ts
}

func readFileString(name string) string {
	bs, err := os.ReadFile(name)
	if err != nil {
		panic(err)
	}
	return string(bs)
}

func decodeJSONUseNumber(s string) any {
	d := json.NewDecoder(bytes.NewBuffer([]byte(s)))
	d.UseNumber()
	var x any
	if err := d.Decode(&x); err != nil {
		panic(err)
	}
	return x
}
