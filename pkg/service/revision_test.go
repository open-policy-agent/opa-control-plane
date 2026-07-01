package service

import (
	"slices"
	"strings"
	"testing"
)

func TestExtractRevisionRefs(t *testing.T) {
	tests := []struct {
		name           string
		revision       string
		want           []ReferencedSource
		wantBundleHash bool
		wantErr        bool
	}{
		{
			name:     "empty revision",
			revision: "",
			want:     nil,
		},
		{
			name:     "static string no references",
			revision: `"REVISION-091"`,
			want:     []ReferencedSource{},
		},
		{
			name:     "single source with sql hash",
			revision: `input.sources["sql-source"].sql.hash`,
			want: []ReferencedSource{
				{SourceName: "sql-source", Fields: []string{"sql", "hash"}},
			},
		},
		{
			name:     "single source with git commit",
			revision: `input.sources.policies.git.commit`,
			want: []ReferencedSource{
				{SourceName: "policies", Fields: []string{"git", "commit"}},
			},
		},
		{
			name:     "template string with substring of git commit",
			revision: `$"git-{substring(input.sources.policies.git.commit, 0, 7)}"`,
			want: []ReferencedSource{
				{SourceName: "policies", Fields: []string{"git", "commit"}},
			},
		},
		{
			name:     "multiple sources",
			revision: `$"git-{input.sources.foo.git.commit}-{substring(input.sources.bar.sql.hash,0,7)}"`,
			want: []ReferencedSource{
				{SourceName: "foo", Fields: []string{"git", "commit"}},
				{SourceName: "bar", Fields: []string{"sql", "hash"}},
			},
		},
		{
			name:     "nested field access",
			revision: `input.sources.policies.git.ref`,
			want: []ReferencedSource{
				{SourceName: "policies", Fields: []string{"git", "ref"}},
			},
		},
		{
			name:     "invalid rego",
			revision: "not a valid {{{ rego",
			wantErr:  true,
		},
		{
			name:     "using input.config instead of input.sources - allowed at extract time",
			revision: `input.config.policies.git.commit`,
			want:     []ReferencedSource{}, // No sources refs since it's not input.sources
		},
		{
			name:     "using input.data instead of input.sources - allowed at extract time",
			revision: `input.data["sql-source"].sql.hash`,
			want:     []ReferencedSource{}, // No sources refs since it's not input.sources
		},
		{
			name:     "invalid source type (http) - allowed at extract time",
			revision: `input.sources.policies.http.url`,
			want: []ReferencedSource{
				{SourceName: "policies", Fields: []string{"http", "url"}},
			},
		},
		{
			name:     "invalid source type (file) - allowed at extract time",
			revision: `input.sources["sql-source"].file.path`,
			want: []ReferencedSource{
				{SourceName: "sql-source", Fields: []string{"file", "path"}},
			},
		},
		{
			name:           "bundle hash only",
			revision:       `input.bundle.hash`,
			want:           []ReferencedSource{},
			wantBundleHash: true,
		},
		{
			name:     "bundle hash combined with source",
			revision: `$"{input.sources.policies.git.commit}-{input.bundle.hash}"`,
			want: []ReferencedSource{
				{SourceName: "policies", Fields: []string{"git", "commit"}},
			},
			wantBundleHash: true,
		},
		{
			name:     "http datasource with name",
			revision: `input.sources["my-data"].http.users.hash`,
			want: []ReferencedSource{
				{SourceName: "my-data", Fields: []string{"http", "users", "hash"}},
			},
		},
		{
			name:     "http datasource with bracket notation",
			revision: `input.sources["my-data"].http["user-list"].hash`,
			want: []ReferencedSource{
				{SourceName: "my-data", Fields: []string{"http", "user-list", "hash"}},
			},
		},
		{
			name:     "s3 datasource with name",
			revision: `input.sources["my-data"].s3["model-weights"].hash`,
			want: []ReferencedSource{
				{SourceName: "my-data", Fields: []string{"s3", "model-weights", "hash"}},
			},
		},
		{
			name:     "multiple datasources from same source",
			revision: `$"{input.sources.data.http.users.hash}-{input.sources.data.http.products.hash}"`,
			want: []ReferencedSource{
				{SourceName: "data", Fields: []string{"http", "users", "hash", "products"}},
			},
		},
		{
			name:     "mixed git and http datasource",
			revision: `$"{input.sources.policies.git.commit}-{input.sources.data.http.users.hash}"`,
			want: []ReferencedSource{
				{SourceName: "policies", Fields: []string{"git", "commit"}},
				{SourceName: "data", Fields: []string{"http", "users", "hash"}},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, gotBundleHash, err := extractRevisionRefs(tt.revision)
			if (err != nil) != tt.wantErr {
				t.Errorf("error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr {
				return
			}

			if gotBundleHash != tt.wantBundleHash {
				t.Errorf("needsBundleHash = %v, want %v", gotBundleHash, tt.wantBundleHash)
			}

			if len(got) != len(tt.want) {
				t.Errorf("got %d sources, want %d", len(got), len(tt.want))
				return
			}

			for _, wantSrc := range tt.want {
				found := false
				for _, gotSrc := range got {
					if gotSrc.SourceName == wantSrc.SourceName {
						found = true
						if len(gotSrc.Fields) != len(wantSrc.Fields) {
							t.Errorf("Source %q: got %d fields, want %d", wantSrc.SourceName, len(gotSrc.Fields), len(wantSrc.Fields))
						}
						for _, wantField := range wantSrc.Fields {
							if !slices.Contains(gotSrc.Fields, wantField) {
								t.Errorf("Source %q: missing field %q", wantSrc.SourceName, wantField)
							}
						}
						break
					}
				}
				if !found {
					t.Errorf("Expected source %q not found in results", wantSrc.SourceName)
				}
			}
		})
	}
}

func TestValidationErrorMessages(t *testing.T) {
	tests := []struct {
		name             string
		revision         string
		availableSources []string
		wantErrContains  string
	}{
		{
			name:            "input.x not sources - config (schema validation)",
			revision:        `input.config.policies.git.commit`,
			wantErrContains: `undefined ref: input.config.policies.git.commit`,
		},
		{
			name:            "input.x not sources - data (schema validation)",
			revision:        `input.data["sql-source"].sql.hash`,
			wantErrContains: `undefined ref: input.data["sql-source"].sql.hash`,
		},
		{
			name:             "unknown source name with available sources (schema validation)",
			revision:         `input.sources.unknown.git.commit`,
			availableSources: []string{"policies", "sql-source"},
			wantErrContains:  `undefined ref: input.sources.unknown.git.commit`,
		},
		{
			name:             "unknown source name with single source (schema validation)",
			revision:         `input.sources.nothere.git.commit`,
			availableSources: []string{"policies"},
			wantErrContains:  `undefined ref: input.sources.nothere.git.commit`,
		},
		{
			name:             "invalid source type - http without datasources (schema validation)",
			revision:         `input.sources.policies.http.url`,
			availableSources: []string{"policies"},
			wantErrContains:  `undefined ref: input.sources.policies.http.url`,
		},
		{
			name:             "invalid source type - file (schema validation)",
			revision:         `input.sources.policies.file.path`,
			availableSources: []string{"policies"},
			wantErrContains:  `undefined ref: input.sources.policies.file.path`,
		},
		{
			name:             "invalid source type - s3 without datasources (schema validation)",
			revision:         `input.sources.policies.s3.bucket`,
			availableSources: []string{"policies"},
			wantErrContains:  `undefined ref: input.sources.policies.s3.bucket`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sourceMetadata := make(map[string]map[string]any)
			for _, src := range tt.availableSources {
				sourceMetadata[src] = map[string]any{
					"git": map[string]any{"commit": "abc123"},
					"sql": map[string]any{"hash": "def456"},
				}
			}

			_, err := resolveRevision(t.Context(), tt.revision, sourceMetadata, "")
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tt.wantErrContains)
			}

			if !strings.Contains(err.Error(), tt.wantErrContains) {
				t.Errorf("error message %q does not contain expected substring %q", err.Error(), tt.wantErrContains)
			}
		})
	}
}

func TestValidationErrorMessagesWithDatasources(t *testing.T) {
	tests := []struct {
		name            string
		revision        string
		sourceMetadata  map[string]map[string]any
		wantErrContains string
	}{
		{
			name:     "unknown datasource name under http",
			revision: `input.sources.data.http.unknown.hash`,
			sourceMetadata: map[string]map[string]any{
				"data": {
					"http": map[string]any{
						"users":    map[string]any{"hash": "abc123"},
						"products": map[string]any{"hash": "def456"},
					},
				},
			},
			wantErrContains: `undefined ref: input.sources.data.http.unknown.hash`,
		},
		{
			name:     "unknown datasource name under s3",
			revision: `input.sources.data.s3.unknown.hash`,
			sourceMetadata: map[string]map[string]any{
				"data": {
					"s3": map[string]any{
						"model-weights": map[string]any{"hash": "abc123"},
					},
				},
			},
			wantErrContains: `undefined ref: input.sources.data.s3.unknown.hash`,
		},
		{
			name:     "accessing http.hash directly without datasource name",
			revision: `input.sources.data.http.hash`,
			sourceMetadata: map[string]map[string]any{
				"data": {
					"http": map[string]any{
						"users": map[string]any{"hash": "abc123"},
					},
				},
			},
			wantErrContains: `undefined ref: input.sources.data.http.hash`,
		},
		{
			name:     "wrong field name on datasource",
			revision: `input.sources.data.http.users.url`,
			sourceMetadata: map[string]map[string]any{
				"data": {
					"http": map[string]any{
						"users": map[string]any{"hash": "abc123"},
					},
				},
			},
			wantErrContains: `undefined ref: input.sources.data.http.users.url`,
		},
		{
			name:     "http not in schema when no http datasources exist",
			revision: `input.sources.policies.http.users.hash`,
			sourceMetadata: map[string]map[string]any{
				"policies": {
					"git": map[string]any{"commit": "abc123"},
				},
			},
			wantErrContains: `undefined ref: input.sources.policies.http.users.hash`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := resolveRevision(t.Context(), tt.revision, tt.sourceMetadata, "")
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tt.wantErrContains)
			}

			if !strings.Contains(err.Error(), tt.wantErrContains) {
				t.Errorf("error message %q does not contain expected substring %q", err.Error(), tt.wantErrContains)
			}
		})
	}
}

func TestResolveRevision(t *testing.T) {
	tests := []struct {
		name            string
		revision        string
		sourceMetadata  map[string]map[string]any
		bundleHash      string
		want            string
		wantErr         bool
		wantErrContains string
	}{
		{
			name:     "empty revision",
			revision: "",
			want:     "",
		},
		{
			name:     "static string",
			revision: `"v1.0.0"`,
			want:     "v1.0.0",
		},
		{
			name:     "git commit",
			revision: `input.sources.policies.git.commit`,
			sourceMetadata: map[string]map[string]any{
				"policies": {
					"git": map[string]any{"commit": "abc123def456"},
				},
			},
			want: "abc123def456",
		},
		{
			name:     "sql hash",
			revision: `input.sources["sql-source"].sql.hash`,
			sourceMetadata: map[string]map[string]any{
				"sql-source": {
					"sql": map[string]any{"hash": "deadbeef"},
				},
			},
			want: "deadbeef",
		},
		{
			name:     "http datasource hash",
			revision: `input.sources.data.http.users.hash`,
			sourceMetadata: map[string]map[string]any{
				"data": {
					"http": map[string]any{
						"users": map[string]any{"hash": "a1b2c3d4"},
					},
				},
			},
			want: "a1b2c3d4",
		},
		{
			name:     "s3 datasource hash",
			revision: `input.sources.data.s3["model-weights"].hash`,
			sourceMetadata: map[string]map[string]any{
				"data": {
					"s3": map[string]any{
						"model-weights": map[string]any{"hash": "s3hash999"},
					},
				},
			},
			want: "s3hash999",
		},
		{
			name:     "template with git commit substring",
			revision: `$"git-{substring(input.sources.policies.git.commit, 0, 7)}"`,
			sourceMetadata: map[string]map[string]any{
				"policies": {
					"git": map[string]any{"commit": "abc123def456"},
				},
			},
			want: "git-abc123d",
		},
		{
			name:     "template combining git and http datasource",
			revision: `$"{substring(input.sources.policies.git.commit, 0, 7)}-{substring(input.sources.data.http.users.hash, 0, 7)}"`,
			sourceMetadata: map[string]map[string]any{
				"policies": {
					"git": map[string]any{"commit": "abc123def456"},
				},
				"data": {
					"http": map[string]any{
						"users": map[string]any{"hash": "fedcba9876543210"},
					},
				},
			},
			want: "abc123d-fedcba9",
		},
		{
			name:     "template combining two http datasources from same source",
			revision: `$"{substring(input.sources.data.http.users.hash, 0, 8)}-{substring(input.sources.data.http.products.hash, 0, 8)}"`,
			sourceMetadata: map[string]map[string]any{
				"data": {
					"http": map[string]any{
						"users":    map[string]any{"hash": "1111111122222222"},
						"products": map[string]any{"hash": "3333333344444444"},
					},
				},
			},
			want: "11111111-33333333",
		},
		{
			name:     "http datasource with bracket notation",
			revision: `input.sources.data.http["user-list"].hash`,
			sourceMetadata: map[string]map[string]any{
				"data": {
					"http": map[string]any{
						"user-list": map[string]any{"hash": "bracket-hash"},
					},
				},
			},
			want: "bracket-hash",
		},
		{
			name:       "input.bundle.hash resolves to provided hash",
			revision:   `input.bundle.hash`,
			bundleHash: "abc123def456",
			want:       "abc123def456",
		},
		{
			name:     "template combining bundle hash and source metadata",
			revision: `$"{input.sources.policies.git.commit}-{input.bundle.hash}"`,
			sourceMetadata: map[string]map[string]any{
				"policies": {"git": map[string]any{"commit": "deadbeef"}},
			},
			bundleHash: "abc123",
			want:       "deadbeef-abc123",
		},
		{
			name:            "schema error on input.bundle.nonexistent",
			revision:        `input.bundle.nonexistent`,
			bundleHash:      "abc123",
			wantErr:         true,
			wantErrContains: "undefined ref",
		},
		{
			name:     "revision exceeding max length",
			revision: `$"{input.sources.policies.git.commit}-{input.sources.data.sql.hash}"`,
			sourceMetadata: map[string]map[string]any{
				"policies": {"git": map[string]any{"commit": strings.Repeat("a", 200)}},
				"data":     {"sql": map[string]any{"hash": strings.Repeat("b", 200)}},
			},
			wantErr:         true,
			wantErrContains: "resolved revision exceeds maximum length",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := resolveRevision(t.Context(), tt.revision, tt.sourceMetadata, tt.bundleHash)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				if tt.wantErrContains != "" && !strings.Contains(err.Error(), tt.wantErrContains) {
					t.Errorf("error message %q does not contain expected substring %q", err.Error(), tt.wantErrContains)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}
