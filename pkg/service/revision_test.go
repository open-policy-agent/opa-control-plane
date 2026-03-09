package service

import (
	"slices"
	"strings"
	"testing"
)

func TestExtractRevisionRefs(t *testing.T) {
	tests := []struct {
		name     string
		revision string
		want     []ReferencedSource
		wantErr  bool
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
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ExtractRevisionRefs(tt.revision)
			if (err != nil) != tt.wantErr {
				t.Errorf("error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr {
				return
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
			name:             "invalid source type - http (schema validation)",
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
			name:             "invalid source type - s3 (schema validation)",
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

			_, err := ResolveRevision(t.Context(), tt.revision, sourceMetadata)
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tt.wantErrContains)
			}

			if !strings.Contains(err.Error(), tt.wantErrContains) {
				t.Errorf("error message %q does not contain expected substring %q", err.Error(), tt.wantErrContains)
			}
		})
	}
}
