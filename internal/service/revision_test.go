package service

import (
	"context"
	"slices"
	"strings"
	"testing"
)

func TestAnalyzeRevisionReferences(t *testing.T) {
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
			name:     "using input.config instead of input.sources",
			revision: `input.config.policies.git.commit`,
			wantErr:  true,
		},
		{
			name:     "using input.data instead of input.sources",
			revision: `input.data["sql-source"].sql.hash`,
			wantErr:  true,
		},
		{
			name:     "invalid source type (http)",
			revision: `input.sources.policies.http.url`,
			wantErr:  true,
		},
		{
			name:     "invalid source type (file)",
			revision: `input.sources["sql-source"].file.path`,
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ExtractRevisionRefs(tt.revision)
			if (err != nil) != tt.wantErr {
				t.Errorf("AnalyzeRevisionReferences() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr {
				return
			}

			// Compare results (order may vary)
			if len(got) != len(tt.want) {
				t.Errorf("AnalyzeRevisionReferences() got %d sources, want %d", len(got), len(tt.want))
				return
			}

			for _, wantSrc := range tt.want {
				found := false
				for _, gotSrc := range got {
					if gotSrc.SourceName == wantSrc.SourceName {
						found = true
						// Check fields (order may vary)
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
			name:            "input.x not sources - config",
			revision:        `input.config.policies.git.commit`,
			wantErrContains: "revision references must use 'input.sources', found 'input.config'",
		},
		{
			name:            "input.x not sources - data",
			revision:        `input.data["sql-source"].sql.hash`,
			wantErrContains: "revision references must use 'input.sources', found 'input.data'",
		},
		{
			name:             "unknown source name with available sources",
			revision:         `input.sources.unknown.git.commit`,
			availableSources: []string{"policies", "sql-source"},
			wantErrContains:  "revision references unknown source 'unknown', available sources: policies, sql-source",
		},
		{
			name:             "unknown source name with single source",
			revision:         `input.sources.nothere.git.commit`,
			availableSources: []string{"policies"},
			wantErrContains:  "revision references unknown source 'nothere', available sources: policies",
		},
		{
			name:            "invalid source type - http",
			revision:        `input.sources.policies.http.url`,
			wantErrContains: "revision source type must be 'git' or 'sql', found 'http'",
		},
		{
			name:            "invalid source type - file",
			revision:        `input.sources["sql-source"].file.path`,
			wantErrContains: "revision source type must be 'git' or 'sql', found 'file'",
		},
		{
			name:            "invalid source type - s3",
			revision:        `input.sources.data.s3.bucket`,
			wantErrContains: "revision source type must be 'git' or 'sql', found 's3'",
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

			_, err := ResolveRevision(context.Background(), tt.revision, sourceMetadata)
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tt.wantErrContains)
			}

			if !strings.Contains(err.Error(), tt.wantErrContains) {
				t.Errorf("error message %q does not contain expected substring %q", err.Error(), tt.wantErrContains)
			}
		})
	}
}
