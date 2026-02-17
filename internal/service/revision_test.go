package service

import (
	"slices"
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
