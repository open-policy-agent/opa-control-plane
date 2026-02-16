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
			name:     "single source with hashsum",
			revision: `input.sources["sql-source"].hashsum`,
			want: []ReferencedSource{
				{SourceName: "sql-source", Fields: []string{"hashsum"}},
			},
		},
		{
			name:     "single source with commit",
			revision: `input.sources.policies.commit`,
			want: []ReferencedSource{
				{SourceName: "policies", Fields: []string{"commit"}},
			},
		},
		{
			name:     "template string with substring of commit",
			revision: `$"git-{substring(input.sources.policies.commit, 0, 7)}"`,
			want: []ReferencedSource{
				{SourceName: "policies", Fields: []string{"commit"}},
			},
		},
		{
			name:     "multiple sources",
			revision: `$"git-{input.sources.foo.commit}-{substring(input.sources.bar.hashsum,0,7)}"`,
			want: []ReferencedSource{
				{SourceName: "foo", Fields: []string{"commit"}},
				{SourceName: "bar", Fields: []string{"hashsum"}},
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
			got, err := AnalyzeRevisionReferences(tt.revision)
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
