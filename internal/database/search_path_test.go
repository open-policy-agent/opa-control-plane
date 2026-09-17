package database

import (
	"testing"
)

func TestWithSchema(t *testing.T) {
	cases := map[string]struct {
		schema  string
		wantErr bool
	}{
		"empty is allowed":    {"", false},
		"simple":              {"ocp", false},
		"underscore":          {"ocp_v2", false},
		"leading underscore":  {"_ocp", false},
		"mixed case":          {"MySchema", true},
		"leading digit":       {"1ocp", true},
		"space":               {"ocp oma", true},
		"hyphen":              {"ocp-schema", true},
		"semicolon injection": {"ocp; DROP TABLE bundles", true},
		"quote":               {`ocp"`, true},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			d, err := New().WithSchema(tc.schema)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("WithSchema(%q): expected error, got nil", tc.schema)
				}
				return
			}
			if err != nil {
				t.Fatalf("WithSchema(%q): unexpected error: %v", tc.schema, err)
			}
			if d.schema != tc.schema {
				t.Fatalf("WithSchema(%q): schema = %q", tc.schema, d.schema)
			}
		})
	}
}

func TestSearchPathStmt(t *testing.T) {
	cases := map[string]struct {
		kind   int
		schema string
		want   string
	}{
		"cockroach with schema": {cockroach, "ocp", "SET LOCAL search_path = ocp"},
		"postgres with schema":  {postgres, "ocp", "SET LOCAL search_path = ocp"},
		"cockroach no schema":   {cockroach, "", ""},
		"sqlite is no-op":       {sqlite, "ocp", ""},
		"mysql is no-op":        {mysql, "ocp", ""},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			d := &Database{kind: tc.kind, schema: tc.schema}
			if got := d.searchPathStmt(); got != tc.want {
				t.Fatalf("searchPathStmt() = %q, want %q", got, tc.want)
			}
		})
	}
}
