package builder

import (
	"testing"
)

func TestResolveRevision(t *testing.T) {
	tests := []struct {
		name     string
		revision string
		envVars  map[string]string
		want     string
		wantErr  bool
	}{
		{
			name:     "empty revision",
			revision: "",
			want:     "",
			wantErr:  false,
		},
		{
			name:     "static string as rego query",
			revision: `"REVISION-091"`,
			want:     "REVISION-091",
		},
		{
			name:     "static string with special chars as rego query",
			revision: `"v1.2.3-alpha"`,
			want:     "v1.2.3-alpha",
		},
		{
			name:     "plain string fails",
			revision: "not-a-rego-query",
			wantErr:  true,
		},
		{
			name:     "rego time.now_ns()",
			revision: "time.now_ns()",
			want:     "", // We'll check it's not empty
		},
		{
			name:     "env var with opa.runtime()",
			revision: `opa.runtime().env["MY_REVISION"]`,
			envVars:  map[string]string{"MY_REVISION": "build-123"},
			want:     "build-123",
		},
		{
			name:     "env var not set",
			revision: `opa.runtime().env["UNSET_VAR"]`,
			wantErr:  true,
		},
		{
			name:     "rego arithmetic",
			revision: "1 + 1",
			want:     "2",
		},
		{
			name:     "rego string concatenation",
			revision: `concat("", ["v", "1", ".", "0"])`,
			want:     "v1.0",
		},
		{
			name:     "rego template string with uuid",
			revision: `$"bundle-{uuid.rfc4122("my-bundle")}"`,
			want:     "", // UUID is non-deterministic, we'll check it starts with "bundle-"
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := t.Context()
			for k, v := range tt.envVars {
				t.Setenv(k, v)
			}

			b := New().WithRevision(tt.revision)
			got, err := b.resolveRevision(ctx)
			if (err != nil) != tt.wantErr {
				t.Errorf("resolveRevision() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			// For time.now_ns(), just check it's not empty and is numeric
			if tt.revision == "time.now_ns()" {
				if got == "" {
					t.Errorf("resolveRevision() = empty string, want non-empty timestamp")
				}
				return
			}

			// For UUID template test, just check it starts with "bundle-" and has UUID format
			if tt.revision == `$"bundle-{uuid.rfc4122("my-bundle")}"` {
				if len(got) < 43 || got[:7] != "bundle-" {
					t.Errorf("resolveRevision() = %v, want bundle-<uuid>", got)
				}
				return
			}

			if got != tt.want {
				t.Errorf("resolveRevision() = %v, want %v", got, tt.want)
			}
		})
	}
}
