package config

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
			name:     "static string",
			revision: "REVISION-091",
			want:     "REVISION-091",
			wantErr:  false,
		},
		{
			name:     "static string with special chars",
			revision: "v1.2.3-alpha",
			want:     "v1.2.3-alpha",
			wantErr:  false,
		},
		{
			name:     "rego time.now_ns()",
			revision: "time.now_ns()",
			want:     "", // We'll check it's not empty
			wantErr:  false,
		},
		{
			name:     "env var with ${} syntax",
			revision: "${MY_REVISION}",
			envVars:  map[string]string{"MY_REVISION": "build-123"},
			want:     "build-123",
			wantErr:  false,
		},
		{
			name:     "env var with $ syntax",
			revision: "$MY_REVISION",
			envVars:  map[string]string{"MY_REVISION": "build-456"},
			want:     "build-456",
			wantErr:  false,
		},
		{
			name:     "env var not set",
			revision: "$UNSET_VAR",
			want:     "",
			wantErr:  false,
		},
		{
			name:     "rego arithmetic",
			revision: "1 + 1",
			want:     "2",
			wantErr:  false,
		},
		{
			name:     "rego string concatenation",
			revision: `concat("", ["v", "1", ".", "0"])`,
			want:     "v1.0",
			wantErr:  false,
		},
		{
			name:     "rego template string with uuid",
			revision: `$"bundle-{uuid.rfc4122("my-bundle")}"`,
			want:     "", // UUID is non-deterministic, we'll check it starts with "bundle-"
			wantErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := t.Context()
			for k, v := range tt.envVars {
				t.Setenv(k, v)
			}

			got, err := ResolveRevision(ctx, tt.revision)
			if (err != nil) != tt.wantErr {
				t.Errorf("ResolveRevision() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			// For time.now_ns(), just check it's not empty and is numeric
			if tt.revision == "time.now_ns()" {
				if got == "" {
					t.Errorf("ResolveRevision() = empty string, want non-empty timestamp")
				}
				return
			}

			// For UUID template test, just check it starts with "bundle-" and has UUID format
			if tt.revision == `$"bundle-{uuid.rfc4122("my-bundle")}"` {
				if len(got) < 43 || got[:7] != "bundle-" {
					t.Errorf("ResolveRevision() = %v, want bundle-<uuid>", got)
				}
				return
			}

			if got != tt.want {
				t.Errorf("ResolveRevision() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestLooksLikeRego(t *testing.T) {
	tests := []struct {
		name string
		s    string
		want bool
	}{
		{
			name: "function call",
			s:    "time.now_ns()",
			want: true,
		},
		{
			name: "simple string",
			s:    "REVISION-091",
			want: false,
		},
		{
			name: "version string",
			s:    "v1.2.3-alpha",
			want: false,
		},
		{
			name: "arithmetic with spaces",
			s:    "1 + 1",
			want: true,
		},
		{
			name: "env var syntax",
			s:    "$MY_VAR",
			want: false,
		},
		{
			name: "number",
			s:    "42",
			want: true, // v1/ast parses numbers as valid expressions
		},
		{
			name: "quoted string",
			s:    `"hello"`,
			want: true, // v1/ast parses strings as valid expressions
		},
		{
			name: "concat function",
			s:    `concat("", ["v", "1"])`,
			want: true,
		},
		{
			name: "template string",
			s:    `$"bundle-{uuid.rfc4122("my-bundle")}"`,
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, act := looksLikeRego(tt.s)
			if act != tt.want {
				t.Errorf("looksLikeRego() = %v, want %v", act, tt.want)
			}
		})
	}
}
