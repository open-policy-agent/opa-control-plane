package cmd

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/open-policy-agent/opa/v1/bundle"
)

func TestCompareBundle(t *testing.T) {
	type testCase struct {
		note  string
		a     map[string]string
		b     map[string]string
		equal bool
	}

	tests := []testCase{
		{
			note:  "empty bundles",
			a:     map[string]string{},
			b:     map[string]string{},
			equal: true,
		},
		{
			note: "bundle with identical rego and data",
			a: map[string]string{
				"data.json": `{"A": 7}`,
				"a.rego": `package a
				p = 1`,
			},
			b: map[string]string{
				"data.json": `{"A": 7}`,
				"a.rego": `package a
				p = 1`,
			},
			equal: true,
		},
		{
			note: "bundle with non identical rego",
			a: map[string]string{
				"a.rego": `package a
				p = 1`,
			},
			b: map[string]string{
				"a.rego": `package a
				p = 2`,
			},
			equal: false,
		},
		{
			note: "bundle with non identical json",
			a: map[string]string{
				"data.json": `{"A": 7}`,
			},
			b: map[string]string{
				"data.json": `{"A": 8}`,
			},
			equal: false,
		},
	}

	for _, test := range tests {
		t.Run(test.note, func(t *testing.T) {
			a := build(test.a)
			b := build(test.b)

			report, err := compareBundle(a, b)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if report.Empty() != test.equal {
				t.Fatalf("unexpected report, got: %v", report)
			}
		})
	}
}

func build(files map[string]string) bundle.Bundle {
	var b bundle.Bundle
	for path, content := range files {
		if strings.HasSuffix(path, ".rego") {
			b.Modules = append(b.Modules, bundle.ModuleFile{
				Path: path,
				Raw:  []byte(content),
			})
		} else if path == "data.json" {
			var value map[string]interface{}
			err := json.Unmarshal([]byte(content), &value)
			if err != nil {
				panic(err)
			}
			b.Data = value
		}
	}
	return b
}
