package config_test

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/goccy/go-yaml"

	"github.com/open-policy-agent/opa-control-plane/internal/config"
	"github.com/open-policy-agent/opa-control-plane/internal/test/tempfs"
)

func TestMerge(t *testing.T) {

	config1 := `{
			"keep0": 0,
			"merge": {
				"keep0": 0,
				"merge1": {
					"keep0": 0,
					"overwrite1": 0
				},
				"overwrite2": 0
			},
			"overwrite1": 0
		}`

	config2 := `{
			"keep1": 1,
			"merge": {
				"keep1": 1,
				"merge1": {
					"overwrite1": 1
				},
				"overwrite2": 1
			},
			"overwrite1": 1
		}`

	config3 := `{
			"keep2": 2,
			"merge": {
				"keep2": 2,
				"overwrite2": 2
			}
		}`

	files := map[string]string{
		"config.d/1.yaml": config1,
		"config.d/2.yaml": config2,
		"config.d/3.yaml": config3,
	}

	tempfs.WithTempFS(t, files, func(t *testing.T, dir string) {
		bs, err := config.Merge([]string{dir}, false)
		if err != nil {
			t.Fatal(err)
		}

		// roundtrip the config bytes to make reflect.DeepEqual work below
		var x interface{}
		if err := yaml.Unmarshal(bs, &x); err != nil {
			t.Fatal(err)
		}
		roundtrip, err := json.Marshal(x)
		if err != nil {
			t.Fatal(err)
		}
		var result map[string]interface{}
		if err := json.Unmarshal(roundtrip, &result); err != nil {
			t.Fatal(err)
		}

		bs2 := []byte(`{
			"keep0": 0,
			"overwrite1": 1,
			"merge": {
				"keep0": 0,
				"overwrite2": 2,
				"merge1": {
					"keep0": 0,
					"overwrite1": 1
				},
				"keep2": 2,
				"keep1": 1
			},
			"keep2": 2,
			"keep1": 1
		}`)

		var exp map[string]interface{}
		if err := json.Unmarshal(bs2, &exp); err != nil {
			t.Fatal(err)
		}

		if !reflect.DeepEqual(result, exp) {
			t.Fatalf("expected %v but got %v", exp, result)
		}

		// Test with conflict errors enabled

		_, err = config.Merge([]string{dir}, true)
		if err.Error() != "conflict for config path /merge/merge1/overwrite1" {
			t.Fatal(err)
		}

	})
}
