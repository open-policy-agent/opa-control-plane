package config

import (
	"fmt"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"reflect"
	"slices"

	"gopkg.in/yaml.v3"
)

func Merge(configFiles []string, conflictError bool) ([]byte, error) {

	var paths []string
	for _, f := range configFiles {
		if err := filepath.Walk(f, func(path string, fi fs.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if fi.IsDir() {
				return nil
			}
			paths = append(paths, path)
			return nil
		}); err != nil {
			return nil, err
		}
	}

	docs := make([]map[string]any, 0, len(paths))
	for _, f := range paths {
		bs, err := os.ReadFile(f)
		if err != nil {
			return nil, fmt.Errorf("failed to read configuration file %v: %v", f, err)
		}
		var x map[string]any
		if err := yaml.Unmarshal(bs, &x); err != nil {
			return nil, fmt.Errorf("failed to unmarshal configuration file %v: %v", f, err)
		}
		docs = append(docs, x)
	}

	merged, err := merge(docs, "", conflictError)
	if err != nil {
		return nil, err
	}

	bs, err := yaml.Marshal(merged)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal merged configuration: %v", err)
	}

	return bs, nil
}

func merge(docs []map[string]any, path string, conflictError bool) (map[string]any, error) {
	result := make(map[string]any)
	for _, doc := range docs {
		for _, key := range slices.Sorted(maps.Keys(doc)) { // Sort keys to ensure deterministic merge errors.
			value := doc[key]
			if existing, ok := result[key]; ok {
				if existingMap, ok1 := existing.(map[string]any); ok1 {
					if valueMap, ok2 := value.(map[string]any); ok2 {
						var err error
						result[key], err = merge([]map[string]any{existingMap, valueMap}, path+"/"+key, conflictError)
						if err != nil {
							return nil, err
						}
						continue
					}
				}

				if conflictError && !reflect.DeepEqual(existing, value) {
					return nil, fmt.Errorf("conflict for config path %s", path+"/"+key)
				}
			}
			result[key] = value
		}
	}
	return result, nil
}
