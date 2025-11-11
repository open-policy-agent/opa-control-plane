//go:generate go run ../build/gen-config-schema.go schema.json

package config

import (
	_ "embed"
)

//go:embed "schema.json"
var schema []byte

func Schema() []byte {
	return schema
}
