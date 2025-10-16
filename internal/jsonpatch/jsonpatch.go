package jsonpatch

import (
	"encoding/json"
	"fmt"

	jp "github.com/evanphx/json-patch/v5"
)

type PatchError struct {
	msg string
}

func (p *PatchError) Error() string {
	return p.msg
}

type Patch = jp.Patch

var opts = jp.ApplyOptions{
	EnsurePathExistsOnAdd:    true, // will create paths
	AllowMissingPathOnRemove: true,
}

func Apply(p Patch, doc json.RawMessage) (json.RawMessage, error) {
	// We only support add/remove/replace
	for _, op := range p {
		switch op.Kind() {
		case "replace", "remove", "add": // OK
		default:
			return nil, &PatchError{fmt.Sprintf("unsupported patch operation %q, must be one of \"replace\", \"add\", \"remove\"", op.Kind())}
		}
	}
	return p.ApplyWithOptions(doc, &opts)
}
