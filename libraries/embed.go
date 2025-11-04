package libraries

import (
	"embed"

	_ "github.com/open-policy-agent/opa/cmd" // for running library tests

	"github.com/open-policy-agent/opa-control-plane/internal/fs"
)

//go:embed *
var fs_ embed.FS

var FS = fs.NewEscapeFS(fs_)
