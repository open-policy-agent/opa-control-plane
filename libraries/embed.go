package libraries

import (
	"embed"

	_ "github.com/open-policy-agent/opa/cmd" // for running library tests

	"github.com/open-policy-agent/opa-control-plane/internal/util"
)

//go:embed *
var fs_ embed.FS

var FS = util.NewEscapeFS(fs_)
