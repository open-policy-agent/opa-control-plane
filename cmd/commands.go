package cmd

import (
	"os"
	"path"

	"github.com/spf13/cobra"

	pkgsync "github.com/open-policy-agent/opa-control-plane/pkg/sync"
)

// RootCommand is the base CLI command that all subcommands are added to.
var RootCommand = &cobra.Command{
	Use:   path.Base(os.Args[0]),
	Short: "OPA Control Plane",
	Long:  "An open source control plane for Open Policy Agent (OPA).",
}

// SourceProviders holds the source types that sources' providers entries can
// use in the build and run commands. It is empty in opactl; programs that
// embed OCP's commands register their source providers here before
// executing RootCommand.
var SourceProviders = pkgsync.NewSourceProviderRegistry()
