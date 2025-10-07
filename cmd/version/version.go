package cmd

import (
	"fmt"
	"io"
	"os"
	"runtime"
	"runtime/debug"

	"github.com/open-policy-agent/opa-control-plane/cmd"
	"github.com/spf13/cobra"
)

var Version = "0.1.0-dev"

func init() {
	version := &cobra.Command{
		Use:   "version",
		Short: "Print the version of OPA Control Plane",
		Long:  "Show version and build information for OPA Control Plane.",
		Run: func(cmd *cobra.Command, args []string) {
			generateCmdOutput(os.Stdout)
		},
	}

	cmd.RootCommand.AddCommand(
		version,
	)
}

func generateCmdOutput(out io.Writer) {
	goVersion := runtime.Version()
	platform := runtime.GOOS + "/" + runtime.GOARCH
	binVcs := ""
	binTimestamp := ""
	hostname := ""

	bi, ok := debug.ReadBuildInfo()
	if !ok {
		return
	}
	var dirty bool

	for _, s := range bi.Settings {
		switch s.Key {
		case "vcs.time":
			binTimestamp = s.Value
		case "vcs.revision":
			binVcs = s.Value
		case "vcs.modified":
			dirty = s.Value == "true"
		}
	}

	if dirty {
		binVcs += "-dirty"
	}

	fmt.Fprintln(out, "Version: "+Version)
	fmt.Fprintln(out, "Build Commit: "+binVcs)
	fmt.Fprintln(out, "Build Timestamp: "+binTimestamp)
	fmt.Fprintln(out, "Build Hostname: "+hostname)
	fmt.Fprintln(out, "Go Version: "+goVersion)
	fmt.Fprintln(out, "Platform: "+platform)

}
