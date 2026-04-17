package cmd

import (
	"fmt"
	"io"
	"os"
	"runtime"
	"runtime/debug"
	"strings"

	"github.com/spf13/cobra"

	"github.com/open-policy-agent/opa-control-plane/cmd"
)

func init() {
	cmd.RootCommand.AddCommand(
		&cobra.Command{
			Use:   "version",
			Short: "Print the version of OPA Control Plane",
			Long:  "Show version and build information for OPA Control Plane.",
			Run: func(*cobra.Command, []string) {
				generateCmdOutput(os.Stdout)
			},
		},
	)
}

type info struct {
	Version  string
	Revision string
	Time     string
	Modified bool
}

func (i info) Short() string {
	if len(i.Revision) > 12 {
		return i.Revision[:12]
	}
	return i.Revision
}

func (i info) String() string {
	s := i.Short()
	if s == "" {
		return "<no VCS info>"
	}
	if i.Modified {
		return s + " (modified)"
	}
	return s
}

func readBuildInfo() info {
	bi, ok := debug.ReadBuildInfo()
	if !ok {
		return info{}
	}
	var i info
	i.Version = bi.Main.Version
	for _, s := range bi.Settings {
		switch s.Key {
		case "vcs.revision":
			i.Revision = s.Value
		case "vcs.time":
			i.Time = s.Value
		case "vcs.modified":
			i.Modified = s.Value == "true"
		}
	}
	if i.Revision == "" {
		// Fallback: extract revision from module version string.
		// e.g. "v0.0.0-20260105212325-7a5757f46310" → "7a5757f46310"
		if idx := strings.LastIndexByte(i.Version, '-'); idx > -1 {
			i.Revision = i.Version[idx+1:]
		}
	}
	return i
}

func generateCmdOutput(out io.Writer) {
	i := readBuildInfo()

	fmt.Fprintln(out, "Version:", i.Version)
	fmt.Fprintln(out, "Build Commit:", i)
	fmt.Fprintln(out, "Build Timestamp:", i.Time)
	fmt.Fprintln(out, "Go Version:", runtime.Version())
	fmt.Fprintln(out, "Platform:", runtime.GOOS+"/"+runtime.GOARCH)
}
