package main

import (
	"os"

	"github.com/open-policy-agent/opa-control-plane/cmd"
	_ "github.com/open-policy-agent/opa-control-plane/cmd/backtest"
	_ "github.com/open-policy-agent/opa-control-plane/cmd/build"
	_ "github.com/open-policy-agent/opa-control-plane/cmd/compare"
	_ "github.com/open-policy-agent/opa-control-plane/cmd/db"
	_ "github.com/open-policy-agent/opa-control-plane/cmd/migrate"
	_ "github.com/open-policy-agent/opa-control-plane/cmd/run"
	_ "github.com/open-policy-agent/opa-control-plane/cmd/version"
)

func main() {
	if err := cmd.RootCommand.Execute(); err != nil {
		os.Exit(1)
	}
}
