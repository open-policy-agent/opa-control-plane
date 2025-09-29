package main

import (
	"os"

	"github.com/styrainc/opa-control-plane/cmd"
	_ "github.com/styrainc/opa-control-plane/cmd/backtest"
	_ "github.com/styrainc/opa-control-plane/cmd/build"
	_ "github.com/styrainc/opa-control-plane/cmd/compare"
	_ "github.com/styrainc/opa-control-plane/cmd/db"
	_ "github.com/styrainc/opa-control-plane/cmd/migrate"
	_ "github.com/styrainc/opa-control-plane/cmd/run"
	_ "github.com/styrainc/opa-control-plane/cmd/version"
)

func main() {
	if err := cmd.RootCommand.Execute(); err != nil {
		os.Exit(1)
	}
}
