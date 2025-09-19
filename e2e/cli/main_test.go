// Copyright 2025 The OPA Authors
// SPDX-License-Identifier: Apache-2.0

//go:build e2e

package cli

import (
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/rogpeppe/go-internal/testscript"
)

func TestScript(t *testing.T) {
	testscript.Run(t, testscript.Params{
		Dir: ".",
		Setup: func(e *testscript.Env) error {
			e.Vars = append(e.Vars, "OPACTL="+os.Getenv("OPACTL"))
			for _, kv := range os.Environ() {
				if strings.HasPrefix(kv, "E2E_") {
					e.Vars = append(e.Vars, kv)
				}
			}
			return nil
		},
		Condition: func(cond string) (bool, error) {
			args := strings.Split(cond, ":")
			name := args[0]
			switch name {
			case "env":
				if len(args) < 2 {
					return false, fmt.Errorf("syntax: [env:SOME_VAR]")
				}
				return os.Getenv(args[1]) != "", nil
			default:
				return false, fmt.Errorf("unknown condition %s", name)
			}
		},
	})
}
