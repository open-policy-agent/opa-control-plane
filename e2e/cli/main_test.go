// Copyright 2025 The OPA Authors
// SPDX-License-Identifier: Apache-2.0

//go:build e2e

package cli

import (
	"cmp"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"testing"

	"github.com/rogpeppe/go-internal/testscript"
)

func testServer() {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /headers", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("content-type", "application/json")
		if err := json.NewEncoder(w).Encode(r.Header); err != nil {
			fmt.Fprintln(w, err.Error())
		}
	})

	http.ListenAndServe(":9991", mux)
}

func TestScript(t *testing.T) {
	opactl := cmp.Or(os.Getenv("OPACTL"), "opactl")
	go testServer()

	testscript.Run(t, testscript.Params{
		Dir: ".",
		Setup: func(e *testscript.Env) error {
			e.Vars = append(e.Vars, "OPACTL="+opactl)
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
