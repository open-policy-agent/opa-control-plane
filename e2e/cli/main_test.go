// Copyright 2025 The OPA Authors
// SPDX-License-Identifier: Apache-2.0

//go:build e2e

package cli

import (
	"cmp"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/rogpeppe/go-internal/testscript"

	"github.com/open-policy-agent/opa-control-plane/cmd"
	// The same subcommands as opactl's main package.
	_ "github.com/open-policy-agent/opa-control-plane/cmd/backtest"
	_ "github.com/open-policy-agent/opa-control-plane/cmd/build"
	_ "github.com/open-policy-agent/opa-control-plane/cmd/compare"
	_ "github.com/open-policy-agent/opa-control-plane/cmd/db"
	_ "github.com/open-policy-agent/opa-control-plane/cmd/migrate"
	_ "github.com/open-policy-agent/opa-control-plane/cmd/run"
	_ "github.com/open-policy-agent/opa-control-plane/cmd/version"
)

// TestMain makes "opactl-with-providers" available to test scripts: OCP's
// commands, with the E2E test source provider (see provider_test.go)
// registered. opactl itself registers none, so scripts exercising providers
// entries use this instead of $OPACTL.
func TestMain(m *testing.M) {
	testscript.Main(m, map[string]func(){
		"opactl-with-providers": func() {
			if err := cmd.SourceProviders.Register(filesProvider{}); err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
			if err := cmd.RootCommand.Execute(); err != nil {
				os.Exit(1)
			}
		},
	})
}

func testServer() *httptest.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /headers", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("content-type", "application/json")
		if err := json.NewEncoder(w).Encode(r.Header); err != nil {
			fmt.Fprintln(w, err.Error())
		}
	})
	mux.HandleFunc("GET /users", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("content-type", "application/json")
		if err := json.NewEncoder(w).Encode(map[string]any{
			"users": []map[string]any{
				{
					"id":    "alice",
					"roles": []string{"admin", "editor"},
				},
				{
					"id":    "bob",
					"roles": []string{"viewer"},
				},
			},
		}); err != nil {
			fmt.Fprintln(w, err.Error())
		}
	})

	return httptest.NewServer(mux)
}

func TestScript(t *testing.T) {
	opactl := cmp.Or(os.Getenv("OPACTL"), "opactl")
	srv := testServer()
	t.Cleanup(srv.Close)
	endpoint := srv.Listener.Addr().String()

	testscript.Run(t, testscript.Params{
		Dir: ".",
		Setup: func(e *testscript.Env) error {
			e.Vars = append(e.Vars,
				"HTTP_ENDPOINT="+endpoint,
				"OPACTL="+opactl,
			)
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
		Cmds: map[string]func(*testscript.TestScript, bool, []string){
			"retry": retryCmd,
		},
		// NB: To quickly update expectations in txtar files, try re-running the tests with
		// E2E_UPDATE=y, for example:
		//   E2E_UPDATE=y go test -tags e2e ./e2e/cli -run TestScript/build_sources_from_migrate -v -count=1
		UpdateScripts: os.Getenv("E2E_UPDATE") != "",
	})
}

// retryCmd implements a builtin command that waits until a command is successful
// by retrying up to 5 times with exponential delay starting with 2 seconds.
func retryCmd(ts *testscript.TestScript, neg bool, args []string) {
	if len(args) == 0 {
		ts.Fatalf("usage: retry command [args...]")
	}

	const maxRetries = 5
	const initialDelay = 2 * time.Second

	var lastErr error
	for i := 0; i < maxRetries; i++ {
		if i > 0 {
			delay := initialDelay * (1 << (i - 1))
			ts.Logf("retrying in %v (attempt %d/%d)", delay, i+1, maxRetries)
			time.Sleep(delay)
		}

		err := ts.Exec(args[0], args[1:]...)
		if err == nil {
			if neg {
				ts.Fatalf("unexpected command success")
			}
			return
		}
		lastErr = err
	}

	if neg {
		return
	}

	ts.Fatalf("command failed after %d attempts: %v", maxRetries, lastErr)
}
