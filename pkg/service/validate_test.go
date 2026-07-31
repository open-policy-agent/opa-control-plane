package service_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing/object"

	"github.com/open-policy-agent/opa-control-plane/internal/config"
	"github.com/open-policy-agent/opa-control-plane/pkg/service"
)

func TestValidateSourceAccess_NoBindings(t *testing.T) {
	src := &config.Source{Name: "s"}

	results := service.ValidateSourceAccess(t.Context(), src, nil)
	if len(results) != 0 {
		t.Fatalf("expected no results, got %v", results)
	}
}

func TestValidateSourceAccess_Git(t *testing.T) {
	t.Run("reachable repository", func(t *testing.T) {
		repoPath := t.TempDir() + "/repo"
		repository, err := git.PlainInit(repoPath, false)
		if err != nil {
			t.Fatalf("init test repository: %v", err)
		}
		w, err := repository.Worktree()
		if err != nil {
			t.Fatalf("worktree: %v", err)
		}
		if _, err := w.Commit("init", &git.CommitOptions{Author: &object.Signature{}, AllowEmptyCommits: true}); err != nil {
			t.Fatalf("commit: %v", err)
		}

		ref := "refs/heads/master"
		src := &config.Source{
			Name: "s",
			Git:  config.Git{Repo: repoPath, Reference: &ref},
		}

		results := service.ValidateSourceAccess(t.Context(), src, nil)
		if len(results) != 1 {
			t.Fatalf("expected 1 result, got %v", results)
		}
		if results[0].Type != "git" || results[0].Err != nil {
			t.Fatalf("expected successful git result, got %+v", results[0])
		}
	})

	t.Run("unreachable repository", func(t *testing.T) {
		ref := "refs/heads/master"
		src := &config.Source{
			Name: "s",
			Git:  config.Git{Repo: t.TempDir() + "/does-not-exist", Reference: &ref},
		}

		results := service.ValidateSourceAccess(t.Context(), src, nil)
		if len(results) != 1 {
			t.Fatalf("expected 1 result, got %v", results)
		}
		if results[0].Type != "git" || results[0].Err == nil {
			t.Fatalf("expected a git error, got %+v", results[0])
		}
		if !results[0].UserError {
			t.Fatalf("expected UserError=true for an unreachable repository, got %+v", results[0])
		}
	})
}

func TestValidateSourceAccess_HTTPDatasource(t *testing.T) {
	t.Run("reachable endpoint", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(`{}`))
		}))
		defer ts.Close()

		src := &config.Source{
			Name: "s",
			Datasources: config.Datasources{
				{Name: "ds1", Path: "ds1", Type: "http", Config: map[string]any{"url": ts.URL}},
			},
		}

		results := service.ValidateSourceAccess(t.Context(), src, nil)
		if len(results) != 1 {
			t.Fatalf("expected 1 result, got %v", results)
		}
		if results[0].Type != "http" || results[0].Name != "ds1" || results[0].Err != nil {
			t.Fatalf("expected successful http result, got %+v", results[0])
		}
	})

	t.Run("unauthorized endpoint", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
		}))
		defer ts.Close()

		src := &config.Source{
			Name: "s",
			Datasources: config.Datasources{
				{Name: "ds1", Path: "ds1", Type: "http", Config: map[string]any{"url": ts.URL}},
			},
		}

		results := service.ValidateSourceAccess(t.Context(), src, nil)
		if len(results) != 1 {
			t.Fatalf("expected 1 result, got %v", results)
		}
		if results[0].Err == nil {
			t.Fatalf("expected an error, got %+v", results[0])
		}
		if !results[0].UserError {
			t.Fatalf("expected UserError=true for a 401 response, got %+v", results[0])
		}
	})
}

func TestValidateSourceAccess_UnknownDatasourceTypeSkipped(t *testing.T) {
	src := &config.Source{
		Name: "s",
		Datasources: config.Datasources{
			{Name: "ds1", Path: "ds1", Type: "sql", Config: map[string]any{}},
		},
	}

	results := service.ValidateSourceAccess(t.Context(), src, nil)
	if len(results) != 0 {
		t.Fatalf("expected sql datasources to be skipped (validated separately), got %v", results)
	}
}
