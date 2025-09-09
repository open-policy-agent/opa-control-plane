package builtinsync_test

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/styrainc/opa-control-plane/internal/builtinsync"
	"github.com/styrainc/opa-control-plane/internal/test/libraries"
	"github.com/styrainc/opa-control-plane/internal/test/tempfs"
	"github.com/styrainc/opa-control-plane/internal/util"
)

func TestBuiltinSync(t *testing.T) {
	tempfs.WithTempFS(t, map[string]string{}, func(t *testing.T, dir string) {
		s := builtinsync.New(util.NewEscapeFS(libraries.FS), dir, "root/subdir")
		err := s.Execute(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		var paths []string
		if err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			paths = append(paths, strings.TrimPrefix(path, dir))
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		// root directory is included so expect "" in addition to fixtures
		exp := []string{"", "/test", "/test/test.rego"}
		if !reflect.DeepEqual(paths, exp) {
			t.Fatalf("exp: %v\ngot: %v", exp, paths)
		}
	})
}
