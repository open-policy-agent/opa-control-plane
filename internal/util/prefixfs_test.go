package util

import (
	"os"
	"testing"
	"testing/fstest"
)

func TestFS(t *testing.T) {
	t0 := PrefixFS("foo/bar", os.DirFS("."))
	if err := fstest.TestFS(t0, "foo/bar"); err != nil {
		t.Error(err)
	}
}
