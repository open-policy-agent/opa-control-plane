package util

import (
	"io/fs"
	"testing/fstest"
)

func MapFS(m map[string]string) fs.FS {
	m0 := make(map[string]*fstest.MapFile, len(m))
	for p, f := range m {
		m0[p] = &fstest.MapFile{Data: []byte(f)}
	}
	return fstest.MapFS(m0)
}
