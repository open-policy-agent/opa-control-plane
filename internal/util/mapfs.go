package util

import (
	"io/fs"

	"github.com/knieriem/fsutil"
)

func MapFS(m map[string]string) fs.FS {
	return fsutil.StringMap(m)
}
