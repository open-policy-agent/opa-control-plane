package util

import (
	"io/fs"
	"path/filepath"

	"github.com/knieriem/fsutil"
)

type NamespaceFS interface {
	fs.FS
	Bind(string, fs.FS) error
}

type ns struct {
	ns *fsutil.NameSpace
}

func Namespace() NamespaceFS {
	return &ns{
		ns: &fsutil.NameSpace{},
	}
}

func (n *ns) Bind(old string, fsys fs.FS) error {
	return n.ns.Bind(old, fsys)
}

func (n *ns) Open(p string) (fs.File, error) {
	// This is needed because when OPA's compile.Build() produces a bundle
	// from fs.FS, it'll attempt to access files by calling `filepath.Join(path, filename)`,
	// which gives `\`-separated paths on Windows, and knieriem/fsutil can't
	// deal with that.
	return n.ns.Open(filepath.ToSlash(p))
}
