package util

import (
	"io/fs"
	"path/filepath"
	"slices"

	"github.com/gobwas/glob"
)

var _ fs.FS = (*FilterFS)(nil)

type FilterFS struct {
	fs       fs.FS
	included []glob.Glob // List of file patterns to include
	excluded []glob.Glob // List of file patterns to exclude (overrides includes)
}

type filteredDir struct {
	d        fs.ReadDirFile
	path     string
	included []glob.Glob
	excluded []glob.Glob
}

func NewFilterFS(fs fs.FS, include []string, exclude []string) (*FilterFS, error) {
	ffs := FilterFS{fs: fs}

	for _, pattern := range include {
		g, err := glob.Compile(pattern)
		if err != nil {
			return nil, err
		}

		ffs.included = append(ffs.included, g)
	}

	for _, pattern := range exclude {
		g, err := glob.Compile(pattern)
		if err != nil {
			return nil, err
		}

		ffs.excluded = append(ffs.excluded, g)
	}

	return &ffs, nil
}

func (f *FilterFS) Open(name string) (fs.File, error) {
	sname := filepath.ToSlash(filepath.Clean(name))

	if isExcluded(f.excluded, name) {
		return nil, &fs.PathError{
			Op:   "open",
			Path: name,
			Err:  fs.ErrNotExist,
		}
	}

	file, err := f.fs.Open(sname)
	if err != nil {
		return nil, err
	}

	if dir, ok := file.(fs.ReadDirFile); ok {
		return &filteredDir{d: dir, path: sname, included: f.included, excluded: f.excluded}, nil
	}

	if !isIncluded(f.included, sname) {
		return nil, &fs.PathError{
			Op:   "open",
			Path: name,
			Err:  fs.ErrNotExist,
		}
	}

	return file, nil
}

func (d *filteredDir) ReadDir(n int) ([]fs.DirEntry, error) {
	entries, err := d.d.ReadDir(n)
	if err != nil {
		return nil, err
	}

	var filtered []fs.DirEntry
	for _, entry := range entries {
		path := filepath.ToSlash(filepath.Join(d.path, entry.Name())) // Join calls Clean
		if !isExcluded(d.excluded, path) {
			if !entry.IsDir() && !isIncluded(d.included, path) {
				continue
			}
			filtered = append(filtered, entry)
		}
	}

	return filtered, nil
}

func (d *filteredDir) Close() error {
	return d.d.Close()
}

func (d *filteredDir) Stat() (fs.FileInfo, error) {
	return d.d.Stat()
}

func (d *filteredDir) Read(bs []byte) (int, error) {
	return d.d.Read(bs)
}

func isExcluded(excluded []glob.Glob, name string) bool {
	name = filepath.ToSlash(filepath.Clean(name))
	return slices.ContainsFunc(excluded, func(g glob.Glob) bool {
		return g.Match(name)
	})
}

func isIncluded(included []glob.Glob, name string) bool {
	name = filepath.ToSlash(filepath.Clean(name))
	return len(included) == 0 || slices.ContainsFunc(included, func(g glob.Glob) bool {
		return g.Match(name)
	})
}
