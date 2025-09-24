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

// NewFilterFS takes an fs.FS instances and lists of glob strings to be included and excluded.
// On Open(), it'll return `fs.ErrNotExist` if the file is excluded, or if the include list is
// non-empty and the file wasn't explicitly included.
// Both glob lists expect /-separated paths.
// On ReadDir(), the same logic applies, except that any directory is returned, unless it is
// explicitly excluded. With typical usage, it'll result in many empty directories; but for
// our use case of feeding the `fs.FS` into OPA's bundle build machinery, that doesn't make a
// difference.
// Filtering by ReadDir() lets us avoid listing files that we'll not allow access to. When
// building a bundle using fs.FS, not doing this would give us "file does not exist" errors
// for excluded files.
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
