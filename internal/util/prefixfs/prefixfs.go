// based on testing/fstest, go1.25.2:
// Copyright 2020 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package prefixfs

import (
	"io"
	"io/fs"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"time"
)

// A PrefixFS is a simple in-memory filesystem for creating new [fs.FS]
// from existing ones, under specific prefixes.
//
// The map need not include parent directories for files contained
// in the map; those will be synthesized if needed.
//
// File system operations must not run concurrently with changes to the
// map, which would be a race.
// Another implication is that opening or reading a directory requires
// iterating over the entire map, so a PrefixFS should typically be
// used with not more than a few hundred entries or directory reads.
type PrefixFS map[string]fs.FS

// A MapFile describes a single file in a [PrefixFS].
type MapFile struct {
	Data    []byte      // file content or symlink destination
	Mode    fs.FileMode // fs.FileInfo.Mode
	ModTime time.Time   // fs.FileInfo.ModTime
	Sys     any         // fs.FileInfo.Sys
}

var _ fs.FS = PrefixFS(nil)

// Open opens the named file after following any symbolic links.
func (fsys PrefixFS) Open(name string) (fs.File, error) {
	if !fs.ValidPath(name) {
		return nil, &fs.PathError{Op: "open", Path: name, Err: fs.ErrNotExist}
	}
	name = filepath.ToSlash(name)
	fs_ := fsys[name]
	if fs_ != nil {
		return &mntDir{path: name, mapFileInfo: mapFileInfo{name: path.Base(name), dir: true}, fsys: fs_}, nil
	}
	for fname := range fsys {
		if strings.HasPrefix(name, fname+"/") {
			name = name[len(fname)+1:]
			return fsys[fname].Open(name)
		}
	}

	// Directory, possibly synthesized.
	// Note that file can be nil here: the map need not contain explicit parent directories for all its files.
	// But file can also be non-nil, in case the user wants to set metadata for the directory explicitly.
	// Either way, we need to construct the list of children of this directory.
	var list []mapFileInfo //nolint:prealloc
	var need = make(map[string]bool)
	if name == "." {
		for fname := range fsys {
			i := strings.Index(fname, "/")
			if i < 0 {
				if fname != "." {
					list = append(list, mapFileInfo{name: fname, dir: true})
				}
			} else {
				need[fname[:i]] = true
			}
		}
	} else {
		prefix := name + "/"
		for fname := range fsys {
			if strings.HasPrefix(fname, prefix) {
				felem := fname[len(prefix):]
				i := strings.Index(felem, "/")
				if i < 0 {
					list = append(list, mapFileInfo{name: felem, dir: true})
				} else {
					need[fname[len(prefix):len(prefix)+i]] = true
				}
			}
		}
		// If the directory name is not in the map,
		// and there are no children of the name in the map,
		// then the directory is treated as not existing.
		if list == nil && len(need) == 0 {
			return nil, &fs.PathError{Op: "open", Path: name, Err: fs.ErrNotExist}
		}
	}
	for _, fi := range list {
		delete(need, fi.name)
	}
	for name := range need {
		list = append(list, mapFileInfo{name: name, f: &MapFile{Mode: fs.ModeDir | 0555}})
	}
	slices.SortFunc(list, func(a, b mapFileInfo) int {
		return strings.Compare(a.name, b.name)
	})

	file := &MapFile{Mode: fs.ModeDir | 0555}
	var elem string
	if name == "." {
		elem = "."
	} else {
		elem = name[strings.LastIndex(name, "/")+1:]
	}
	return &mapDir{path: name, mapFileInfo: mapFileInfo{name: elem, f: file}, entry: list, offset: 0}, nil
}

// A mapFileInfo implements fs.FileInfo and fs.DirEntry for a given map file.
type mapFileInfo struct {
	name string
	dir  bool
	f    *MapFile
}

func (i *mapFileInfo) Name() string               { return path.Base(i.name) }
func (i *mapFileInfo) Size() int64                { return int64(len(i.f.Data)) }
func (i *mapFileInfo) Mode() fs.FileMode          { return i.f.Mode }
func (i *mapFileInfo) Type() fs.FileMode          { return i.f.Mode.Type() }
func (i *mapFileInfo) ModTime() time.Time         { return i.f.ModTime }
func (i *mapFileInfo) IsDir() bool                { return i.dir || i.f.Mode&fs.ModeDir != 0 }
func (i *mapFileInfo) Sys() any                   { return i.f.Sys }
func (i *mapFileInfo) Info() (fs.FileInfo, error) { return i, nil }

func (i *mapFileInfo) String() string {
	return fs.FormatFileInfo(i)
}

// A mapDir is a directory fs.File (so also a fs.ReadDirFile) open for reading.
type mapDir struct {
	path string
	mapFileInfo
	entry  []mapFileInfo
	offset int
}

func (d *mapDir) Stat() (fs.FileInfo, error) { return &d.mapFileInfo, nil }
func (*mapDir) Close() error                 { return nil }
func (d *mapDir) Read(b []byte) (int, error) {
	return 0, &fs.PathError{Op: "read", Path: d.path, Err: fs.ErrInvalid}
}

func (d *mapDir) ReadDir(count int) ([]fs.DirEntry, error) {
	n := len(d.entry) - d.offset
	if n == 0 && count > 0 {
		return nil, io.EOF
	}
	if count > 0 && n > count {
		n = count
	}
	list := make([]fs.DirEntry, n)
	for i := range list {
		list[i] = &d.entry[d.offset+i]
	}
	d.offset += n
	return list, nil
}

type mntDir struct {
	path string
	mapFileInfo
	fsys fs.FS
}

func (*mntDir) Close() error                 { return nil }
func (d *mntDir) Stat() (fs.FileInfo, error) { return &d.mapFileInfo, nil }
func (d *mntDir) Read(b []byte) (int, error) {
	return 0, &fs.PathError{Op: "read", Path: d.path, Err: fs.ErrInvalid}
}

func (d *mntDir) ReadDir(_ int) ([]fs.DirEntry, error) {
	return fs.ReadDir(d.fsys, ".") // NB(sr): We're ignoring the count, for our usage, that's OK.
}
