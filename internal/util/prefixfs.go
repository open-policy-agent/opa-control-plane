package util

import (
	"io"
	"io/fs"
	"log"
	"path/filepath"
	"strings"
	"time"
)

type prefixFS struct {
	pathPrefix string
	underlying fs.FS
	prefixInfo prefixBaseInfo
}

// PrefixFS returns a file system with a pathPrefix added in front
// of each file and directory of the provided file system fsys.
// Options allow to specify a modification time and permissions for the
// path elements of the prefix, with current time and 0755 used as defaults.
func PrefixFS(pathPrefix string, fsys fs.FS, option ...PrefixFSOption) fs.FS {
	pfs := &prefixFS{pathPrefix: pathPrefix, underlying: fsys}
	pfs.prefixInfo.perm = 0o755
	for _, o := range option {
		o(pfs)
	}
	if pfs.prefixInfo.modTime.IsZero() {
		pfs.prefixInfo.modTime = time.Now()
	}
	return pfs
}

type PrefixFSOption func(*prefixFS)

// WithModTime sets the modification time of prefix path elements.
func WithModTime(t time.Time) PrefixFSOption {
	return func(fsys *prefixFS) {
		fsys.prefixInfo.modTime = t
	}
}

// WithPerm sets the permissions of prefix path elements to perm.
func WithPerm(perm fs.FileMode) PrefixFSOption {
	return func(fsys *prefixFS) {
		fsys.prefixInfo.perm = perm
	}
}

var _ fs.ReadDirFS = &prefixFS{}

func (fsys *prefixFS) Open(p string) (fs.File, error) {
	lfs, name, err := fsys.lookupFS(p, "open")
	if err != nil {
		return nil, err
	}
	log.Printf("<%T>.Open(%s), name:%s", lfs, p, name)
	return lfs.Open(name)
}

func (fsys *prefixFS) ReadDir(p string) ([]fs.DirEntry, error) {
	lfs, name, err := fsys.lookupFS(p, "readdir")
	if err != nil {
		return nil, err
	}
	log.Printf("<%T>.ReadDir(%s), name:%s", lfs, p, name)
	return fs.ReadDir(lfs, name)
}

func (fsys *prefixFS) lookupFS(path, op string) (fs.FS, string, error) {
	log.Printf("prefix<%s>.lookupFS(%s, %s)", fsys.pathPrefix, path, op)
	name := path
	if !fs.ValidPath(name) {
		return nil, "", &fs.PathError{Op: op, Path: name, Err: fs.ErrInvalid}
	}
	if name == "." {
		name = ""
	}
	newErrNotExist := func() error {
		return &fs.PathError{Op: op, Path: name, Err: fs.ErrNotExist}
	}
	if strings.HasPrefix(name, fsys.pathPrefix) {
		name = name[len(fsys.pathPrefix):]
		if name != "" {
			if name[0] != '/' {
				return nil, "", newErrNotExist()
			}
			name = name[1:]
			return fsys.underlying, name, nil
		} else { // name == "", split point
			seg := &pathseg{name: filepath.Base(fsys.pathPrefix), fsys: fsys.underlying, baseInfo: &fsys.prefixInfo}
			return &pathsegFS{mount: true, seg: seg}, name, nil
		}
	}
	if len(name) >= len(fsys.pathPrefix) {
		return nil, "", newErrNotExist()
	}
	if !strings.HasPrefix(fsys.pathPrefix, name) {
		return nil, "", newErrNotExist()
	}
	s := fsys.pathPrefix[len(name):]
	t := fsys.pathPrefix[:len(name)]
	log.Printf("s: %s, t: %s", s, t)
	if name != "" {
		if s[0] != '/' {
			return nil, "", newErrNotExist()
		}
		s = s[1:]
	}
	if op == "open" {
		if i := strings.LastIndexByte(name, '/'); i != -1 {
			s = name[i+1:]
		} else if path == "." { // treat with suspicion
			s = "."
		} else {
			s = t // heh
		}
		log.Printf("~~> s: %s", s)
	} else {
		if i := strings.IndexByte(s, '/'); i != -1 {
			s = s[:i]
		}
	}

	seg := pathseg{name: s, fsys: fsys, baseInfo: &fsys.prefixInfo}
	return &pathsegFS{seg: &seg}, name, nil
}

type pathsegFS struct {
	mount bool
	seg   *pathseg
}

func (s *pathsegFS) Open(name string) (fs.File, error) {
	log.Printf("Open(%s), s.seg.name: %s", name, s.seg.name)
	return s.seg, nil
}

func (s *pathsegFS) ReadDir(name string) ([]fs.DirEntry, error) {
	log.Printf("ReadDir(%s), mount %v, s.seg.name: %v", name, s.mount, s.seg.name)
	if s.mount {
		return fs.ReadDir(s.seg.fsys, ".")
	}
	return []fs.DirEntry{&pathsegInfo{s.seg}}, nil
}

type pathseg struct {
	name     string
	baseInfo *prefixBaseInfo
	fsys     fs.FS
}

func (*pathseg) Read([]byte) (int, error) {
	return 0, io.EOF
}

func (p *pathseg) ReadDir(int) ([]fs.DirEntry, error) {
	return fs.ReadDir(p.fsys, ".")
}

func (*pathseg) ReadFiles([]byte) (int, error) {
	return 0, io.EOF
}

func (s *pathseg) Stat() (fs.FileInfo, error) {
	return &pathsegInfo{s}, nil
}

func (*pathseg) Close() error {
	return nil
}

type pathsegInfo struct {
	seg *pathseg
}

func (info *pathsegInfo) Name() string {
	return info.seg.name
}

func (*pathsegInfo) Size() int64 {
	return 0
}

func (*pathsegInfo) Type() fs.FileMode {
	return fs.ModeDir
}

func (info *pathsegInfo) Info() (fs.FileInfo, error) {
	return info, nil
}

func (*pathsegInfo) IsDir() bool {
	return true
}

func (*pathsegInfo) Sys() interface{} {
	return nil
}

func (info *pathsegInfo) Mode() fs.FileMode {
	return info.seg.baseInfo.perm | fs.ModeDir
}

func (info *pathsegInfo) ModTime() time.Time {
	return info.seg.baseInfo.modTime
}

type prefixBaseInfo struct {
	modTime time.Time
	perm    fs.FileMode
}
