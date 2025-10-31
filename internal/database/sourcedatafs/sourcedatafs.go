package sourcedatafs

import (
	"context"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sync"
	"time"

	"github.com/open-policy-agent/opa-control-plane/internal/fs/mountfs"
	"github.com/yalue/merged_fs"
)

func New(ctx context.Context,
	files []string,
	fetchFn func(string) func(context.Context) ([]byte, error),
) fs.FS {
	fses := make([]fs.FS, 0, len(files))
	for _, file := range files {
		p := filepath.Dir(file)
		fs_ := NewSingleFS(ctx, fetchFn(file))
		fses = append(fses, mountfs.New(map[string]fs.FS{p: fs_}))
	}
	return merged_fs.MergeMultiple(fses...)
}

// sourceDataFS implements fs.FS for a single "data.json" file.
type sourceDataFS struct {
	dataFn func(context.Context) ([]byte, error)
	data   []byte
	err    error
	once   sync.Once
	ctx    context.Context
}

// NewSingleFS creates a new fs.FS instance. The dataFn is a function that will be
// called to generate the JSON data the first time the file is accessed.
func NewSingleFS(ctx context.Context, dataFn func(context.Context) ([]byte, error)) fs.FS {
	return newSingleReadDirFS(&sourceDataFS{dataFn: dataFn, ctx: ctx})
}

// Open implements fs.FS.Open. It returns a file for "data.json" or an error
// if the file is not found.
func (f *sourceDataFS) Open(name string) (fs.File, error) {
	if name != "data.json" {
		return nil, &fs.PathError{Op: "open", Path: name, Err: fs.ErrNotExist}
	}

	f.once.Do(func() {
		f.data, f.err = f.dataFn(f.ctx)
	})

	if f.err != nil {
		return nil, f.err // Return the error from the data function
	}

	return &single{data: f.data, name: name}, nil
}

// single implements fs.File and fs.Stat for the "data.json" file.
type single struct {
	data []byte
	off  int
	name string
}

// Read implements io.Reader.
func (f *single) Read(p []byte) (n int, err error) {
	if f.off >= len(f.data) {
		return 0, io.EOF
	}
	n = copy(p, f.data[f.off:])
	f.off += n
	return n, nil
}

// Stat implements fs.Stat.
func (f *single) Stat() (fs.FileInfo, error) {
	return &singleInfo{name: f.name, size: int64(len(f.data))}, nil
}

// Close implements io.Closer.
func (*single) Close() error {
	return nil
}

// singleInfo implements fs.FileInfo.
type singleInfo struct {
	name string
	size int64
}

func (i *singleInfo) Name() string     { return path.Base(i.name) }
func (i *singleInfo) Size() int64      { return i.size }
func (*singleInfo) Mode() os.FileMode  { return 0444 }        // Read-only for all.
func (*singleInfo) ModTime() time.Time { return time.Time{} } // Zero value since it's synthetic.
func (*singleInfo) IsDir() bool        { return false }
func (*singleInfo) Sys() any           { return nil }

// Implement ReadDirFS to provide directory listing of one file: data.json
type singleDir struct {
	fsys fs.FS
}

func newSingleReadDirFS(fsys fs.FS) fs.ReadDirFS {
	return &singleDir{fsys: fsys}
}

func (r *singleDir) Open(name string) (fs.File, error) {
	return r.fsys.Open(name)
}

func (r *singleDir) ReadDir(name string) ([]fs.DirEntry, error) {
	if name != "." {
		return nil, &fs.PathError{Op: "readdir", Path: name, Err: fs.ErrNotExist}
	}

	// Create a DirEntry for "data.json"
	fileInfo, err := fs.Stat(r.fsys, "data.json")
	if err != nil {
		return nil, err
	}

	return []fs.DirEntry{fs.FileInfoToDirEntry(fileInfo)}, nil
}
