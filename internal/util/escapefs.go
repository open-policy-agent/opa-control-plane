package util

import (
	"errors"
	"io"
	"io/fs"
	"strings"
	"time"
)

var (
	_ fs.FS          = (*escapeFS)(nil)
	_ fs.ReadDirFS   = (*escapeFS)(nil)
	_ fs.FileInfo    = (*file)(nil)
	_ fs.DirEntry    = (*file)(nil)
	_ fs.File        = (*openFile)(nil)
	_ fs.ReadDirFile = (*openDir)(nil)
)

type file struct {
	f interface{}
}

func (f *file) file() fs.FileInfo {
	return f.f.(fs.FileInfo)
}

func (f *file) dir() fs.DirEntry {
	return f.f.(fs.DirEntry)
}

func (f *file) Name() string {
	return unescape(f.file().Name())
}

func (f *file) Size() int64        { return f.file().Size() }
func (f *file) ModTime() time.Time { return f.file().ModTime() }
func (f *file) IsDir() bool        { return f.file().IsDir() }
func (f *file) Sys() any           { return f.file().Sys() }
func (f *file) Type() fs.FileMode  { return f.dir().Type() }

func (f *file) Info() (fs.FileInfo, error) {
	info, err := f.dir().Info()
	return unescapeInfo(info), err
}

func (f *file) Mode() fs.FileMode { return f.file().Mode() }
func (f *file) String() string    { return fs.FormatFileInfo(f) }

type escapeFS struct {
	fs fs.ReadDirFS
}

func NewEscapeFS(f fs.ReadDirFS) fs.ReadDirFS {
	return &escapeFS{fs: f}
}

func (f *escapeFS) Open(name string) (fs.File, error) {
	entry, err := f.fs.Open(escape(name))
	if err != nil {
		return nil, unescapeError(err)
	}

	stat, err := entry.Stat()
	if err != nil {
		return nil, unescapeError(err)
	}

	if stat.IsDir() {
		return &openDir{stat, entry.(fs.ReadDirFile)}, nil
	}

	return &openFile{entry}, nil
}

func (f *escapeFS) ReadDir(name string) ([]fs.DirEntry, error) {
	entries, err := f.fs.ReadDir(escape(name))
	for i := range entries {
		entries[i] = &file{entries[i]}
	}

	return entries, unescapeError(err)
}

type openFile struct {
	f fs.File
}

func (f openFile) Close() error {
	return f.f.Close()
}
func (f *openFile) Stat() (fs.FileInfo, error) {
	info, err := f.f.Stat()
	return unescapeInfo(info), err
}
func (f *openFile) Read(b []byte) (int, error) { return f.f.Read(b) }
func (f *openFile) Seek(offset int64, whence int) (int64, error) {
	return f.f.(io.Seeker).Seek(offset, whence)
}
func (f *openFile) ReadAt(b []byte, offset int64) (int, error) {
	return f.f.(io.ReaderAt).ReadAt(b, offset)
}

type openDir struct {
	f fs.FileInfo
	d fs.ReadDirFile
}

func (*openDir) Close() error { return nil }
func (d *openDir) Stat() (fs.FileInfo, error) {
	return unescapeInfo(d.f), nil
}

func (d *openDir) Read([]byte) (int, error) {
	return 0, &fs.PathError{Op: "read", Path: unescape(d.f.Name()), Err: errors.New("is a directory")}
}

func (d *openDir) ReadDir(n int) ([]fs.DirEntry, error) {
	entries, err := d.d.ReadDir(n)
	for i := range entries {
		entries[i] = &file{entries[i]}
	}

	return entries, unescapeError(err)
}

type fileInfo struct {
	info fs.FileInfo
}

func (f *fileInfo) Name() string       { return unescape(f.info.Name()) }
func (f *fileInfo) Size() int64        { return f.info.Size() }
func (f *fileInfo) Mode() fs.FileMode  { return f.info.Mode() }
func (f *fileInfo) ModTime() time.Time { return f.info.ModTime() }
func (f *fileInfo) IsDir() bool        { return f.info.IsDir() }
func (f *fileInfo) Sys() any           { return f.info.Sys() }

func unescapeError(err error) error {
	if err == nil {
		return nil
	}

	if err, ok := err.(*fs.PathError); ok {
		return &fs.PathError{Op: "open", Path: unescape(err.Path), Err: err.Err}
	}

	return err
}

func unescapeInfo(info fs.FileInfo) fs.FileInfo {
	if info == nil {
		return nil
	}

	return &fileInfo{info}
}

// Escape ':' with "#" and '#' with double '#'. This is to work around the restricted ':' in embedded file names.

// unescape replaces first "##" with "#" and then replaces all remaining "#" with ":".
func unescape(path string) string {
	var result string

	for len(path) > 0 {
		if i := strings.Index(path, "##"); i != -1 {
			result += path[:i+1] // Drop the second '#' to treat "##" as a single '#'.
			path = path[i+2:]
		} else if i := strings.Index(path, "#"); i != -1 {
			result += path[:i] + ":" // Replace single '#' with ':'
			path = path[i+1:]
		} else {
			result += path // No more "##" found, append the rest
			path = ""
		}
	}

	return result
}

// escape replaces first '#' with '##' and then replaces all remaining ':' with '#'.
func escape(path string) string {
	path = strings.ReplaceAll(path, "#", "##")
	return strings.ReplaceAll(path, ":", "#")
}
