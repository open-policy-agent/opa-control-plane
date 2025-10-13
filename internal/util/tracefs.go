package util

import (
	"io/fs"
	"log"
)

type TraceFS struct{ fsys fs.FS }

func NewTraceFS(fsys fs.FS) fs.FS {
	return &TraceFS{fsys: fsys}
}

func (t *TraceFS) Open(p string) (fs.File, error) {
	f, err := t.fsys.Open(p)
	if err != nil {
		log.Printf("Open(%s) => %v, %v", p, f, err)
	} else {
		fi, _ := f.Stat()
		if !fi.IsDir() {
			log.Printf("Open(%s) => %v size=%d", p, fi.Name(), fi.Size())
		} else {
			log.Printf("Open(%s) => %v dir", p, fi.Name())
		}
	}
	return f, err
}

func Walk(fs_ fs.FS) {
	if err := fs.WalkDir(fs_, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			log.Printf("+ %s/\n", path)
		} else {
			log.Printf("- %s\n", path)
		}
		return nil
	}); err != nil {
		log.Printf("walk: %v", err.Error())
	}
}
