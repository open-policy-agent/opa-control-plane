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
