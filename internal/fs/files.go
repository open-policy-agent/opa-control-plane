package fs

import (
	"errors"
	"io/fs"
	"os"
)

// FSContainsFiles returns true if the given fs.FS contains any files, and false otherwise.
func FSContainsFiles(fsys fs.FS) (bool, error) {
	// errFound is a sentinel error used to stop the walk when a file is found.
	errFound := os.ErrExist

	err := fs.WalkDir(fsys, ".", func(_ string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() {
			// Found a file, so return a special error to stop the walk.
			return errFound
		}
		return nil
	})
	if err == errFound {
		return true, nil
	}
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}

	return false, err
}
