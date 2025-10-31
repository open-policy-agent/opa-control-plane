package database

import "errors"

var (
	ErrNotFound      = errors.New("not found")
	ErrNotAuthorized = errors.New("not authorized")
	ErrDataConflict  = errors.New("data conflict")
)
