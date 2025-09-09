package database

import (
	"errors"
)

var ErrNotFound = errors.New("not found")
var ErrNotAuthorized = errors.New("not authorized")
