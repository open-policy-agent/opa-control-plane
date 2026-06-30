// Package syncerr defines error types for source synchronization.
package syncerr

import "errors"

// UserError wraps a synchronization error that is caused by user
// misconfiguration (e.g. invalid credentials, non-existent repository, bad
// URL) rather than a transient service-side failure. These errors should not
// be retried and should not contribute to service-health alerts.
type UserError struct {
	Cause error
}

func (e UserError) Error() string {
	return e.Cause.Error()
}

func (e UserError) Unwrap() error {
	return e.Cause
}

// IsUserError reports whether err (or any error in its chain) is a UserError.
func IsUserError(err error) bool {
	var u UserError
	return errors.As(err, &u)
}
