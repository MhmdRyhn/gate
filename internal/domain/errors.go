package domain

import (
	"errors"
	"fmt"
)

// Sentinel errors shared by all layers. The HTTP layer maps them to status
// codes; wrap them with fmt.Errorf("%w: ...") to add detail.
var (
	ErrNotFound           = errors.New("not found")
	ErrConflict           = errors.New("conflict")
	ErrUnauthenticated    = errors.New("authentication required")
	ErrInvalidCredentials = errors.New("invalid email or password")
	ErrInvalidToken       = errors.New("invalid or expired token")
	ErrUserDisabled       = errors.New("account is disabled")
	ErrForbidden          = errors.New("forbidden")
)

// ValidationError reports invalid input from the client.
type ValidationError struct {
	Message string
}

func (e *ValidationError) Error() string { return e.Message }

func Invalid(format string, args ...any) error {
	return &ValidationError{Message: fmt.Sprintf(format, args...)}
}
