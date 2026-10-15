// Package code is a failure name with no wrapped text.
//
// Threats: an error string that includes a bearer, a grant key, a route
// token, a URL, or file bytes. Callers return Code values and nothing else.
// It does not stop a different package from formatting its own errors.
package code

// Error is a closed-set failure name. Error() is that name alone.
type Error struct {
	C string
}

func (e *Error) Error() string {
	if e == nil || e.C == "" {
		return "internal"
	}
	return e.C
}

// New returns an error whose text is c.
func New(c string) error {
	return &Error{C: c}
}
