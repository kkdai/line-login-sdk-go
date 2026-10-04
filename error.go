package social

import (
	"bytes"
	"errors"
	"fmt"
)

// errors
var (
	ErrInvalidSignature = errors.New("invalid signature")
)

// APIError type
type APIError struct {
	Code     int
	Response *ErrorResponse

	// RequestID is the value of the x-line-request-id response header, useful when
	// contacting LINE support. Empty if the header was not present.
	RequestID string
}

// Error method
func (e *APIError) Error() string {
	var buf bytes.Buffer
	fmt.Fprintf(&buf, "Social SDK: APIError %d ", e.Code)
	if e.RequestID != "" {
		fmt.Fprintf(&buf, "(x-line-request-id: %s) ", e.RequestID)
	}
	if e.Response != nil {
		fmt.Fprintf(&buf, "%s", e.Response.Message)
		for _, d := range e.Response.Details {
			fmt.Fprintf(&buf, "\n[%s] %s", d.Property, d.Message)
		}
	}
	return buf.String()
}
