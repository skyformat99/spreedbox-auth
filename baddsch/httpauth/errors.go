package httpauth

import (
	"errors"
	"net/http"
)

var (
	ErrStatusUnauthorized = errors.New(http.StatusText(http.StatusUnauthorized))
	ErrStatusForbidden    = errors.New(http.StatusText(http.StatusForbidden))
)
