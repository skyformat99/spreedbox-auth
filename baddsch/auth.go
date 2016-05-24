package baddsch

import (
	"net/http"
)

type AuthProvider interface {
	Authorization(string, []*http.Cookie) (AuthProvided, error)
}

type AuthProviderConfig interface {
	SkipSSLValidation() bool
	PoolSize() int
}

type AuthProvided interface {
	Status() bool
	UserID() string
	PrivateClaims() map[string]interface{}
	Authorize() bool
	RedirectError(error, *AuthenticationRequest) (int, interface{}, http.Header)
}

type NoAuthProvided struct{}

func (nap *NoAuthProvided) Status() bool {
	return false
}

func (nap *NoAuthProvided) UserID() string {
	return ""
}

func (nap *NoAuthProvided) PrivateClaims() map[string]interface{} {
	return nil
}

func (nap *NoAuthProvided) Authorize() bool {
	return false
}

func (nap *NoAuthProvided) RedirectError(err error, ar *AuthenticationRequest) (int, interface{}, http.Header) {
	return http.StatusNotFound, "", nil
}
