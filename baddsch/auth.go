package baddsch

import (
	"net/http"
	"net/url"
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
	RedirectSuccess(*url.URL, interface{}, bool, *AuthenticationRequest) (int, interface{}, http.Header)
	BrowserState() *BrowserState
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

func (nap *NoAuthProvided) RedirectSuccess(url *url.URL, params interface{}, fragment bool, ar *AuthenticationRequest) (int, interface{}, http.Header) {
	return http.StatusNotFound, "", nil
}

func (nap *NoAuthProvided) BrowserState() *BrowserState {
	return nil
}

type BrowserState struct {
	value string
	ref   string
}

func NewBrowserState(value, ref string) *BrowserState {
	return &BrowserState{value, ref}
}

func (bs *BrowserState) Value() string {
	return bs.value
}

func (bs *BrowserState) Ref() string {
	return bs.ref
}

func (bs *BrowserState) String() string {
	return bs.Value()
}
