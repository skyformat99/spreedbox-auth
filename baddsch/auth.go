package baddsch

type AuthProvider interface {
	Authorization(string) (AuthProvided, error)
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
}

type NoAuthProvided struct{}

func (nap *NoAuthProvided) Status() bool {
	return false
}

func (nap *NoAuthProvided) UserID() string {
	return ""
}

func (nap *NoAuthProvided) PrivateClaims() map[string]interface{} {
	return make(map[string]interface{})
}

func (nap *NoAuthProvided) Authorize() bool {
	return false
}
