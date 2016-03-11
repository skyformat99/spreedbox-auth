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
}
