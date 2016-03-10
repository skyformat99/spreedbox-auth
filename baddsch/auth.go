package baddsch

type AuthProvider interface {
	RequestAuth(string) (AuthProvided, error)
}

type AuthProvided interface {
	Status() bool
	UserID() string
}
