package baddsch

type AuthProvider interface {
	Authorization(string) (AuthProvided, error)
}

type AuthProvided interface {
	Status() bool
	UserID() string
}
