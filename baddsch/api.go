package baddsch

import (
	"net/http"
)

// APIResourceHolder defines a holder which allow adding of API resources.
type APIResourceHolder interface {
	AddResource(resource interface{}, paths ...string)
	AddResourceWithWrapper(resource interface{}, wrapper func(handler http.HandlerFunc) http.HandlerFunc, paths ...string)
}

// API is a flexible way to define an API and combining it with a holder.
type API interface {
	AddResources(holder APIResourceHolder, authProvider AuthProvider) error
}
