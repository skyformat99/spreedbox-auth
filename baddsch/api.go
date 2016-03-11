package baddsch

import (
	"net/http"
)

// APIResourceHolder defines a holder which allow adding of API resources.
type APIResourceHolder interface {
	AddResource(resource interface{}, paths ...string)
	AddResourceWithWrapper(resource interface{}, wrapper func(handler http.HandlerFunc) http.HandlerFunc, paths ...string)
}
