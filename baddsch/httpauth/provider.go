package httpauth

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"

	"golang.struktur.de/spreedbox/spreedbox-auth/baddsch"

	"golang.struktur.de/sling"
)

type ProvidedHandler func([]byte, error) (baddsch.AuthProvided, error)

type Provider struct {
	client     sling.HTTP
	handler    ProvidedHandler
	serviceURL *url.URL
}

func NewProvider(serviceURLString string, handler ProvidedHandler) (*Provider, error) {
	serviceURL, err := url.Parse(serviceURLString)
	if err != nil {
		return nil, err
	}
	config := sling.Config{
		SkipSSLValidation: true,
	}
	client, err := sling.NewHTTP(fmt.Sprintf("%s://%s", serviceURL.Scheme, serviceURL.Host), config)
	if err != nil {
		return nil, err
	}
	return &Provider{
		client:     client,
		handler:    handler,
		serviceURL: serviceURL,
	}, nil
}

func (provider *Provider) Authorization(authorization string) (baddsch.AuthProvided, error) {
	request := sling.JSONRequest("GET", provider.serviceURL.Path)

	var responseData json.RawMessage
	request.
		Header("Authorization", authorization).
		StatusError(http.StatusUnauthorized, ErrStatusUnauthorized).
		StatusError(http.StatusForbidden, ErrStatusForbidden).
		Response(&responseData)

	err := provider.client.Do(request)
	return provider.handler([]byte(responseData), err)
}
