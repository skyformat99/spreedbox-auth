package httpauth

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"golang.struktur.de/spreedbox/spreedbox-auth/baddsch"

	"golang.struktur.de/sling"
)

type ProvidedHandler func([]byte, error) (baddsch.AuthProvided, error)

type Provider struct {
	client     sling.HTTP
	handler    ProvidedHandler
	serviceURL *url.URL
}

func NewProvider(serviceURLString string, handler ProvidedHandler, config baddsch.AuthProviderConfig) (*Provider, error) {
	serviceURL, err := url.Parse(serviceURLString)
	if err != nil {
		return nil, err
	}
	c := sling.Config{}
	if config != nil {
		c.SkipSSLValidation = config.SkipSSLValidation()
		c.PoolSize = config.PoolSize()
	}

	client, err := sling.NewHTTP(fmt.Sprintf("%s://%s", serviceURL.Scheme, serviceURL.Host), c)
	if err != nil {
		return nil, err
	}
	return &Provider{
		client:     client,
		handler:    handler,
		serviceURL: serviceURL,
	}, nil
}

func (provider *Provider) Authorization(authorization string, cookies []*http.Cookie) (baddsch.AuthProvided, error) {
	request := sling.JSONRequest("GET", provider.serviceURL.Path)

	if authorization != "" {
		request.Header("Authorization", authorization)
	}
	if len(cookies) > 0 {
		var encodedCookies []string
		for _, cookie := range cookies {
			encodedCookies = append(encodedCookies, cookie.String())
		}
		request.Header("Cookie", strings.Join(encodedCookies, "; "))
	}

	var responseData json.RawMessage
	request.
		StatusError(http.StatusUnauthorized, ErrStatusUnauthorized).
		StatusError(http.StatusForbidden, ErrStatusForbidden).
		Response(&responseData)

	err := provider.client.Do(request)
	return provider.handler([]byte(responseData), err)
}
