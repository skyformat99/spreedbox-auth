package httpauth

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"time"

	"golang.struktur.de/spreedbox/spreedbox-auth/baddsch"

	"golang.struktur.de/sling"
)

var (
	httpauthTimingBase      = int64(1600)
	httpauthTimingOffsetMax = big.NewInt(300)
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

	// Constant time to avoid timing based information leaks.
	add, _ := rand.Int(rand.Reader, httpauthTimingOffsetMax)
	timer := time.NewTimer(time.Duration(httpauthTimingBase+add.Int64()) * time.Millisecond)

	var responseData json.RawMessage
	request.
		StatusError(http.StatusUnauthorized, ErrStatusUnauthorized).
		StatusError(http.StatusForbidden, ErrStatusForbidden).
		Response(&responseData)

	err := provider.client.Do(request)

	// Wait until timer reached.
	<-timer.C

	return provider.handler([]byte(responseData), err)
}
