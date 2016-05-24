package owncloud

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"

	"github.com/google/go-querystring/query"
	"golang.struktur.de/spreedbox/spreedbox-auth/auth/owncloud"
	"golang.struktur.de/spreedbox/spreedbox-auth/baddsch"
	"golang.struktur.de/spreedbox/spreedbox-auth/baddsch/httpauth"
)

var DefaultConfigEndpoint = "api/v1/user/config"
var DefaultProviderPoolSize = 4
var DefaultProviderSkipSSLValidation = false
var DefaultProviderLoginFormURL = "/"

func NewProvider(url string, config *ProviderConfig) (baddsch.AuthProvider, error) {
	fullURL := fmt.Sprintf("%s/%s", url, DefaultConfigEndpoint)
	if config == nil {
		config = NewProviderConfig(DefaultProviderSkipSSLValidation, DefaultProviderPoolSize, DefaultProviderLoginFormURL)
	}

	return httpauth.NewProvider(fullURL, func(message []byte, err error) (baddsch.AuthProvided, error) {
		switch err {
		case nil:
			// No error.
		case httpauth.ErrStatusForbidden:
			fallthrough
		case httpauth.ErrStatusUnauthorized:
			// Owncloud returns auth errors as 401.
			return newAuthProvided(config, nil), nil
		default:
			return nil, err
		}

		var response spreedmePluginUserConfig
		err = json.Unmarshal(message, &response)
		if err != nil {
			return nil, err
		}

		return newAuthProvided(config, &response), nil
	}, config)
}

type spreedmePluginUserConfig struct {
	Success     bool   `json:"success"`
	ID          string `json:"id"`
	DisplayName string `json:"display_name"`
	IsAdmin     bool   `json:"is_admin"`
}

type authProvided struct {
	providerConfig *ProviderConfig
	userConfig     *spreedmePluginUserConfig
}

func newAuthProvided(providerConfig *ProviderConfig, userConfig *spreedmePluginUserConfig) *authProvided {
	if userConfig == nil {
		userConfig = &spreedmePluginUserConfig{}
	}
	return &authProvided{providerConfig, userConfig}
}

func (ap *authProvided) Status() bool {
	return ap.userConfig.Success
}

func (ap *authProvided) UserID() string {
	return ap.userConfig.ID
}

func (ap *authProvided) PrivateClaims() map[string]interface{} {
	claims := map[string]interface{}{
		owncloud.DisplayNameClaimID: ap.userConfig.DisplayName,
		owncloud.IsAdminClaimID:     ap.userConfig.IsAdmin,
	}
	return claims
}

func (ap *authProvided) Authorize() bool {
	return ap.Status() == true
}

func (ap *authProvided) RedirectError(err error, ar *baddsch.AuthenticationRequest) (int, interface{}, http.Header) {
	if ap.providerConfig.loginFormURL == "" {
		return http.StatusForbidden, err.Error(), nil
	}

	url, err := url.Parse(ap.providerConfig.loginFormURL)
	if err != nil {
		return http.StatusInternalServerError, err.Error(), nil
	}

	v, _ := query.Values(&LoginRedirectRequest{
		RedirectURL: ar.Options.RedirectURL.String(),
	})
	url.RawQuery = v.Encode()
	url.Fragment = "authprovided=1"

	return http.StatusFound, "", http.Header{
		"Location":      {url.String()},
		"Cache-Control": {"no-store"},
		"Pragma":        {"no-cache"},
	}
}

type ProviderConfig struct {
	skipSSLValidation bool
	poolSize          int
	loginFormURL      string
}

func NewProviderConfig(skipSSLValidation bool, poolSize int, loginFormURL string) *ProviderConfig {
	return &ProviderConfig{skipSSLValidation, poolSize, loginFormURL}
}

func (apc *ProviderConfig) SkipSSLValidation() bool {
	return apc.skipSSLValidation
}

func (apc *ProviderConfig) PoolSize() int {
	if apc.poolSize <= 0 {
		return DefaultProviderPoolSize
	}
	return apc.poolSize
}

type LoginRedirectRequest struct {
	RedirectURL string `url:"redirect_url"`
}
