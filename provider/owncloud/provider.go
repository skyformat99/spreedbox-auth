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

var (
	DefaultConfigEndpoint                 = "api/v1/user/config"
	DefaultProviderPoolSize               = 4
	DefaultProviderSkipSSLValidation      = false
	DefaultProviderLoginFormURL           = "/"
	DefaultProviderBrowserStateCookieName = "oc_spreedbox"
)

func NewProvider(url string, config *ProviderConfig) (baddsch.AuthProvider, error) {
	fullURL := fmt.Sprintf("%s/%s", url, DefaultConfigEndpoint)
	if config == nil {
		config = NewProviderConfig(DefaultProviderSkipSSLValidation, DefaultProviderPoolSize, DefaultProviderLoginFormURL, DefaultProviderBrowserStateCookieName)
	}

	return httpauth.NewProvider(fullURL, func(message []byte, cookies []*http.Cookie, err error) (baddsch.AuthProvided, error) {
		if true {
			// XXX(longsleep): Development helper.
			testResponse := &spreedmePluginUserConfig{
				true,
				"admin",
				"Debug Admin",
				true,
				true,
			}
			return newAuthProvided(config, testResponse, ""), nil
		}

		switch err {
		case nil:
			// No error.
		case httpauth.ErrStatusForbidden:
			fallthrough
		case httpauth.ErrStatusUnauthorized:
			// Owncloud returns auth errors as 401.
			return newAuthProvided(config, nil, ""), nil
		default:
			return nil, err
		}

		var response spreedmePluginUserConfig
		err = json.Unmarshal(message, &response)
		if err != nil {
			return nil, err
		}

		var browserState string
		if cookies != nil && config.browserStateCookieName != "" {
			// Add browser state from cookie.
			for _, cookie := range cookies {
				if cookie.Name == config.browserStateCookieName {
					browserState = cookie.Value
					break
				}
			}
		}

		return newAuthProvided(config, &response, browserState), nil
	}, config)
}

type spreedmePluginUserConfig struct {
	Success         bool   `json:"success"`
	ID              string `json:"id"`
	DisplayName     string `json:"display_name"`
	IsAdmin         bool   `json:"is_admin"`
	IsSpreedmeAdmin bool   `json:"is_spreedme_admin"`
}

type authProvided struct {
	providerConfig *ProviderConfig
	userConfig     *spreedmePluginUserConfig
	browserState   string
}

func newAuthProvided(providerConfig *ProviderConfig, userConfig *spreedmePluginUserConfig, browserState string) *authProvided {
	if userConfig == nil {
		userConfig = &spreedmePluginUserConfig{}
	}
	return &authProvided{providerConfig, userConfig, browserState}
}

func (ap *authProvided) Status() bool {
	return ap.userConfig.Success
}

func (ap *authProvided) UserID() string {
	return ap.userConfig.ID
}

func (ap *authProvided) PrivateClaims() map[string]interface{} {
	claims := map[string]interface{}{
		owncloud.DisplayNameClaimID:     ap.userConfig.DisplayName,
		owncloud.IsAdminClaimID:         ap.userConfig.IsAdmin,
		owncloud.IsSpreedmeAdminClaimID: ap.userConfig.IsSpreedmeAdmin,
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

	// NOTE(longsleep): ownCloud only supports relative URLs, lets hope
	// that the setup is done right, and everything can be relative.
	relativeRedirectURL, _ := url.Parse(ar.Options.RedirectURL.String())
	relativeRedirectURL.Scheme = ""
	relativeRedirectURL.Host = ""
	v, _ := query.Values(&LoginRedirectRequest{
		RedirectURL: relativeRedirectURL.String(),
	})
	url.RawQuery = v.Encode()
	url.Fragment = "authprovided=1"

	return http.StatusFound, "", http.Header{
		"Location":      {url.String()},
		"Cache-Control": {"no-store"},
		"Pragma":        {"no-cache"},
	}
}

func (ap *authProvided) BrowserState() (string, bool) {
	result := false
	if ap.browserState != "" {
		result = true
	}

	return ap.browserState, result
}

type ProviderConfig struct {
	skipSSLValidation      bool
	poolSize               int
	loginFormURL           string
	browserStateCookieName string
}

func NewProviderConfig(skipSSLValidation bool, poolSize int, loginFormURL string, browserStateCookieName string) *ProviderConfig {
	return &ProviderConfig{skipSSLValidation, poolSize, loginFormURL, browserStateCookieName}
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
