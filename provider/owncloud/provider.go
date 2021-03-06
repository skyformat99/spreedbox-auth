package owncloud

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"

	"golang.struktur.de/spreedbox/spreedbox-auth/auth"
	"golang.struktur.de/spreedbox/spreedbox-auth/auth/owncloud"
	"golang.struktur.de/spreedbox/spreedbox-auth/baddsch"
	"golang.struktur.de/spreedbox/spreedbox-auth/baddsch/httpauth"
)

var (
	DefaultConfigEndpoint                 = "api/v1/user/config"
	DefaultProviderPoolSize               = 4
	DefaultProviderSkipSSLValidation      = false
	DefaultProviderLoginFormURL           = "/login"
	DefaultProviderBrowserStateCookieName = "oc_spreedbox"
)

func NewProvider(url string, config *ProviderConfig) (baddsch.AuthProvider, error) {
	fullURL := fmt.Sprintf("%s/%s", url, DefaultConfigEndpoint)
	if config == nil {
		config = NewProviderConfig(DefaultProviderSkipSSLValidation, DefaultProviderPoolSize, DefaultProviderLoginFormURL, DefaultProviderBrowserStateCookieName)
	}

	return httpauth.NewProvider(fullURL, func(message []byte, cookies []*http.Cookie, err error) (baddsch.AuthProvided, error) {
		if false {
			// XXX(longsleep): Development helper.
			log.Println("DEBUG auth path enabled", cookies)
			var testResponse *spreedmePluginUserConfig
			for _, cookie := range cookies {
				if cookie.Name == "spreedbox-auth-test" && cookie.Value == "true" {
					testResponse = &spreedmePluginUserConfig{
						true,
						"admin",
						"Debug Admin",
						true,
						true,
						"some-state",
					}
					break
				}
			}

			return newAuthProvided(config, testResponse, cookies), nil
		}

		switch err {
		case nil:
			// No error.
		case httpauth.ErrStatusForbidden:
			fallthrough
		case httpauth.ErrStatusUnauthorized:
			// Owncloud returns auth errors as 401.
			return newAuthProvided(config, nil, cookies), nil
		default:
			// Handle all other errors similar to unauthorized, but with error.
			return newAuthProvided(config, nil, cookies), err
		}

		var response spreedmePluginUserConfig
		err = json.Unmarshal(message, &response)
		if err != nil {
			return nil, err
		}

		return newAuthProvided(config, &response, cookies), nil
	}, config)
}

type spreedmePluginUserConfig struct {
	Success         bool   `json:"success"`
	ID              string `json:"id"`
	DisplayName     string `json:"display_name"`
	IsAdmin         bool   `json:"is_admin"`
	IsSpreedmeAdmin bool   `json:"is_spreedme_admin"`
	State           string `json:"state"`
}

type authProvided struct {
	providerConfig *ProviderConfig
	userConfig     *spreedmePluginUserConfig
	browserState   *baddsch.BrowserState
}

func newAuthProvided(providerConfig *ProviderConfig, userConfig *spreedmePluginUserConfig, cookies []*http.Cookie) *authProvided {
	if userConfig == nil {
		userConfig = &spreedmePluginUserConfig{}
	}

	var browserState *baddsch.BrowserState
	if cookies != nil && providerConfig.browserStateCookieName != "" {
		// Add browser state from cookie.
		for _, cookie := range cookies {
			if cookie.Name == providerConfig.browserStateCookieName {
				browserState = baddsch.NewBrowserState(cookie.Value, cookie.Name)
				break
			}
		}
	}

	return &authProvided{providerConfig, userConfig, browserState}
}

func (ap *authProvided) Status() bool {
	return ap.userConfig.Success
}

func (ap *authProvided) UserID() string {
	return ap.userConfig.ID
}

func (ap *authProvided) PrivateClaims(idToken bool, ar *baddsch.AuthenticationRequest) map[string]interface{} {
	claims := make(map[string]interface{})

	// ID token only claims.
	if idToken {
		if profile, _ := ar.Options.Scopes["profile"]; profile {
			// Support a subset of the profile scope, when asked for.
			claims["name"] = ap.userConfig.DisplayName
		}

		return claims
	}

	// access tokens claims.

	// Spreedbox scope support. Also used when "token" request for
	// legacy reasons.
	if spreedbox, _ := ar.Options.Scopes[auth.SpreedboxScopeID]; spreedbox ||
		ar.ResponseType == "token" {
		if ap.userConfig.ID != "" && ap.userConfig.Success {
			claims[auth.SpreedboxIsUserClaimID] = true
			claims[owncloud.IsAdminClaimID] = ap.userConfig.IsAdmin
			claims[owncloud.IsSpreedmeAdminClaimID] = ap.userConfig.IsSpreedmeAdmin
		}
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
	query := &LoginRedirectRequest{
		RedirectURL: relativeRedirectURL.String(),
	}
	url.Fragment = "authprovided=1"

	return ar.Redirect(url, query, false, nil)
}

func (ap *authProvided) RedirectSuccess(url *url.URL, params interface{}, fragment bool, ar *baddsch.AuthenticationRequest) (int, interface{}, http.Header) {
	var headers http.Header

	if ar.Options.WithSessionState {
		// The ownCloud provider sets the ownCloud state as cookie so the
		// Javascript library can detect changes quickly.
		browserState := ap.BrowserState()
		ocState := ap.userConfig.State

		var cookie *http.Cookie
		if ap.providerConfig.browserStateCookieName != "" {
			if ocState == "" && browserState != nil {
				// Expire cookie.
				cookie = &http.Cookie{
					Name:   ap.providerConfig.browserStateCookieName,
					MaxAge: -1,
					Secure: true,
				}
			} else if ocState != "" && (browserState == nil || ocState != browserState.Value()) {
				// Set new cookie.
				cookie = &http.Cookie{
					Name:   ap.providerConfig.browserStateCookieName,
					Value:  ocState,
					Secure: true,
				}
			}
		}

		// Set cookie for browser state in Javascript.
		if cookie != nil {
			headers = http.Header{}
			headers.Add("Set-Cookie", cookie.String())
		}
	}

	return ar.Redirect(url, params, fragment, headers)
}

func (ap *authProvided) BrowserState() *baddsch.BrowserState {
	if ap.browserState != nil {
		return ap.browserState
	}

	return baddsch.NewBrowserState("provider_without_state", ap.providerConfig.browserStateCookieName)
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
