package owncloud

import (
	"encoding/json"
	"fmt"

	"golang.struktur.de/spreedbox/spreedbox-auth/baddsch"
	"golang.struktur.de/spreedbox/spreedbox-auth/baddsch/httpauth"
)

var DefaultConfigEndpoint = "api/v1/user/config"
var DefaultProviderPoolSize = 4
var DefaultProviderSkipSSLValidation = false

func NewProvider(url string, config *ProviderConfig) (baddsch.AuthProvider, error) {
	fullURL := fmt.Sprintf("%s/%s", url, DefaultConfigEndpoint)
	if config == nil {
		config = NewProviderConfig(DefaultProviderSkipSSLValidation, DefaultProviderPoolSize)
	}

	return httpauth.NewProvider(fullURL, func(message []byte, err error) (baddsch.AuthProvided, error) {
		switch err {
		case nil:
			// No error.
		case httpauth.ErrStatusForbidden:
			fallthrough
		case httpauth.ErrStatusUnauthorized:
			// Owncloud returns auth errors as 401.
			return newAuthProvided(nil), nil
		default:
			return nil, err
		}

		var response spreedmePluginUserConfig
		err = json.Unmarshal(message, &response)
		if err != nil {
			return nil, err
		}

		return newAuthProvided(&response), nil
	}, config)
}

type spreedmePluginUserConfig struct {
	Success     bool   `json:"success"`
	ID          string `json:"id"`
	DisplayName string `json:"display_name"`
	IsAdmin     bool   `json:"is_admin"`
}

type authProvided struct {
	userConfig *spreedmePluginUserConfig
}

func newAuthProvided(config *spreedmePluginUserConfig) *authProvided {
	if config == nil {
		config = &spreedmePluginUserConfig{}
	}
	return &authProvided{config}
}

func (ap *authProvided) Status() bool {
	return ap.userConfig.Success
}

func (ap *authProvided) UserID() string {
	return ap.userConfig.ID
}

func (ap *authProvided) PrivateClaims() map[string]interface{} {
	claims := make(map[string]interface{})
	claims["oc/is_admin"] = ap.userConfig.IsAdmin
	claims["oc/display_name"] = ap.userConfig.DisplayName
	return claims
}

func (ap *authProvided) Authorize() bool {
	return ap.Status() == true
}

type ProviderConfig struct {
	skipSSLValidation bool
	poolSize          int
}

func NewProviderConfig(skipSSLValidation bool, poolSize int) *ProviderConfig {
	return &ProviderConfig{skipSSLValidation, poolSize}
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
