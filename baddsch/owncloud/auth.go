package owncloud

import (
	"encoding/json"
	"fmt"

	"golang.struktur.de/spreedbox/spreedbox-auth/baddsch"
	"golang.struktur.de/spreedbox/spreedbox-auth/baddsch/httpauth"
)

var configEndpoint = "api/v1/user/config"

func NewProvider(url string) (baddsch.AuthProvider, error) {
	fullURL := fmt.Sprintf("%s/%s", url, configEndpoint)
	return httpauth.NewProvider(fullURL, func(message []byte, err error) (baddsch.AuthProvided, error) {
		switch err {
		case nil:
			// No error.
		case httpauth.ErrStatusForbidden:
			fallthrough
		case httpauth.ErrStatusUnauthorized:
			// Owncloud returns auth errors as 401.
			return NewOwncloudAuthProvided(nil), nil
		default:
			return nil, err
		}

		var response spreedmePluginUserConfig
		err = json.Unmarshal(message, &response)
		if err != nil {
			return nil, err
		}

		return NewOwncloudAuthProvided(&response), nil
	})
}

type spreedmePluginUserConfig struct {
	Success     bool   `json:"success"`
	ID          string `json:"id"`
	DisplayName string `json:"display_name"`
	IsAdmin     bool   `json:"is_admin"`
}

type OwncloudAuthProvided struct {
	userConfig *spreedmePluginUserConfig
}

func NewOwncloudAuthProvided(config *spreedmePluginUserConfig) *OwncloudAuthProvided {
	if config == nil {
		config = &spreedmePluginUserConfig{}
	}
	return &OwncloudAuthProvided{config}
}

func (ap *OwncloudAuthProvided) Status() bool {
	return ap.userConfig.Success
}

func (ap *OwncloudAuthProvided) UserID() string {
	return ap.userConfig.ID
}
