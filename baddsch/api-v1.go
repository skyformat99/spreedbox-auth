package baddsch

import (
	"time"

	"github.com/strukturag/phoenix"
)

// APIv1 defines end points of baddsch API version 1.
type APIv1 struct {
	Config phoenix.Config
}

// NewAPIv1 creates a APIv1 instance return it as API interface
// optionally adding the API resources to a API holder.
func NewAPIv1(holder APIResourceHolder, config phoenix.Config) (API, error) {
	api := &APIv1{
		Config: config,
	}
	var err error
	if holder != nil {
		err = api.AddResources(holder)
	}
	return api, err
}

// AddResources adds the resources of this API to the API holder.
func (api *APIv1) AddResources(holder APIResourceHolder) error {
	holder.AddResource(&JSONDocument{map[string]interface{}{
		"owncloud_endpoint":          "https://{{.Host}}/index.php",
		"owncloud-spreedme_endpoint": "https://{{.Host}}/index.php/apps/spreedme",
		"spreed-webrtc_endpoint":     "https://{{.Host}}/webrtc",
		"authorization_endpoint":     "https://{{.Host}}/auth/authorize",
	}}, "/well-known/spreed-configuration")

	// Authorize support.
	tokenPrivateKeyFile, err := api.Config.GetString("auth", "tokenPrivateKey")
	if err != nil {
		return err
	}
	tokenPrivateKey, err := LoadRSAPrivateKeyFromPEMFile(tokenPrivateKeyFile)
	if err != nil {
		return err
	}
	tokenAlg := api.Config.GetStringDefault("auth", "tokenAlg", "RS256")
	holder.AddResource(&AuthorizeDocument{
		IssueIdentifier: api.Config.GetStringDefault("auth", "tokenIssueIdentifier", "https://spreedbox.localdomain"),
		TokenAlg:        tokenAlg,
		TokenTyp:        api.Config.GetStringDefault("auth", "tokenTyp", "JWT"),
		TokenDuration:   time.Duration(api.Config.GetIntDefault("auth", "tokenDuration", 3600)) * time.Second,
		TokenPrivateKey: tokenPrivateKey,
	}, "/authorize")

	// Validate support.
	holder.AddResource(&ValidateDocument{
		TokenAlg:       tokenAlg,
		TokenPublicKey: tokenPrivateKey.Public(),
	}, "/validate")

	return nil
}
