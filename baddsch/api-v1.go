package baddsch

import (
	"time"

	"github.com/strukturag/phoenix"
)

// APIv1 defines end points of baddsch API version 1.
type APIv1 struct {
	Config                               phoenix.Config
	WellKnownSpreedConfigurationDocument *JSONDocument
	AuthorizeDocument                    *AuthorizeDocument
	ValidateDocument                     *ValidateDocument
}

// NewAPIv1 creates a APIv1 instance return it as API interface
// optionally adding the API resources to a API holder.
func NewAPIv1(holder APIResourceHolder, config phoenix.Config, authProvider AuthProvider) (*APIv1, error) {
	api := &APIv1{
		Config: config,
	}
	var err error
	if holder != nil {
		err = api.AddResources(holder, authProvider)
	}
	return api, err
}

// AddResources adds the resources of this API to the API holder.
func (api *APIv1) AddResources(holder APIResourceHolder, authProvider AuthProvider) error {
	tokenAlg := api.Config.GetStringDefault("auth", "tokenAlg", "RS256")
	tokenPrivateKeyFile, err := api.Config.GetString("auth", "tokenPrivateKey")
	if err != nil {
		return err
	}
	tokenPrivateKey, err := LoadRSAPrivateKeyFromPEMFile(tokenPrivateKeyFile)
	if err != nil {
		return err
	}
	tokenIssueIdentifier := api.Config.GetStringDefault("auth", "tokenIssueIdentifier", "https://self-issued.me")
	tokenAccessTokenClaim := api.Config.GetStringDefault("auth", "tokenAccessTokenClaim", "baddsch/at")

	api.WellKnownSpreedConfigurationDocument = &JSONDocument{map[string]interface{}{
		"owncloud_endpoint":                           "https://{{.Host}}/index.php",
		"owncloud-spreedme_endpoint":                  "https://{{.Host}}/index.php/apps/spreedme",
		"spreed-webrtc_endpoint":                      "https://{{.Host}}/webrtc",
		"authorization_endpoint":                      "https://{{.Host}}/spreedbox-auth/authorize",
		"scopes_supported":                            []string{"openid"},
		"response_types_supported":                    []string{"id_token", "token id_token", "token"},
		"id_token_signing_alg_values_supported":       []string{tokenAlg},
		"request_object_signing_alg_values_supported": []string{tokenAlg},
		"subject_types_supported":                     []string{"pairwise"},
		"spreedbox-setup_endpoint":                    "https://{{.Host}}/spreedbox-setup", // TODO(longsleep): Add a registry for services.
	}}

	api.AuthorizeDocument = &AuthorizeDocument{
		IssueIdentifier:       tokenIssueIdentifier,
		TokenAlg:              tokenAlg,
		TokenTyp:              api.Config.GetStringDefault("auth", "tokenTyp", "JWT"),
		TokenDuration:         time.Duration(api.Config.GetIntDefault("auth", "tokenDuration", 3600)) * time.Second,
		TokenAccessTokenClaim: tokenAccessTokenClaim,
		TokenPrivateKey:       tokenPrivateKey,
		AuthProvider:          authProvider,
	}

	api.ValidateDocument = &ValidateDocument{
		IssueIdentifier:       tokenIssueIdentifier,
		TokenAlg:              tokenAlg,
		TokenAccessTokenClaim: tokenAccessTokenClaim,
		TokenPublicKey:        tokenPrivateKey.Public(),
	}

	// Bind documents to resource endpoints.
	holder.AddResource(api.WellKnownSpreedConfigurationDocument,
		"/well-known/spreed-configuration")
	holder.AddResource(api.AuthorizeDocument,
		"/authorize")
	holder.AddResource(api.ValidateDocument,
		"/validate")

	return nil
}
