package baddsch

import (
	"time"

	"github.com/strukturag/phoenix"

	"golang.struktur.de/spreedbox/spreedbox-auth/lockmap"
)

// APIv1 defines end points of baddsch API version 1.
type APIv1 struct {
	Config                               phoenix.Config
	WellKnownSpreedConfigurationDocument *JSONDocument
	AuthorizeDocument                    *AuthorizeDocument
	ValidateDocument                     *ValidateDocument
	RevocateDocument                     *RevocateDocument
	JWKSDocument                         *JWKSDocument
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
	tokenIssueIdentifier := api.Config.GetStringDefault("auth", "tokenIssueIdentifier", "https://spreedbox.local")
	tokenAccessTokenClaim := api.Config.GetStringDefault("auth", "tokenAccessTokenClaim", "baddsch/at")

	// Based on OpenID provider metadata as specified in
	// http://openid.net/specs/openid-connect-discovery-1_0-21.html
	api.WellKnownSpreedConfigurationDocument = &JSONDocument{map[string]interface{}{
		"issuer":                                tokenIssueIdentifier,
		"owncloud_endpoint":                     "https://{{.Host}}/index.php",
		"owncloud-spreedme_endpoint":            "https://{{.Host}}/index.php/apps/spreedme",
		"spreed-webrtc_endpoint":                "https://{{.Host}}/webrtc",
		"authorization_endpoint":                "https://{{.Host}}/spreedbox-auth/api/v1/authorize",
		"jwks_uri":                              "https://{{.Host}}/spreedbox-auth/api/v1/jwks.json",
		"revocation_endpoint":                   "https://{{.Host}}/spreedbox-auth/api/v1/revocate",
		"scopes_supported":                      []string{"openid", "spreedbox"},
		"response_types_supported":              []string{"id_token", "token id_token", "token"},
		"grant_types_supported":                 []string{"implicit"},
		"id_token_signing_alg_values_supported": []string{tokenAlg},
		"subject_types_supported":               []string{"public"},
		"spreedbox-setup_endpoint":              "https://{{.Host}}/spreedbox-setup", // TODO(longsleep): Add a registry for services.
		"spreedbox-auth_endpoint":               "https://{{.Host}}/spreedbox-auth",
	}}
	//TODO(longsleep): Add endpoints for session management
	// according to http://openid.net/specs/openid-connect-session-1_0.html

	blacklist := lockmap.New()

	api.AuthorizeDocument = &AuthorizeDocument{
		IssueIdentifier:       tokenIssueIdentifier,
		TokenAlg:              tokenAlg,
		TokenTyp:              api.Config.GetStringDefault("auth", "tokenTyp", "JWT"),
		TokenDuration:         time.Duration(api.Config.GetIntDefault("auth", "tokenDuration", 3600)) * time.Second,
		TokenAccessTokenClaim: tokenAccessTokenClaim,
		TokenPrivateKey:       tokenPrivateKey,
		TokenPublicKey:        tokenPrivateKey.Public(),
		AuthProvider:          authProvider,
	}

	api.ValidateDocument = &ValidateDocument{
		IssueIdentifier:       tokenIssueIdentifier,
		TokenAlg:              tokenAlg,
		TokenAccessTokenClaim: tokenAccessTokenClaim,
		TokenPublicKey:        tokenPrivateKey.Public(),
		Blacklist:             blacklist,
	}

	api.RevocateDocument = &RevocateDocument{
		ValidateDocument: api.ValidateDocument,
	}

	api.JWKSDocument = NewJWKSDocument(tokenPrivateKey.Public())

	// Bind documents to resource endpoints.
	holder.AddResource(api.WellKnownSpreedConfigurationDocument,
		"/well-known/spreed-configuration")
	holder.AddResource(api.JWKSDocument,
		"/jwks.json")
	holder.AddResource(api.AuthorizeDocument,
		"/authorize")
	holder.AddResource(api.ValidateDocument,
		"/validate")
	holder.AddResource(api.RevocateDocument,
		"/revocate")

	return nil
}
