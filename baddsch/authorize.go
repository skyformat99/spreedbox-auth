package baddsch

import (
	"crypto"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"golang.struktur.de/spreedbox/spreedbox-auth/baddsch/jwt"

	"github.com/google/go-querystring/query"
	"github.com/gorilla/schema"
)

// curl -v "http://user:password@localhost:7031/api/v1/authorize?response_type=id_token&redirect_url=http://localhost&nonce=123&state=abc&prompt=none&scope=openid"

var decoder = schema.NewDecoder()

// AuthorizeDocument im defines the JSON data to return and receive to
// provide the OpenID connect authorization endpoint with authentication
// requests.
type AuthorizeDocument struct {
	IssueIdentifier string
	TokenTyp        string
	TokenAlg        string
	TokenDuration   time.Duration
	TokenPrivateKey crypto.PrivateKey
}

// Get is the HTTP response handler for requests to the authorization endpoint.
func (doc *AuthorizeDocument) Get(r *http.Request) (int, interface{}, http.Header) {
	// http://openid.net/specs/openid-connect-core-1_0.html
	// Implemented flow:
	// Authentication Request
	// - Implicit flow
	//   response_type: 'id_token' or 'id_token token' (MUST)
	//   redirect_uri: http://localhost/redirect (MUST)
	//   nonce: some-random-string (MUST)
	//   state: another-random-string (MAY)
	//   prompt: none (MAY)
	//   scope: openid (MUST) (others allowed)
	// Authentication Request Validation
	// Authorization Server Authenticates End-User
	// Authorization Server Obtains End-User Consent/Authorization
	// Successful Authentication Response
	ar, err := NewAuthenticationRequest(r)
	if err != nil {
		return 400, err.Error(), nil
	}
	return ar.Response(doc)
}

// Post is the HTTP response handler for requests to the authentication endpoint.
func (doc *AuthorizeDocument) Post(r *http.Request) (int, interface{}, http.Header) {
	return doc.Get(r)
}

type AuthenticationRequestOptions struct {
	RedirectURL   *url.URL
	UseFragment   bool
	Authorization string
	ResponseTypes map[string]bool
	Scopes        map[string]bool
}

type AuthenticationRequest struct {
	Options      *AuthenticationRequestOptions `schema:"-"`
	ResponseType string                        `schema:"response_type"`
	RedirectURL  string                        `schema:"redirect_url"`
	Nonce        string                        `schema:"nonce"`
	State        string                        `schema:"state"`
	Scope        string                        `schema:"scope"`
	Prompt       string                        `schema:"prompt"`
	userID       string                        `schema:"-"`
	clientID     string                        `schema:"-"`
}

func NewAuthenticationRequest(r *http.Request) (*AuthenticationRequest, error) {
	ar := &AuthenticationRequest{}
	if err := decoder.Decode(ar, r.Form); err != nil {
		return nil, err
	}

	ar.Options = &AuthenticationRequestOptions{
		Authorization: r.Header.Get("Authorization"),
		ResponseTypes: make(map[string]bool),
		Scopes:        make(map[string]bool),
	}
	for _, rt := range strings.Split(ar.ResponseType, " ") {
		ar.Options.ResponseTypes[rt] = true
	}
	for _, scope := range strings.Split(ar.Scope, " ") {
		ar.Options.Scopes[scope] = true
	}

	return ar, nil
}

func (ar *AuthenticationRequest) Validate() (error, string) {
	if _, ok := ar.Options.Scopes["openid"]; !ok {
		return errors.New("invalid_scope"), "must have openid scope"
	}
	switch ar.ResponseType {
	case "id_token":
		fallthrough
	case "token":
		// NOTE(longsleep): The token only mode violates the OpenID specification
		// as this mode usually does not make any sense as no ID token will be
		// returned. We still implement it, to provide auth to clients which do
		// not require the ID token.
		fallthrough
	case "id_token token":
		ar.Options.UseFragment = true
	default:
		return errors.New("unsupported_response_type"), ""
	}

	if ar.Options.RedirectURL.Scheme != "http" || ar.Options.RedirectURL.Host != "localhost" {
		return errors.New("invalid_request"), "redirect_url must start with http://localhost"
	}

	if ar.Nonce == "" {
		return errors.New("invalid_request"), "nonce cannot be empty"
	}

	if ar.Prompt != "none" && ar.Prompt != "" {
		return errors.New("invalid_request"), "prompt must be none"
	}

	return nil, ""
}

func (ar *AuthenticationRequest) Authenticate() (error, string) {
	if ar.Options.Authorization == "" {
		return errors.New("invalid_request"), "authorization header required"
	}

	auth := strings.SplitN(ar.Options.Authorization, " ", 2)
	if len(auth) != 2 || auth[0] != "Basic" {
		return errors.New("invalid_request"), "authorization header is invalid"
	}

	if ar.clientID == "" && ar.RedirectURL != "" {
		// We support self issued mode as defined in http://openid.net/specs/openid-connect-core-1_0.html#SelfIssued
		// and defines the client ID is the redirect URL.
		ar.clientID = ar.RedirectURL
	}
	if ar.clientID == "" {
		return errors.New("invalid_client"), "client id cannot be empty"
	}

	// TODO(longsleep): Set ar.userID and ar.clientID here.
	ar.userID = "todo-add-userid"

	return nil, ""
}

func (ar *AuthenticationRequest) Authorize() (error, string) {
	return nil, ""
}

func (ar *AuthenticationRequest) Response(doc *AuthorizeDocument) (int, interface{}, http.Header) {
	redirectURL, err := url.Parse(ar.RedirectURL)
	if err != nil {
		return 400, err.Error(), nil
	}
	ar.Options.RedirectURL = redirectURL

	var errDescription string
	err, errDescription = ar.Validate()
	if err == nil {
		err, errDescription = ar.Authenticate()
	}
	if err == nil {
		err, errDescription = ar.Authorize()
	}

	var accessToken *jwt.Token
	var idToken *jwt.Token
	if err == nil {
		tokenHeader := &jwt.Header{
			Alg: doc.TokenAlg,
			Typ: doc.TokenTyp,
		}

		if _, ok := ar.Options.ResponseTypes["token"]; ok {
			// Create access token
			accessTokenClaims := &jwt.Claims{
				Iss:           doc.IssueIdentifier,
				Sub:           ar.userID,
				Aud:           ar.clientID,
				Nonce:         ar.Nonce,
				PrivateClaims: make(map[string]interface{}),
			}
			accessTokenClaims.PrivateClaims["spreedbox/at"] = true
			accessToken, err = jwt.Encode(tokenHeader, accessTokenClaims, &doc.TokenDuration, doc.TokenPrivateKey)
		}

		if err == nil {
			if _, ok := ar.Options.ResponseTypes["id_token"]; ok {
				// Create ID token
				idTokenClaims := &jwt.Claims{
					Iss:           doc.IssueIdentifier,
					Sub:           ar.userID,
					Aud:           ar.clientID,
					Nonce:         ar.Nonce,
					PrivateClaims: make(map[string]interface{}),
				}
				if accessToken != nil {
					// TODO(longsleep): Add at_hash claim as defined in
					// http://openid.net/specs/openid-connect-core-1_0.html#CodeValidation
					idTokenClaims.PrivateClaims["at_hash"] = ""
				}
				idToken, err = jwt.Encode(tokenHeader, idTokenClaims, &doc.TokenDuration, doc.TokenPrivateKey)
			}
		}
	}

	if err != nil {
		errResponse := &AuthenticationErrorResponse{
			Error: err.Error(),
		}
		if ar.State != "" {
			errResponse.State = ar.State
		}
		if errDescription != "" {
			errResponse.ErrorDescription = errDescription
		}
		return ar.Redirect(ar.Options.RedirectURL, errResponse, ar.Options.UseFragment)
	}

	successResponse := &AuthenticationSuccessResponse{}
	if ar.State != "" {
		successResponse.State = ar.State
	}

	if _, ok := ar.Options.ResponseTypes["token"]; ok {
		successResponse.TokenType = "Bearer"
		if accessToken != nil {
			successResponse.AccessToken = accessToken.Raw
			successResponse.ExpiresIn = accessToken.ExpiresIn
		}
	}

	if idToken != nil {
		successResponse.IDToken = idToken.Raw
	}

	return ar.Redirect(ar.Options.RedirectURL, successResponse, ar.Options.UseFragment)
}

func (ar *AuthenticationRequest) Redirect(url *url.URL, params interface{}, fragment bool) (int, interface{}, http.Header) {
	v, _ := query.Values(params)
	if fragment {
		url.Fragment = v.Encode()
	} else {
		url.RawQuery = v.Encode()
	}

	return 302, "", http.Header{
		"Location":      {url.String()},
		"Cache-Control": {"no-store"},
		"Pragma":        {"no-cache"},
	}
}

type AuthenticationSuccessResponse struct {
	AccessToken string `url:"access_token,omitempty"`
	TokenType   string `url:"token_type,omitempty"`
	IDToken     string `url:"id_token,omitempty"`
	State       string `url:"state"`
	ExpiresIn   int64  `url:"expires_in,omitempty"`
}

type AuthenticationErrorResponse struct {
	Error            string `url:"error"`
	ErrorDescription string `url:"error_description,omitempty"`
	State            string `url:"state,omitempty"`
}

func init() {
	decoder.IgnoreUnknownKeys(true)
}
