package baddsch

import (
	"crypto/rsa"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"golang.struktur.de/spreedbox/spreedbox-auth/baddsch/jwt"

	"github.com/google/go-querystring/query"
	"github.com/gorilla/schema"
)

var decoder = schema.NewDecoder()

// AuthorizeDocument im defines the JSON data to return and receive to
// provide the OpenID connect authorization endpoint with authentication
// requests.
type AuthorizeDocument struct {
	IssueIdentifier string
	TokenTyp        string
	TokenAlg        string
	TokenDuration   time.Duration
	TokenPrivateKey *rsa.PrivateKey
}

// Get is the HTTP response handler for requests to the authorization endpoint.
func (doc *AuthorizeDocument) Get(r *http.Request) (int, interface{}, http.Header) {
	// http://openid.net/specs/openid-connect-core-1_0.html
	// Implemented flow:
	// Authentication Request
	// - Implicit flow
	//   response_type: id_token (MUST)
	//   redirect_uri: http://localhost/redirect (MUST)
	//   nonce: some-random-string (MUST)
	//   state: another-random-string (MAY)
	//   prompt: none (MAY)
	// Authentication Request Validation
	// Authorization Server Authenticates End-User
	// Authorization Server Obtains End-User Consent/Authorization
	// Successful Authentication Response
	var err error
	ar := &AuthenticationRequest{}
	if err = decoder.Decode(ar, r.Form); err != nil {
		return 400, err.Error(), nil
	}

	ar.Options = &AuthenticationRequestOptions{
		Authorization: r.Header.Get("Authorization"),
	}

	return ar.Response(doc)
}

type AuthenticationRequestOptions struct {
	RedirectURL   *url.URL
	UseFragment   bool
	Authorization string
}

type AuthenticationRequest struct {
	Options      *AuthenticationRequestOptions `schema:"-"`
	ResponseType string                        `schema:"response_type"`
	RedirectURL  string                        `schema:"redirect_url"`
	Nonce        string                        `schema:"nonce"`
	State        string                        `schema:"state"`
	Scope        string                        `schema:"scope"`
	Prompt       string                        `schema:"prompt"`
}

func (ar *AuthenticationRequest) Validate() (error, string) {
	switch ar.ResponseType {
	case "id_token":
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

	/*var privateKey *rsa.PrivateKey
	privateKey, err = rsa.GenerateKey(rand.Reader, 1024)*/

	var idToken *jwt.Token
	idToken, err = jwt.Encode(&jwt.Header{
		Alg: doc.TokenAlg,
		Typ: doc.TokenTyp,
	}, &jwt.Claims{
		Iss:   doc.IssueIdentifier,
		Sub:   "todo-user-id",
		Aud:   "client-id",
		Nonce: ar.Nonce,
	}, &doc.TokenDuration, doc.TokenPrivateKey)

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

	successResponse := &AuthenticationSuccessResponse{
		TokenType: "Bearer",
		IDToken:   idToken.Raw,
		ExpiresIn: idToken.ExpiresIn,
	}
	if ar.State != "" {
		successResponse.State = ar.State
	}

	/*token, err := jwt.Decode(idToken, func(header *jwt.Header, claims *jwt.Claims) (interface{}, error) {
		if header.Alg != "RS256" {
			return nil, fmt.Errorf("unexpected signing method: %v", header.Alg)
		}
		return privateKey.Public(), nil
	})
	log.Println("xxx token valid", token, err)*/

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
	//AccessToken  string `url:"access_token"`
	//RefreshToken string `url:"refresh_token"`
	TokenType string `url:"token_type"`
	IDToken   string `url:"id_token"`
	State     string `url:"state"`
	ExpiresIn int64  `url:"expires_in"`
}

type AuthenticationErrorResponse struct {
	Error            string `url:"error"`
	ErrorDescription string `url:"error_description,omitempty"`
	State            string `url:"state,omitempty"`
}

func init() {
	decoder.IgnoreUnknownKeys(true)
}
