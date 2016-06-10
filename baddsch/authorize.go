package baddsch

import (
	"crypto"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"golang.struktur.de/spreedbox/spreedbox-auth/baddsch/jwt"
	"golang.struktur.de/spreedbox/spreedbox-auth/randomstring"

	"github.com/google/go-querystring/query"
)

// AuthorizeDocument im defines the JSON data to return and receive to
// provide the OpenID connect authorization endpoint with authentication
// requests.
type AuthorizeDocument struct {
	IssueIdentifier       string
	TokenTyp              string
	TokenAlg              string
	TokenDuration         time.Duration
	TokenAccessTokenClaim string
	TokenPrivateKey       crypto.PrivateKey
	TokenPublicKey        crypto.PublicKey
	AuthProvider          AuthProvider
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
		return http.StatusBadRequest, err.Error(), nil
	}
	return ar.Response(doc)
}

// Post is the HTTP response handler for requests to the authentication endpoint.
func (doc *AuthorizeDocument) Post(r *http.Request) (int, interface{}, http.Header) {
	return doc.Get(r)
}

type AuthenticationRequestOptions struct {
	RedirectURL      *url.URL
	UseFragment      bool
	Authorization    string
	ResponseTypes    map[string]bool
	Scopes           map[string]bool
	WithSessionState bool
}

type AuthenticationRequest struct {
	Request       *http.Request                 `schema:"-"`
	Options       *AuthenticationRequestOptions `schema:"-"`
	ResponseType  string                        `schema:"response_type"`
	RedirectURL   string                        `schema:"redirect_url"`
	Nonce         string                        `schema:"nonce"`
	State         string                        `schema:"state"`
	Scope         string                        `schema:"scope"`
	Prompt        string                        `schema:"prompt"`
	RequestObject string                        `schema:"request"`
	//Claims        string                        `schema:"claims"` // No support for now. Lets see if we can get away with scopes.
	IDTokenHint string `schema:"id_token_hint"`
	userID      string `schema:"-"`
	clientID    string `schema:"-"`
}

func NewAuthenticationRequest(r *http.Request) (*AuthenticationRequest, error) {
	ar := &AuthenticationRequest{}
	if err := DecodeRequestSchema(ar, r.Form); err != nil {
		return nil, err
	}

	ar.Request = r
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

func (ar *AuthenticationRequest) Validate(doc *AuthorizeDocument) (error, string) {
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

	if ar.RequestObject != "" {
		return errors.New("request_not_supported"), "request object is not supported"
	}

	if _, ok := ar.Options.Scopes["openid"]; !ok {
		return errors.New("invalid_scope"), "must have openid scope"
	}

	for {
		if ar.Options.RedirectURL.Scheme == "https" {
			if ar.Options.RedirectURL.Host == ar.Request.Host {
				// Allow all targets on the host which was used to access us.
				// NOTE(longsleep): This is a implicit white list which does
				// not have a path component.
				break
			}
		}

		if ar.Options.RedirectURL.Scheme == "http" && ar.Options.RedirectURL.Host == "localhost" {
			// http://localhost allowed for native applications.
			break
		}

		// Everything else is invalid.
		return errors.New("invalid_request"), "unknown redirect_url"
	}

	if ar.Nonce == "" {
		return errors.New("invalid_request"), "nonce cannot be empty"
	}

	if ar.Prompt != "none" && ar.Prompt != "" {
		return errors.New("invalid_request"), "prompt must be none"
	}

	return nil, ""
}

func (ar *AuthenticationRequest) Authenticate(doc *AuthorizeDocument) (AuthProvided, error, string) {
	// Split authorization header value which is of format "Type Value".
	auth := strings.SplitN(ar.Options.Authorization, " ", 2)

	if ar.clientID == "" && ar.RedirectURL != "" {
		// We support self issued mode as defined in http://openid.net/specs/openid-connect-core-1_0.html#SelfIssued
		// and defines the client ID is the redirect URL.
		ar.clientID = ar.RedirectURL
	}
	if ar.clientID == "" {
		return nil, errors.New("invalid_client"), "client id cannot be empty"
	}

	var requestedUserID string
	var authProvided AuthProvided
	var err error
	switch auth[0] {
	case "Basic":
		// curl -v "http://user:password@localhost:7031/api/v1/authorize?response_type=id_token&redirect_url=http://localhost&nonce=123&state=abc&prompt=none&scope=openid"
		if len(auth) != 2 {
			return nil, errors.New("invalid_request"), "invalid basic value"
		}
		if basic, err := base64.StdEncoding.DecodeString(auth[1]); err == nil {
			requestedUserID = strings.SplitN(string(basic), ":", 2)[0]
		} else {
			return nil, errors.New("invalid_request"), err.Error()
		}
		//log.Printf("basic authentication request for: %s\n", requestedUserID)
		if doc.AuthProvider != nil {
			authProvided, err = doc.AuthProvider.Authorization(ar.Options.Authorization, nil)
		}
	case "Cookie":
		// curl -v -H Authorization "Cookie" --cookie "blah=lala" "http://localhost:7031/api/v1/authorize?response_type=id_token&redirect_url=http://localhost&nonce=123&state=abc&prompt=none&scope=openid"
		if len(ar.Request.Cookies()) == 0 {
			return nil, errors.New("invalid_request"), "missing cookie"
		}
		fallthrough
	case "":
		//log.Printf("cookie authentication request\n")
		ar.Options.WithSessionState = true // Enable session state for cookie based auth.
		cookies := ar.Request.Cookies()
		if doc.AuthProvider != nil {
			authProvided, err = doc.AuthProvider.Authorization("", cookies)
		}
	default:
		return nil, errors.New("invalid_request"), "invalid authorization type"
	}

	if err != nil {
		log.Println("authorization provider failure", err.Error())
		return nil, errors.New("server_error"), "authorization provider failure"
	}

	// Set gathered data.
	if doc.AuthProvider != nil {
		if authProvided != nil && authProvided.Status() {
			//log.Println("authentication provided:", authProvided.Status(), authProvided.UserID())
			ar.userID = authProvided.UserID()
		} else {
			if ar.Prompt == "none" {
				return nil, errors.New("login_required"), "login required"
			}
			return authProvided, errors.New("access_denied"), "authentication failed"
		}
	} else {
		ar.userID = requestedUserID
	}
	return authProvided, nil, ""
}

func (ar *AuthenticationRequest) Authorize(doc *AuthorizeDocument, authProvided AuthProvided) (AuthProvided, error, string) {
	var err error

	for {
		// No provider?
		if authProvided == nil {
			// Create dummy false auth which will always fail all checks if
			// we do not have another provided value at this point.
			authProvided = &NoAuthProvided{}
			break
		}

		// Check what the privider has to say.
		if !authProvided.Authorize() {
			break
		}

		// Check ID token hint to match.
		if ar.IDTokenHint != "" {
			if _, err = jwt.Decode(ar.IDTokenHint, func(header *jwt.Header, claims *jwt.Claims) (interface{}, error) {
				if header.Alg != doc.TokenAlg {
					return nil, fmt.Errorf("unexpected signing method: %v", header.Alg)
				}
				if ar.userID != claims.Sub {
					return nil, fmt.Errorf("wrong user")
				}

				// Ignore expiration.
				claims.IgnoreValidate("exp")

				return doc.TokenPublicKey, nil
			}); err != nil {
				// ID token provided by hint is either invalid our the additional
				// checks above failed. Means this is an error according to spec
				// at http://openid.net/specs/openid-connect-core-1_0.html#AuthRequestValidation
				break
			}
		}

		// Reached the end, so nothing failed.
		return authProvided, nil, ""
	}

	if err == nil {
		err = fmt.Errorf("authorization failed")
	}

	return authProvided, errors.New("access_denied"), err.Error()
}

func (ar *AuthenticationRequest) Response(doc *AuthorizeDocument) (int, interface{}, http.Header) {
	redirectURL, err := url.Parse(ar.RedirectURL)
	if err != nil {
		return http.StatusBadRequest, err.Error(), nil
	}
	ar.Options.RedirectURL = redirectURL

	var errDescription string
	var authProvided AuthProvided
	var tokenHeader *jwt.Header
	var accessToken *jwt.Token
	var idToken *jwt.Token

	if err, errDescription = ar.Validate(doc); err != nil {
		goto done
	}
	if authProvided, err, errDescription = ar.Authenticate(doc); err != nil {
		goto done
	}
	if authProvided, err, errDescription = ar.Authorize(doc, authProvided); err != nil {
		goto done
	}

	tokenHeader = &jwt.Header{
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
			PrivateClaims: authProvided.PrivateClaims(false, ar),
		}
		if doc.TokenAccessTokenClaim != "" {
			accessTokenClaims.PrivateClaims[doc.TokenAccessTokenClaim] = true
		}
		if accessToken, err = jwt.Encode(tokenHeader, accessTokenClaims, &doc.TokenDuration, doc.TokenPrivateKey); err != nil {
			goto done
		}
	}

	if _, ok := ar.Options.ResponseTypes["id_token"]; ok {
		// Create ID token
		idTokenClaims := &jwt.Claims{
			Iss:           doc.IssueIdentifier,
			Sub:           ar.userID,
			Aud:           ar.clientID,
			Nonce:         ar.Nonce,
			PrivateClaims: authProvided.PrivateClaims(true, ar),
		}
		if accessToken != nil {
			// Add at_hash claim as defined in
			// http://openid.net/specs/openid-connect-core-1_0.html#CodeValidation
			var hash crypto.Hash
			switch tokenHeader.Alg {
			case "RS256":
				hash = crypto.SHA256
			case "RS384":
				hash = crypto.SHA384
			case "RS512":
				hash = crypto.SHA512
			}
			if hash.Available() {
				idTokenClaims.PrivateClaims["at_hash"] = LeftmostHashBase64URLEncoding([]byte(accessToken.Raw), hash)
			} else {
				log.Println("selected hashing alg not available", tokenHeader.Alg)
				err = errors.New("server_error")
				goto done
			}
		}

		if idToken, err = jwt.Encode(tokenHeader, idTokenClaims, &doc.TokenDuration, doc.TokenPrivateKey); err != nil {
			goto done
		}
	}

done:
	if err != nil {
		if authProvided != nil {
			// Error but have authProvided, let it handle it.
			return authProvided.RedirectError(err, ar)
		}

		// Return error response.
		errResponse := &AuthenticationErrorResponse{
			Error:            err.Error(),
			ErrorDescription: errDescription,
			State:            ar.State,
		}
		if ar.Options.WithSessionState {
			errResponse.SessionState = ar.SessionState(NewBrowserState(err.Error(), ""))
		}
		//log.Println("authorize failed http", err, errDescription)
		return ar.Redirect(ar.Options.RedirectURL, errResponse, ar.Options.UseFragment, nil)
	}

	successResponse := &AuthenticationSuccessResponse{
		State: ar.State,
	}

	if ar.Options.WithSessionState {
		var browserState *BrowserState
		if authProvided != nil {
			browserState = authProvided.BrowserState()
		}
		if browserState == nil {
			browserState = NewBrowserState("provider_without_state", "")
		}

		successResponse.SessionState = ar.SessionState(browserState)
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

	//log.Println("authorize success http")
	if authProvided != nil {
		return authProvided.RedirectSuccess(ar.Options.RedirectURL, successResponse, ar.Options.UseFragment, ar)
	}

	return ar.Redirect(ar.Options.RedirectURL, successResponse, ar.Options.UseFragment, nil)
}

func (ar *AuthenticationRequest) Redirect(url *url.URL, params interface{}, fragment bool, headers http.Header) (int, interface{}, http.Header) {
	var urlString string
	v, _ := query.Values(params)
	if fragment {
		urlString = fmt.Sprintf("%s#%s", url.String(), v.Encode())
	} else {
		url.RawQuery = v.Encode()
		urlString = url.String()
	}

	if headers == nil {
		headers = http.Header{}
	}
	headers.Set("Location", urlString)
	headers.Set("Cache-Control", "no-store")
	headers.Set("Pragma", "no-cache")

	return http.StatusFound, "", headers
}

func (ar *AuthenticationRequest) SessionState(browserState *BrowserState) string {
	origin := ar.Request.Header.Get("Origin")
	if origin == "" {
		origin = fmt.Sprintf("https://%s", ar.Request.Host)
	}

	// Create sessionState.
	// sha256(clientID + " " + origin + " " + browserState + " " + salt + " " + ref) + "." + salt + "." + ref
	hasher := sha256.New()
	hasher.Write([]byte(ar.clientID))
	hasher.Write([]byte(" "))
	hasher.Write([]byte(origin))
	hasher.Write([]byte(" "))
	hasher.Write([]byte(browserState.Value()))
	hasher.Write([]byte(" "))
	salt := randomstring.NewRandomString(8)
	hasher.Write([]byte(salt))
	hasher.Write([]byte(" "))
	hasher.Write([]byte(browserState.Ref()))

	return fmt.Sprintf("%s.%s.%s", base64.StdEncoding.EncodeToString(hasher.Sum(nil)), salt, browserState.Ref())
}

type AuthenticationSuccessResponse struct {
	AccessToken  string `url:"access_token,omitempty"`
	TokenType    string `url:"token_type,omitempty"`
	IDToken      string `url:"id_token,omitempty"`
	State        string `url:"state"`
	ExpiresIn    int64  `url:"expires_in,omitempty"`
	SessionState string `url:"session_state,omitempty"`
}

type AuthenticationErrorResponse struct {
	Error            string `url:"error"`
	ErrorDescription string `url:"error_description,omitempty"`
	State            string `url:"state,omitempty"`
	SessionState     string `url:"session_state,omitempty"`
}
