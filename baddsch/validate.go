package baddsch

import (
	"crypto"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"

	"golang.struktur.de/spreedbox/spreedbox-auth/baddsch/jwt"
)

// curl -v -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJjbGllbnQtaWQiLCJleHAiOjE0NTgxNDgzNDAsImlhdCI6MTQ1NzU0MzU0MCwiaXNzIjoiaHR0cHM6Ly9zcHJlZWRib3gubG9jYWxkb21haW4iLCJub25jZSI6IjEyMyIsInN1YiI6InRvZG8tdXNlci1pZCJ9.mD-TKPlPxb3WPr0yfafUupcHYjCFei84_HEpG8CZolbEOxGZaS_l75sl0mKmKEUrFfwoxRcLSOtciOVElISoXrZDJRu3x7HnvSBVR3il4T9uoKs8MawNxPAjKBUo3rw3L4lACNYpXri0-lQ3LVthJJEThWszcfTO3meX5F8AREU7_4Jsj0idOcThSJh7121acgkOoAKsgTE2Gvm3t6e7gcW9aeym74DiOP5M_eHd8AQLBjjCf3ioHb92iQQolA7YnRn9kGDToqwuhsIQym6gFtFAeek6anALjDgzLsda649joLwK4NzaPk3VgH1XlykAMOP-_7Qla3fyqigAvjV8v9XD3Lz5WcOUjZnW4xjfVDGk72rNZll_zVGBmhHvTGCZaDqqX5_TbrpgCW4s1cjV6w8osEFLif_0-NClUshwnA8EuCVnr3cIK-LIyKkmllxoLem3BgEB201LimRRlYRVv23GNODmva1e92zMkbTgxOpTgMpAxMU_QOOKCWzAYVdph4XGSHzs1Ih-DiAG7pSIeAD-67MOGVNrJzWEHQkw5i_4CGpbM2nRz-uT4qDfJS3tJxtgpT-CPRnA_GJYRKltPplucCib01JRhjUumo-ewQc5HIs2prsa0v_f_J7Vyb7c2PsjMh6u-jhmv3DimwznQXB3dyJhdAmlDDtINDUAli0" http://localhost:7031/api/v1/validate

type ValidateDocument struct {
	IssueIdentifier       string
	TokenAlg              string
	TokenAccessTokenClaim string
	TokenPublicKey        crypto.PublicKey
}

func (doc *ValidateDocument) Get(r *http.Request) (int, interface{}, http.Header) {
	log.Println("validation http")
	vr, err := NewValidationRequest(r)
	if err != nil {
		return 400, err.Error(), nil
	}
	return vr.Response(doc)
}

func (doc *ValidateDocument) Post(r *http.Request) (int, interface{}, http.Header) {
	return doc.Get(r)
}

type ValidationRequestOptions struct {
	Authorization string
}

type ValidationRequest struct {
	Options   *ValidationRequestOptions `schema:"-"`
	TokenType string                    `schema:"token_type"`
}

func NewValidationRequest(r *http.Request) (*ValidationRequest, error) {
	vr := &ValidationRequest{}
	if err := DecodeRequestSchema(vr, r.Form); err != nil {
		return nil, err
	}

	vr.Options = &ValidationRequestOptions{
		Authorization: r.Header.Get("Authorization"),
	}
	return vr, nil
}

func (vr *ValidationRequest) Validate(doc *ValidateDocument) (error, string) {
	auth := strings.SplitN(vr.Options.Authorization, " ", 2)
	if len(auth) != 2 || auth[0] != "Bearer" {
		return errors.New("invalid_request"), "Bearer authentication required"
	}

	token, err := jwt.Decode(auth[1], func(header *jwt.Header, claims *jwt.Claims) (interface{}, error) {
		if header.Alg != doc.TokenAlg {
			return nil, fmt.Errorf("unexpected signing method: %v", header.Alg)
		}
		return doc.TokenPublicKey, nil
	})
	if err != nil {
		return errors.New("validation_failed"), err.Error()
	}

	switch vr.TokenType {
	case "access_token":
		if doc.TokenAccessTokenClaim != "" && !token.Claims.CheckBool(doc.TokenAccessTokenClaim, true) {
			// Access token claim failed.
			return errors.New("access_denied"), "Not an access token"
		}
	case "":
		fallthrough
	case "id_token":
	default:
		return errors.New("invalid_request"), "Invalid token_type"
	}

	if token.Valid {
		return nil, ""
	}
	return errors.New("invalid_token"), "Token is not valid"
}

func (vr *ValidationRequest) Response(doc *ValidateDocument) (int, interface{}, http.Header) {
	headers := http.Header{
		"Cache-Control": {"no-store"},
		"Pragma":        {"no-cache"},
	}
	if err, errDescription := vr.Validate(doc); err != nil {
		log.Println("validation failed http", err, errDescription)
		headers.Add("WWW-Authenticate", fmt.Sprintf("error=%s, error_description=%s", strconv.QuoteToASCII(err.Error()), strconv.QuoteToASCII(errDescription)))
		return 401, err.Error(), headers
	}

	return 200, "ok", headers
}
