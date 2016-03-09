package baddsch

import (
	"crypto"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"golang.struktur.de/spreedbox/spreedbox-auth/baddsch/jwt"
)

// curl -v -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJjbGllbnQtaWQiLCJleHAiOjE0NTgxNDgzNDAsImlhdCI6MTQ1NzU0MzU0MCwiaXNzIjoiaHR0cHM6Ly9zcHJlZWRib3gubG9jYWxkb21haW4iLCJub25jZSI6IjEyMyIsInN1YiI6InRvZG8tdXNlci1pZCJ9.mD-TKPlPxb3WPr0yfafUupcHYjCFei84_HEpG8CZolbEOxGZaS_l75sl0mKmKEUrFfwoxRcLSOtciOVElISoXrZDJRu3x7HnvSBVR3il4T9uoKs8MawNxPAjKBUo3rw3L4lACNYpXri0-lQ3LVthJJEThWszcfTO3meX5F8AREU7_4Jsj0idOcThSJh7121acgkOoAKsgTE2Gvm3t6e7gcW9aeym74DiOP5M_eHd8AQLBjjCf3ioHb92iQQolA7YnRn9kGDToqwuhsIQym6gFtFAeek6anALjDgzLsda649joLwK4NzaPk3VgH1XlykAMOP-_7Qla3fyqigAvjV8v9XD3Lz5WcOUjZnW4xjfVDGk72rNZll_zVGBmhHvTGCZaDqqX5_TbrpgCW4s1cjV6w8osEFLif_0-NClUshwnA8EuCVnr3cIK-LIyKkmllxoLem3BgEB201LimRRlYRVv23GNODmva1e92zMkbTgxOpTgMpAxMU_QOOKCWzAYVdph4XGSHzs1Ih-DiAG7pSIeAD-67MOGVNrJzWEHQkw5i_4CGpbM2nRz-uT4qDfJS3tJxtgpT-CPRnA_GJYRKltPplucCib01JRhjUumo-ewQc5HIs2prsa0v_f_J7Vyb7c2PsjMh6u-jhmv3DimwznQXB3dyJhdAmlDDtINDUAli0" http://localhost:7031/api/v1/validate

type ValidateDocument struct {
	TokenAlg       string
	TokenPublicKey crypto.PublicKey
}

func (doc *ValidateDocument) Get(r *http.Request) (int, interface{}, http.Header) {
	vr := &ValidationRequest{
		Authorization: r.Header.Get("Authorization"),
	}
	return vr.Response(doc)
}

type ValidationRequest struct {
	Authorization string
}

func (vr *ValidationRequest) Validate(tokenAlg string, publicKey crypto.PublicKey) (error, string) {
	auth := strings.SplitN(vr.Authorization, " ", 2)
	if len(auth) != 2 || auth[0] != "Bearer" {
		return errors.New("invalid_request"), "Bearer authentication required"
	}

	token, err := jwt.Decode(auth[1], func(header *jwt.Header, claims *jwt.Claims) (interface{}, error) {
		if header.Alg != tokenAlg {
			return nil, fmt.Errorf("unexpected signing method: %v", header.Alg)
		}
		return publicKey, nil
	})
	if err != nil {
		return errors.New("validation_failed"), err.Error()
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
	if err, errDescription := vr.Validate(doc.TokenAlg, doc.TokenPublicKey); err != nil {
		return 403, fmt.Sprintf("%s: %s", err.Error(), errDescription), headers
	}

	return 200, "", headers
}
