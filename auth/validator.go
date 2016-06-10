package auth

import (
	"errors"
	"net/http"

	"golang.struktur.de/spreedbox/spreedbox-auth/auth/claim"
)

type Validator struct {
	Client         *Client
	requiredClaims map[string]interface{}
	tokenType      string
}

func (v *Validator) RequireClaim(claim *claim.Claim) *Validator {
	if v.requiredClaims == nil {
		v.requiredClaims = make(map[string]interface{})
	}
	claim.Add(v.requiredClaims)
	return v
}

func (v *Validator) RequireIsAdminClaim() *Validator {
	return v.RequireClaim(IsAdminClaim)
}

func (v *Validator) RequireIsUserClaim() *Validator {
	return v.RequireClaim(IsUserClaim)
}

func (v *Validator) RequireAccessToken() *Validator {
	v.tokenType = AccessTokenType
	return v
}

func (v *Validator) RequireIDToken() *Validator {
	v.tokenType = IDTokenType
	return v
}

func (v *Validator) ValidateRequest() *ValidateRequest {
	request := &ValidateRequest{}
	if v.requiredClaims != nil {
		// Copy base claims.
		requiredClaims := make(map[string]interface{})
		for k, v := range v.requiredClaims {
			requiredClaims[k] = v
		}
		request.RequiredClaims = requiredClaims
	}
	request.TokenType = v.tokenType
	return request
}

func (v *Validator) DoValidateRequest(request *ValidateRequest) error {
	return v.Client.DoValidateRequest(request)
}

func (v *Validator) DoValidateAuth(auth string) error {
	request := v.ValidateRequest()
	request.Authorization = auth
	return v.DoValidateRequest(request)
}

func (v *Validator) DoValidateHTTPRequest(r *http.Request) error {
	auth := r.Header.Get("Authorization")
	if auth == "" {
		return errors.New("authorization_missing")
	}

	return v.DoValidateAuth(auth)
}

func (v *Validator) AuthRequiredHTTPHandler(handler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := v.DoValidateHTTPRequest(r); err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}
		handler(w, r)
	}
}
