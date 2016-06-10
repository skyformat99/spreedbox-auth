package baddsch

import (
	"crypto"
	"net/http"

	"golang.struktur.de/spreedbox/spreedbox-auth/baddsch/jwk"
)

type JWKSDocument struct {
	keys *jwk.Key
}

func NewJWKSDocument(tokenPublicKey crypto.PublicKey) *JWKSDocument {
	var keys *jwk.Key
	if key, err := jwk.PublicKey(tokenPublicKey); err == nil {
		key.Use = "sig"
		key.KeyOps = []string{"verify"}
		keys = jwk.Keys(key)
	} else {
		keys = &jwk.Key{}
	}

	return &JWKSDocument{keys}
}

func (doc *JWKSDocument) Get(r *http.Request) (int, interface{}, http.Header) {
	data, _ := jwk.Marshal(doc.keys)
	return 200, data, http.Header{"Content-Type": {"application/jwk-set+json"}}
}
