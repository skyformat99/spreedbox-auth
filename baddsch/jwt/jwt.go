package jwt

import (
	"crypto"
	"errors"
	"fmt"
	"time"

	jwtgo "github.com/dgrijalva/jwt-go"
)

var DefaultTokenDuration = 60 * time.Minute

type Header struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
}

func NewHeader(data map[string]interface{}) (*Header, error) {
	h := &Header{}
	for k, v := range data {
		switch k {
		case "alg":
			if alg, found := v.(string); found {
				h.Alg = alg
			}
		case "typ":
			if typ, found := v.(string); found {
				h.Typ = typ
			}
		}
	}
	return h, nil
}

func (h *Header) SigningMethod() (jwtgo.SigningMethod, error) {
	if h.Typ != "JWT" {
		return nil, fmt.Errorf("unknown typ: %s", h.Typ)
	}
	method := jwtgo.GetSigningMethod(h.Alg)
	if method == nil {
		return nil, fmt.Errorf("unknown alg: %s", h.Alg)
	}
	return method, nil
}

type Claims struct {
	// http://openid.net/specs/openid-connect-core-1_0.html#IDToken
	Iss           string                 `json:"iss"`
	Aud           string                 `json:"aud"`
	Scope         string                 `json:"scope,omitempty"`
	Exp           int64                  `json:"exp"`
	Iat           int64                  `json:"iat"`
	Sub           string                 `json:"sub,omitempty"`
	Nonce         string                 `json:"nonce,omitempty"`
	PrivateClaims map[string]interface{} `json:"-"`
}

func NewClaims(data map[string]interface{}) (*Claims, error) {
	c := &Claims{
		PrivateClaims: make(map[string]interface{}),
	}
	for k, v := range data {
		switch k {
		case "iss":
			if iss, found := v.(string); found {
				c.Iss = iss
			}
		case "aud":
			if aud, found := v.(string); found {
				c.Aud = aud
			}
		case "scope":
			if scope, found := v.(string); found {
				c.Scope = scope
			}
		case "exp":
			switch v.(type) {
			case float64:
				c.Exp = int64(v.(float64))
			case int64:
				c.Exp = v.(int64)
			}
		case "iat":
			switch v.(type) {
			case float64:
				c.Iat = int64(v.(float64))
			case int64:
				c.Iat = v.(int64)
			}
		case "sub":
			if sub, found := v.(string); found {
				c.Sub = sub
			}
		case "nonce":
			if nonce, found := v.(string); found {
				c.Nonce = nonce
			}
		default:
			c.PrivateClaims[k] = v
		}
	}
	return c, nil
}

func Encode(header *Header, claims *Claims, duration *time.Duration, key crypto.PrivateKey) (*Token, error) {
	method, err := header.SigningMethod()
	if err != nil {
		return nil, err
	}
	now := time.Now().Add(-10 * time.Second)
	if claims.Iat == 0 {
		claims.Iat = now.Unix()
	}
	if claims.Exp == 0 {
		if duration == nil {
			duration = &DefaultTokenDuration
		}
		claims.Exp = now.Add(*duration).Unix()
	}
	if claims.Exp < claims.Iat {
		return nil, errors.New("invalid exp, must be later than iat")
	}

	token := jwtgo.New(method)
	token.Claims["iss"] = claims.Iss
	token.Claims["aud"] = claims.Aud
	token.Claims["exp"] = claims.Exp
	token.Claims["iat"] = claims.Iat
	if claims.Scope != "" {
		token.Claims["scope"] = claims.Scope
	}
	if claims.Sub != "" {
		token.Claims["sub"] = claims.Sub
	}
	if claims.Nonce != "" {
		token.Claims["nonce"] = claims.Nonce
	}

	if claims.PrivateClaims != nil {
		for k, v := range claims.PrivateClaims {
			token.Claims[k] = v
		}
	}

	raw, err := token.SignedString(key)
	if err != nil {
		return nil, err
	}
	return &Token{
		Raw:       raw,
		ExpiresIn: int64((time.Duration(claims.Exp-now.Unix()) * time.Second).Seconds()),
	}, nil
}

type Validator func(header *Header, claims *Claims) (interface{}, error)

type Token struct {
	Raw       string
	Header    *Header
	Claims    *Claims
	Valid     bool
	ExpiresIn int64
}

func Decode(encodedToken string, validator Validator) (*Token, error) {
	var header *Header
	var claims *Claims
	token, err := jwtgo.Parse(encodedToken, func(token *jwtgo.Token) (interface{}, error) {
		header, _ = NewHeader(token.Header)
		claims, _ = NewClaims(token.Claims)
		return validator(header, claims)
	})
	return &Token{
		Raw:    encodedToken,
		Header: header,
		Claims: claims,
		Valid:  token.Valid,
	}, err
}
