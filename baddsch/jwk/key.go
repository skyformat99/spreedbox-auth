package jwk

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/binary"
	"fmt"
	"math/big"
)

// Key implements JSON Web Keys specifed at
// https://tools.ietf.org/html/rfc7517 and https://tools.ietf.org/html/rfc7518
type Key struct {
	Keys []*Key `json:"keys,omitempty"`

	Kty     string   `json:"kty,omitempty"`      // Key Type
	Use     string   `json:"use,omitempty"`      // Public Key Use
	KeyOps  []string `json:"key_ops,omitempty"`  // Key Operations
	Alg     string   `json:"alg,omitempty"`      // Algorithm
	Kid     string   `json:"kid,omitempty"`      // Key ID
	X5u     string   `json:"x5u,omitempty"`      // X.509 URL
	X5c     string   `json:"x5c,omitempty"`      // X.509 Certificate Chain
	X5t     string   `json:"x5t,omitempty"`      // X.509 Certificate SHA-1 Thumbprint
	X5tS256 string   `json:"x5t#S256,omitempty"` // X.509 Certificate SHA-256 Thumbprint

	// Elliptic Curve Public Keys
	Crv string `json:"crv,omitempty"` // Curve
	X   string `json:"x,omitempty"`   // X Coordinate
	Y   string `json:"y,omitempty"`   // Y Coordinate

	// Elliptic Curve Private Keys
	D string `json:"d,omitempty"` // ECC Private Key, RSA Private Key Private Exponent

	// RSA Public Keys
	N string `json:"n,omitempty"` // Modulus
	E string `json:"e,omitempty"` // Exponent

	// RSA Private Keys
	P  string `json:"p,omitempty"`  // First Prime Factor
	Q  string `json:"q,omitempty"`  // Second Prime Factor
	Dp string `json:"dp,omitempty"` // First Factor CRT Exponent
	Dq string `json:"dq,omitempty"` // Second Factor CRT Exponent
	Qi string `json:"qi,omitempty"` // First CRT Coefficient

	// Symmetric Keys
	K string `json:"k,omitempty"` //Key Value
}

func PublicKey(key crypto.PublicKey) (*Key, error) {
	switch key := key.(type) {
	case *rsa.PublicKey:
		// RSA Public Key
		jwk := &Key{
			Kty: "RSA",
			N:   encodeBytes(key.N.Bytes()),
			E:   encodeBytes(big.NewInt(int64(key.E)).Bytes()),
		}

		return jwk, nil
	case *ecdsa.PublicKey:
		// ECDSA Public Key
		jwk := &Key{
			Kty: "EC",
			X:   encodeBytes(key.X.Bytes()),
			Y:   encodeBytes(key.Y.Bytes()),
		}
		switch key.Curve {
		case elliptic.P224():
			jwk.Crv = "P-224"
		case elliptic.P256():
			jwk.Crv = "P-256"
		case elliptic.P384():
			jwk.Crv = "P-384"
		case elliptic.P521():
			jwk.Crv = "P-521"
		default:
			return nil, fmt.Errorf("Unsupported ECDSA curve")
		}

		return jwk, nil
	case []byte:
		// Symmetric Key
		jwk := &Key{
			Kty: "oct",
			K:   encodeBytes(key),
		}

		return jwk, nil
	default:

		return nil, fmt.Errorf("Unknown key type %T", key)
	}
}

func (jwk *Key) DecodePublicKey() (crypto.PublicKey, error) {
	switch jwk.Kty {
	case "RSA":
		if jwk.N == "" || jwk.E == "" {
			return nil, fmt.Errorf("Invalid JWK RSA key")
		}

		modulusBytes, err := decodeBytes(jwk.N)
		if err != nil {
			return nil, fmt.Errorf("Invalid JWK RSA key: %s", err.Error())
		}
		modulus := &big.Int{}
		modulus.SetBytes(modulusBytes)

		exponentBytes, err := decodeBytes(jwk.E)
		if err != nil {
			return nil, fmt.Errorf("Invalid JWK RSA key: %s", err.Error())
		}
		if len(exponentBytes) < 4 {
			// Make sure we have at least 4 bytes.
			tmpExponentBytes := make([]byte, 4)
			copy(tmpExponentBytes, exponentBytes)
			exponentBytes = tmpExponentBytes
		}

		return &rsa.PublicKey{
			N: modulus,
			E: int(binary.BigEndian.Uint32(exponentBytes)),
		}, nil
	case "EC":
		if jwk.Crv == "" || jwk.X == "" || jwk.Y == "" {
			return nil, fmt.Errorf("Invalid JWK EC key")
		}

		var curve elliptic.Curve
		switch jwk.Crv {
		case "P-224":
			curve = elliptic.P224()
		case "P-256":
			curve = elliptic.P256()
		case "P-384":
			curve = elliptic.P384()
		case "P-521":
			curve = elliptic.P521()
		default:
			return nil, fmt.Errorf("Unknown curve type: %s", jwk.Crv)
		}

		xBytes, err := decodeBytes(jwk.X)
		if err != nil {
			return nil, fmt.Errorf("Invalid JWK EC key: %s", err.Error())
		}
		x := &big.Int{}
		x.SetBytes(xBytes)

		yBytes, err := decodeBytes(jwk.Y)
		if err != nil {
			return nil, fmt.Errorf("Invalid JWK EC key: %s", err.Error())
		}
		y := &big.Int{}
		y.SetBytes(yBytes)

		return &ecdsa.PublicKey{
			Curve: curve,
			X:     x,
			Y:     y,
		}, nil
	case "oct":
		if jwk.K == "" {
			return nil, fmt.Errorf("Invalid JWK Octet key")
		}

		key, err := decodeBytes(jwk.K)
		if err != nil {
			return nil, fmt.Errorf("Invalid JWK Octet key: %s", err.Error())
		}

		return key, nil
	default:

		return nil, fmt.Errorf("Unknown JWK key type %s", jwk.Kty)
	}
}
