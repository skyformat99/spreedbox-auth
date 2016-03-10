package baddsch

import (
	"crypto"
	"encoding/base64"
)

func LeftmostHash(data []byte, hash crypto.Hash) []byte {
	h := hash.New()
	hashed := h.Sum(data)
	return hashed[:len(hashed)/2]
}

func LeftmostHashBase64URLEncoding(data []byte, hash crypto.Hash) string {
	leftMost := LeftmostHash(data, hash)
	return base64.URLEncoding.EncodeToString(leftMost)
}
