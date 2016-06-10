package jwk

import (
	"encoding/base64"
	"strings"
)

func encodeBytes(b []byte) string {
	s := base64.URLEncoding.EncodeToString(b)

	// Strip padding.
	return strings.TrimRight(s, "=")
}

func decodeBytes(s string) ([]byte, error) {
	// Bring back padding.
	pad := len(s) % 4
	if pad > 0 {
		s = s + strings.Repeat("=", 4-pad)
	}

	return base64.URLEncoding.DecodeString(s)
}
