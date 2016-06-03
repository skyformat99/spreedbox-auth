package randomstring

import (
	"crypto/rand"
	"math/big"
)

const (
	dict = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
)

func NewRandomInt(max *big.Int) int {
	rand, err := rand.Int(rand.Reader, max)
	if err != nil {
		// This should never happen.
		panic(err)
	}
	return int(rand.Int64())
}

// NewRandomString returns a alphanumeric random string with
// the specified length using crypto/rand with fallback to
// math/rand on error.
func NewRandomString(length int) string {
	buf := make([]byte, length)
	max := big.NewInt(int64(len(dict)))
	for i := 0; i < length; i++ {
		buf[i] = dict[NewRandomInt(max)]
	}
	return string(buf)
}
