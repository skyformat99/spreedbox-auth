package baddsch

import (
	"github.com/gorilla/schema"
)

var decoder = schema.NewDecoder()

func DecodeRequestSchema(dst interface{}, src map[string][]string) error {
	return decoder.Decode(dst, src)
}

func init() {
	decoder.IgnoreUnknownKeys(true)
}
