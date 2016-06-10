package jwk

import (
	"encoding/json"
)

func Marshal(key *Key) ([]byte, error) {
	return json.Marshal(key)
}

func Unmarshal(b []byte) (*Key, error) {
	jwk := &Key{}
	err := json.Unmarshal(b, jwk)
	if err != nil {
		return nil, err
	}

	return jwk, nil
}
