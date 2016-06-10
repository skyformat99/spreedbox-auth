package jwk

func Keys(keys ...*Key) *Key {
	return &Key{
		Keys: keys,
	}
}
