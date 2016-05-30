package lockmap

import (
	"sync"
)

// A threadsafe map of type string:interface{}.
type LockMap struct {
	items map[string]interface{}
	sync.RWMutex
}

func New() *LockMap {
	return &LockMap{
		items: make(map[string]interface{}),
	}
}

// Sets the given value under the specified key.
func (lm *LockMap) Set(key string, value interface{}) {
	lm.Lock()
	lm.items[key] = value
	lm.Unlock()
}

// Sets the given value under the specified key if key is not already set.
// Returns true when value was set, false otherwise.
func (lm *LockMap) SetIfAbsent(key string, value interface{}) bool {
	lm.Lock()
	_, ok := lm.items[key]
	if !ok {
		lm.items[key] = value
	}
	lm.Unlock()

	return !ok
}

// Retrieves the element from the map by the given key.
func (lm *LockMap) Get(key string, value interface{}) (interface{}, bool) {
	lm.RLock()
	val, ok := lm.items[key]
	lm.RUnlock()

	return val, ok
}

// Checks if the map has the given key.
func (lm *LockMap) Has(key string) bool {
	lm.RLock()
	_, ok := lm.items[key]
	lm.RUnlock()

	return ok
}

// Removes an element from the map.
func (lm *LockMap) Remove(key string) {
	lm.Lock()
	delete(lm.items, key)
	lm.Unlock()
}
