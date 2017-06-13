package baddsch

import (
	"net/http"
	"net/url"
	"testing"
)

func Test_IsValidRedirectNoPort(t *testing.T) {
	tests := map[string]bool{
		"http://localhost":        true,
		"http://localhost:123":    false,
		"https://localhost":       false,
		"https://localhost:123":   false,
		"http://sample-host:123":  false,
		"https://sample-host":     true,
		"https://sample-host:123": false,
	}

	ar := AuthenticationRequest{
		Request: &http.Request{
			Host: "sample-host",
		},
	}

	if v := ar.IsValidRedirect(nil); v {
		t.Error("nil should be invalid")
	}
	for u, valid := range tests {
		url, err := url.Parse(u)
		if err != nil {
			t.Error(err)
			continue
		}

		v := ar.IsValidRedirect(url)
		if v != valid {
			t.Errorf("failed for %s: got %v, expected %v", u, v, valid)
		}
	}
}

func Test_IsValidRedirectPort(t *testing.T) {
	tests := map[string]bool{
		"http://localhost":        true,
		"http://localhost:123":    false,
		"https://localhost":       false,
		"https://localhost:123":   false,
		"http://sample-host:123":  false,
		"https://sample-host":     false,
		"https://sample-host:123": true,
	}

	ar := AuthenticationRequest{
		Request: &http.Request{
			Host: "sample-host:123",
		},
	}

	if v := ar.IsValidRedirect(nil); v {
		t.Error("nil should be invalid")
	}
	for u, valid := range tests {
		url, err := url.Parse(u)
		if err != nil {
			t.Error(err)
			continue
		}

		v := ar.IsValidRedirect(url)
		if v != valid {
			t.Errorf("failed for %s: got %v, expected %v", u, v, valid)
		}
	}
}
