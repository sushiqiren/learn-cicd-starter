package auth

import (
	"net/http"
	"testing"
)

func TestGetAPIKey_NoAuthHeader(t *testing.T) {
	headers := http.Header{}
	_, err := GetAPIKey(headers)
	if err != ErrNoAuthHeaderIncluded {
		t.Errorf("expected error %v, got %v", ErrNoAuthHeaderIncluded, err)
	}
}

func TestGetAPIKey_MalformedAuthHeader(t *testing.T) {
	headers := http.Header{}
	headers.Set("Authorization", "Bearer token123")
	_, err := GetAPIKey(headers)
	if err == nil || err.Error() != "malformed authorization header" {
		t.Errorf("expected error 'malformed authorization header', got %v", err)
	}
}

func TestGetAPIKey_ValidAuthHeader(t *testing.T) {
	headers := http.Header{}
	headers.Set("Authorization", "ApiKey validApiKey123")
	apiKey, err := GetAPIKey(headers)
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
	if apiKey != "validApiKey123" {
		t.Errorf("expected apiKey 'validApiKey123', got %v", apiKey)
	}
}
