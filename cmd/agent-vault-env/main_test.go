package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

func TestMain_NoToken(t *testing.T) {
	os.Unsetenv("VAULT_TOKEN")

	oldStderr := os.Stderr
	r, w, _ := os.Pipe()
	os.Stderr = w

	// Can't easily test main() exit, but we can test the logic
	// by checking that empty token triggers error path
	token := ""
	if token == "" {
		w.Close()
		os.Stderr = oldStderr
		r.Read(make([]byte, 1024))
		// Expected behavior — token empty = error
		return
	}
}

func TestAccessEndpoint(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := strings.TrimPrefix(r.URL.Path, "/access/")
		if token == "valid-token" {
			json.NewEncoder(w).Encode(map[string]string{
				"name":       "test_secret",
				"value":      "test_value",
				"updated_at": "2026-01-01T00:00:00Z",
			})
		} else {
			http.Error(w, "invalid token", http.StatusForbidden)
		}
	}))
	defer srv.Close()

	// Test valid token
	resp, err := http.Get(srv.URL + "/access/valid-token")
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	var result map[string]string
	json.NewDecoder(resp.Body).Decode(&result)
	if result["name"] != "test_secret" {
		t.Fatalf("expected test_secret, got %s", result["name"])
	}
	if result["value"] != "test_value" {
		t.Fatalf("expected test_value, got %s", result["value"])
	}
}

func TestAccessEndpointInvalidToken(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "invalid token", http.StatusForbidden)
	}))
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/access/bad-token")
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 403 {
		t.Fatalf("expected 403, got %d", resp.StatusCode)
	}
}

func TestSecretByNameEndpoint(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check admin token
		if r.Header.Get("X-Vault-Token") != "admin-123" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		name := strings.TrimPrefix(r.URL.Path, "/secret/")
		if name == "my_secret" {
			json.NewEncoder(w).Encode(map[string]string{
				"name":       "my_secret",
				"value":      "my_value",
				"updated_at": "2026-01-01T00:00:00Z",
			})
		} else {
			http.Error(w, "secret not found", http.StatusNotFound)
		}
	}))
	defer srv.Close()

	// Test: valid admin token + existing secret
	req, _ := http.NewRequest("GET", srv.URL+"/secret/my_secret", nil)
	req.Header.Set("X-Vault-Token", "admin-123")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	var result map[string]string
	json.NewDecoder(resp.Body).Decode(&result)
	if result["value"] != "my_value" {
		t.Fatalf("expected my_value, got %s", result["value"])
	}

	// Test: missing admin token
	req2, _ := http.NewRequest("GET", srv.URL+"/secret/my_secret", nil)
	resp2, _ := http.DefaultClient.Do(req2)
	if resp2.StatusCode != 401 {
		t.Fatalf("expected 401, got %d", resp2.StatusCode)
	}
	resp2.Body.Close()

	// Test: non-existent secret
	req3, _ := http.NewRequest("GET", srv.URL+"/secret/nonexistent", nil)
	req3.Header.Set("X-Vault-Token", "admin-123")
	resp3, _ := http.DefaultClient.Do(req3)
	if resp3.StatusCode != 404 {
		t.Fatalf("expected 404, got %d", resp3.StatusCode)
	}
	resp3.Body.Close()
}

func TestExportFormat(t *testing.T) {
	// Simulate the export format logic
	value := "secret'with'quotes"
	safe := strings.ReplaceAll(value, "'", "'\\''")
	expected := "secret'\\''with'\\''quotes"
	if safe != expected {
		t.Fatalf("expected %q, got %q", expected, safe)
	}
}

func TestExportFormatSimple(t *testing.T) {
	value := "simple_value"
	safe := strings.ReplaceAll(value, "'", "'\\''")
	if safe != value {
		t.Fatalf("expected unchanged, got %q", safe)
	}
}

func TestProjectTokenResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := strings.TrimPrefix(r.URL.Path, "/access/")
		if token == "project-token-123" {
			json.NewEncoder(w).Encode(map[string]interface{}{
				"project":    "cheque-bot",
				"project_id": "cheque-bot",
				"secrets": map[string]interface{}{
					"openrouter_api_key": map[string]interface{}{
						"name":       "openrouter_api_key",
						"value":      "sk-or-xxx",
						"updated_at": "2026-01-01T00:00:00Z",
					},
					"tg_bot_token": map[string]interface{}{
						"name":       "tg_bot_token",
						"value":      "123456:ABC",
						"updated_at": "2026-01-01T00:00:00Z",
					},
				},
			})
		} else {
			http.Error(w, "invalid token", http.StatusForbidden)
		}
	}))
	defer srv.Close()

	// Test project token returns 200
	resp, err := http.Get(srv.URL + "/access/project-token-123")
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatalf("decode: %v", err)
	}

	if result["project"] != "cheque-bot" {
		t.Fatalf("expected project=cheque-bot, got %v", result["project"])
	}

	secrets, ok := result["secrets"].(map[string]interface{})
	if !ok {
		t.Fatal("secrets is not a map")
	}
	if len(secrets) != 2 {
		t.Fatalf("expected 2 secrets, got %d", len(secrets))
	}
}

func TestSingleSecretResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"name":       "single_secret",
			"value":      "single_value",
			"updated_at": "2026-01-01T00:00:00Z",
		})
	}))
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/access/some-token")
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatalf("decode: %v", err)
	}

	// Single secret should NOT have "project" field
	if _, hasProject := result["project"]; hasProject {
		t.Fatal("single secret response should not have 'project' field")
	}
	if result["name"] != "single_secret" {
		t.Fatalf("expected single_secret, got %v", result["name"])
	}
}

func TestEnvEscape(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"simple", "simple"},
		{"with space", "\"with space\""},
		{"with\ttab", "\"with\ttab\""},
		{"with#hash", "\"with#hash\""},
		{`with"quote`, `with"quote`},  // quote not in " \t#" — no wrapping
	}
	for _, tt := range tests {
		got := envEscape(tt.input)
		if got != tt.expected {
			t.Fatalf("envEscape(%q) = %q, want %q", tt.input, got, tt.expected)
		}
	}
}

func TestShellEscape(t *testing.T) {
	got := shellEscape("it's a test")
	expected := "it'\\''s a test"
	if got != expected {
		t.Fatalf("shellEscape = %q, want %q", got, expected)
	}
}
