package main

import (
	"bytes"
	"encoding/json"
	"net"
	"net/http"
	"runtime"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// === STORE TESTS ===

func TestStoreSetGet(t *testing.T) {
	s := NewStore("")
	s.Set("api_key", "secret123")

	secret, ok := s.Get("api_key")
	if !ok {
		t.Fatal("expected secret to exist")
	}
	if secret.Value != "secret123" {
		t.Fatalf("expected secret123, got %s", secret.Value)
	}
	if secret.Name != "api_key" {
		t.Fatalf("expected name api_key, got %s", secret.Name)
	}
}

func TestStoreGetMissing(t *testing.T) {
	s := NewStore("")
	_, ok := s.Get("nonexistent")
	if ok {
		t.Fatal("expected false for missing secret")
	}
}

func TestStoreUpdate(t *testing.T) {
	s := NewStore("")
	s.Set("key", "v1")
	s.Set("key", "v2")

	sec, ok := s.Get("key")
	if !ok {
		t.Fatal("expected secret")
	}
	if sec.Value != "v2" {
		t.Fatalf("expected v2, got %s", sec.Value)
	}

	// Only one secret should exist
	if s.Count() != 1 {
		t.Fatalf("expected 1 secret, got %d", s.Count())
	}
}

func TestStoreDelete(t *testing.T) {
	s := NewStore("")
	s.Set("key1", "val1")

	if !s.Delete("key1") {
		t.Fatal("expected delete to return true")
	}
	if _, ok := s.Get("key1"); ok {
		t.Fatal("expected secret to be deleted")
	}
	if s.Delete("key1") {
		t.Fatal("expected delete of non-existent to return false")
	}
}

func TestStoreDeleteAll(t *testing.T) {
	s := NewStore("")
	s.Set("k1", "v1")
	s.Set("k2", "v2")

	s.DeleteAll()
	if s.Count() != 0 {
		t.Fatalf("expected 0 secrets, got %d", s.Count())
	}
}

func TestStoreList(t *testing.T) {
	s := NewStore("")
	s.Set("a", "1")
	s.Set("b", "2")

	list := s.List()
	if len(list) != 2 {
		t.Fatalf("expected 2 secrets, got %d", len(list))
	}
}

func TestStoreListEmpty(t *testing.T) {
	s := NewStore("")
	list := s.List()
	if len(list) != 0 {
		t.Fatalf("expected 0 secrets, got %d", len(list))
	}
}

func TestStoreCount(t *testing.T) {
	s := NewStore("")
	if s.Count() != 0 {
		t.Fatal("expected 0")
	}
	s.Set("k", "v")
	if s.Count() != 1 {
		t.Fatal("expected 1")
	}
}

func TestStorePreservesOnUpdate(t *testing.T) {
	s := NewStore("")
	s.Set("key", "v1")
	sec1, _ := s.Get("key")
	if sec1.UpdatedAt.IsZero() {
		t.Fatal("UpdatedAt should be set")
	}
	if sec1.Name != "key" {
		t.Fatalf("expected name 'key', got %q", sec1.Name)
	}

	s.Set("key", "v2")
	sec2, _ := s.Get("key")
	if sec2.Value != "v2" {
		t.Fatalf("expected v2, got %s", sec2.Value)
	}
	if sec2.Name != "key" {
		t.Fatal("name should be preserved")
	}
	if s.Count() != 1 {
		t.Fatal("should still have exactly 1 secret")
	}
}

// === SEALED STORE TESTS ===

func TestSealedStoreEncryptDecrypt(t *testing.T) {
	s := NewStore("test-password")
	s.Set("api_key", "super-secret-value")

	// Internal storage should be encrypted (not plaintext)
	s.mu.RLock()
	rawValue := s.secrets["api_key"].Value
	s.mu.RUnlock()
	if rawValue == "super-secret-value" {
		t.Fatal("sealed store: value should be encrypted in memory")
	}

	// Get should decrypt transparently
	secret, ok := s.Get("api_key")
	if !ok {
		t.Fatal("expected secret to exist")
	}
	if secret.Value != "super-secret-value" {
		t.Fatalf("sealed store: expected super-secret-value, got %s", secret.Value)
	}
}

func TestSealedStoreGetReturnsDecrypted(t *testing.T) {
	s := NewStore("sealed-pass")
	s.Set("db_pass", "p@ssw0rd!")

	sec, ok := s.Get("db_pass")
	if !ok {
		t.Fatal("expected secret to exist")
	}
	if sec.Value != "p@ssw0rd!" {
		t.Fatalf("expected p@ssw0rd!, got %s", sec.Value)
	}
}

func TestSealedStoreUpdatePreservesEncryption(t *testing.T) {
	s := NewStore("pass")
	s.Set("key", "v1")
	s.Set("key", "v2")

	sec, ok := s.Get("key")
	if !ok {
		t.Fatal("expected secret to exist")
	}
	if sec.Value != "v2" {
		t.Fatalf("expected v2, got %s", sec.Value)
	}

	// Internal should still be encrypted
	s.mu.RLock()
	rawValue := s.secrets["key"].Value
	s.mu.RUnlock()
	if rawValue == "v2" {
		t.Fatal("updated value should be encrypted in memory")
	}
}

func TestSealedStoreListReturnsDecrypted(t *testing.T) {
	s := NewStore("pass")
	s.Set("a", "val-a")
	s.Set("b", "val-b")

	secrets := s.List()
	if len(secrets) != 2 {
		t.Fatalf("expected 2 secrets, got %d", len(secrets))
	}

	// Values should be decrypted
	for _, sec := range secrets {
		switch sec.Name {
		case "a":
			if sec.Value != "val-a" {
				t.Fatalf("expected val-a, got %s", sec.Value)
			}
		case "b":
			if sec.Value != "val-b" {
				t.Fatalf("expected val-b, got %s", sec.Value)
			}
		}
	}
}

// === CONFIG TESTS ===

func TestLoadConfigNonExistent(t *testing.T) {
	cfg, err := loadConfig("/nonexistent/config.yaml")
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if cfg.ListenAddr != "127.0.0.1:8301" {
		t.Fatalf("expected default listen addr, got %s", cfg.ListenAddr)
	}
	if cfg.SnapshotPath != "snapshot.enc" {
		t.Fatalf("expected default snapshot path, got %s", cfg.SnapshotPath)
	}
	if cfg.TokenTTLHours != 720 {
		t.Fatalf("expected default TTL 720, got %d", cfg.TokenTTLHours)
	}
}

func TestLoadConfigFromFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")

	content := `admin_token: test-admin
tg_bot_token: test-bot-token
tg_admin_id: 12345
listen_addr: 127.0.0.1:9999
token_ttl_hours: 24
`
	os.WriteFile(path, []byte(content), 0600)

	cfg, err := loadConfig(path)
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	if cfg.AdminToken != "test-admin" {
		t.Fatalf("expected test-admin, got %s", cfg.AdminToken)
	}
	if cfg.ListenAddr != "127.0.0.1:9999" {
		t.Fatalf("expected custom addr, got %s", cfg.ListenAddr)
	}
	if cfg.TokenTTLHours != 24 {
		t.Fatalf("expected 24, got %d", cfg.TokenTTLHours)
	}
}

func TestLoadConfigEnvOverride(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	os.WriteFile(path, []byte("admin_token: file-admin"), 0600)

	os.Setenv("VAULT_ADMIN_TOKEN", "env-admin")
	defer os.Unsetenv("VAULT_ADMIN_TOKEN")

	cfg, err := loadConfig(path)
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	if cfg.AdminToken != "env-admin" {
		t.Fatalf("expected env-admin, got %s", cfg.AdminToken)
	}
}

func TestConfigSaveAndLoad(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")

	cfg := &Config{
		AdminToken:   "save-test",
		ListenAddr:   "127.0.0.1:7777",
		SecretTokens: make(map[string]*SecretToken),
	}
	cfg.SecretTokens[hashToken("tok1")] = &SecretToken{
		SecretName: "s1",
		Token:      hashToken("tok1"),
		Revoked:    false,
	}

	if err := cfg.save(path); err != nil {
		t.Fatalf("save: %v", err)
	}

	// No .tmp left
	if _, err := os.Stat(path + ".tmp"); !os.IsNotExist(err) {
		t.Fatal("tmp file should not exist after save")
	}

	// Reload
	loaded, err := loadConfig(path)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if loaded.AdminToken != "save-test" {
		t.Fatalf("expected save-test, got %s", loaded.AdminToken)
	}
	if loaded.ListenAddr != "127.0.0.1:7777" {
		t.Fatalf("expected custom addr, got %s", loaded.ListenAddr)
	}
}

// === SERVER / HTTP API TESTS ===

func newTestServerForMain(store *Store) (*Server, *Config) {
	cfg := &Config{
		AdminToken:   "test-admin-token",
		ListenAddr:   "127.0.0.1:0",
		SecretTokens: make(map[string]*SecretToken),
	}
	return NewServer(store, cfg, "/tmp/test-config.yaml"), cfg
}

func TestHandleHealth(t *testing.T) {
	srv, _ := newTestServerForMain(NewStore(""))
	req := httptest.NewRequest("GET", "/health", nil)
	w := httptest.NewRecorder()

	srv.handleHealth(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var resp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["status"] != "ok" {
		t.Fatalf("expected status=ok, got %v", resp["status"])
	}
}

func TestHandleHealthWithSecrets(t *testing.T) {
	s := NewStore("")
	s.Set("k", "v")
	srv, _ := newTestServerForMain(s)

	req := httptest.NewRequest("GET", "/health", nil)
	w := httptest.NewRecorder()
	srv.handleHealth(w, req)

	var resp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["secrets"].(float64) != 1 {
		t.Fatalf("expected 1 secret, got %v", resp["secrets"])
	}
}

func TestHandleSecretsGetUnauthorized(t *testing.T) {
	srv, _ := newTestServerForMain(NewStore(""))

	req := httptest.NewRequest("GET", "/secrets", nil)
	w := httptest.NewRecorder()
	srv.handleSecrets(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
}

func TestHandleSecretsGetAdmin(t *testing.T) {
	s := NewStore("")
	s.Set("key1", "val1")
	srv, _ := newTestServerForMain(s)

	req := httptest.NewRequest("GET", "/secrets", nil)
	req.Header.Set("X-Vault-Token", "test-admin-token")
	w := httptest.NewRecorder()

	srv.handleSecrets(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var secrets []*Secret
	json.Unmarshal(w.Body.Bytes(), &secrets)
	if len(secrets) != 1 {
		t.Fatalf("expected 1 secret, got %d", len(secrets))
	}
}

func TestHandleSecretsPost(t *testing.T) {
	srv, _ := newTestServerForMain(NewStore(""))

	body := `{"name":"new_key","value":"new_val"}`
	req := httptest.NewRequest("POST", "/secrets", bytes.NewBufferString(body))
	req.Header.Set("X-Vault-Token", "test-admin-token")
	w := httptest.NewRecorder()

	srv.handleSecrets(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]string
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["status"] != "created" {
		t.Fatalf("expected created, got %s", resp["status"])
	}
}

func TestHandleSecretsPostUnauthorized(t *testing.T) {
	srv, _ := newTestServerForMain(NewStore(""))

	body := `{"name":"k","value":"v"}`
	req := httptest.NewRequest("POST", "/secrets", bytes.NewBufferString(body))
	w := httptest.NewRecorder()
	srv.handleSecrets(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
}

func TestHandleSecretsPostBadRequest(t *testing.T) {
	srv, _ := newTestServerForMain(NewStore(""))

	// Missing value
	body := `{"name":"k"}`
	req := httptest.NewRequest("POST", "/secrets", bytes.NewBufferString(body))
	req.Header.Set("X-Vault-Token", "test-admin-token")
	w := httptest.NewRecorder()
	srv.handleSecrets(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}

	// Invalid JSON
	req = httptest.NewRequest("POST", "/secrets", bytes.NewBufferString("not json"))
	req.Header.Set("X-Vault-Token", "test-admin-token")
	w = httptest.NewRecorder()
	srv.handleSecrets(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

func TestHandleSecretsDelete(t *testing.T) {
	s := NewStore("")
	s.Set("k1", "v1")
	s.Set("k2", "v2")
	srv, _ := newTestServerForMain(s)

	req := httptest.NewRequest("DELETE", "/secrets", nil)
	req.Header.Set("X-Vault-Token", "test-admin-token")
	w := httptest.NewRecorder()
	srv.handleSecrets(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if s.Count() != 0 {
		t.Fatal("expected all secrets deleted")
	}
}

func TestHandleSecretsDeleteUnauthorized(t *testing.T) {
	srv, _ := newTestServerForMain(NewStore(""))

	req := httptest.NewRequest("DELETE", "/secrets", nil)
	w := httptest.NewRecorder()
	srv.handleSecrets(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
}

func TestHandleSecretMethodNotAllowed(t *testing.T) {
	srv, _ := newTestServerForMain(NewStore(""))

	req := httptest.NewRequest("PUT", "/secrets", nil)
	req.Header.Set("X-Vault-Token", "test-admin-token")
	w := httptest.NewRecorder()
	srv.handleSecrets(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", w.Code)
	}
}

// === ACCESS ENDPOINT TESTS ===

func TestHandleAccessValid(t *testing.T) {
	s := NewStore("")
	s.Set("my_secret", "my_value")
	srv, cfg := newTestServerForMain(s)
	token := "abc123"
	cfg.SecretTokens[hashToken(token)] = &SecretToken{
		SecretName: "my_secret",
		Token:      hashToken(token),
		Revoked:    false,
	}

	req := httptest.NewRequest("GET", "/access", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	srv.handleAccess(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["name"] != "my_secret" {
		t.Fatalf("expected name my_secret, got %v", resp["name"])
	}
	if resp["value"] != "my_value" {
		t.Fatalf("expected value my_value, got %v", resp["value"])
	}
}

func TestHandleAccessInvalidToken(t *testing.T) {
	srv, _ := newTestServerForMain(NewStore(""))

	req := httptest.NewRequest("GET", "/access", nil)
	req.Header.Set("Authorization", "Bearer invalidtoken")
	w := httptest.NewRecorder()
	srv.handleAccess(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", w.Code)
	}
}

func TestHandleAccessRevokedToken(t *testing.T) {
	s := NewStore("")
	s.Set("s1", "v1")
	srv, cfg := newTestServerForMain(s)
	token := "tok1"
	cfg.SecretTokens[hashToken(token)] = &SecretToken{
		SecretName: "s1",
		Token:      hashToken(token),
		Revoked:    true,
	}

	req := httptest.NewRequest("GET", "/access", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	srv.handleAccess(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", w.Code)
	}
}

func TestHandleAccessExpired(t *testing.T) {
	s := NewStore("")
	s.Set("s1", "v1")
	srv, cfg := newTestServerForMain(s)
	token := "tok1"
	cfg.SecretTokens[hashToken(token)] = &SecretToken{
		SecretName: "s1",
		Token:      hashToken(token),
		Revoked:    false,
		ExpiresAt:  time.Now().Add(-1 * time.Hour), // expired 1h ago
	}

	req := httptest.NewRequest("GET", "/access", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	srv.handleAccess(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", w.Code)
	}
}

func TestHandleAccessSecretNotFound(t *testing.T) {
	srv, cfg := newTestServerForMain(NewStore(""))
	token := "tok1"
	cfg.SecretTokens[hashToken(token)] = &SecretToken{
		SecretName: "deleted_secret",
		Token:      hashToken(token),
		Revoked:    false,
	}

	req := httptest.NewRequest("GET", "/access", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	srv.handleAccess(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", w.Code)
	}
}

func TestHandleAccessEmptyToken(t *testing.T) {
	srv, _ := newTestServerForMain(NewStore(""))

	req := httptest.NewRequest("GET", "/access", nil)
	w := httptest.NewRecorder()
	srv.handleAccess(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
}

func TestHandleAccessMethodNotAllowed(t *testing.T) {
	srv, _ := newTestServerForMain(NewStore(""))

	req := httptest.NewRequest("POST", "/access", nil)
	req.Header.Set("Authorization", "Bearer tok1")
	w := httptest.NewRecorder()
	srv.handleAccess(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", w.Code)
	}
}

// === EXPORT TESTS ===

func TestHandleExport(t *testing.T) {
	s := NewStore("")
	s.Set("k1", "v1")
	s.Set("k2", "v2")
	srv, _ := newTestServerForMain(s)

	req := httptest.NewRequest("GET", "/export", nil)
	req.Header.Set("X-Vault-Token", "test-admin-token")
	w := httptest.NewRecorder()
	srv.handleExport(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var resp map[string]string
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["k1"] != "v1" || resp["k2"] != "v2" {
		t.Fatalf("unexpected export: %v", resp)
	}

	ct := w.Header().Get("Content-Type")
	if ct != "application/json" {
		t.Fatalf("expected json content-type, got %s", ct)
	}
}

func TestHandleExportUnauthorized(t *testing.T) {
	srv, _ := newTestServerForMain(NewStore(""))

	req := httptest.NewRequest("GET", "/export", nil)
	w := httptest.NewRecorder()
	srv.handleExport(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
}

func TestHandleExportEmpty(t *testing.T) {
	srv, _ := newTestServerForMain(NewStore(""))

	req := httptest.NewRequest("GET", "/export", nil)
	req.Header.Set("X-Vault-Token", "test-admin-token")
	w := httptest.NewRecorder()
	srv.handleExport(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var resp map[string]string
	json.Unmarshal(w.Body.Bytes(), &resp)
	if len(resp) != 0 {
		t.Fatalf("expected empty export, got %v", resp)
	}
}

// === ISADMIN TESTS ===

func TestIsAdminValid(t *testing.T) {
	srv, _ := newTestServerForMain(NewStore(""))

	req := httptest.NewRequest("GET", "/secrets", nil)
	req.Header.Set("X-Vault-Token", "test-admin-token")
	if !srv.isAdmin(req) {
		t.Fatal("expected admin")
	}
}

func TestIsAdminInvalid(t *testing.T) {
	srv, _ := newTestServerForMain(NewStore(""))

	req := httptest.NewRequest("GET", "/secrets", nil)
	req.Header.Set("X-Vault-Token", "wrong")
	if srv.isAdmin(req) {
		t.Fatal("expected not admin")
	}
}

func TestIsAdminEmpty(t *testing.T) {
	srv, _ := newTestServerForMain(NewStore(""))

	req := httptest.NewRequest("GET", "/secrets", nil)
	if srv.isAdmin(req) {
		t.Fatal("expected not admin for empty token")
	}
}

func TestIsAdminTimingSafe(t *testing.T) {
	srv, cfg := newTestServerForMain(NewStore(""))

	// Different length tokens should not panic
	req := httptest.NewRequest("GET", "/secrets", nil)
	req.Header.Set("X-Vault-Token", "x")
	srv.isAdmin(req)

	cfg.AdminToken = ""
	req.Header.Set("X-Vault-Token", "something")
	srv.isAdmin(req)
}

// === RANDOM TOKEN TESTS ===

func TestRandomToken(t *testing.T) {
	token, err := randomToken(32)
	if err != nil {
		t.Fatalf("randomToken: %v", err)
	}
	if len(token) != 32 {
		t.Fatalf("expected 32 chars, got %d", len(token))
	}
}

func TestRandomTokenUniqueness(t *testing.T) {
	tokens := make(map[string]bool)
	for i := 0; i < 100; i++ {
		tok, err := randomToken(32)
		if err != nil {
			t.Fatalf("randomToken: %v", err)
		}
		if tokens[tok] {
			t.Fatal("duplicate token generated")
		}
		tokens[tok] = true
	}
}

func TestRandomTokenDifferentLengths(t *testing.T) {
	for _, length := range []int{8, 16, 32, 64} {
		tok, err := randomToken(length)
		if err != nil {
			t.Fatalf("randomToken(%d): %v", length, err)
		}
		if len(tok) != length {
			t.Fatalf("expected %d chars, got %d", length, len(tok))
		}
	}
}

// === ESCAPE HTML TESTS ===

func TestEscapeHTML(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"plain", "hello", "hello"},
		{"ampersand", "a&b", "a&amp;b"},
		{"less", "a<b", "a&lt;b"},
		{"greater", "a>b", "a&gt;b"},
		{"empty", "", ""},
		{"no_special", "smtp_pass", "smtp_pass"},
		{"code_block", "x <script>alert(1)</script>", "x &lt;script&gt;alert(1)&lt;/script&gt;"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := escapeHTML(tt.input)
			if result != tt.expected {
				t.Fatalf("escapeHTML(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

// === ONE-TIME TOKEN TESTS ===

func TestHandleAccessOneTimeToken(t *testing.T) {
	s := NewStore("")
	s.Set("my_secret", "my_value")
	srv, cfg := newTestServerForMain(s)
	token := "onetime123"
	cfg.SecretTokens[hashToken(token)] = &SecretToken{
		SecretName: "my_secret",
		Token:      hashToken(token),
		Revoked:    false,
	}

	// First access — should succeed
	req := httptest.NewRequest("GET", "/access", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	srv.handleAccess(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("first access: expected 200, got %d: %s", w.Code, w.Body.String())
	}

	// Second access — token should be revoked (one-time)
	req = httptest.NewRequest("GET", "/access", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w = httptest.NewRecorder()
	srv.handleAccess(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("second access: expected 403 (revoked), got %d", w.Code)
	}
}

// === RATE LIMITER TESTS ===

func TestRateLimiterAllows(t *testing.T) {
	rl := newIPRateLimiter(5, time.Minute)
	for i := 0; i < 5; i++ {
		if !rl.allow("192.168.1.1") {
			t.Fatalf("request %d should be allowed", i+1)
		}
	}
}

func TestRateLimiterBlocks(t *testing.T) {
	rl := newIPRateLimiter(3, time.Minute)
	for i := 0; i < 3; i++ {
		rl.allow("192.168.1.1")
	}
	if rl.allow("192.168.1.1") {
		t.Fatal("4th request should be blocked")
	}
}

func TestRateLimiterPerIP(t *testing.T) {
	rl := newIPRateLimiter(2, time.Minute)
	rl.allow("192.168.1.1")
	rl.allow("192.168.1.1")
	if !rl.allow("192.168.1.2") {
		t.Fatal("different IP should be allowed")
	}
}

// === HASH TOKEN TESTS ===

func TestHashToken(t *testing.T) {
	h1 := hashToken("test-token")
	h2 := hashToken("test-token")
	if h1 != h2 {
		t.Fatal("same token should produce same hash")
	}
	if len(h1) != 64 {
		t.Fatalf("expected 64 char hex, got %d", len(h1))
	}
}

func TestHashTokenDifferent(t *testing.T) {
	h1 := hashToken("token-a")
	h2 := hashToken("token-b")
	if h1 == h2 {
		t.Fatal("different tokens should produce different hashes")
	}
}

// === CRYPTO TESTS ===

func TestEncryptDecryptSnapshot(t *testing.T) {
	password := "test-password-123"
	plaintext := []byte(`{"secret1":{"name":"secret1","value":"val1"}}`)

	encrypted, err := encryptSnapshot(plaintext, password)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if string(encrypted) == string(plaintext) {
		t.Fatal("encrypted should differ from plaintext")
	}

	decrypted, err := decryptSnapshot(encrypted, password)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if string(decrypted) != string(plaintext) {
		t.Fatalf("decrypted mismatch: got %q, want %q", decrypted, plaintext)
	}
}

func TestDecryptWrongPassword(t *testing.T) {
	plaintext := []byte(`{"secret1":{"name":"secret1","value":"val1"}}`)
	encrypted, _ := encryptSnapshot(plaintext, "correct-password")

	_, err := decryptSnapshot(encrypted, "wrong-password")
	if err == nil {
		t.Fatal("expected error for wrong password")
	}
}

func TestDecryptCorrupted(t *testing.T) {
	plaintext := []byte(`{"secret1":{"name":"secret1","value":"val1"}}`)
	encrypted, _ := encryptSnapshot(plaintext, "password")

	encrypted[len(encrypted)-1] ^= 0xFF

	_, err := decryptSnapshot(encrypted, "password")
	if err == nil {
		t.Fatal("expected error for corrupted ciphertext")
	}
}

func TestDecryptTooShort(t *testing.T) {
	_, err := decryptSnapshot([]byte("short"), "password")
	if err == nil {
		t.Fatal("expected error for short input")
	}
}

func TestEncryptUniqueNonce(t *testing.T) {
	plaintext := []byte("same data")
	password := "test"

	enc1, _ := encryptSnapshot(plaintext, password)
	enc2, _ := encryptSnapshot(plaintext, password)

	if string(enc1) == string(enc2) {
		t.Fatal("same plaintext should produce different ciphertext")
	}
}

// === ESCAPE HTML QUOTES TESTS ===

func TestEscapeHTMLQuotes(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"double_quote", `say "hello"`, "say &quot;hello&quot;"},
		{"single_quote", "it's", "it&#39;s"},
		{"mixed", `a"b'c<d>e&f`, "a&quot;b&#39;c&lt;d&gt;e&amp;f"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := escapeHTML(tt.input)
			if result != tt.expected {
				t.Fatalf("escapeHTML(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

// === CONFIG WITHOUT TOKENS FIELD ===

func TestLoadConfigNoTokensField(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	content := `admin_token: test-admin
listen_addr: 127.0.0.1:9999
`
	os.WriteFile(path, []byte(content), 0600)

	cfg, err := loadConfig(path)
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	if cfg.SecretTokens == nil {
		t.Fatal("SecretTokens should be initialized")
	}
	if len(cfg.SecretTokens) != 0 {
		t.Fatal("SecretTokens should be empty")
	}
}

// === DELETE /secret/<name> ===

func TestHandleSecretDelete(t *testing.T) {
	store := NewStore("")
	store.Set("to_delete", "val1")
	store.Set("keep", "val2")
	cfg := &Config{
		AdminToken:   "test-admin",
		SecretTokens: make(map[string]*SecretToken),
	}
	cfg.SecretTokens[hashToken("tok1")] = &SecretToken{SecretName: "to_delete", Token: hashToken("tok1")}
	cfg.SecretTokens[hashToken("tok2")] = &SecretToken{SecretName: "keep", Token: hashToken("tok2")}
	srv := NewServer(store, cfg, "/tmp/test-config-delete.yaml")

	rr := httptest.NewRecorder()
	req := httptest.NewRequest("DELETE", "/secret/to_delete", nil)
	req.Header.Set("X-Vault-Token", "test-admin")
	srv.handleSecretDelete(rr, req, "to_delete")

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	if _, ok := store.Get("to_delete"); ok {
		t.Fatal("secret should be deleted from store")
	}
	if _, ok := store.Get("keep"); !ok {
		t.Fatal("other secret should remain")
	}

	cfg.mu.RLock()
	if _, ok := cfg.SecretTokens[hashToken("tok1")]; ok {
		t.Fatal("token for deleted secret should be removed")
	}
	if _, ok := cfg.SecretTokens[hashToken("tok2")]; !ok {
		t.Fatal("token for other secret should remain")
	}
	cfg.mu.RUnlock()
}

func TestHandleSecretDeleteNotFound(t *testing.T) {
	store := NewStore("")
	cfg := &Config{
		AdminToken:   "test-admin",
		SecretTokens: make(map[string]*SecretToken),
	}
	srv := NewServer(store, cfg, "/tmp/test-config-delete-nf.yaml")

	rr := httptest.NewRecorder()
	req := httptest.NewRequest("DELETE", "/secret/nonexistent", nil)
	req.Header.Set("X-Vault-Token", "test-admin")
	srv.handleSecretDelete(rr, req, "nonexistent")

	if rr.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", rr.Code)
	}
}

func TestHandleSecretDeleteUnauthorized(t *testing.T) {
	store := NewStore("")
	store.Set("s1", "v1")
	cfg := &Config{
		AdminToken:   "test-admin",
		SecretTokens: make(map[string]*SecretToken),
	}
	srv := NewServer(store, cfg, "/tmp/test-config-delete-ua.yaml")

	rr := httptest.NewRecorder()
	req := httptest.NewRequest("DELETE", "/secret/s1", nil)
	srv.handleSecretDelete(rr, req, "s1")

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rr.Code)
	}
	if _, ok := store.Get("s1"); !ok {
		t.Fatal("secret should not be deleted without auth")
	}
}

// === CLEANUP REVOKED TOKENS ===

func TestCleanupRevokedTokens(t *testing.T) {
	cfg := newTestConfig()
	now := time.Now()

	cfg.SecretTokens["active"] = &SecretToken{
		SecretName: "s1", Token: "active", Revoked: false,
	}
	cfg.SecretTokens["revoked"] = &SecretToken{
		SecretName: "s1", Token: "revoked", Revoked: true,
	}
	cfg.SecretTokens["expired"] = &SecretToken{
		SecretName: "s2", Token: "expired", Revoked: false,
		ExpiresAt: now.Add(-time.Hour),
	}
	cfg.SecretTokens["not_expired"] = &SecretToken{
		SecretName: "s3", Token: "not_expired", Revoked: false,
		ExpiresAt: now.Add(time.Hour),
	}

	cfg.cleanupRevokedTokens()

	if _, ok := cfg.SecretTokens["active"]; !ok {
		t.Fatal("active token should remain")
	}
	if _, ok := cfg.SecretTokens["revoked"]; ok {
		t.Fatal("revoked token should be removed")
	}
	if _, ok := cfg.SecretTokens["expired"]; ok {
		t.Fatal("expired token should be removed")
	}
	if _, ok := cfg.SecretTokens["not_expired"]; !ok {
		t.Fatal("not-expired token should remain")
	}
}

// === MIDDLEWARE ===

func TestRecoveryMiddleware(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		panic("test panic")
	})

	store := NewStore("")
	cfg := newTestConfig()
	srv := NewServer(store, cfg, "dummy.yaml")
	wrapped := srv.recoveryMiddleware(handler)

	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/panic", nil)
	wrapped.ServeHTTP(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", rr.Code)
	}
}

// === O(1) TOKEN LOOKUP ===

func TestHandleAccessO1Lookup(t *testing.T) {
	store := NewStore("")
	store.Set("api_key", "secret-value")
	cfg := &Config{
		AdminToken:   "test-admin",
		SecretTokens: make(map[string]*SecretToken),
	}
	tokenHash := hashToken("mytoken123")
	cfg.SecretTokens[tokenHash] = &SecretToken{
		SecretName: "api_key", Token: tokenHash, Revoked: false,
	}
	srv := NewServer(store, cfg, "/tmp/test-config-o1.yaml")

	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/access", nil)
	req.Header.Set("Authorization", "Bearer mytoken123")
	srv.handleAccess(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	var result map[string]interface{}
	json.Unmarshal(rr.Body.Bytes(), &result)
	if result["value"] != "secret-value" {
		t.Fatalf("expected secret-value, got %v", result["value"])
	}

	cfg.mu.RLock()
	if _, ok := cfg.SecretTokens[tokenHash]; ok {
		t.Fatal("one-time token should be deleted after use")
	}
	cfg.mu.RUnlock()
}

func TestServerDevMode(t *testing.T) {
	cfg := &Config{
		ListenAddr: "127.0.0.1:28301",
		UseTLS:     false,
		DevMode:    true,
	}
	srv := NewServer(NewStore(""), cfg, "")

	errCh := make(chan error, 1)
	go func() {
		errCh <- srv.ListenAndServe()
	}()

	// Proper synchronization: dial the server until it accepts connections or fails
	ready := make(chan struct{})
	go func() {
		for {
			conn, err := net.Dial("tcp", "127.0.0.1:28301")
			if err == nil {
				conn.Close()
				close(ready)
				return
			}
			runtime.Gosched() // yield to scheduler
		}
	}()

	select {
	case err := <-errCh:
		if err != nil && err != http.ErrServerClosed {
			t.Fatalf("server failed to start: %v", err)
		}
	case <-ready:
		// server started successfully
		if srv.srv != nil {
			srv.srv.Close()
		}
		<-errCh // wait for goroutine to finish
	}

	cfgProd := &Config{
		ListenAddr: "127.0.0.1:0",
		UseTLS:     false,
		DevMode:    false,
	}
	srvProd := NewServer(NewStore(""), cfgProd, "")
	err := srvProd.ListenAndServe()
	if err == nil {
		t.Fatal("expected error in production mode without TLS")
	}
	if err.Error() != "TLS is required in production" {
		t.Fatalf("unexpected error message: %v", err)
	}

	cfgProdFallback := &Config{
		ListenAddr:  "127.0.0.1:0",
		UseTLS:      true,
		TLSCertPath: "non-existent.crt",
		TLSKeyPath:  "non-existent.key",
		DevMode:     false,
	}
	srvProdFallback := NewServer(NewStore(""), cfgProdFallback, "")
	err = srvProdFallback.ListenAndServe()
	if err == nil {
		t.Fatal("expected error in production mode with missing certs")
	}
}
