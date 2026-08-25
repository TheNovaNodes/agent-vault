package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestSealedStoreE2ERestart(t *testing.T) {
	dir := t.TempDir()
	snapshotPath := filepath.Join(dir, "snapshot.enc")

	password := "my-secure-password"

	// 1. Simulate initial startup
	cfg1 := &Config{
		SnapshotPath: snapshotPath,
		SealedSalt:   "0123456789abcdef0123456789abcdef",
	}
	s1 := NewStore(password, cfg1.SealedSalt)
	s1.Set("db_host", "localhost")

	// Save encrypted snapshot
	data, err := json.Marshal(s1.secrets)
	if err != nil {
		t.Fatalf("marshal error: %v", err)
	}
	encrypted, err := encryptSnapshot(data, password)
	if err != nil {
		t.Fatalf("encrypt error: %v", err)
	}
	if err := os.WriteFile(snapshotPath, encrypted, 0600); err != nil {
		t.Fatalf("write error: %v", err)
	}

	// 2. Simulate restart
	cfg2 := &Config{
		SnapshotPath: snapshotPath,
		SealedSalt:   "0123456789abcdef0123456789abcdef",
	}
	s2 := NewStore(password, cfg2.SealedSalt)

	// Load snapshot (same logic as main.go)
	loadedData, err := os.ReadFile(cfg2.SnapshotPath)
	if err != nil {
		t.Fatalf("read snapshot error: %v", err)
	}
	decrypted, err := decryptSnapshot(loadedData, password)
	if err != nil {
		t.Fatalf("decrypt snapshot error: %v", err)
	}
	var secrets map[string]*Secret
	if err := json.Unmarshal(decrypted, &secrets); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}

	s2.mu.Lock()
	for name, sec := range secrets {
		s2.secrets[name] = sec
	}
	s2.mu.Unlock()

	// Verify plaintext retrieval
	sec, ok := s2.Get("db_host")
	if !ok {
		t.Fatal("expected secret to exist")
	}
	if sec.Value != "localhost" {
		t.Fatalf("expected 'localhost', got '%s'", sec.Value)
	}
}
