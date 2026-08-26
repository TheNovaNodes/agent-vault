package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestSealedStoreE2ERestart(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.yaml")
	snapshotPath := filepath.Join(dir, "snapshot.enc")

	password := "my-secure-password"

	// 1. Simulate initial startup
	initialCfg := []byte(`snapshot_path: ` + snapshotPath + "\n")
	if err := os.WriteFile(configPath, initialCfg, 0600); err != nil {
		t.Fatalf("write config error: %v", err)
	}

	cfg1, err := loadConfig(configPath)
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}

	s1, err := NewStore(password, cfg1.SealedSalt)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	s1.Set("db_host", "localhost")

	// Save encrypted snapshot (as agent-vault does on shutdown/save)
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

	// 2. Simulate restart like main.go does
	cfg2, err := loadConfig(configPath)
	if err != nil {
		t.Fatalf("loadConfig restart: %v", err)
	}

	s2, err := NewStore(password, cfg2.SealedSalt)
	if err != nil {
		t.Fatalf("NewStore restart: %v", err)
	}

	// Load snapshot identical to main.go logic
	if _, err := os.Stat(cfg2.SnapshotPath); err == nil {
		data, err := os.ReadFile(cfg2.SnapshotPath)
		if err == nil && len(data) > 0 {
			decrypted, decErr := decryptSnapshot(data, password)
			if decErr == nil {
				var secrets map[string]*Secret
				if err := json.Unmarshal(decrypted, &secrets); err == nil {
					s2.mu.Lock()
					for name, sec := range secrets {
						s2.secrets[name] = sec
					}
					s2.mu.Unlock()
				} else {
					t.Fatalf("unmarshal error: %v", err)
				}
			} else {
				t.Fatalf("decrypt error: %v", decErr)
			}
		}
	} else {
		t.Fatalf("snapshot missing: %v", err)
	}

	// Verify plaintext retrieval
	sec, ok := s2.Get("db_host")
	if !ok {
		t.Fatal("expected secret to exist")
	}
	if sec.Value != "localhost" {
		t.Fatalf("expected 'localhost', got '%s'", sec.Value)
	}
}
