package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func buildBinary(dest string) error {
	_, file, _, _ := runtime.Caller(0)
	dir := filepath.Dir(file)
	return exec.Command("go", "build", "-o", dest, dir).Run()
}

// === HELPER: create test server ===

func newTestCLIServer() *httptest.Server {
	store := map[string]map[string]string{
		"key1": {"name": "key1", "value": "val1", "updated_at": "2026-01-01T00:00:00Z"},
		"key2": {"name": "key2", "value": "val2", "updated_at": "2026-01-02T00:00:00Z"},
	}

	mux := http.NewServeMux()

	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":  "ok",
			"secrets": len(store),
			"uptime":  "10m",
		})
	})

	mux.HandleFunc("/secrets", func(w http.ResponseWriter, r *http.Request) {
		token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if token != "test-admin" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		switch r.Method {
		case http.MethodGet:
			var secrets []map[string]string
			for _, s := range store {
				secrets = append(secrets, s)
			}
			json.NewEncoder(w).Encode(secrets)

		case http.MethodPost:
			var req struct {
				Name  string `json:"name"`
				Value string `json:"value"`
			}
			json.NewDecoder(r.Body).Decode(&req)
			store[req.Name] = map[string]string{
				"name":       req.Name,
				"value":      req.Value,
				"updated_at": "2026-01-03T00:00:00Z",
			}
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(map[string]string{"status": "created"})

		case http.MethodDelete:
			for k := range store {
				delete(store, k)
			}
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(map[string]string{"status": "deleted"})

		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	})

	mux.HandleFunc("/secret/", func(w http.ResponseWriter, r *http.Request) {
		token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if token != "test-admin" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		name := strings.TrimPrefix(r.URL.Path, "/secret/")
		if name == "" {
			http.Error(w, "secret name required", http.StatusBadRequest)
			return
		}

		switch r.Method {
		case http.MethodGet:
			s, ok := store[name]
			if !ok {
				http.Error(w, "secret not found", http.StatusNotFound)
				return
			}
			json.NewEncoder(w).Encode(s)

		case http.MethodDelete:
			if _, ok := store[name]; !ok {
				http.Error(w, "secret not found", http.StatusNotFound)
				return
			}
			delete(store, name)
			json.NewEncoder(w).Encode(map[string]string{"status": "deleted", "name": name})

		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	})

	mux.HandleFunc("/export", func(w http.ResponseWriter, r *http.Request) {
		token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if token != "test-admin" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		result := make(map[string]string)
		for _, s := range store {
			result[s["name"]] = s["value"]
		}
		json.NewEncoder(w).Encode(result)
	})

	return httptest.NewServer(mux)
}

// === TEST: doRequest ===

func TestDoRequest_GET(t *testing.T) {
	srv := newTestCLIServer()
	defer srv.Close()

	resp, err := doRequest(srv.URL, "GET", "/health", "", nil)
	if err != nil {
		t.Fatalf("doRequest: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	var result map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&result)
	if result["status"] != "ok" {
		t.Fatalf("expected status=ok, got %v", result["status"])
	}
}

func TestDoRequest_POST(t *testing.T) {
	srv := newTestCLIServer()
	defer srv.Close()

	body := map[string]string{"name": "new_key", "value": "new_val"}
	resp, err := doRequest(srv.URL, "POST", "/secrets", "test-admin", body)
	if err != nil {
		t.Fatalf("doRequest: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
}

func TestDoRequest_Unauthorized(t *testing.T) {
	srv := newTestCLIServer()
	defer srv.Close()

	resp, err := doRequest(srv.URL, "GET", "/secrets", "wrong-token", nil)
	if err != nil {
		t.Fatalf("doRequest: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 401 {
		t.Fatalf("expected 401, got %d", resp.StatusCode)
	}
}

// === TEST: cmdHealth ===

func TestCmdHealth(t *testing.T) {
	srv := newTestCLIServer()
	defer srv.Close()

	// Capture stdout
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	cmdHealth(srv.URL)

	w.Close()
	os.Stdout = old

	var buf [4096]byte
	n, _ := r.Read(buf[:])
	output := string(buf[:n])

	if !strings.Contains(output, "ok") {
		t.Fatalf("expected health ok, got: %s", output)
	}
}

// === TEST: cmdList ===

func TestCmdList(t *testing.T) {
	srv := newTestCLIServer()
	defer srv.Close()

	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	cmdList(srv.URL, "test-admin")

	w.Close()
	os.Stdout = old

	var buf [4096]byte
	n, _ := r.Read(buf[:])
	output := string(buf[:n])

	if !strings.Contains(output, "key1") {
		t.Fatalf("expected key1 in list, got: %s", output)
	}
	if !strings.Contains(output, "key2") {
		t.Fatalf("expected key2 in list, got: %s", output)
	}
}

func TestCmdListEmpty(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode([]map[string]string{})
	}))
	defer srv.Close()

	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	cmdList(srv.URL, "test-admin")

	w.Close()
	os.Stdout = old

	var buf [4096]byte
	n, _ := r.Read(buf[:])
	output := string(buf[:n])

	if !strings.Contains(output, "No secrets") {
		t.Fatalf("expected 'No secrets', got: %s", output)
	}
}

// === TEST: cmdGet ===

func TestCmdGet(t *testing.T) {
	srv := newTestCLIServer()
	defer srv.Close()

	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	cmdGet(srv.URL, "test-admin", "key1")

	w.Close()
	os.Stdout = old

	var buf [4096]byte
	n, _ := r.Read(buf[:])
	output := string(buf[:n])

	if !strings.Contains(output, "val1") {
		t.Fatalf("expected val1, got: %s", output)
	}
}

func TestCmdGetNotFound(t *testing.T) {
	// cmdGet calls os.Exit(1) on not found, so we test via binary
	srv := newTestCLIServer()
	defer srv.Close()

	binary := "/tmp/agent-vault-cli-test"
	err := buildBinary(binary)
	if err != nil {
		t.Skipf("go build not available: %v", err)
	}
	defer os.Remove(binary)

	cmd := exec.Command(binary, "-addr", srv.URL, "-token", "test-admin", "get", "nonexistent")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	err = cmd.Run()

	if err == nil {
		t.Fatal("expected error exit for not found")
	}

	if !strings.Contains(stderr.String(), "not found") {
		t.Fatalf("expected 'not found' error, got: %s", stderr.String())
	}
}

// === TEST: cmdSet ===

func TestCmdSet(t *testing.T) {
	srv := newTestCLIServer()
	defer srv.Close()

	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	cmdSet(srv.URL, "test-admin", "new_secret", "new_value")

	w.Close()
	os.Stdout = old

	var buf [4096]byte
	n, _ := r.Read(buf[:])
	output := string(buf[:n])

	if !strings.Contains(output, "created") {
		t.Fatalf("expected creation confirmation, got: %s", output)
	}
}

// === TEST: cmdDelete ===

func TestCmdDelete(t *testing.T) {
	srv := newTestCLIServer()
	defer srv.Close()

	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	cmdDelete(srv.URL, "test-admin", "key1")

	w.Close()
	os.Stdout = old

	var buf [4096]byte
	n, _ := r.Read(buf[:])
	output := string(buf[:n])

	if !strings.Contains(output, "deleted") {
		t.Fatalf("expected deletion confirmation, got: %s", output)
	}
}

func TestCmdDeleteNotFound(t *testing.T) {
	srv := newTestCLIServer()
	defer srv.Close()

	binary := "/tmp/agent-vault-cli-test"
	err := buildBinary(binary)
	if err != nil {
		t.Skipf("go build not available: %v", err)
	}
	defer os.Remove(binary)

	cmd := exec.Command(binary, "-addr", srv.URL, "-token", "test-admin", "delete", "nonexistent")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	err = cmd.Run()

	if err == nil {
		t.Fatal("expected error exit for not found")
	}

	if !strings.Contains(stderr.String(), "not found") {
		t.Fatalf("expected 'not found', got: %s", stderr.String())
	}
}

// === TEST: cmdExport ===

func TestCmdExport(t *testing.T) {
	srv := newTestCLIServer()
	defer srv.Close()

	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	cmdExport(srv.URL, "test-admin")

	w.Close()
	os.Stdout = old

	var buf [4096]byte
	n, _ := r.Read(buf[:])
	output := string(buf[:n])

	if !strings.Contains(output, "key1") || !strings.Contains(output, "val1") {
		t.Fatalf("expected export with key1/val1, got: %s", output)
	}
}

// === TEST: printUsage ===

func TestPrintUsage(t *testing.T) {
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	printUsage()

	w.Close()
	os.Stdout = old

	var buf [4096]byte
	n, _ := r.Read(buf[:])
	output := string(buf[:n])

	required := []string{"health", "list", "get", "set", "delete", "wipe", "export", "version"}
	for _, cmd := range required {
		if !strings.Contains(output, cmd) {
			t.Fatalf("usage missing command: %s", cmd)
		}
	}
}

// === TEST: prettyPrint ===

func TestPrettyPrint(t *testing.T) {
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	prettyPrint(map[string]string{"key": "value"})

	w.Close()
	os.Stdout = old

	var buf [4096]byte
	n, _ := r.Read(buf[:])
	output := string(buf[:n])

	if !strings.Contains(output, `"key": "value"`) {
		t.Fatalf("expected pretty JSON, got: %s", output)
	}
}

// === INTEGRATION: full flow ===

func TestIntegration_SetGetDelete(t *testing.T) {
	srv := newTestCLIServer()
	defer srv.Close()

	// Set
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w
	cmdSet(srv.URL, "test-admin", "integration_key", "integration_val")
	w.Close()
	os.Stdout = old
	r.Read(make([]byte, 4096))

	// Get
	r, w, _ = os.Pipe()
	os.Stdout = w
	cmdGet(srv.URL, "test-admin", "integration_key")
	w.Close()
	os.Stdout = old

	var buf [4096]byte
	n, _ := r.Read(buf[:])
	output := string(buf[:n])

	if !strings.Contains(output, "integration_val") {
		t.Fatalf("expected integration_val, got: %s", output)
	}

	// Delete
	r, w, _ = os.Pipe()
	os.Stdout = w
	cmdDelete(srv.URL, "test-admin", "integration_key")
	w.Close()
	os.Stdout = old
	r.Read(make([]byte, 4096))

	// Verify deleted — list should not contain it
	r, w, _ = os.Pipe()
	os.Stdout = w
	cmdList(srv.URL, "test-admin")
	w.Close()
	os.Stdout = old

	n, _ = r.Read(buf[:])
	listOutput := string(buf[:n])

	if strings.Contains(listOutput, "integration_key") {
		t.Fatalf("integration_key should be deleted, list: %s", listOutput)
	}

	_ = fmt.Sprintf("%d", n) // suppress unused
}
