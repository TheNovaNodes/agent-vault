package main

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestStreamRedactor_NoTokens(t *testing.T) {
	var buf bytes.Buffer
	r := NewStreamRedactor(&buf, [][]byte{})
	r.Write([]byte("hello world"))
	r.Close()

	if buf.String() != "hello world" {
		t.Fatalf("expected hello world, got %q", buf.String())
	}
}

func TestStreamRedactor_WithTokens(t *testing.T) {
	var buf bytes.Buffer
	tokens := [][]byte{[]byte("supersecret"), []byte("tiny_")}
	r := NewStreamRedactor(&buf, tokens)
	
	r.Write([]byte("this is a supersecret and a tiny_ token"))
	r.Close()

	expected := "this is a **********[MASKED]********** and a **********[MASKED]********** token"
	if buf.String() != expected {
		t.Fatalf("expected %q, got %q", expected, buf.String())
	}
}

func TestStreamRedactor_ChunkedBoundary(t *testing.T) {
	var buf bytes.Buffer
	tokens := [][]byte{[]byte("supersecret")}
	r := NewStreamRedactor(&buf, tokens)

	r.Write([]byte("this is a super"))
	r.Write([]byte("secret token"))
	r.Close()

	expected := "this is a **********[MASKED]********** token"
	if buf.String() != expected {
		t.Fatalf("expected %q, got %q", expected, buf.String())
	}
}

func TestRun_InvalidArgs(t *testing.T) {
	oldArgs := os.Args
	defer func() { os.Args = oldArgs }()

	os.Args = []string{"with-secret"}
	if code := run(); code != 1 {
		t.Fatalf("expected exit code 1, got %d", code)
	}

	os.Args = []string{"with-secret", "id", "--wrong-flag", "VAR", "--", "echo", "hi"}
	if code := run(); code != 1 {
		t.Fatalf("expected exit code 1, got %d", code)
	}
}

func TestRun_MissingCommand(t *testing.T) {
	oldArgs := os.Args
	defer func() { os.Args = oldArgs }()

	os.Args = []string{"with-secret", "id", "--secret-path-env", "VAR", "--"}
	if code := run(); code != 1 {
		t.Fatalf("expected exit code 1, got %d", code)
	}
}

func TestRun_SecretNotFound(t *testing.T) {
	oldArgs := os.Args
	defer func() { os.Args = oldArgs }()

	os.Args = []string{"with-secret", "non-existent-id", "--secret-path-env", "MY_VAR", "--", "echo", "hi"}
	
	oldStderr := os.Stderr
	r, w, _ := os.Pipe()
	os.Stderr = w

	code := run()
	
	w.Close()
	os.Stderr = oldStderr

	if code != 1 {
		t.Fatalf("expected exit code 1, got %d", code)
	}
	
	var buf bytes.Buffer
	io.Copy(&buf, r)
	if !strings.Contains(buf.String(), "not found") {
		t.Fatalf("expected 'not found' in stderr, got %q", buf.String())
	}
}

func TestRun_Success(t *testing.T) {
	shmDir := "/dev/shm/agent_vault"
	err := os.MkdirAll(shmDir, 0755)
	if err != nil {
		t.Skipf("cannot create /dev/shm/agent_vault: %v", err)
	}
	
	pointerID := "test_pointer_123"
	secretPath := filepath.Join(shmDir, pointerID)
	
	err = os.WriteFile(secretPath, []byte("my_secret_token_12345"), 0600)
	if err != nil {
		t.Skipf("cannot write to /dev/shm: %v", err)
	}
	
	oldArgs := os.Args
	defer func() { os.Args = oldArgs }()

	if runtime.GOOS == "windows" {
		t.Skip("skipping on windows")
	}

	script := `#!/bin/sh
cat "$TEST_VAR"
echo ""
echo "my_secret_token_12345"
`
	scriptPath := filepath.Join(t.TempDir(), "script.sh")
	os.WriteFile(scriptPath, []byte(script), 0755)
	os.Chmod(scriptPath, 0755)

	os.Args = []string{"with-secret", pointerID, "--secret-path-env", "TEST_VAR", "--", scriptPath}
	
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	code := run()
	
	w.Close()
	os.Stdout = oldStdout

	if code != 0 {
		t.Fatalf("expected exit code 0, got %d", code)
	}
	
	var buf bytes.Buffer
	io.Copy(&buf, r)
	
	if !strings.Contains(buf.String(), "**********[MASKED]**********") {
		t.Fatalf("expected masked output, got %q", buf.String())
	}
}

func TestRun_CommandFailure(t *testing.T) {
	shmDir := "/dev/shm/agent_vault"
	os.MkdirAll(shmDir, 0755)
	
	pointerID := "test_pointer_fail"
	secretPath := filepath.Join(shmDir, pointerID)
	os.WriteFile(secretPath, []byte("token"), 0600)
	
	oldArgs := os.Args
	defer func() { os.Args = oldArgs }()

	os.Args = []string{"with-secret", pointerID, "--secret-path-env", "VAR", "--", "false"}
	
	code := run()
	if code == 0 {
		t.Fatalf("expected non-zero exit code")
	}
}

func TestRun_CommandNotFound(t *testing.T) {
	shmDir := "/dev/shm/agent_vault"
	os.MkdirAll(shmDir, 0755)
	
	pointerID := "test_pointer_notfound"
	secretPath := filepath.Join(shmDir, pointerID)
	os.WriteFile(secretPath, []byte("token"), 0600)
	
	oldArgs := os.Args
	defer func() { os.Args = oldArgs }()

	os.Args = []string{"with-secret", pointerID, "--secret-path-env", "VAR", "--", "/does/not/exist"}
	
	code := run()
	if code != 1 {
		t.Fatalf("expected exit code 1, got %d", code)
	}
}

func TestStreamRedactor_FlushAll(t *testing.T) {
	var buf bytes.Buffer
	r := NewStreamRedactor(&buf, [][]byte{[]byte("token")})
	r.Write([]byte("start t"))
	r.Write([]byte("oken end"))
	r.Close()
	
	expected := "start **********[MASKED]********** end"
	if buf.String() != expected {
		t.Fatalf("expected %q, got %q", expected, buf.String())
	}
}

func TestStreamRedactor_ShortValid(t *testing.T) {
	var buf bytes.Buffer
	// token < 4 chars
	tokens := [][]byte{[]byte("hi_")}
	r := NewStreamRedactor(&buf, tokens)
	r.Write([]byte("say hi_ to me"))
	r.Close()
	
	expected := "say hi_ to me" // Note: NewStreamRedactor filters out tokens <= 4 length unless no valid length >4 exists, wait let's check code
	
	// Let's see what streamredactor actually does if all tokens are <= 4 chars.
	// It falls back to adding all tokens. So it WILL mask "hi_"
	
	expected = "say **********[MASKED]********** to me"
	if buf.String() != expected {
		t.Fatalf("expected %q, got %q", expected, buf.String())
	}
}

func TestMain_ExitCode(t *testing.T) {
}

func TestRun_PathTraversalRejected(t *testing.T) {
	oldArgs := os.Args
	defer func() { os.Args = oldArgs }()

	badIDs := []string{
		"../../etc/passwd",
		"../secret",
		"foo/bar",
		"/tmp/test",
		"id;rm -rf",
		"id with spaces",
	}

	for _, badID := range badIDs {
		os.Args = []string{"with-secret", badID, "--secret-path-env", "MY_VAR", "--", "echo", "hi"}
		if code := run(); code != 1 {
			t.Errorf("expected exit code 1 for bad pointerID %q, got %d", badID, code)
		}
	}
}

func TestRun_InvalidVarNameRejected(t *testing.T) {
	oldArgs := os.Args
	defer func() { os.Args = oldArgs }()

	badVars := []string{
		"123BAD",
		"MY-VAR",
		"VAR=VAL",
		"VAR;echo",
		"",
	}

	for _, badVar := range badVars {
		os.Args = []string{"with-secret", "valid-id", "--secret-path-env", badVar, "--", "echo", "hi"}
		if code := run(); code != 1 {
			t.Errorf("expected exit code 1 for bad varName %q, got %d", badVar, code)
		}
	}
}

