package main

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"regexp"
	"sort"
	"strings"
	"sync"
	"syscall"
)

// StreamRedactor buffers output and replaces secrets, ensuring boundary safety.
type StreamRedactor struct {
	target io.Writer
	tokens [][]byte
	maxLen int
	buf    []byte
	mu     sync.Mutex
}

func NewStreamRedactor(target io.Writer, tokens []string) *StreamRedactor {
	var valid [][]byte
	maxL := 0
	for _, t := range tokens {
		t = strings.TrimSpace(t)
		if len(t) > 4 {
			valid = append(valid, []byte(t))
			if len(t) > maxL {
				maxL = len(t)
			}
		}
	}
	
	if len(valid) == 0 {
		for _, t := range tokens {
			valid = append(valid, []byte(t))
			if len(t) > maxL {
				maxL = len(t)
			}
		}
	}
	
	// Sort by length descending to match longest secrets first
	sort.Slice(valid, func(i, j int) bool {
		return len(valid[i]) > len(valid[j])
	})

	return &StreamRedactor{
		target: target,
		tokens: valid,
		maxLen: maxL,
	}
}

func (r *StreamRedactor) Write(p []byte) (n int, err error) {
	if len(r.tokens) == 0 || r.maxLen == 0 {
		return r.target.Write(p)
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	r.buf = append(r.buf, p...)
	r.processBuffer(false)
	return len(p), nil
}

func (r *StreamRedactor) Close() error {
	if len(r.tokens) == 0 || r.maxLen == 0 {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.processBuffer(true)
	return nil
}

func (r *StreamRedactor) processBuffer(flushAll bool) {
	for _, t := range r.tokens {
		r.buf = bytes.ReplaceAll(r.buf, t, []byte("**********[MASKED]**********"))
	}

	if flushAll {
		if len(r.buf) > 0 {
			r.target.Write(r.buf)
			r.buf = nil
		}
		return
	}

	if r.maxLen == 0 {
		r.target.Write(r.buf)
		r.buf = nil
		return
	}

	safeLen := len(r.buf) - r.maxLen + 1
	if safeLen > 0 {
		r.target.Write(r.buf[:safeLen])
		r.buf = r.buf[safeLen:]
	}
}

func main() {
	if len(os.Args) < 5 || os.Args[2] != "--env" {
		fmt.Fprintf(os.Stderr, "Usage: with-secret <pointer_id> --env <VAR_NAME> -- <command...>\n")
		os.Exit(1)
	}

	pointerID := os.Args[1]
	varName := os.Args[3]
	cmdArgs := os.Args[5:]

	secretPath := fmt.Sprintf("/dev/shm/agent_vault/%s", pointerID)
	secretBytes, err := os.ReadFile(secretPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "❌ Error: Secret pointer %s not found.\n", pointerID)
		os.Exit(1)
	}
	secretValue := string(secretBytes)

	// Tokenize secret
	re := regexp.MustCompile(`[\s\n]+`)
	rawTokens := re.Split(secretValue, -1)
	if len(rawTokens) == 0 {
		rawTokens = []string{secretValue}
	}

	cmd := exec.Command(cmdArgs[0], cmdArgs[1:]...)
	cmd.Env = append(os.Environ(), fmt.Sprintf("%s=%s", varName, secretValue))
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true} // Process group for signals

	outRedactor := NewStreamRedactor(os.Stdout, rawTokens)
	errRedactor := NewStreamRedactor(os.Stderr, rawTokens)

	cmd.Stdout = outRedactor
	cmd.Stderr = errRedactor

	if err := cmd.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "❌ Failed to start command: %v\n", err)
		os.Exit(1)
	}

	// Signal forwarding
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		sig := <-sigs
		if cmd.Process != nil {
			// Kill the entire process group
			syscall.Kill(-cmd.Process.Pid, sig.(syscall.Signal))
		}
	}()

	err = cmd.Wait()
	outRedactor.Close()
	errRedactor.Close()

	if err != nil {
		if exiterr, ok := err.(*exec.ExitError); ok {
			os.Exit(exiterr.ExitCode())
		}
		os.Exit(1)
	}
	os.Exit(0)
}
