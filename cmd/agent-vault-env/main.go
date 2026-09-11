package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"
)

const (
	defaultTimeout    = 10 * time.Second
	defaultMaxRetries = 3
	defaultRetryWait  = 1 * time.Second
)

func main() {
	var (
		vaultAddr  = flag.String("addr", "http://127.0.0.1:8301", "vault address")
		token      = flag.String("token", os.Getenv("VAULT_TOKEN"), "access token")
		raw        = flag.Bool("raw", false, "output raw JSON instead of export format")
		writeTo    = flag.String("write-to", "", "write all secrets to .env file (for project tokens)")
		timeout    = flag.Duration("timeout", defaultTimeout, "request timeout")
		maxRetries = flag.Int("retries", defaultMaxRetries, "max retries on transient errors")
	)
	flag.Parse()

	if *token == "" {
		fmt.Fprintln(os.Stderr, "Error: -token or VAULT_TOKEN required")
		os.Exit(1)
	}

	url := fmt.Sprintf("%s/access", *vaultAddr)
	client := &http.Client{Timeout: *timeout}

	var resp *http.Response
	var respCancel context.CancelFunc
	var err error
	for attempt := 0; attempt <= *maxRetries; attempt++ {
		if attempt > 0 {
			wait := defaultRetryWait * time.Duration(1<<(attempt-1))
			fmt.Fprintf(os.Stderr, "Retry %d/%d (wait %v)...\n", attempt, *maxRetries, wait)
			time.Sleep(wait)
		}

		ctx, cancel := context.WithTimeout(context.Background(), *timeout)
		req, reqErr := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if reqErr != nil {
			err = reqErr
			cancel()
			break
		}
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", *token))

		resp, err = client.Do(req)
		if err == nil && resp.StatusCode < 500 && resp.StatusCode != http.StatusTooManyRequests {
			respCancel = cancel
			break
		}
		cancel()
		if err == nil {
			resp.Body.Close()
			fmt.Fprintf(os.Stderr, "Server error (attempt %d): %d\n", attempt+1, resp.StatusCode)
		} else {
			fmt.Fprintf(os.Stderr, "Connection error (attempt %d): %v\n", attempt+1, err)
		}
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "Error connecting to vault after %d retries: %v\n", *maxRetries, err)
		os.Exit(1)
	}
	if respCancel != nil {
		defer respCancel()
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		fmt.Fprintf(os.Stderr, "Error (%d): %s\n", resp.StatusCode, http.StatusText(resp.StatusCode))
		os.Exit(1)
	}

	// Read body once, then try both formats
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading response: %v\n", err)
		os.Exit(1)
	}

	// Try project token response first
	var projectResult struct {
		Project   string                            `json:"project"`
		ProjectID string                            `json:"project_id"`
		Secrets   map[string]map[string]interface{} `json:"secrets"`
	}
	if err := json.Unmarshal(body, &projectResult); err == nil && projectResult.Project != "" {
		// Project token response
		if *writeTo != "" {
			f, err := os.OpenFile(*writeTo, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error opening %s: %v\n", *writeTo, err)
				os.Exit(1)
			}
			defer f.Close()

			for name, data := range projectResult.Secrets {
				key, err := sanitizeIdent(name)
				if err != nil {
					fmt.Fprintf(os.Stderr, "Warning: skipping secret %q: %v\n", name, err)
					continue
				}
				if val, ok := data["value"].(string); ok {
					fmt.Fprintf(f, "%s=%s\n", key, envEscape(val))
				}
			}
			fmt.Fprintf(os.Stderr, "✅ %d secrets written to %s (project: %s)\n", len(projectResult.Secrets), *writeTo, projectResult.Project)
			return
		}

		if *raw {
			var out bytes.Buffer
			json.Indent(&out, body, "", "  ")
			out.WriteTo(os.Stdout)
			return
		}

		// Output as shell export statements
		for name, data := range projectResult.Secrets {
			key, err := sanitizeIdent(name)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Warning: skipping secret %q: %v\n", name, err)
				continue
			}
			if val, ok := data["value"].(string); ok {
				fmt.Printf("export %s='%s'\n", key, shellEscape(val))
			}
		}
		return
	}

	// Single secret response
	var secretResult struct {
		Name      string `json:"name"`
		Value     string `json:"value"`
		UpdatedAt string `json:"updated_at"`
	}
	if err := json.Unmarshal(body, &secretResult); err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing response: %v\n", err)
		os.Exit(1)
	}

	if *raw {
		fmt.Fprintf(os.Stdout, "{\n  \"name\": %q,\n  \"value\": %q,\n  \"updated_at\": %q\n}\n",
			secretResult.Name, secretResult.Value, secretResult.UpdatedAt)
		return
	}

	key, err := sanitizeIdent(secretResult.Name)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("export %s='%s'\n", key, shellEscape(secretResult.Value))
}

var validIdent = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_]*$`)

func sanitizeIdent(name string) (string, error) {
	sanitized := strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' {
			return r
		}
		if r == '-' || r == ' ' || r == '.' {
			return '_'
		}
		return -1
	}, name)

	for strings.Contains(sanitized, "__") {
		sanitized = strings.ReplaceAll(sanitized, "__", "_")
	}
	sanitized = strings.Trim(sanitized, "_")

	if sanitized == "" {
		return "", fmt.Errorf("invalid secret name %q cannot be converted to shell identifier", name)
	}
	if sanitized[0] >= '0' && sanitized[0] <= '9' {
		sanitized = "V_" + sanitized
	}
	if !validIdent.MatchString(sanitized) {
		return "", fmt.Errorf("invalid secret name %q cannot be converted to shell identifier", name)
	}
	return sanitized, nil
}

func shellEscape(s string) string {
	return strings.ReplaceAll(s, "'", "'\\''")
}

func envEscape(s string) string {
	// For .env files: escape newlines and wrap values with special chars in quotes
	s = strings.ReplaceAll(s, "\n", `\n`)
	s = strings.ReplaceAll(s, "\r", "")
	// If value contains spaces or special chars, wrap in double quotes
	if strings.ContainsAny(s, " \t#") {
		s = `"` + strings.ReplaceAll(s, `"`, `\"`) + `"`
	}
	return s
}
