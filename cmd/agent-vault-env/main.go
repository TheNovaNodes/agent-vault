package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
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

	url := fmt.Sprintf("%s/access/%s", *vaultAddr, *token)
	client := &http.Client{Timeout: *timeout}

	var resp *http.Response
	var err error
	for attempt := 0; attempt <= *maxRetries; attempt++ {
		if attempt > 0 {
			wait := defaultRetryWait * time.Duration(1<<(attempt-1))
			fmt.Fprintf(os.Stderr, "Retry %d/%d (wait %v)...\n", attempt, *maxRetries, wait)
			time.Sleep(wait)
		}

		resp, err = client.Get(url)
		if err == nil && resp.StatusCode < 500 && resp.StatusCode != http.StatusTooManyRequests {
			break
		}
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
				if val, ok := data["value"].(string); ok {
					fmt.Fprintf(f, "%s=%s\n", name, envEscape(val))
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
			if val, ok := data["value"].(string); ok {
				fmt.Printf("export %s='%s'\n", name, shellEscape(val))
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

	fmt.Printf("export %s='%s'\n", secretResult.Name, shellEscape(secretResult.Value))
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
