package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"time"
)

const version = "2.0.0"

func main() {
	var (
		vaultAddr = flag.String("addr", "http://127.0.0.1:8301", "vault address")
		token     = flag.String("token", os.Getenv("VAULT_ADMIN_TOKEN"), "admin token")
	)
	flag.Parse()

	if *token == "" {
		fmt.Fprintln(os.Stderr, "Error: -token or VAULT_ADMIN_TOKEN required")
		os.Exit(1)
	}

	args := flag.Args()
	if len(args) == 0 {
		printUsage()
		os.Exit(0)
	}

	switch args[0] {
	case "help", "--help", "-h":
		printUsage()
	case "version", "--version", "-v":
		fmt.Println("agent-vault-cli", version)
	case "health":
		cmdHealth(*vaultAddr)
	case "list":
		cmdList(*vaultAddr, *token)
	case "set":
		if len(args) < 3 {
			fmt.Fprintln(os.Stderr, "Usage: agent-vault-cli set <name> <value>")
			os.Exit(1)
		}
		cmdSet(*vaultAddr, *token, args[1], args[2])
	case "get":
		if len(args) < 2 {
			fmt.Fprintln(os.Stderr, "Usage: agent-vault-cli get <name>")
			os.Exit(1)
		}
		cmdGet(*vaultAddr, *token, args[1])
	case "delete":
		if len(args) < 2 {
			fmt.Fprintln(os.Stderr, "Usage: agent-vault-cli delete <name>")
			os.Exit(1)
		}
		cmdDelete(*vaultAddr, *token, args[1])
	case "wipe":
		cmdWipe(*vaultAddr, *token)
	case "export":
		cmdExport(*vaultAddr, *token)
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n", args[0])
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println(`agent-vault-cli — Lab Vault admin CLI v2.0

Usage: agent-vault-cli [options] <command> [args]

Options:
  -addr    Vault address (default: http://127.0.0.1:8301)
  -token   Admin token (or VAULT_ADMIN_TOKEN env)

Commands:
  health                   Check vault health
  list                     List all secret names
  get <name>               Get secret value
  set <name> <value>       Create/update secret
  delete <name>            Delete secret
  wipe                     Delete ALL secrets
  export                   Export all secrets as JSON
  version                  Show version

Examples:
  agent-vault-cli health
  agent-vault-cli list
  agent-vault-cli get api_key
  agent-vault-cli set db_pass secret123
  agent-vault-cli export`)
}

func doRequest(addr, method, path, token string, body interface{}) (*http.Response, error) {
	var bodyReader *bytes.Reader
	if body != nil {
		data, _ := json.Marshal(body)
		bodyReader = bytes.NewReader(data)
	} else {
		bodyReader = bytes.NewReader(nil)
	}

	url := fmt.Sprintf("%s%s", addr, path)
	req, err := http.NewRequest(method, url, bodyReader)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-Vault-Token", token)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 10 * time.Second}
	return client.Do(req)
}

func cmdHealth(addr string) {
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(fmt.Sprintf("%s/health", addr))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()

	var result map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&result)
	prettyPrint(result)
}

func cmdList(addr, token string) {
	resp, err := doRequest(addr, "GET", "/secrets", token, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		fmt.Fprintf(os.Stderr, "Error: %s\n", resp.Status)
		os.Exit(1)
	}

	var secrets []map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&secrets)

	if len(secrets) == 0 {
		fmt.Println("No secrets")
		return
	}

	for _, s := range secrets {
		name, _ := s["name"].(string)
		updated, _ := s["updated_at"].(string)
		fmt.Printf("%-30s %s\n", name, updated)
	}
}

func cmdGet(addr, token, name string) {
	resp, err := doRequest(addr, "GET", "/secret/"+name, token, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()

	if resp.StatusCode == 404 {
		fmt.Fprintf(os.Stderr, "Secret '%s' not found\n", name)
		os.Exit(1)
	}
	if resp.StatusCode != 200 {
		fmt.Fprintf(os.Stderr, "Error: %s\n", resp.Status)
		os.Exit(1)
	}

	var result map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&result)
	prettyPrint(result)
}

func cmdSet(addr, token, name, value string) {
	body := map[string]string{"name": name, "value": value}
	resp, err := doRequest(addr, "POST", "/secrets", token, body)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		fmt.Fprintf(os.Stderr, "Error: %s\n", resp.Status)
		os.Exit(1)
	}

	fmt.Printf("✅ Secret '%s' created/updated\n", name)
}

func cmdDelete(addr, token, name string) {
	resp, err := doRequest(addr, "DELETE", "/secret/"+name, token, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()

	if resp.StatusCode == 404 {
		fmt.Fprintf(os.Stderr, "Secret '%s' not found\n", name)
		os.Exit(1)
	}
	if resp.StatusCode != 200 {
		fmt.Fprintf(os.Stderr, "Error: %s\n", resp.Status)
		os.Exit(1)
	}

	fmt.Printf("🗑  Secret '%s' deleted\n", name)
}

func cmdWipe(addr, token string) {
	fmt.Print("⚠️  Delete ALL secrets? Type 'yes' to confirm: ")
	var confirm string
	fmt.Scanln(&confirm)
	if confirm != "yes" {
		fmt.Println("Cancelled")
		return
	}

	resp, err := doRequest(addr, "DELETE", "/secrets", token, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		fmt.Fprintf(os.Stderr, "Error: %s\n", resp.Status)
		os.Exit(1)
	}

	fmt.Println("☠️  All secrets deleted")
}

func cmdExport(addr, token string) {
	client := &http.Client{Timeout: 10 * time.Second}
	url := fmt.Sprintf("%s/export", addr)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	req.Header.Set("X-Vault-Token", token)

	resp, err := client.Do(req)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		fmt.Fprintf(os.Stderr, "Error: %s\n", resp.Status)
		os.Exit(1)
	}

	var result map[string]string
	json.NewDecoder(resp.Body).Decode(&result)
	prettyPrint(result)
}

func prettyPrint(v interface{}) {
	data, _ := json.MarshalIndent(v, "", "  ")
	fmt.Println(string(data))
}
