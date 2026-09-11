# TheNovaNodes AGENTS.md Manifest

## Part 1: TheNovaNodes Core Invariants (Universal Standard)
1. **Strict Git Flow (ПРАВИЛА КРОВИ):**
   - NEVER push directly to main or master branches.
   - All changes must go through dedicated branches (feat/..., fix/..., docs/...) and Pull Requests.
   - NEVER merge PRs without explicit approval from maintainers.
   - No force-push on upstream branches.
2. **Security & Credential Hygiene:**
   - NEVER hardcode or log passwords, tokens, or master keys (especially VAULT_PASSWORD, VAULT_BOT_TOKEN, VAULT_ADMIN_TOKEN).
   - All master secrets must be loaded dynamically from environment variables or encrypted storage.
3. **Deadlock & Timeout Guardrails:**
   - All network and cryptographic operations must have explicit timeouts and bounds.
   - Auxiliary commands must use hard timeouts.
   - Never loop endlessly without bounds.
4. **Continuous Verification:**
   - Never report a task complete without running local verification commands.
   - Use native project tools directly.

## Part 2: Repository Profile & Specific Directives (agent-vault)
1. **Project Overview & Tech Stack:**
   - Go (1.22+ compatible), Makefile-driven tooling.
   - Binaries: `agent-vault` (server), `agent-vault-env`, `agent-vault-cli`.
   - Role: Secret management daemon, encrypted snapshot persistence (`snapshot.enc`), and token authentication for autonomous agents.
2. **The Golden Loop (Mandatory Verification Commands):**
   - `go vet ./...`
   - `go test -race ./...`
   - `make build` (or `go build -v -o agent-vault .`)
3. **Architectural Invariants & Taboos:**
   - **Zero Plaintext Leakage:** Plaintext secrets must NEVER be persisted to unencrypted files or logged to stdout/stderr.
   - **Memory Hygiene:** Wipe sensitive plaintext byte slices from memory after encryption/decryption when possible.
   - **Concurrency Safety:** Internal secret registries and token tables must be concurrency-safe (`sync.RWMutex`). Zero race conditions tolerated.
   - **Strict Auth Guard:** All agent requests must require valid bearer/bot tokens. Agents are FORBIDDEN from bypassing token validation.
4. **PR & Commit Conventions:**
   - Conventional Commits (e.g. `docs(agents): ...`).
