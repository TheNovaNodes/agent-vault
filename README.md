```yaml
module_type: core-component
status: active
protocol: http
primary_capability: secret-management
requires: go, telegram-bot-api
works_with: agent-vault-env, agent-vault-cli
last_verified: 2026-08-26
---
Status: Active / Core Component
Last Verified: 2026-08-26

## What it does / does not do
**What it does:**
- Securely stores secrets using in-memory structures backed by ChaCha20-Poly1305 encrypted snapshots (`snapshot.enc`).
- Provides a Telegram Bot interface for admins to manage secrets and access tokens.
- Supports single-secret tokens and project-level tokens (groups of secrets).
- Exposes a minimal HTTP API for agent access.
- Provides CLI tools (`agent-vault-env`, `agent-vault-cli`) for environment-variable generation and administration.
- Maintains a ring-buffer audit log of all access and management actions.

**What it does not do:**
- Does not claim automatic onboarding (agents must be explicitly granted tokens).
- Does not implement an MCP server natively (acts as an HTTP service).
- Does not support high-availability clustering or complex RBAC.

## Why an agent would use it
Agents use Agent Vault to securely retrieve credentials, API keys, or environment variables at runtime without hardcoding sensitive data into their configuration or prompts. By using `agent-vault-env`, agents can transparently inject secrets into their execution environments.

## Architecture and dependencies
**Architecture:**
- **Store:** In-memory key-value store, periodically flushed to disk.
- **Sealed Mode:** Data is encrypted at rest using a key derived from a password or randomly generated.
- **Interfaces:** HTTP REST API (port 8301 by default), Telegram Bot, and CLI binaries.

**Dependencies:**
- Go 1.25.0
- `github.com/go-telegram-bot-api/telegram-bot-api/v5`
- `golang.org/x/crypto/chacha20poly1305`
- `gopkg.in/yaml.v3`

## Compatibility
Fully compatible with Linux environments and can run as a standard systemd service.

## Quick start and health check
1. Build the binaries:
   ```bash
   make build
   ```
2. Create a `config.yaml` based on `config.yaml.example`.
3. Start the server (with an optional password for sealed mode). For development without TLS, you must pass `-dev`:
   ```bash
   VAULT_PASSWORD="my-secure-password" ./agent-vault -config config.yaml -dev
   ```
4. Health check:
   ```bash
   curl https://127.0.0.1:8301/health
   ```

## Configuration and environment variables
- `VAULT_PASSWORD`: Used to enable sealed mode (encryption at rest).
- `VAULT_ADMIN_TOKEN`: Admin token for HTTP API, overrides `admin_token` in `config.yaml`.
- `VAULT_BOT_TOKEN`: Telegram bot token, overrides `tg_bot_token` in `config.yaml`.
- `VAULT_TOKEN`: Used by `agent-vault-env` to authenticate.

*Priority: Environment Variables > config.yaml > Defaults.*

## Complete MCP tool/API table with side effects
Since Agent Vault provides an HTTP API rather than native MCP tools, here is the API table:

| Endpoint | Method | Requires Auth | Side Effects | Description |
|----------|--------|---------------|--------------|-------------|
| `/health` | GET | None | None | Returns vault status and uptime. |
| `/access` | GET | Token in Header (`Authorization: Bearer <token>`) | Audit Log | Retrieves secret or project secrets. |
| `/secrets` | GET | Admin Token | None | Lists all secrets. |
| `/secrets` | POST | Admin Token | State Mutation | Creates or updates a secret. |
| `/secret/{name}` | GET | Admin Token | None | Retrieves a specific secret by name. |
| `/secret/{name}` | DELETE | Admin Token | State Mutation | Deletes a secret and revokes its tokens. |
| `/export` | GET | Admin Token | None | Exports all secrets. |
| `/projects` | GET, POST | Admin Token | State Mutation | Lists or creates projects. |
| `/project/{id}` | GET, DELETE | Admin Token | State Mutation | Retrieves or deletes a project. |
| `/audit` | GET | Admin Token | None | Returns the audit log. |
| `/token/{hash}` | DELETE | Admin Token | State Mutation | Revokes a token by hash. |
| `/project-tokens/{id}` | GET, POST | Admin Token | State Mutation | Lists or creates project tokens. |

## Security model and trust boundaries
- **Data at Rest:** Encrypted with ChaCha20-Poly1305 if `VAULT_PASSWORD` is provided.
- **Authentication:** Admin actions require the Admin Token. Agent access is strictly gated by immutable, expirable, and revocable hash-based tokens.
- **Audit Logging:** Every access or management action is recorded in a ring buffer to detect unauthorized access attempts.

## Tests and exact commands
Run the complete test suite (95+ tests):
```bash
make test
```
To run tests with coverage:
```bash
make test-cov
```

## Operations, logs, backup/restore, rollback
- **Operations:** Run via systemd.
- **Logs:** Application logs to stdout/stderr. Audit logs available via `/audit` API.
- **Backup/Restore:** Back up `snapshot.enc` (and `config.yaml`). If sealed mode is used, ensure the `VAULT_PASSWORD` is securely backed up; otherwise, data cannot be decrypted.
- **Rollback:** Replace `snapshot.enc` with a previous version and restart the service.

## Generic MCP-client example
An agent using an HTTP-based MCP client can fetch secrets using their provisioned token:
```json
{
  "method": "http.get",
  "url": "https://127.0.0.1:8301/access/MY_TOKEN",
  "headers": {}
}
```

## Limitations and roadmap
- Currently missing granular multi-admin roles (only a single admin token or Telegram admin).
- No built-in native MCP server interface.

## Related TheNovaNodes modules
- **Trickster Ecosystem Audit:** Part of the infrastructure audit suite.

## License
Proprietary / Internal. See organizational guidelines for usage.
