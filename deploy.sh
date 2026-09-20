#!/bin/bash
# deploy.sh — build, deploy, and verify agent-vault
set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEV_BIN="$PROJECT_DIR/agent-vault"
PROD_BIN="/usr/local/bin/agent-vault"
API="http://127.0.0.1:8301"

# Токен из переменной окружения или config.yaml
ADMIN_TOKEN="${VAULT_ADMIN_TOKEN:-}"

CONFIG_FILE="$PROJECT_DIR/config.yaml"
if [ -f "/etc/agent-vault/config.yaml" ]; then
    CONFIG_FILE="/etc/agent-vault/config.yaml"
fi

if [ -z "$ADMIN_TOKEN" ] && [ -f "$CONFIG_FILE" ]; then
    ADMIN_TOKEN=$(grep -E '^\s*admin_token:' "$CONFIG_FILE" 2>/dev/null | awk '{print $2}' | tr -d '"'\' || true)
fi

# Check TLS configuration
CURL_OPTS="-sf --max-time 10"
if [ -f "$CONFIG_FILE" ]; then
    USE_TLS=$(grep -E '^\s*use_tls:' "$CONFIG_FILE" 2>/dev/null | awk '{print $2}' | tr -d '"'\' | tr '[:upper:]' '[:lower:]' || echo "false")
    if [ "$USE_TLS" = "true" ]; then
        API="https://127.0.0.1:8301"
        TLS_CERT=$(grep -E '^\s*tls_cert_path:' "$CONFIG_FILE" 2>/dev/null | awk '{print $2}' | tr -d '"'\' || true)
        if [ -n "$TLS_CERT" ] && [ -f "$TLS_CERT" ]; then
            CURL_OPTS="-sf --max-time 10 --cacert $TLS_CERT"
        else
            CURL_OPTS="-sf --max-time 10"
        fi
    fi
fi

PASS=0
FAIL=0

ok() { echo "  ✅ $1"; PASS=$((PASS+1)); }
fail() { echo "  ❌ $1"; FAIL=$((FAIL+1)); }

if [ -z "$ADMIN_TOKEN" ]; then
    echo "⚠️  VAULT_ADMIN_TOKEN not set — admin API checks will be skipped"
fi

echo "=== [1/5] Build & Prepare Production Binary ==="
cd "$PROJECT_DIR"
export PATH=/usr/local/go/bin:$PATH
if ! command -v go &> /dev/null; then
    fail "Go is not installed or not in PATH"
fi
# Backup current production binary for rollback
if [ -f "$PROD_BIN" ]; then
    cp "$PROD_BIN" "$PROD_BIN.bak"
    echo "  Backed up current production binary to $PROD_BIN.bak"
fi
go build -o agent-vault . 2>&1 && ok "Build agent-vault OK" || fail "Build agent-vault failed"
go build -o agent-vault-cli ./cmd/agent-vault-cli 2>&1 && ok "Build agent-vault-cli OK" || fail "Build agent-vault-cli failed"
go build -o agent-vault-env ./cmd/agent-vault-env 2>&1 && ok "Build agent-vault-env OK" || fail "Build agent-vault-env failed"
go build -o with-secret ./cmd/with-secret 2>&1 && ok "Build with-secret OK" || fail "Build with-secret failed"
WAS_ACTIVE=false
if systemctl is-active --quiet agent-vault 2>/dev/null; then
    WAS_ACTIVE=true
    systemctl stop agent-vault
    echo "  Stopped running service before binary replacement"
fi
cp "$DEV_BIN" "$PROD_BIN" && ok "Copied binary to $PROD_BIN" || fail "Failed to copy binary to /usr/local/bin"
for tool in agent-vault-cli agent-vault-env with-secret; do
    if [ -f "$PROJECT_DIR/$tool" ]; then
        cp "$PROJECT_DIR/$tool" "/usr/local/bin/$tool" && ok "Copied $tool to /usr/local/bin/$tool" || fail "Failed to copy $tool"
    fi
done
echo "  Production Binary: $(ls -lh "$PROD_BIN" | awk '{print $5, $6, $7, $8}')"

echo ""
echo "=== [2/5] Deploy ==="
systemctl start agent-vault && ok "Service started" || fail "Service start failed"
sleep 2

# Rollback on failure
if ! systemctl is-active --quiet agent-vault 2>/dev/null; then
    fail "Service not running after deploy — rolling back"
    if [ "$WAS_ACTIVE" = true ]; then
        echo "  ↩️  Restarting previous instance..."
        systemctl start agent-vault
        sleep 2
        if systemctl is-active --quiet agent-vault; then
            ok "Rollback successful"
        else
            fail "Rollback also failed — manual intervention required"
        fi
    fi
fi

echo ""
echo "=== [3/5] Health checks ==="
# systemd status
if systemctl is-active --quiet agent-vault; then
    ok "systemd: active"
else
    fail "systemd: inactive"
    journalctl -u agent-vault --no-pager -n 10
fi

# API health (no auth required) with retry
HEALTH=""
for i in {1..5}; do
    HEALTH=$(curl $CURL_OPTS "$API/health" 2>/dev/null || echo "")
    if echo "$HEALTH" | grep -q '"status":"ok"'; then
        break
    fi
    sleep 1
done
if echo "$HEALTH" | grep -q '"status":"ok"'; then
    ok "API /health: $HEALTH"
else
    fail "API /health: no response"
fi

# Admin auth (if token available)
if [ -n "$ADMIN_TOKEN" ]; then
    SECRETS_RESP=$(curl $CURL_OPTS -H "X-Vault-Token: $ADMIN_TOKEN" "$API/secrets" 2>/dev/null || echo "")
    if echo "$SECRETS_RESP" | grep -q '\['; then
        ok "Admin auth: OK"
    else
        fail "Admin auth: $SECRETS_RESP"
    fi
else
    echo "  ⏭  Admin auth: skipped (no VAULT_ADMIN_TOKEN)"
fi

echo ""
echo "=== [4/5] API flow test ==="
API_FLOW_OK=true

# Secrets endpoint
SECRETS=$(curl $CURL_OPTS "$API/health" 2>/dev/null || echo "")
if echo "$SECRETS" | grep -q '"status":"ok"'; then
    if command -v jq &>/dev/null; then
        SECRET_COUNT=$(echo "$SECRETS" | jq -r '.secrets // 0' 2>/dev/null || echo "?")
    else
        SECRET_COUNT=$(echo "$SECRETS" | grep -o '"secrets":[0-9]*' | cut -d: -f2 || echo "?")
    fi
    ok "Secrets: $SECRET_COUNT in vault"
else
    fail "Health: no response"
    API_FLOW_OK=false
fi

# Export endpoint (if token available)
if [ -n "$ADMIN_TOKEN" ]; then
    EXPORT=$(curl $CURL_OPTS -H "X-Vault-Token: $ADMIN_TOKEN" "$API/export" 2>/dev/null || echo "")
    if echo "$EXPORT" | grep -q '{'; then
        ok "Export: OK"
    else
        fail "Export: $EXPORT"
        API_FLOW_OK=false
    fi
fi

# Recent errors
ERRORS=$(journalctl -u agent-vault --since "1 min ago" --no-pager 2>/dev/null | grep -c "error\|ERROR\|panic" || true)
if [ "$ERRORS" -eq 0 ]; then
    ok "No recent errors in journal"
else
    fail "$ERRORS recent errors"
    journalctl -u agent-vault --since "1 min ago" --no-pager | grep -i "error\|panic" || true
    API_FLOW_OK=false
fi

# Rollback if API flow failed
if [ "$API_FLOW_OK" = false ] && [ "$WAS_ACTIVE" = true ]; then
    echo ""
    echo "  ⚠️  API flow test failed — rolling back..."
    systemctl stop agent-vault
    sleep 1
    # Restore previous production binary if backup exists
    if [ -f "$PROD_BIN.bak" ]; then
        cp "$PROD_BIN.bak" "$PROD_BIN"
        echo "  ↩️  Restored previous production binary"
    fi
    systemctl start agent-vault
    sleep 2
    if systemctl is-active --quiet agent-vault; then
        ok "Rollback successful"
    else
        fail "Rollback failed — manual intervention required"
    fi
fi

echo ""
echo "=== [5/5] Summary ==="
echo "  $(systemctl show agent-vault --property=ActiveEnterTimestamp --value 2>/dev/null || echo 'N/A')"
HEALTH_JSON=$(curl $CURL_OPTS "$API/health" 2>/dev/null || echo "")
if command -v jq &>/dev/null && [ -n "$HEALTH_JSON" ]; then
    SUMMARY_LINE=$(echo "$HEALTH_JSON" | jq -r '"Secrets: \(.secrets // "?"), Uptime: \(.uptime // "?")"' 2>/dev/null || echo "N/A")
else
    SEC=$(echo "$HEALTH_JSON" | grep -o '"secrets":[0-9]*' | cut -d: -f2 || true)
    UPT=$(echo "$HEALTH_JSON" | grep -o '"uptime":"[^"]*"' | cut -d'"' -f4 || true)
    SUMMARY_LINE="Secrets: ${SEC:-?}, Uptime: ${UPT:-?}"
fi
echo "  $SUMMARY_LINE"

echo ""
echo "=============================="
echo "Results: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ] && echo "ALL CHECKS PASSED" || echo "SOME CHECKS FAILED"
exit $FAIL
