#!/bin/bash
# deploy.sh — build, deploy, and verify agent-vault
set -euo pipefail

PROJECT_DIR="/root/LabDoctorM/projects/agent-vault"
BIN="$PROJECT_DIR/agent-vault"
API="http://127.0.0.1:8301"

# Токен из переменной окружения или config.yaml
ADMIN_TOKEN="${VAULT_ADMIN_TOKEN:-}"

# Check TLS configuration
CURL_OPTS="-sf"
if [ -f "$PROJECT_DIR/config.yaml" ]; then
    USE_TLS=$(python3 -c "import yaml; print(yaml.safe_load(open('$PROJECT_DIR/config.yaml')).get('use_tls', False))" 2>/dev/null || echo "False")
    if [ "$USE_TLS" = "True" ]; then
        API="https://127.0.0.1:8301"
        TLS_CERT=$(python3 -c "import yaml; print(yaml.safe_load(open('$PROJECT_DIR/config.yaml')).get('tls_cert_path', ''))" 2>/dev/null || echo "")
        if [ -n "$TLS_CERT" ] && [ -f "$TLS_CERT" ]; then
            CURL_OPTS="-sf --cacert $TLS_CERT"
        else
            CURL_OPTS="-sf"
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

echo "=== [1/5] Build ==="
cd "$PROJECT_DIR"
export PATH=/usr/local/go/bin:$PATH
# Backup current binary for rollback
if [ -f "$BIN" ]; then
    cp "$BIN" "$BIN.bak"
    echo "  Backed up current binary"
fi
go build -o agent-vault . 2>&1 && ok "Build OK" || fail "Build failed"
echo "  Binary: $(ls -lh "$BIN" | awk '{print $5, $6, $7, $8}')"

echo ""
echo "=== [2/5] Deploy ==="
# Save current state for rollback
WAS_ACTIVE=false
if systemctl is-active --quiet agent-vault 2>/dev/null; then
    WAS_ACTIVE=true
    echo "  Service was active — will rollback on failure"
fi

if systemctl is-active --quiet agent-vault 2>/dev/null; then
    systemctl stop agent-vault
    echo "  Stopped old service"
fi
sleep 1
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

# API health (no auth required)
HEALTH=$(curl $CURL_OPTS "$API/health" 2>/dev/null || echo "")
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
    SECRET_COUNT=$(echo "$SECRETS" | python3 -c "import sys,json; print(json.load(sys.stdin).get('secrets',0))" 2>/dev/null || echo "?")
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
    # Restore previous binary if backup exists
    if [ -f "$BIN.bak" ]; then
        cp "$BIN.bak" "$BIN"
        echo "  ↩️  Restored previous binary"
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
echo "  $(curl $CURL_OPTS "$API/health" 2>/dev/null | python3 -c "import sys,json; d=json.load(sys.stdin); print(f'Secrets: {d.get(\"secrets\",\"?\")}, Uptime: {d.get(\"uptime\",\"?\")}')" 2>/dev/null || echo 'N/A')"

echo ""
echo "=============================="
echo "Results: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ] && echo "ALL CHECKS PASSED" || echo "SOME CHECKS FAILED"
exit $FAIL
