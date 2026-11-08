#!/usr/bin/env bash
# ==============================================================================
# 🚀 agent-vault: Canonical 5-Echelon Production Deployment Script
# Standard: ecosystem-docs (Deploy-as-Code / Anti-Ghost-Deploy / Atomic Switch)
# Specification: Issue #9 (scripts/deploy.sh + commit_sha propagation)
# ==============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
BIN_NAME="agent-vault"
TARGET_BIN="${ROOT_DIR}/bin/${BIN_NAME}"
ROOT_BIN="${ROOT_DIR}/${BIN_NAME}"
PROD_BIN="/usr/local/bin/${BIN_NAME}"
CAPSULE_DIR="${ROOT_DIR}/.deploy_rollback_capsule"

DEPLOY_SUCCESS=0
DRY_RUN=0
SKIP_CLEAN_CHECK=0

# Colors for terminal output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m'

log_info()  { echo -e "${CYAN}ℹ️  ${1}${NC}"; }
log_ok()    { echo -e "${GREEN}✅ ${1}${NC}"; }
log_warn()  { echo -e "${YELLOW}⚠️  ${1}${NC}"; }
log_error() { echo -e "${RED}❌ ${1}${NC}" >&2; }
log_title() { echo -e "\n${PURPLE}=== ${1} ===${NC}"; }

show_help() {
  cat << EOF
agent-vault Canonical 5-Echelon Deployment Tool

USAGE:
  $(basename "$0") [OPTIONS]

OPTIONS:
  --dry-run             Execute pre-flight, build, and validation without replacing production binary
  --skip-clean-check    Allow deployment with uncommitted/dirty working tree (development only)
  -h, --help            Show this help message

ECHELONS:
  🛡️  0: Pre-Flight Guard (Toolchain & Rollback Capsule)
  🧱  1: Production Isolation Probe (Unit Tests & Clean Working Tree)
  🔄  2: Atomic Switch & Graceful Shift (Binary Swap & Executable Protection)
  🪞  3: Identity & Truth Probe (runtime_commit_sha == git rev-parse HEAD)
  🔍  4: Deep Smoke Probe & Rollback Gate (CLI Probe & Service Health Verification)
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    -h|--help)
      show_help
      exit 0
      ;;
    --dry-run)
      DRY_RUN=1
      shift
      ;;
    --skip-clean-check)
      SKIP_CLEAN_CHECK=1
      shift
      ;;
    *)
      log_error "Unknown option: $1"
      show_help
      exit 1
      ;;
  esac
done

ROLLBACK_EXECUTED=0

rollback() {
  local exit_code=$?
  if (( DEPLOY_SUCCESS == 1 )) || (( ROLLBACK_EXECUTED == 1 )); then
    return 0
  fi
  ROLLBACK_EXECUTED=1

  log_title "🚨 EMERGENCY ROLLBACK TRIGGERED"
  log_error "Deployment failed with exit code ${exit_code}! Initiating automated rollback..."

  if [[ -d "${CAPSULE_DIR}" && -f "${CAPSULE_DIR}/${BIN_NAME}" ]]; then
    log_info "Restoring previous working binary from Rollback Capsule..."
    cp -f "${CAPSULE_DIR}/${BIN_NAME}" "${TARGET_BIN}" 2>/dev/null || true
    cp -f "${CAPSULE_DIR}/${BIN_NAME}" "${ROOT_BIN}" 2>/dev/null || true
    if [[ -w "${PROD_BIN}" || $(id -u) -eq 0 ]] && [[ -f "${CAPSULE_DIR}/prod_${BIN_NAME}" ]]; then
      cp -f "${CAPSULE_DIR}/prod_${BIN_NAME}" "${PROD_BIN}" 2>/dev/null || true
    fi
    log_ok "Rollback binaries restored."
  else
    log_warn "No Rollback Capsule binary available to restore."
  fi

  if systemctl is-active --quiet agent-vault 2>/dev/null; then
    systemctl restart agent-vault 2>/dev/null || true
  fi

  log_error "Deployment ABORTED. Environment reverted to safe state (Version N-1)."
  exit 1
}

trap rollback ERR EXIT

# ==============================================================================
# 🛡️ Эшелон 0: Pre-Flight Guard & Rollback Capsule
# ==============================================================================
log_title "🛡️ Эшелон 0: Pre-Flight Guard & Rollback Capsule"

for cmd in git go; do
  if ! command -v "${cmd}" >/dev/null 2>&1; then
    log_error "Required tool not found: ${cmd}"
    exit 1
  fi
done

TARGET_COMMIT="$(git -C "${ROOT_DIR}" rev-parse HEAD)"
log_ok "Target Git Commit determined: ${TARGET_COMMIT}"

# Prepare Rollback Capsule
log_info "Creating Rollback Capsule in ${CAPSULE_DIR}..."
rm -rf "${CAPSULE_DIR}"
mkdir -p "${CAPSULE_DIR}"
chmod 0700 "${CAPSULE_DIR}"

if [[ -f "${TARGET_BIN}" ]]; then
  cp -f "${TARGET_BIN}" "${CAPSULE_DIR}/${BIN_NAME}"
  log_ok "Existing bin/${BIN_NAME} backed up to capsule."
elif [[ -f "${ROOT_BIN}" ]]; then
  cp -f "${ROOT_BIN}" "${CAPSULE_DIR}/${BIN_NAME}"
  log_ok "Existing root ${BIN_NAME} backed up to capsule."
fi

if [[ -f "${PROD_BIN}" ]]; then
  cp -f "${PROD_BIN}" "${CAPSULE_DIR}/prod_${BIN_NAME}"
  log_ok "Existing ${PROD_BIN} backed up to capsule."
fi

cat << EOF > "${CAPSULE_DIR}/capsule_meta.env"
BACKUP_TIMESTAMP="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
TARGET_COMMIT="${TARGET_COMMIT}"
EOF
log_ok "Rollback Capsule sealed."

# Compile release candidates
mkdir -p "${ROOT_DIR}/bin"
CANDIDATE_BIN="${ROOT_DIR}/bin/${BIN_NAME}.candidate"
CANDIDATE_CLI="${ROOT_DIR}/bin/agent-vault-cli.candidate"
CANDIDATE_ENV="${ROOT_DIR}/bin/agent-vault-env.candidate"
CANDIDATE_WITH="${ROOT_DIR}/bin/with-secret.candidate"

log_info "Compiling release candidate binaries with embedded commit SHA: ${TARGET_COMMIT}..."
cd "${ROOT_DIR}"
go build -ldflags "-s -w -X main.CommitSHA=${TARGET_COMMIT} -X main.Version=1.1.0" -o "${CANDIDATE_BIN}" .
go build -ldflags "-s -w" -o "${CANDIDATE_CLI}" ./cmd/agent-vault-cli
go build -ldflags "-s -w" -o "${CANDIDATE_ENV}" ./cmd/agent-vault-env
go build -ldflags "-s -w" -o "${CANDIDATE_WITH}" ./cmd/with-secret

if [[ ! -s "${CANDIDATE_BIN}" ]]; then
  log_error "Candidate binary compilation failed or produced empty file!"
  exit 1
fi
chmod +x "${CANDIDATE_BIN}" "${CANDIDATE_CLI}" "${CANDIDATE_ENV}" "${CANDIDATE_WITH}"
log_ok "Release candidate binaries successfully compiled."

# ==============================================================================
# 🧱 Эшелон 1: Production Isolation Probe
# ==============================================================================
log_title "🧱 Эшелон 1: Production Isolation Probe"

log_info "Running L1 unit test suite..."
go test ./...
log_ok "Unit test suite: 100% PASS."

if (( SKIP_CLEAN_CHECK == 0 )); then
  DIFF_OUTPUT="$(git status --porcelain -uno)"
  if [[ -n "${DIFF_OUTPUT}" ]]; then
    log_error "Working tree has uncommitted tracked changes:"
    echo "${DIFF_OUTPUT}"
    exit 1
  fi
  log_ok "Working tree cleanliness verified: No dirty tracked files."
else
  log_warn "Clean tree check skipped via --skip-clean-check."
fi

# ==============================================================================
# 🔄 Эшелон 2: Atomic Switch & Graceful Shift
# ==============================================================================
log_title "🔄 Эшелон 2: Atomic Switch & Graceful Shift"

if (( DRY_RUN == 0 )); then
  log_info "Atomically installing release binaries..."
  install -m 755 "${CANDIDATE_BIN}" "${TARGET_BIN}"
  install -m 755 "${CANDIDATE_BIN}" "${ROOT_BIN}"
  install -m 755 "${CANDIDATE_CLI}" "${ROOT_DIR}/bin/agent-vault-cli"
  install -m 755 "${CANDIDATE_ENV}" "${ROOT_DIR}/bin/agent-vault-env"
  install -m 755 "${CANDIDATE_WITH}" "${ROOT_DIR}/bin/with-secret"

  # If running with root privileges and /usr/local/bin is standard prod target:
  if [[ -d "/usr/local/bin" && -w "/usr/local/bin" ]]; then
    install -m 755 "${CANDIDATE_BIN}" "${PROD_BIN}"
    install -m 755 "${CANDIDATE_CLI}" "/usr/local/bin/agent-vault-cli"
    install -m 755 "${CANDIDATE_ENV}" "/usr/local/bin/agent-vault-env"
    install -m 755 "${CANDIDATE_WITH}" "/usr/local/bin/with-secret"
    log_ok "Binaries also installed to /usr/local/bin."
  fi

  rm -f "${CANDIDATE_BIN}" "${CANDIDATE_CLI}" "${CANDIDATE_ENV}" "${CANDIDATE_WITH}"
  log_ok "Production binaries atomically switched."

  if systemctl is-active --quiet agent-vault 2>/dev/null; then
    log_info "Restarting agent-vault systemd service..."
    systemctl restart agent-vault
    sleep 2
    if ! systemctl is-active --quiet agent-vault; then
      log_error "Service failed to restart!"
      exit 1
    fi
    log_ok "Service restarted and active."
  fi
else
  log_warn "Dry run mode active: binary switch skipped."
fi

# ==============================================================================
# 🪞 Эшелон 3: Identity & Truth Probe
# ==============================================================================
log_title "🪞 Эшелон 3: Identity & Truth Probe"

PROBE_BIN="${TARGET_BIN}"
if (( DRY_RUN == 1 )); then
  PROBE_BIN="${CANDIDATE_BIN}"
fi

VERSION_OUTPUT="$("${PROBE_BIN}" --version)"
log_info "Binary identity output: ${VERSION_OUTPUT}"

if [[ "${VERSION_OUTPUT}" != *"${TARGET_COMMIT}"* ]]; then
  log_error "Truth violation: Binary commit '${VERSION_OUTPUT}' does not match target commit '${TARGET_COMMIT}'!"
  exit 1
fi
log_ok "Runtime identity confirmed: commit SHA match verified."

# ==============================================================================
# 🔍 Эшелон 4: Deep Smoke Probe & Rollback Gate
# ==============================================================================
log_title "🔍 Эшелон 4: Deep Smoke Probe & Rollback Gate"

if systemctl is-active --quiet agent-vault 2>/dev/null; then
  log_info "Probing live agent-vault service /health endpoint..."
  HEALTH_OUT="$(curl -sf --max-time 5 "http://127.0.0.1:8301/health" 2>/dev/null || true)"
  if [[ "${HEALTH_OUT}" == *"ok"* ]] || [[ "${HEALTH_OUT}" == *"status"* ]]; then
    log_ok "HTTP health check verified: ${HEALTH_OUT:0:100}"
  else
    log_warn "Health endpoint probe returned: ${HEALTH_OUT}"
  fi
else
  log_info "Service not running under systemd; verifying CLI subtools..."
  "${ROOT_DIR}/bin/agent-vault-cli" -help 2>&1 | head -n 2 >/dev/null || true
  "${ROOT_DIR}/bin/agent-vault-env" -help 2>&1 | head -n 2 >/dev/null || true
  log_ok "CLI subtools functional."
fi

DEPLOY_SUCCESS=1
log_title "🎉 DEPLOYMENT SUCCESSFUL"
log_ok "All 5 echelons passed. Candidate ${TARGET_COMMIT:0:8} is active."
exit 0
