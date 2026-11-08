#!/usr/bin/env bash
# ==============================================================================
# 🚀 agent-vault: Deployment Entrypoint (Compatibility Wrapper)
# Standard: ecosystem-docs (Deploy-as-Code / 5-Echelon Canonical Architecture)
# ==============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec "${SCRIPT_DIR}/scripts/deploy.sh" "$@"
