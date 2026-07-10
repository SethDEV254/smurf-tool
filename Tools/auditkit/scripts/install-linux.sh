#!/usr/bin/env bash
# Idempotent installer for auditkit's toolchain on any Linux distro:
# base build tools, bun, Foundry (forge/anvil/cast), Python + slither-analyzer + solc-select.
# Safe to re-run -- every step checks whether its target is already installed first.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

log() { printf '\n== %s ==\n' "$1"; }

log "Detecting package manager"
if command -v apt-get >/dev/null 2>&1; then
  PKG_INSTALL="sudo apt-get update -y && sudo apt-get install -y"
elif command -v dnf >/dev/null 2>&1; then
  PKG_INSTALL="sudo dnf install -y"
elif command -v pacman >/dev/null 2>&1; then
  PKG_INSTALL="sudo pacman -Sy --noconfirm"
else
  PKG_INSTALL=""
  echo "no known package manager found (apt/dnf/pacman) -- skipping base-tools install," \
       "assuming curl/git/python3/pip are already present."
fi

log "Base build tools (curl, git, python3, pip)"
if [ -n "$PKG_INSTALL" ]; then
  MISSING=()
  for bin in curl git python3 pip3; do
    command -v "$bin" >/dev/null 2>&1 || MISSING+=("$bin")
  done
  if [ ${#MISSING[@]} -gt 0 ]; then
    eval "$PKG_INSTALL curl git python3 python3-pip"
  else
    echo "already installed."
  fi
fi

log "bun"
if command -v bun >/dev/null 2>&1; then
  echo "already installed: $(bun --version)"
else
  curl -fsSL https://bun.sh/install | bash
  export PATH="$HOME/.bun/bin:$PATH"
fi

log "Foundry (forge/anvil/cast)"
if command -v forge >/dev/null 2>&1; then
  echo "already installed: $(forge --version)"
else
  curl -fsSL https://foundry.paradigm.xyz | bash
  export PATH="$HOME/.foundry/bin:$PATH"
  foundryup
fi

log "slither-analyzer + solc-select"
if command -v slither >/dev/null 2>&1; then
  echo "already installed: $(slither --version 2>&1 | head -n1)"
else
  pip3 install --user slither-analyzer solc-select
  export PATH="$HOME/.local/bin:$PATH"
fi

log "Project dependencies (bun install + forge-std)"
cd "$PROJECT_DIR"
bun install
if [ ! -d "lib/forge-std" ]; then
  forge install foundry-rs/forge-std --no-commit
fi

log "Done"
cat <<'EOF'
Next steps:
  1. Copy .env.example to .env and set ETHERSCAN_API_KEY / FORK_RPC_URL.
  2. Add these to your shell profile if this was a fresh install:
       export PATH="$HOME/.bun/bin:$HOME/.foundry/bin:$HOME/.local/bin:$PATH"
  3. Try it:
       bun run src/cli.ts static contracts/
       bun run src/cli.ts recon --address 0x... --chain mainnet
EOF
