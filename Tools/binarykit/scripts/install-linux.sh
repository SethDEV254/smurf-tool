#!/usr/bin/env bash
# Idempotent installer for binarykit's toolchain on any Linux distro:
# bun, binutils (objdump/nm/readelf), strace, bubblewrap.
# Safe to re-run -- every step checks whether its target is already installed first.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

log() { printf '\n== %s ==\n' "$1"; }

log "Detecting package manager"
if command -v apt-get >/dev/null 2>&1; then
  PKG_INSTALL="sudo apt-get update -y && sudo apt-get install -y"
  PKGS="binutils strace bubblewrap curl"
elif command -v dnf >/dev/null 2>&1; then
  PKG_INSTALL="sudo dnf install -y"
  PKGS="binutils strace bubblewrap curl"
elif command -v pacman >/dev/null 2>&1; then
  PKG_INSTALL="sudo pacman -Sy --noconfirm"
  PKGS="binutils strace bubblewrap curl"
else
  PKG_INSTALL=""
  PKGS=""
  echo "no known package manager found (apt/dnf/pacman) -- install binutils, strace, and" \
       "bubblewrap manually, then re-run this script."
fi

log "binutils / strace / bubblewrap"
if [ -n "$PKG_INSTALL" ]; then
  MISSING=()
  for bin in objdump nm strace bwrap; do
    command -v "$bin" >/dev/null 2>&1 || MISSING+=("$bin")
  done
  if [ ${#MISSING[@]} -gt 0 ]; then
    eval "$PKG_INSTALL $PKGS"
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

log "Project dependencies"
cd "$PROJECT_DIR"
bun install

log "Done"
cat <<'EOF'
Next steps:
  bun run src/cli.ts inspect /path/to/binary --md reports/example.md
  bun run src/cli.ts sandbox /path/to/binary --timeout 15 --md reports/example-sandbox.md
    (sandbox has no network access unless you pass --allow-network)
  bun run src/cli.ts disasm /path/to/binary --symbol main
EOF
