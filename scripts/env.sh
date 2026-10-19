# Sourced by the other scripts. Finds the repo root and a working cargo.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CORE="$ROOT/core"
BUILD="$ROOT/build"
FLYNNKIT="$ROOT/apple/FlynnKit"

# Homebrew's rustup is keg-only: its cargo/rustc proxies are not on PATH.
if ! command -v cargo >/dev/null 2>&1; then
    for dir in "$HOME/.cargo/bin" "/opt/homebrew/opt/rustup/bin" "/usr/local/opt/rustup/bin"; do
        if [ -x "$dir/cargo" ]; then
            export PATH="$dir:$PATH"
            break
        fi
    done
fi
command -v cargo >/dev/null 2>&1 || { echo "error: cargo not found; install rustup" >&2; exit 1; }

step() { printf '\n\033[1m==> %s\033[0m\n' "$*"; }
