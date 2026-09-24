#!/usr/bin/env bash
# pc-mcp launcher for macOS and Linux: ./start.sh  (extra arguments are passed to pc-mcp, e.g. --mode read-only)
# First run installs uv (Python manager), Python and dependencies automatically - about a minute.
set -euo pipefail
cd "$(dirname "$0")"

if ! command -v uv >/dev/null 2>&1; then
  export PATH="$HOME/.local/bin:$PATH"
fi
if ! command -v uv >/dev/null 2>&1; then
  echo "Installing uv, the Python manager pc-mcp runs on - one time only..."
  if command -v curl >/dev/null 2>&1; then
    curl -LsSf https://astral.sh/uv/install.sh | sh
  else
    wget -qO- https://astral.sh/uv/install.sh | sh
  fi
fi
command -v uv >/dev/null 2>&1 || { echo "Could not install uv - see https://docs.astral.sh/uv/"; exit 1; }

args=("$@")
if [ ${#args[@]} -eq 0 ] && [ -t 0 ]; then
  echo
  echo " How much should Claude be allowed to do on this computer?"
  echo "   [1] Full access - run commands, manage files and processes  (default)"
  echo "   [2] Full access, but ask me here before every command or change"
  echo "   [3] Read-only - diagnose and inspect only, change nothing"
  echo
  read -r -t 20 -p " Press 1, 2 or 3 then Enter (defaults to 1 in 20 seconds): " choice || choice=1
  case "${choice:-1}" in
    2) args=(--confirm) ;;
    3) args=(--mode read-only) ;;
  esac
fi

echo
echo "Starting pc-mcp - the first start downloads Python and dependencies, please wait..."
exec uv run --quiet pc-mcp "${args[@]}"
