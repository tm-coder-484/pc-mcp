#!/usr/bin/env bash
# Double-click in Finder to start pc-mcp. If macOS blocks it, run ./start.sh from Terminal instead.
cd "$(dirname "$0")"
exec ./start.sh "$@"
