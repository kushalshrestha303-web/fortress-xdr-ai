#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [ ! -d "$ROOT_DIR/frontend/node_modules" ]; then
  echo "Missing frontend dependencies. Run ./setup.sh first."
  exit 1
fi

cd "$ROOT_DIR/frontend"
exec npm run dev -- --host 127.0.0.1 --port 5173
