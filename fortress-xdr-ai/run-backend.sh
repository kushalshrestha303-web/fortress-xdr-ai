#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [ ! -f "$ROOT_DIR/.env" ]; then
  echo "Missing .env. Copy .env.example to .env and add your Wazuh Indexer settings."
  exit 1
fi

if [ ! -x "$ROOT_DIR/backend/.venv/bin/python" ]; then
  echo "Missing backend virtual environment. Run ./setup.sh first."
  exit 1
fi

set -a
source "$ROOT_DIR/.env"
set +a

BACKEND_PORT="${BACKEND_PORT:-8000}"

cd "$ROOT_DIR/backend"
exec "$ROOT_DIR/backend/.venv/bin/python" -m uvicorn main:app --host 127.0.0.1 --port "$BACKEND_PORT"
