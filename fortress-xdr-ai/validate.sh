#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BACKEND_PORT="${BACKEND_PORT:-18000}"
BACKEND_LOG="/tmp/fortress-xdr-ai-backend-validate.log"

fail() {
  echo "FAIL: $1"
  exit 1
}

echo "[1/7] Checking Python"
command -v python3 >/dev/null 2>&1 || fail "python3 is not installed"

echo "[2/7] Checking Node and npm"
command -v node >/dev/null 2>&1 || fail "node is not installed"
command -v npm >/dev/null 2>&1 || fail "npm is not installed"

echo "[3/7] Checking .env"
[ -f "$ROOT_DIR/.env" ] || fail ".env is missing. Copy .env.example to .env and configure it."

echo "[4/7] Checking backend requirements"
[ -x "$ROOT_DIR/backend/.venv/bin/python" ] || fail "backend/.venv is missing. Run ./setup.sh."
"$ROOT_DIR/backend/.venv/bin/python" - <<'PY'
import fastapi
import httpx
import dotenv
import pydantic
import uvicorn
PY

echo "[5/7] Checking frontend dependencies"
[ -d "$ROOT_DIR/frontend/node_modules" ] || fail "frontend/node_modules is missing. Run ./setup.sh."

echo "[6/7] Checking backend syntax and startup"
"$ROOT_DIR/backend/.venv/bin/python" -m py_compile "$ROOT_DIR/backend/main.py" "$ROOT_DIR/backend/wazuh_client.py" "$ROOT_DIR/backend/investigation_engine.py" "$ROOT_DIR/backend/models.py"
cd "$ROOT_DIR/backend"
BACKEND_PORT="$BACKEND_PORT" "$ROOT_DIR/backend/.venv/bin/python" -m uvicorn main:app --host 127.0.0.1 --port "$BACKEND_PORT" > "$BACKEND_LOG" 2>&1 &
PID=$!
trap 'kill "$PID" >/dev/null 2>&1 || true' EXIT
sleep 3
curl -fsS "http://127.0.0.1:$BACKEND_PORT/health" >/dev/null || fail "backend did not answer /health. See $BACKEND_LOG"
kill "$PID" >/dev/null 2>&1 || true
trap - EXIT

echo "[7/7] Building frontend"
cd "$ROOT_DIR/frontend"
npm run build

echo "Validation passed."
