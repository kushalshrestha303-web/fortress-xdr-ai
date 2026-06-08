#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "[1/4] Preparing Python backend environment"
python3 -m venv "$ROOT_DIR/backend/.venv"
"$ROOT_DIR/backend/.venv/bin/python" -m pip install --upgrade pip
"$ROOT_DIR/backend/.venv/bin/python" -m pip install -r "$ROOT_DIR/backend/requirements.txt"

echo "[2/4] Installing frontend dependencies"
cd "$ROOT_DIR/frontend"
npm install

echo "[3/4] Checking environment file"
cd "$ROOT_DIR"
if [ ! -f ".env" ]; then
  cp ".env.example" ".env"
  echo "Created .env from .env.example. Edit it with your Wazuh Indexer URL and password."
else
  echo ".env already exists."
fi

echo "[4/4] Setup complete"
echo "Run ./run-backend.sh in one terminal and ./run-frontend.sh in another."
