# Release Package

Use this checklist before creating the hackathon ZIP.

## Test Before Zip

```bash
chmod +x setup.sh run-backend.sh run-frontend.sh validate.sh
./setup.sh
./validate.sh
```

Manual smoke test:

1. Start Wazuh and Suricata.
2. Start backend with `./run-backend.sh`.
3. Start frontend with `./run-frontend.sh`.
4. Open `http://127.0.0.1:5173`.
5. Confirm Live Alerts loads.
6. Confirm the Suricata counter is visible.
7. Confirm the `Suricata` filter shows IDS alerts.
8. Click `Investigate` on a Suricata alert.

## Create Zip

From the parent directory:

```bash
zip -r fortress-xdr-ai-release.zip fortress-xdr-ai \
  -x "fortress-xdr-ai/.env" \
  -x "fortress-xdr-ai/backend/.venv/*" \
  -x "fortress-xdr-ai/frontend/node_modules/*" \
  -x "fortress-xdr-ai/frontend/dist/*" \
  -x "fortress-xdr-ai/node_modules/*" \
  -x "fortress-xdr-ai/__pycache__/*" \
  -x "fortress-xdr-ai/*.log" \
  -x "fortress-xdr-ai/*.pcap" \
  -x "fortress-xdr-ai/*.pcapng" \
  -x "fortress-xdr-ai/*.sqlite" \
  -x "fortress-xdr-ai/.DS_Store"
```

## Include

- `backend/`
- `frontend/`
- `docs/`
- `.env.example`
- `.gitignore`
- `README.md`
- `TROUBLESHOOTING.md`
- `RELEASE.md`
- `setup.sh`
- `run-backend.sh`
- `run-frontend.sh`
- `validate.sh`
- `LICENSE`

## Exclude

- `.env`
- `backend/.venv/`
- `frontend/node_modules/`
- `frontend/dist/`
- `node_modules/`
- `__pycache__/`
- `.pytest_cache/`
- `.npm-cache/`
- `.pip-cache/`
- `*.log`
- `*.pcap`
- `*.pcapng`
- `*.sqlite`
- `.DS_Store`

## Final Check

Unzip the package into a clean folder and run:

```bash
./setup.sh
cp .env.example .env
./validate.sh
```
