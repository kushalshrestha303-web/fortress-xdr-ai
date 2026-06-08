# Architecture

FORTRESS XDR AI is a two-service application.

## Backend

The backend is a FastAPI service in `backend/`.

- `main.py` exposes the API routes.
- `wazuh_client.py` connects to Wazuh Indexer/OpenSearch.
- `investigation_engine.py` creates alert classification, timelines, playbooks, and reports.
- `models.py` defines the response models used by the frontend.

The backend reads Wazuh connection settings from `.env`.

## Frontend

The frontend is a React app in `frontend/`.

- `src/App.jsx` owns page state and dashboard flow.
- `src/api.js` calls the backend.
- `src/components/` contains alert tables, details, investigations, hunts, reports, and metrics.

The frontend never receives Wazuh credentials.

## Data Flow

```text
Suricata -> eve.json -> Wazuh Manager -> Wazuh Indexer -> FastAPI -> React
Endpoint logs -> Wazuh Agent/Manager -> Wazuh Indexer -> FastAPI -> React
```

## Security Boundary

- Credentials stay in `.env` on the backend host.
- The frontend talks only to FastAPI.
- Active response actions are recommendations only; no endpoint action is executed by this app.
