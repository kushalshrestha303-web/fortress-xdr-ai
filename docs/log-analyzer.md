# AI Log Attack Analyzer

Route: `/security/log-analyzer`

Backend APIs:

- `POST /api/security/logs/upload`
- `POST /api/security/logs/analyze`
- `GET /api/security/reports/{id}`
- `GET /api/security/reports/{id}/export/pdf`
- `GET /api/security/reports/{id}/export/csv`
- `GET /api/security/reports/{id}/export/diagram.svg`

The analyzer accepts `.log`, `.txt`, `.csv`, `.json`, `.xlsx`, and safely stores `.pcapng` uploads. Binary packet decoding is intentionally not executed in-process; add a sandboxed worker with tshark/scapy for full pcapng parsing.

Security controls:

- File extensions and 8 MiB size limit are enforced.
- Uploaded files are never executed.
- Log content is sanitized before rendering.
- Upload paths are generated server-side.
- Simple per-client rate limiting and audit logging are included.

Sample logs live in `services/api/sample-logs`.
