# FORTRESS XDR AI

FORTRESS XDR AI is a real Wazuh-connected SOC analyst dashboard. It pulls alerts from Wazuh Indexer/OpenSearch, shows live Wazuh and Suricata events, and lets an analyst investigate alerts with evidence-based classification, attack-chain reconstruction, MITRE context, risk scoring, and reports.

This release does not depend on fake alert feeds. The main workflow reads real Wazuh alerts from `wazuh-alerts-*`.

## Architecture

- Wazuh Manager collects endpoint and integration logs.
- Suricata writes IDS events to `eve.json`.
- Wazuh ingests Suricata events and stores alerts in Wazuh Indexer.
- FastAPI backend queries Wazuh Indexer and runs investigation logic.
- React frontend displays alerts, investigation results, hunts, and reports.

## Requirements

- Kali Linux or another Linux host with Wazuh installed.
- Wazuh Indexer reachable on port `9200`.
- Suricata installed if you want network IDS alerts.
- Python 3.10+.
- Node.js 18+ and npm.
- VS Code.

## Open In VS Code

```bash
cd fortress-xdr-ai
code .
```

Open two terminals in VS Code: one for the backend and one for the frontend.

## Configure Environment

```bash
cp .env.example .env
nano .env
```

Example:

```env
WAZUH_INDEXER_URL=https://192.168.1.3:9200
WAZUH_INDEXER_USER=admin
WAZUH_INDEXER_PASSWORD=your_real_password
WAZUH_ALERT_INDEX=wazuh-alerts-*
VERIFY_SSL=false
BACKEND_PORT=8000
```

Never commit `.env`.

## Start Wazuh

On the Wazuh server:

```bash
sudo systemctl status wazuh-manager
sudo systemctl status wazuh-indexer
sudo systemctl start wazuh-manager
sudo systemctl start wazuh-indexer
```

Check Indexer access:

```bash
curl -k -u admin:your_real_password https://localhost:9200
```

## Start Suricata

```bash
sudo systemctl status suricata
sudo systemctl start suricata
sudo tail -f /var/log/suricata/eve.json
```

Make sure Wazuh is configured to read Suricata `eve.json`.

## Install Project

```bash
chmod +x setup.sh run-backend.sh run-frontend.sh validate.sh
./setup.sh
```

## Start Backend

```bash
./run-backend.sh
```

Health check:

```bash
curl http://127.0.0.1:8000/health
```

## Start Frontend

In a second terminal:

```bash
./run-frontend.sh
```

Open:

```text
http://127.0.0.1:5173
```

## Generate A Safe Suricata Test Alert

From another machine on the same network, request the EICAR test string over HTTP from the monitored Kali host, or run a controlled IDS test rule in a lab network. Do not run exploit traffic on networks you do not own.

For the existing GPL test alert shown in this project, verify Wazuh contains rule `86601`:

```bash
curl -k -u admin:your_real_password \
  "https://localhost:9200/wazuh-alerts-*/_search?q=rule.id:86601&pretty"
```

## Verify Alert Flow

1. Confirm Suricata writes to `/var/log/suricata/eve.json`.
2. Confirm Wazuh reads the Suricata log.
3. Confirm Wazuh Indexer has `rule.id:86601` or `rule.groups:suricata`.
4. Open the dashboard and check the Suricata counter.
5. Choose the `Suricata` filter.
6. Click `Investigate` on a Suricata alert.

## Troubleshooting

See [TROUBLESHOOTING.md](TROUBLESHOOTING.md).

## Demo Script For Judges

1. Show `.env.example` and explain credentials live only in `.env`.
2. Run backend health check.
3. Open Live Alerts and show real Wazuh alerts.
4. Select the `Suricata` filter and show rule `86601`.
5. Click `Investigate`.
6. Walk through classification, evidence, MITRE, timeline, recommendations, and reports.
7. Explain that the app does not execute active response automatically. It recommends analyst-reviewed actions.

## Validate Before Release

```bash
./validate.sh
```
