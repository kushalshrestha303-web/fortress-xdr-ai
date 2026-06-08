# Demo Script

## 1. Opening

"FORTRESS XDR AI is a real Wazuh-connected SOC analyst. It reads alerts from Wazuh Indexer, including Suricata IDS alerts, and turns raw alerts into investigation output an analyst can use."

## 2. Prove The Integration

Show `.env.example`, then explain that `.env` contains the local Wazuh Indexer URL and credentials.

Run:

```bash
curl http://127.0.0.1:8000/health
```

Point out the source mode and configured alert index.

## 3. Live Alerts

Open:

```text
http://127.0.0.1:5173
```

Show that the dashboard has real alert rows from Wazuh.

## 4. Suricata

Select the `Suricata` filter. Show fields such as source IP, destination IP, signature, category, IDS severity, and protocol.

Use rule `86601` if it is present:

```text
Suricata: Alert - GPL ATTACK_RESPONSE id check returned root
```

## 5. Investigation

Click `Investigate`.

Explain:

- The alert is classified by type first.
- Network IDS alerts are not mixed with unrelated sudo/login alerts.
- The timeline and recommendations are generated from real Wazuh evidence.

## 6. Report

Open `Reports` and show the executive summary, business impact, affected assets, severity, and recommended actions.

## 7. Close

"The key difference is that FORTRESS XDR AI is not just a log viewer. It connects to Wazuh, understands alert type, correlates evidence, and writes an analyst-ready investigation."
