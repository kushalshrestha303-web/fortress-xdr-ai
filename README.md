```text
███████╗ ██████╗ ██████╗ ████████╗██████╗ ███████╗███████╗███████╗
██╔════╝██╔═══██╗██╔══██╗╚══██╔══╝██╔══██╗██╔════╝██╔════╝██╔════╝
█████╗  ██║   ██║██████╔╝   ██║   ██████╔╝█████╗  ███████╗███████╗
██╔══╝  ██║   ██║██╔══██╗   ██║   ██╔══██╗██╔══╝  ╚════██║╚════██║
██║     ╚██████╔╝██║  ██║   ██║   ██║  ██║███████╗███████║███████║
╚═╝      ╚═════╝ ╚═╝  ╚═╝   ╚═╝   ╚═╝  ╚═╝╚══════╝╚══════╝╚══════╝

██╗  ██╗██████╗ ██████╗      █████╗ ██╗
╚██╗██╔╝██╔══██╗██╔══██╗    ██╔══██╗██║
 ╚███╔╝ ██║  ██║██████╔╝    ███████║██║
 ██╔██╗ ██║  ██║██╔══██╗    ██╔══██║██║
██╔╝ ██╗██████╔╝██║  ██║    ██║  ██║██║
╚═╝  ╚═╝╚═════╝ ╚═╝  ╚═╝    ╚═╝  ╚═╝╚═╝

AI-Powered Security Operations Center
```

# FORTRESS XDR AI

> Real-Time Threat Detection • AI Investigation • Wazuh SIEM • Suricata IDS • MITRE ATT&CK Mapping




**AI-powered SOC assistant for real Wazuh and Suricata alerts.**

FORTRESS XDR AI turns raw security alerts into clear investigations, risk scores, recommendations, and executive reports.

---

## What It Does

```text
┌───────────────┐
│ Windows Host │
└───────┬───────┘
        │
        ▼
┌───────────────┐
│ Network Traffic │
└───────┬───────┘
        │
        ▼
┌───────────────┐
│ Suricata IDS │
└───────┬───────┘
        │
        ▼
┌───────────────┐
│  Wazuh SIEM  │
└───────┬───────┘
        │
        ▼
┌────────────────────┐
│  FORTRESS XDR AI   │
├────────────────────┤
│ AI Investigation   │
│ MITRE Mapping      │
│ Risk Scoring       │
│ Recommendations    │
│ Executive Report   │
└─────────┬──────────┘
          │
          ▼
     SOC Analyst
```


---

## Main Features

| Feature              | Description                                      |
| -------------------- | ------------------------------------------------ |
| Wazuh Integration    | Pulls real alerts from Wazuh Indexer             |
| Suricata Integration | Shows real IDS network alerts                    |
| AI Investigation     | Explains what happened and why                   |
| Risk Scoring         | Classifies alert severity                        |
| SOC Recommendations  | Gives analyst next steps                         |
| Executive Report     | Converts technical alerts into business language |

---

## Requirements

Install these first:

* Python 3.11+
* Node.js 20+
* Wazuh
* Suricata
* Git

---

# How To Run

## 1. Start Security Services on Kali

```bash
sudo systemctl start wazuh-manager
sudo systemctl start wazuh-indexer
sudo systemctl start wazuh-dashboard
sudo systemctl start suricata
```

Check they are running:

```bash
sudo systemctl status wazuh-manager
sudo systemctl status wazuh-indexer
sudo systemctl status suricata
```

You should see:

```text
active (running)
```

---

## 2. Start Backend on Windows

Open PowerShell:

```powershell
cd "C:\Users\kusha\Documents\New project\fortress-xdr-ai\backend"
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
uvicorn main:app --reload --host 127.0.0.1 --port 8000



Backend runs at:

```text
http://127.0.0.1:8000
```

---

## 3. Start Frontend on Windows

Open another PowerShell:

```powershell
cd "C:\Users\kusha\Documents\New project\fortress-xdr-ai\frontend"
npm install
npm run dev
```

Open:

```text
http://127.0.0.1:5173
```

---

# How To Test

## Step 1: Open Dashboard

Look for:

```text
OK - INDEXER
```

That means the app can reach Wazuh Indexer.

---

## Step 2: Generate Safe Test Traffic

Run this on Kali:

```bash
curl http://testmynids.org/uid/index.html
```

This should generate a Suricata alert.

---

## Step 3: Refresh Dashboard

You should see a new alert like:

```text
Source: Suricata
Rule: 86601
Signature: GPL ATTACK_RESPONSE id check returned root
Category: Potentially Bad Traffic
Protocol: TCP
```

---

## Step 4: Investigate

Click:

```text
Investigate
```

The AI should show:

```text
Alert Type
Evidence
Reasoning
Risk Score
SOC Recommendations
Final Classification
```

---

# Demo Flow

Use this flow for hackathon judging:

```text
1. Open dashboard
2. Show OK - INDEXER
3. Generate Suricata test alert
4. Refresh dashboard
5. Open new Suricata alert
6. Click Investigate
7. Show AI reasoning
8. Show SOC recommendations
9. Show executive report
```

---

# Troubleshooting

## Frontend says "Failed to fetch"

Start backend again:

```powershell
cd "C:\Users\kusha\Documents\New project\fortress-xdr-ai\backend"
.\.venv\Scripts\Activate.ps1
uvicorn main:app --reload --host 127.0.0.1 --port 8000
```

---

## No Suricata alerts

Restart Suricata and Wazuh:

```bash
sudo systemctl restart suricata
sudo systemctl restart wazuh-manager
```

Check alert file:

```bash
sudo tail -5 /var/log/suricata/eve-alerts.json
```

---

## No Wazuh data

Restart Wazuh Indexer:

```bash
sudo systemctl restart wazuh-indexer
```

---

## NPM does not run in PowerShell

Use:

```powershell
npm.cmd install
npm.cmd run dev
```

---

# Project Value

Traditional SIEM tools show alerts.

FORTRESS XDR AI goes further:

```text
Alert
  ↓
Investigation
  ↓
Reasoning
  ↓
Recommendations
  ↓
Report
```

This helps junior SOC analysts understand alerts faster and respond with confidence.
