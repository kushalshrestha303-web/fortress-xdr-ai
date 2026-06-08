# Architecture Overview - Fortress XDR AI

## System Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              DATA SOURCES                                    │
├──────────────┬──────────────┬──────────────┬──────────────┬─────────────────┤
│   Wazuh      │   Sysmon     │   Windows    │  Suricata    │  Threat Intel   │
│   SIEM       │   Events     │   Event Logs │  IDS/IPS     │  Sources        │
└──────┬───────┴──────┬───────┴──────┬───────┴──────┬───────┴────────┬────────┘
       │              │              │              │                │
       └──────────────┼──────────────┼──────────────┼────────────────┘
                      │
                      ▼
        ┌─────────────────────────────────────┐
        │    Data Ingestion & Normalization   │
        │  • Event parsing                    │
        │  • Format standardization           │
        │  • Timestamp normalization          │
        │  • Field mapping                    │
        └────────────┬────────────────────────┘
                     │
                     ▼
        ┌─────────────────────────────────────┐
        │      OpenSearch / PostgreSQL        │
        │  • Raw event storage               │
        │  • Alert indexing                  │
        │  • Time-series data                │
        └────────────┬────────────────────────┘
                     │
        ┌────────────┴──────────────┐
        │                           │
        ▼                           ▼
┌───────────────────┐      ┌───────────────────┐
│  Correlation      │      │  Detection        │
│  Engine           │      │  Engine           │
│                   │      │                   │
│ • Event           │      │ • Signature rules │
│   correlation     │      │ • Anomaly detect  │
│ • Pattern         │      │ • Behavior anal.  │
│   matching        │      │ • Threshold trig. │
│ • Attack chains   │      │ • ML models       │
└─────────┬─────────┘      └─────────┬─────────┘
          │                         │
          └────────────┬────────────┘
                       │
                       ▼
        ┌─────────────────────────────────────┐
        │    Alert & Incident Management      │
        │  • Alert deduplication              │
        │  • Risk scoring                     │
        │  • MITRE mapping                    │
        │  • Incident creation                │
        └────────────┬────────────────────────┘
                     │
        ┌────────────┴──────────────┐
        │                           │
        ▼                           ▼
┌───────────────────┐      ┌───────────────────┐
│  AI Analysis      │      │  Investigation    │
│  Engine           │      │  Module           │
│                   │      │                   │
│ • ChatGPT API     │      │ • Timeline gen    │
│ • Ollama (local)  │      │ • Correlation     │
│ • Prompt craft    │      │ • Evidence link   │
│ • Context build   │      │ • Impact assess   │
└──────────────────┘      └──────────────────┘
        │                         │
        └────────────┬────────────┘
                     │
                     ▼
        ┌─────────────────────────────────────┐
        │      Reporting & Response           │
        │  • Report generation                │
        │  • Active response                  │
        │  • Playbook execution               │
        │  • Compliance export                │
        └────────────┬────────────────────────┘
                     │
                     ▼
        ┌─────────────────────────────────────┐
        │      Frontend Dashboard             │
        │  • React/Next.js UI                 │
        │  • Real-time updates                │
        │  • Investigation console            │
        │  • Reporting interface              │
        └─────────────────────────────────────┘
```

## Component Breakdown

### Data Ingestion
- Wazuh Connector: OpenSearch API integration
- Sysmon Connector: Windows Event Log parsing
- Suricata Connector: IDS alert ingestion
- Threat Intel Connector: VirusTotal, custom feeds

### Processing
- Correlation Engine: Event linking and pattern matching
- Detection Engine: Rule and model-based detection
- Alert Manager: Deduplication and scoring

### Analysis
- AI Engine: OpenAI/Ollama integration
- Investigation Module: Timeline generation
- Report Generator: Multi-format report creation

### Presentation
- React Dashboard: Real-time visualization
- Investigation Console: Interactive analysis
- Reporting Interface: Custom report builder
