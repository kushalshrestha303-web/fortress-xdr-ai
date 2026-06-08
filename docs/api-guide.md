# API Documentation - Fortress XDR AI

## Authentication

All API endpoints require JWT authentication.

```bash
curl -H "Authorization: Bearer YOUR_JWT_TOKEN" http://localhost:8000/api/v1/alerts
```

## Endpoints

### Alerts

#### List Alerts
```
GET /api/v1/alerts?skip=0&limit=50&severity=critical&source=wazuh
```

Response:
```json
{
  "alerts": [
    {
      "id": "alert_001",
      "timestamp": "2026-06-08T10:30:00Z",
      "severity": "critical",
      "source": "wazuh",
      "message": "Brute Force Attack Detected"
    }
  ],
  "total": 1247
}
```

### Incidents

#### Create Incident
```
POST /api/v1/incidents

Body:
{
  "title": "Brute Force Attack",
  "description": "Multiple failed login attempts",
  "severity": "critical"
}
```

### Threat Hunting

#### Execute Hunt
```
POST /api/v1/hunts/execute

Body:
{
  "query_type": "kql",
  "query": "process.name: powershell AND command_line: *DownloadString*",
  "timeframe": "24h"
}
```

### AI Analysis

#### Analyze Alert
```
POST /api/v1/ai/analyze-alert

Body:
{
  "alert_id": "alert_001",
  "include_mitre": true,
  "include_recommendations": true
}
```

### Reporting

#### Generate Report
```
POST /api/v1/reports/generate

Body:
{
  "report_type": "incident",
  "incident_id": "inc_001"
}
```
