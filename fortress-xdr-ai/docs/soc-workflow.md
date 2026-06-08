# SOC Workflow

When an analyst clicks `Investigate`, the backend follows this workflow:

1. Determine alert type.
2. Extract evidence from the selected alert.
3. Correlate relevant alerts by agent, user, source IP, destination IP, hostname, groups, and MITRE tactic.
4. Reconstruct a timeline.
5. Map MITRE data already present in Wazuh.
6. Score risk.
7. Classify the alert as benign, informational, suspicious, malicious, or unknown.
8. Generate reasoning and confidence.
9. Recommend containment, eradication, recovery, and hunt actions.
10. Produce analyst and executive summaries.

## Network IDS Handling

Suricata alerts are treated as Network IDS events. They correlate with network events and shared IP indicators, not unrelated sudo or login activity. This prevents IDS alerts such as rule `86601` from being classified as normal administrative behavior.

## Analyst Review

The platform recommends response actions but does not execute them. This keeps containment decisions under human control.
