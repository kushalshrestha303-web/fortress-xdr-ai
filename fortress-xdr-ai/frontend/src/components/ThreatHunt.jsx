const presets = [
  "Show high severity alerts from last 24 hours",
  "Show authentication failures",
  "Show privilege escalation",
  "Show Windows PowerShell alerts",
  "Show malware detections",
  "Show Suricata alerts",
  "Show rootcheck warnings",
  "Show syscheck file integrity alerts",
  "MITRE ATT&CK tactic search: Privilege Escalation",
];

export function ThreatHunt({ query, setQuery, onHunt, results, loading, onInvestigate }) {
  return (
    <section className="panel">
      <h2>Threat Hunt</h2>
      <div className="hunt-box">
        <input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search Wazuh alerts using a preset or query string" />
        <button className="primary" onClick={() => onHunt(query)} disabled={loading}>Hunt</button>
      </div>
      <div className="preset-grid">
        {presets.map((preset) => (
          <button key={preset} onClick={() => { setQuery(preset); onHunt(preset); }} disabled={loading}>{preset}</button>
        ))}
      </div>
      {results && (
        <div>
          <p>{results.total} alerts from {results.source} for: <b>{results.query}</b></p>
          <div className="hunt-results">
            {results.alerts.map((alert) => (
              <article key={alert.id}>
                <span>Level {alert.rule_level} - {alert.agent_name || "unknown"}</span>
                <b>{alert.rule_description || "No description"}</b>
                <p>Rule {alert.rule_id || "-"} - {(alert.rule_groups || []).join(", ")}</p>
                <p>MITRE: {[...(alert.mitre_tactics || []), ...(alert.mitre_techniques || [])].join(", ") || "-"}</p>
                <button onClick={() => onInvestigate(alert)} disabled={loading}>Investigate Hunt Result</button>
              </article>
            ))}
          </div>
        </div>
      )}
    </section>
  );
}
