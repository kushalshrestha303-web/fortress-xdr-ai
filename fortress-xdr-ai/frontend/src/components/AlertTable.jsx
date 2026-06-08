export function AlertTable({ alerts, selectedId, onSelect, onInvestigate }) {
  return (
    <div className="table-wrap">
      <table>
        <thead>
          <tr>
            <th>Time</th>
            <th>Source</th>
            <th>Agent</th>
            <th>Rule</th>
            <th>Level</th>
            <th>Description</th>
            <th>MITRE</th>
            <th>Source IP</th>
            <th>Destination IP</th>
            <th>Signature</th>
            <th>Category</th>
            <th>IDS Severity</th>
            <th>Protocol</th>
            <th></th>
          </tr>
        </thead>
        <tbody>
          {alerts.map((alert) => (
            <tr key={alert.id} className={selectedId === alert.id ? "selected-row" : ""} onClick={() => onSelect(alert)}>
              <td>{formatTime(alert.timestamp)}</td>
              <td>{alert.alert_source || "Wazuh"}</td>
              <td>{alert.agent_name || "unknown"}</td>
              <td>{alert.rule_id || "-"}</td>
              <td><span className={`level ${levelClass(alert.rule_level)}`}>{alert.rule_level}</span></td>
              <td>{alert.rule_description || "No description"}</td>
              <td>{[...(alert.mitre_tactics || []), ...(alert.mitre_techniques || [])].slice(0, 3).join(", ") || "-"}</td>
              <td>{alert.srcip || "-"}</td>
              <td>{alert.dstip || "-"}</td>
              <td>{alert.suricata_signature || "-"}</td>
              <td>{alert.suricata_category || "-"}</td>
              <td>{alert.suricata_severity || "-"}</td>
              <td>{alert.suricata_protocol || "-"}</td>
              <td>
                <button onClick={(event) => { event.stopPropagation(); onInvestigate(alert); }}>
                  Investigate
                </button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function formatTime(value) {
  if (!value) return "-";
  return new Date(value).toLocaleString();
}

function levelClass(level) {
  if (level >= 12) return "critical";
  if (level >= 10) return "high";
  if (level >= 7) return "medium";
  return "low";
}
