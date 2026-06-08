export function AlertDetail({ alert, onInvestigate }) {
  if (!alert) {
    return <section className="panel"><h2>Alert Detail</h2><p>Select a real Wazuh alert to inspect it.</p></section>;
  }

  const fields = [
    ["Timestamp", alert.timestamp],
    ["Agent name", alert.agent_name],
    ["Manager name", alert.manager_name],
    ["Rule ID", alert.rule_id],
    ["Rule level", alert.rule_level],
    ["Rule description", alert.rule_description],
    ["Decoder", alert.decoder_name],
    ["Source IP", alert.srcip],
    ["Destination IP", alert.dstip],
    ["User", alert.user_name],
    ["MITRE tactic", (alert.mitre_tactics || []).join(", ")],
    ["MITRE technique", (alert.mitre_techniques || []).join(", ")],
  ];

  return (
    <section className="panel detail">
      <div className="panel-heading">
        <h2>Alert Detail</h2>
        <button className="primary" onClick={() => onInvestigate(alert)}>Investigate</button>
      </div>
      <div className="field-grid">
        {fields.map(([label, value]) => (
          <div key={label}>
            <span>{label}</span>
            <b>{value || "-"}</b>
          </div>
        ))}
      </div>
      <h3>Full Log</h3>
      <pre>{alert.full_log || "No full_log field present on this alert."}</pre>
      <h3>Raw Wazuh JSON</h3>
      <pre>{JSON.stringify(alert.raw || alert, null, 2)}</pre>
    </section>
  );
}
