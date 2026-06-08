export function InvestigationView({ investigation }) {
  if (!investigation) {
    return <section className="panel"><h2>Investigation View</h2><p>Click Investigate on a Wazuh alert to run the SOC workflow.</p></section>;
  }

  return (
    <section className="investigation-layout">
      <section className="panel score-panel">
        <span>Verdict</span>
        <strong>{investigation.verdict}</strong>
        <div className="score">{investigation.risk.score}</div>
        <p>{investigation.confidence_label || "Medium"} confidence - {investigation.classification || "Unknown"} - {investigation.risk.priority}</p>
        <p>Alert type: {investigation.alert_type || "Unknown"}</p>
      </section>

      <section className="panel narrative-panel">
        <h2>AI Analyst Narrative</h2>
        <pre>{investigation.analyst_narrative}</pre>
      </section>

      <section className="panel">
        <h2>Classification Reasoning</h2>
        {investigation.reasoning && Object.entries(investigation.reasoning).map(([section, items]) => (
          <div className="reasoning-section" key={section}>
            <b>{section.replace("_", " ")}</b>
            {items.length ? items.map((item) => <p key={item}>- {item}</p>) : <p>- None recorded.</p>}
          </div>
        ))}
      </section>

      <section className="panel">
        <h2>SOC Workflow</h2>
        <div className="workflow">
          {investigation.workflow_steps.map((step) => (
            <div key={step.step}>
              <b>{step.step}</b>
              <p>{step.summary}</p>
            </div>
          ))}
        </div>
      </section>

      <section className="panel">
        <h2>Attack Chain Reconstruction</h2>
        <div className="attack-chain-visual">
          {(investigation.attack_chain || []).map((event, index) => (
            <div className="attack-stage" key={`${event.alert_id}-${event.event}`}>
              <div className="stage-number">Event {event.event}</div>
              <b>{event.stage}</b>
              <p>{event.summary}</p>
              <span>{event.timestamp ? new Date(event.timestamp).toLocaleString() : "-"} - rule {event.rule_id || "-"}</span>
              {index < investigation.attack_chain.length - 1 && <div className="chain-arrow">↓</div>}
            </div>
          ))}
        </div>
      </section>

      <section className="panel">
        <h2>Timeline Reconstruction</h2>
        {investigation.timeline.map((event) => (
          <div className="timeline-item" key={`${event.alert_id}-${event.timestamp}`}>
            <time>{event.timestamp ? new Date(event.timestamp).toLocaleString() : "-"}</time>
            <b>{event.agent_name || "unknown"} - rule {event.rule_id || "-"}</b>
            <p>{event.summary}</p>
          </div>
        ))}
      </section>

      <section className="panel">
        <h2>MITRE ATT&CK Intelligence</h2>
        <div className="mitre-list">
          {investigation.mitre_intelligence?.length ? investigation.mitre_intelligence.map((item) => (
            <div key={`${item.technique_id}-${item.source_rule_id}`}>
              <span>{item.tactic}</span>
              <b>{item.technique_id} {item.technique_name}</b>
              <p>{item.why_mapped}</p>
              <p>{item.analyst_explanation}</p>
            </div>
          )) : <p>No MITRE mapping was present in Wazuh metadata for this alert.</p>}
        </div>
      </section>

      <section className="panel">
        <h2>SOC Investigation Playbook</h2>
        <div className="playbook-grid">
          {Object.entries(investigation.playbook || {}).map(([section, actions]) => (
            <div key={section}>
              <b>{section.replace("_", " ")}</b>
              {actions.map((action) => <p key={action}>- {action}</p>)}
            </div>
          ))}
        </div>
      </section>

      <section className="panel">
        <h2>Risk Factors</h2>
        {investigation.risk.factors.map((factor) => <p key={factor}>- {factor}</p>)}
      </section>

      <section className="panel">
        <h2>Wazuh Active Response Recommendations</h2>
        <p>Recommendations only. Nothing is executed automatically.</p>
        {(investigation.active_response_recommendations || []).map((action) => <p key={action}>- {action}</p>)}
      </section>
    </section>
  );
}
