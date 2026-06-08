import { useCallback, useEffect, useMemo, useState } from "react";
import { api } from "./api.js";
import { AlertDetail } from "./components/AlertDetail.jsx";
import { AlertTable } from "./components/AlertTable.jsx";
import { InvestigationView } from "./components/InvestigationView.jsx";
import { MetricCard } from "./components/MetricCard.jsx";
import { Reports } from "./components/Reports.jsx";
import { ThreatHunt } from "./components/ThreatHunt.jsx";

const pages = ["Live Alerts", "Alert Detail", "Investigation View", "Threat Hunt", "Reports"];
const REFRESH_INTERVAL_MS = 10000;

export default function App() {
  const [page, setPage] = useState("Live Alerts");
  const [health, setHealth] = useState(null);
  const [alerts, setAlerts] = useState([]);
  const [selectedAlert, setSelectedAlert] = useState(null);
  const [investigation, setInvestigation] = useState(null);
  const [huntQuery, setHuntQuery] = useState("Show high severity alerts from last 24 hours");
  const [huntResults, setHuntResults] = useState(null);
  const [suricataCount, setSuricataCount] = useState(0);
  const [search, setSearch] = useState("");
  const [sourceFilter, setSourceFilter] = useState("All Alerts");
  const [agentFilter, setAgentFilter] = useState("all");
  const [levelFilter, setLevelFilter] = useState("all");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [lastUpdated, setLastUpdated] = useState(null);

  const load = useCallback(async ({ showLoading = false } = {}) => {
    if (showLoading) setLoading(true);
    setError("");
    try {
      const activeQuery = search.trim();
      const alertRequest = activeQuery
        ? api.searchAlerts(activeQuery)
        : sourceFilter === "Suricata"
          ? api.suricataAlerts()
          : api.recentAlerts();
      const [healthResult, alertResult, suricataResult] = await Promise.all([api.health(), alertRequest, api.suricataAlerts()]);
      setHealth(healthResult);
      setAlerts(alertResult.alerts || []);
      setSuricataCount(suricataResult.total || 0);
      setSelectedAlert((current) => {
        if (current && alertResult.alerts?.some((alert) => alert.id === current.id)) return current;
        return alertResult.alerts?.[0] || current;
      });
      setLastUpdated(new Date());
    } catch (err) {
      setError(err.message);
    } finally {
      if (showLoading) setLoading(false);
    }
  }, [search, sourceFilter]);

  useEffect(() => {
    load();
    const timer = window.setInterval(() => load(), REFRESH_INTERVAL_MS);
    return () => window.clearInterval(timer);
  }, [load]);

  async function runSearch() {
    setLoading(true);
    setError("");
    try {
      const result = search.trim() ? await api.searchAlerts(search.trim()) : await api.recentAlerts();
      setAlerts(result.alerts || []);
      setLastUpdated(new Date());
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }

  async function changeSourceFilter(value) {
    setSourceFilter(value);
    setLoading(true);
    setError("");
    try {
      if (value === "Suricata") {
        const result = await api.suricataAlerts();
        setAlerts(result.alerts || []);
        setSuricataCount(result.total || 0);
      } else if (sourceFilter === "Suricata") {
        const result = await api.recentAlerts();
        setAlerts(result.alerts || []);
      }
      setLastUpdated(new Date());
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }

  async function investigate(alert) {
    setLoading(true);
    setError("");
    setSelectedAlert(alert);
    try {
      const result = await api.investigate(alert.id);
      setInvestigation(result);
      setPage("Investigation View");
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }

  async function hunt(query) {
    setLoading(true);
    setError("");
    try {
      const result = await api.hunt({ preset: query, size: 50 });
      setHuntResults(result);
      setPage("Threat Hunt");
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }

  const agents = useMemo(() => Array.from(new Set(alerts.map((alert) => alert.agent_name).filter(Boolean))), [alerts]);
  const filteredAlerts = alerts.filter((alert) => {
    const sourceOk = sourceFilter === "All Alerts" || alert.alert_source === sourceFilter;
    const agentOk = agentFilter === "all" || alert.agent_name === agentFilter;
    const levelOk = levelFilter === "all" || alert.rule_level >= Number(levelFilter);
    return sourceOk && agentOk && levelOk;
  });

  return (
    <main>
      <header className="topbar">
        <div>
          <p className="eyebrow">Real Wazuh-connected SOC AI agent</p>
          <h1>FORTRESS XDR AI</h1>
        </div>
        <div className={`status ${health?.status || "unknown"}`}>
          {health ? `${health.status} - ${health.mode}` : "connecting"}
        </div>
      </header>

      <nav className="tabs">
        {pages.map((name) => (
          <button key={name} className={page === name ? "active" : ""} onClick={() => setPage(name)}>{name}</button>
        ))}
      </nav>

      {error && <div className="error">{error}</div>}
      {health?.status === "error" && (
        <section className="connection-banner">
          <h2>Wazuh Indexer is not reachable yet</h2>
          <p>
            Keep this dashboard open at <b>http://127.0.0.1:5173</b>. Do not browse to <b>https://localhost:9200</b> unless
            your Wazuh Indexer is actually installed on this Windows machine.
          </p>
          <div className="connection-grid">
            <div>
              <span>Configured Indexer</span>
              <b>{health.indexer_url}</b>
            </div>
            <div>
              <span>Alert Index</span>
              <b>{health.alert_index}</b>
            </div>
          </div>
          <pre>{health.warning}</pre>
        </section>
      )}

      {page === "Live Alerts" && (
        <section className="page-stack">
          <section className="metrics">
            <MetricCard label="Wazuh source" value={health?.mode || "unknown"} detail={health?.indexer_url || "Indexer not checked yet"} />
            <MetricCard label="Recent alerts" value={alerts.length} detail="Latest alerts from Wazuh Indexer" />
            <MetricCard label="High severity" value={alerts.filter((alert) => alert.rule_level >= 10).length} detail="Rule level >= 10" />
            <MetricCard label="Suricata alerts" value={suricataCount} detail="rule.groups contains suricata or description contains Suricata" />
            <MetricCard label="Selected agent" value={selectedAlert?.agent_name || "-"} detail={selectedAlert?.rule_description || "No alert selected"} />
          </section>

          <section className="panel">
            <div className="panel-heading">
              <h2>Live Alerts</h2>
              <div className="button-row">
                {lastUpdated && <span className="sync-status">Auto-refresh every 10s - last sync {lastUpdated.toLocaleTimeString()}</span>}
                <button onClick={() => load({ showLoading: true })} disabled={loading}>Refresh</button>
              </div>
            </div>
            <div className="filters">
              <input value={search} onChange={(event) => setSearch(event.target.value)} placeholder="Search agent, rule, MITRE, decoder, full log" />
              <button onClick={runSearch} disabled={loading}>Search</button>
              <select value={sourceFilter} onChange={(event) => changeSourceFilter(event.target.value)}>
                <option>All Alerts</option>
                <option>Wazuh</option>
                <option>Suricata</option>
                <option>Authentication</option>
                <option>Syscheck</option>
                <option>Rootcheck</option>
              </select>
              <select value={agentFilter} onChange={(event) => setAgentFilter(event.target.value)}>
                <option value="all">All agents</option>
                {agents.map((agent) => <option key={agent} value={agent}>{agent}</option>)}
              </select>
              <select value={levelFilter} onChange={(event) => setLevelFilter(event.target.value)}>
                <option value="all">All levels</option>
                <option value="7">Level 7+</option>
                <option value="10">Level 10+</option>
                <option value="12">Level 12+</option>
              </select>
            </div>
            <AlertTable alerts={filteredAlerts} selectedId={selectedAlert?.id} onSelect={(alert) => { setSelectedAlert(alert); setPage("Alert Detail"); }} onInvestigate={investigate} />
          </section>
        </section>
      )}

      {page === "Alert Detail" && <AlertDetail alert={selectedAlert} onInvestigate={investigate} />}
      {page === "Investigation View" && <InvestigationView investigation={investigation} />}
      {page === "Threat Hunt" && <ThreatHunt query={huntQuery} setQuery={setHuntQuery} onHunt={hunt} results={huntResults} loading={loading} onInvestigate={investigate} />}
      {page === "Reports" && <Reports investigation={investigation} />}
    </main>
  );
}
