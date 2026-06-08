"use client";

import { useEffect, useMemo, useState } from "react";
import type { ReactNode } from "react";
import {
  Activity,
  AlertTriangle,
  Brain,
  CheckCircle2,
  Clock,
  FileSearch,
  Flame,
  GitBranch,
  Lock,
  Mail,
  Network,
  PlayCircle,
  RadioTower,
  Send,
  ServerCog,
  ShieldAlert,
  UserCheck,
  Workflow
} from "lucide-react";
import { Bar, BarChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";

import { LogAnalyzer } from "@/components/log-analyzer";
import { PlaybookDesigner } from "@/components/playbooks/PlaybookDesigner";
import { decidePlaybookRun, fetchRecentNgfwLogs, runHighRiskPlaybook, streamUrl, submitNgfwLog } from "@/lib/api";
import type { LiveEvent, NgfwLog, PlaybookRunResult, PlaybookTask, Sector } from "@/lib/types";

const sectors: Sector[] = ["government", "bank", "hospital", "telecom", "critical-infrastructure", "enterprise"];

export function CommandCenter() {
  const [ngfwLogs, setNgfwLogs] = useState<NgfwLog[]>([]);
  const [events, setEvents] = useState<LiveEvent[]>([]);
  const [connection, setConnection] = useState("connecting");
  const [workspace, setWorkspace] = useState<"overview" | "ngfw" | "playbooks" | "architecture" | "logAnalyzer">("overview");
  const [operator, setOperator] = useState("kushal@fortress.local");
  const [notifyEmail, setNotifyEmail] = useState("xitizsthax@gmail.com");
  const [runState, setRunState] = useState("ready");
  const [ingestState, setIngestState] = useState("ready");
  const [activeRunId, setActiveRunId] = useState<string | null>(null);
  const [activeRun, setActiveRun] = useState<PlaybookRunResult | null>(null);

  useEffect(() => {
    fetchRecentNgfwLogs().then(setNgfwLogs);
    const socket = new WebSocket(streamUrl());
    socket.onopen = () => setConnection("live");
    socket.onclose = () => setConnection("offline");
    socket.onerror = () => setConnection("error");
    socket.onmessage = (message) => {
      const event = JSON.parse(message.data) as LiveEvent;
      setEvents((current) => [event, ...current].slice(0, 80));
      if ("sensor_id" in event && event.sensor_id) {
        setNgfwLogs((current) => [event as NgfwLog, ...current].slice(0, 200));
      }
    };
    return () => socket.close();
  }, []);

  const sectorRisk = useMemo(() => {
    return sectors.map((sector) => {
      const sectorLogs = ngfwLogs.filter((log) => log.sector === sector);
      const risk = sectorLogs.length
        ? Math.round(sectorLogs.reduce((sum, log) => sum + (log.risk_score ?? 0), 0) / sectorLogs.length)
        : 0;
      return { sector: sector.replace("-", " "), risk };
    });
  }, [ngfwLogs]);

  const ipsCount = ngfwLogs.filter((log) => log.metrics?.ips_triggered || log.ips?.signature).length;
  const dpiCount = ngfwLogs.filter((log) => log.metrics?.dpi_observed || log.dpi?.payload_sha256 || log.dpi?.tls_sni).length;
  const blockedCount = ngfwLogs.filter((log) => log.action === "blocked" || log.action === "quarantined").length;
  const playbookEvents = events.filter(isPlaybookEvent);

  async function handleNgfwSubmit() {
    setIngestState("sending");
    try {
      await submitNgfwLog({
        tenant_id: "nepal-national-bank",
        sector: "bank",
        sensor_id: "edge-fw-01",
        src_ip: "10.10.4.21",
        dst_ip: "203.0.113.8",
        protocol: "TLS",
        application: "online-banking",
        action: "blocked",
        dpi: {
          tls_sni: "suspicious.example",
          file_type: "exe",
          payload_sha256: "abc"
        },
        ips: {
          signature: "ET MALWARE Possible C2",
          severity: "critical",
          cve: "CVE-2025-0001"
        },
        bytes_in: 9300,
        bytes_out: 512,
        geo: {
          src_country: "NP",
          dst_country: "RU"
        }
      });
      const latest = await fetchRecentNgfwLogs();
      setNgfwLogs(latest);
      setIngestState("accepted");
    } catch {
      setIngestState("failed");
    }
  }

  async function handlePlaybookRun() {
    setRunState("running");
    try {
      const result = await runHighRiskPlaybook({
        tenant_id: "nepal-national-bank",
        incident_id: `INC-${Date.now()}`,
        severity: "critical",
        sector: "bank",
        notify_email: notifyEmail,
        context: {
          operator,
          source: "command-center"
        }
      });
      setActiveRunId(result.run_id);
      setActiveRun(result);
      setRunState("waiting for approval");
    } catch {
      setRunState("failed");
    }
  }

  async function handlePlaybookDecision(decision: "approved" | "rejected") {
    if (!activeRunId) {
      setRunState("run playbook first");
      return;
    }
    setRunState(decision === "approved" ? "approving" : "rejecting");
    try {
      const result = await decidePlaybookRun(activeRunId, {
        approver: operator,
        decision,
        comment: decision === "approved" ? "SOC lead approved containment from command center." : "Rejected from command center and escalated."
      });
      setActiveRun(result);
      setRunState(decision === "approved" ? "approved containment" : "rejected and escalated");
    } catch {
      setRunState("decision failed");
    }
  }

  return (
    <main className="min-h-screen bg-fortress-bg">
      <section className="border-b border-fortress-line bg-[#0b1017]">
        <div className="mx-auto flex max-w-7xl flex-col gap-4 px-6 py-5 lg:flex-row lg:items-center lg:justify-between">
          <div>
            <p className="text-sm uppercase text-fortress-cyan">Nepal Fortress ONE</p>
            <h1 className="mt-1 text-3xl font-semibold tracking-normal text-white">National Cyber Defense Command Center</h1>
          </div>
          <div className="flex flex-wrap items-center gap-3">
            <div className="flex items-center gap-3 rounded border border-fortress-line px-4 py-2 text-sm">
              <Lock className="h-4 w-4 text-fortress-green" />
              <input
                aria-label="Operator identity"
                className="w-48 bg-transparent text-white outline-none"
                value={operator}
                onChange={(event) => setOperator(event.target.value)}
              />
            </div>
            <div className="flex items-center gap-3 rounded border border-fortress-line px-4 py-2 text-sm">
              <RadioTower className="h-4 w-4 text-fortress-cyan" />
              <span className={connection === "live" ? "text-fortress-green" : "text-fortress-amber"}>{connection}</span>
            </div>
          </div>
        </div>
      </section>

      <nav className="border-b border-fortress-line bg-[#080c12]">
        <div className="mx-auto flex max-w-7xl gap-2 overflow-x-auto px-6 py-3">
          <NavButton active={workspace === "overview"} icon={<Activity />} label="Operations" onClick={() => setWorkspace("overview")} />
          <NavButton active={workspace === "ngfw"} icon={<Flame />} label="NGFW Logs" onClick={() => setWorkspace("ngfw")} />
          <NavButton active={workspace === "playbooks"} icon={<Workflow />} label="Playbooks" onClick={() => setWorkspace("playbooks")} />
          <NavButton active={workspace === "architecture"} icon={<Network />} label="Network" onClick={() => setWorkspace("architecture")} />
          <NavButton active={workspace === "logAnalyzer"} icon={<FileSearch />} label="AI Log Analyzer" onClick={() => setWorkspace("logAnalyzer")} />
        </div>
      </nav>

      <section className="mx-auto grid max-w-7xl grid-cols-1 gap-4 px-6 py-6 lg:grid-cols-4">
        <Metric icon={<ShieldAlert />} label="NGFW Blocks" value={blockedCount} />
        <Metric icon={<Activity />} label="DPI Observations" value={dpiCount} />
        <Metric icon={<Brain />} label="IPS Triggers" value={ipsCount} />
        <Metric icon={<Workflow />} label="Live Events" value={events.length} />
      </section>

      {workspace === "overview" && (
      <section className="mx-auto grid max-w-7xl grid-cols-1 gap-5 px-6 pb-8 xl:grid-cols-[1.2fr_1.8fr]">
        <div className="rounded border border-fortress-line bg-fortress-panel p-5">
          <h2 className="text-lg font-semibold text-white">Sector Risk</h2>
          <div className="mt-4 h-72">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={sectorRisk}>
                <CartesianGrid stroke="#27313f" />
                <XAxis dataKey="sector" tick={{ fill: "#9fb0c2", fontSize: 11 }} />
                <YAxis tick={{ fill: "#9fb0c2", fontSize: 11 }} />
                <Tooltip contentStyle={{ background: "#10151d", border: "1px solid #27313f" }} />
                <Bar dataKey="risk" fill="#36d7d7" radius={[4, 4, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>

        <div className="rounded border border-fortress-line bg-fortress-panel">
          <div className="flex items-center justify-between border-b border-fortress-line px-5 py-4">
            <h2 className="text-lg font-semibold text-white">Next-Generation Firewall Logs</h2>
            <span className="text-sm text-[#9fb0c2]">DPI, app filtering, IPS, sectors</span>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full min-w-[920px] text-left text-sm">
              <thead className="bg-[#0b1017] text-xs uppercase text-[#9fb0c2]">
                <tr>
                  <th className="px-4 py-3">Sector</th>
                  <th className="px-4 py-3">Application</th>
                  <th className="px-4 py-3">Flow</th>
                  <th className="px-4 py-3">DPI</th>
                  <th className="px-4 py-3">IPS</th>
                  <th className="px-4 py-3">Action</th>
                  <th className="px-4 py-3">Risk</th>
                </tr>
              </thead>
              <tbody>
                {ngfwLogs.length === 0 ? (
                  <tr>
                    <td className="px-4 py-8 text-center text-[#9fb0c2]" colSpan={7}>
                      Waiting for real NGFW telemetry from Suricata, Zeek, firewall sensors, or API ingestion.
                    </td>
                  </tr>
                ) : (
                  ngfwLogs.map((log) => (
                    <tr key={log.event_id} className="border-t border-fortress-line">
                      <td className="px-4 py-3 capitalize">{log.sector.replace("-", " ")}</td>
                      <td className="px-4 py-3">{log.application}</td>
                      <td className="px-4 py-3 text-[#9fb0c2]">{log.src_ip} to {log.dst_ip}</td>
                      <td className="px-4 py-3">{log.dpi?.tls_sni || log.dpi?.file_type || log.dpi?.payload_sha256 || "observed"}</td>
                      <td className="px-4 py-3">{log.ips?.signature || "none"}</td>
                      <td className="px-4 py-3">
                        <span className="rounded border border-fortress-line px-2 py-1">{log.action}</span>
                      </td>
                      <td className="px-4 py-3 font-semibold text-fortress-amber">{log.risk_score}</td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>
      </section>
      )}

      {workspace === "ngfw" && (
      <section className="mx-auto grid max-w-7xl grid-cols-1 gap-5 px-6 pb-8 xl:grid-cols-[0.9fr_1.6fr]">
        <div className="rounded border border-fortress-line bg-fortress-panel p-5">
          <h2 className="text-lg font-semibold text-white">Real NGFW Collector</h2>
          <p className="mt-2 text-sm text-[#9fb0c2]">Submit a live security event to the backend ingestion API. In production this same route is fed by Suricata, Zeek, Cisco, Palo Alto, Fortinet, and cloud firewall collectors.</p>
          <div className="mt-5 grid gap-3 text-sm">
            <Field label="Tenant" value="nepal-national-bank" />
            <Field label="Sector" value="bank" />
            <Field label="Sensor" value="edge-fw-01" />
            <Field label="Application" value="online-banking" />
            <Field label="IPS" value="ET MALWARE Possible C2" />
          </div>
          <button
            className="mt-5 flex w-full items-center justify-center gap-2 rounded bg-fortress-cyan px-4 py-3 font-semibold text-[#071016]"
            onClick={handleNgfwSubmit}
          >
            <Send className="h-4 w-4" />
            Send Real NGFW Event
          </button>
          <p className="mt-3 text-sm text-fortress-amber">Collector state: {ingestState}</p>
        </div>
        <NgfwTable logs={ngfwLogs} />
      </section>
      )}

      {workspace === "playbooks" && (
        <PlaybookDesigner
          activeRun={activeRun}
          activeRunId={activeRunId}
          notifyEmail={notifyEmail}
          operator={operator}
          runState={runState}
          setNotifyEmail={setNotifyEmail}
          onApprove={() => handlePlaybookDecision("approved")}
          onReject={() => handlePlaybookDecision("rejected")}
          onRun={handlePlaybookRun}
        />
      )}

      {workspace === "architecture" && (
      <section className="mx-auto max-w-7xl px-6 pb-10">
        <div className="grid grid-cols-1 gap-4 lg:grid-cols-4">
          {[
            ["Government", "Citizen DMZ, ministry WAN, CERT monitoring, identity federation"],
            ["Bank", "Internet edge, payment switch, core banking, HSM/SWIFT enclave"],
            ["Hospital", "EHR, PACS/RIS, medical IoT, emergency services network"],
            ["Telecom", "OSS/BSS, subscriber core, signaling protection, NOC/SOC feed"]
          ].map(([title, body]) => (
            <div className="rounded border border-fortress-line bg-fortress-panel p-5" key={title}>
              <Network className="h-5 w-5 text-fortress-cyan" />
              <h2 className="mt-4 text-lg font-semibold text-white">{title}</h2>
              <p className="mt-2 text-sm text-[#9fb0c2]">{body}</p>
            </div>
          ))}
        </div>
        <div className="mt-5 rounded border border-fortress-line bg-fortress-panel p-5">
          <h2 className="text-lg font-semibold text-white">Real-World Packet Security Flow</h2>
          <div className="mt-5 grid grid-cols-1 gap-3 text-sm md:grid-cols-5">
            {["Cisco Core", "NGFW HA Pair", "Suricata and Zeek", "Kafka Backbone", "SOC + SOAR"].map((stage) => (
              <div className="rounded border border-fortress-line bg-[#0b1017] p-4 text-center" key={stage}>{stage}</div>
            ))}
          </div>
        </div>
      </section>
      )}

      {workspace === "logAnalyzer" && (
        <LogAnalyzer embedded />
      )}

      {workspace === "overview" && (
      <section className="mx-auto max-w-7xl px-6 pb-10">
        <PlaybookActivity events={playbookEvents} />
      </section>
      )}
    </main>
  );
}

function PlaybookWorkspace({
  activeRun,
  activeRunId,
  events,
  notifyEmail,
  operator,
  runState,
  setNotifyEmail,
  onApprove,
  onReject,
  onRun
}: {
  activeRun: PlaybookRunResult | null;
  activeRunId: string | null;
  events: Extract<LiveEvent, { stream: string }>[];
  notifyEmail: string;
  operator: string;
  runState: string;
  setNotifyEmail: (value: string) => void;
  onApprove: () => void;
  onReject: () => void;
  onRun: () => void;
}) {
  const tasks = activeRun?.tasks ?? [];
  const notificationStatus = activeRun?.notification?.status ?? "ready";
  const riskScore = Number(activeRun?.context?.["Fortress.Incident.RiskScore"] ?? 95);

  return (
    <section className="mx-auto max-w-7xl px-6 pb-10">
      <div className="grid grid-cols-1 gap-5 xl:grid-cols-[0.85fr_1.65fr]">
        <div className="rounded border border-fortress-line bg-fortress-panel p-5">
          <div className="flex items-start justify-between gap-4">
            <div>
              <p className="text-sm uppercase text-fortress-cyan">Cortex XSOAR-style workflow</p>
              <h2 className="mt-1 text-2xl font-semibold text-white">Enterprise Incident Response</h2>
              <p className="mt-2 text-sm text-[#9fb0c2]">
                Multi-stage triage, enrichment, approval, containment, forensics, verification, and incident reporting for high-risk security events.
              </p>
            </div>
            <span className="rounded border border-fortress-amber px-3 py-1 text-sm text-fortress-amber">{runState}</span>
          </div>

          <div className="mt-5 grid gap-3 text-sm">
            <Field label="Operator" value={operator} />
            <Field label="Tenant" value="nepal-national-bank" />
            <Field label="Scenario" value="Critical banking incident" />
            <label className="rounded border border-fortress-line bg-[#0b1017] px-3 py-2">
              <span className="text-[#9fb0c2]">Report email</span>
              <input
                className="mt-2 w-full bg-transparent text-white outline-none"
                value={notifyEmail}
                onChange={(event) => setNotifyEmail(event.target.value)}
              />
            </label>
          </div>

          <button
            className="mt-5 flex w-full items-center justify-center gap-2 rounded bg-fortress-amber px-4 py-3 font-semibold text-[#100b04]"
            onClick={onRun}
          >
            <PlayCircle className="h-4 w-4" />
            Run Enterprise Playbook
          </button>

          <div className="mt-4 grid grid-cols-1 gap-3 sm:grid-cols-2">
            <button
              className="flex items-center justify-center gap-2 rounded bg-fortress-green px-4 py-3 font-semibold text-[#041008] disabled:cursor-not-allowed disabled:opacity-40"
              disabled={!activeRunId || runState !== "waiting for approval"}
              onClick={onApprove}
            >
              <UserCheck className="h-4 w-4" />
              Approve Containment
            </button>
            <button
              className="rounded border border-fortress-red px-4 py-3 font-semibold text-fortress-red disabled:cursor-not-allowed disabled:opacity-40"
              disabled={!activeRunId || runState !== "waiting for approval"}
              onClick={onReject}
            >
              Reject and Escalate
            </button>
          </div>

          <div className="mt-5 grid grid-cols-2 gap-3">
            <MiniStatus icon={<AlertTriangle />} label="Risk" value={riskScore} />
            <MiniStatus icon={<Mail />} label="Email" value={notificationStatus} />
            <MiniStatus icon={<Clock />} label="SLA" value="15 min" />
            <MiniStatus icon={<GitBranch />} label="Tasks" value={tasks.length || 14} />
          </div>
        </div>

        <div className="rounded border border-fortress-line bg-fortress-panel">
          <div className="flex flex-wrap items-center justify-between gap-3 border-b border-fortress-line px-5 py-4">
            <div>
              <h2 className="text-lg font-semibold text-white">Playbook Canvas</h2>
              <p className="text-sm text-[#9fb0c2]">Triage to containment to report delivery, with approval gates and command outputs.</p>
            </div>
            <span className="rounded border border-fortress-line px-3 py-1 text-sm text-fortress-cyan">
              {activeRun?.run_id ? `Run ${activeRun.run_id.slice(0, 8)}` : "No active run"}
            </span>
          </div>
          <PlaybookCanvas tasks={tasks} />
        </div>
      </div>

      <div className="mt-5 grid grid-cols-1 gap-5 xl:grid-cols-[1.2fr_0.8fr]">
        <PlaybookActivity events={events} />
        <IncidentReportPanel run={activeRun} notifyEmail={notifyEmail} />
      </div>
    </section>
  );
}

function PlaybookCanvas({ tasks }: { tasks: PlaybookTask[] }) {
  const grouped = [
    { label: "Triage", ids: ["0", "1", "2", "3", "4"] },
    { label: "Approval", ids: ["5", "6", "approval-decision"] },
    { label: "Containment", ids: ["7", "8", "9", "10"] },
    { label: "Verify and Report", ids: ["11", "12", "13"] }
  ];
  const visibleTasks = tasks.length ? tasks : defaultPlaybookTasks;

  return (
    <div className="grid grid-cols-1 gap-4 p-5 lg:grid-cols-4">
      {grouped.map((group) => (
        <div className="min-h-72 rounded border border-fortress-line bg-[#0b1017] p-4" key={group.label}>
          <div className="mb-4 flex items-center gap-2 text-sm font-semibold text-white">
            <ServerCog className="h-4 w-4 text-fortress-cyan" />
            {group.label}
          </div>
          <div className="space-y-3">
            {visibleTasks.filter((task) => group.ids.includes(task.task_id)).map((task) => (
              <div className="rounded border border-fortress-line bg-[#10151d] p-3" key={`${task.task_id}-${task.status}`}>
                <div className="flex items-start justify-between gap-3">
                  <p className="text-sm font-semibold text-white">{task.name}</p>
                  <StatusPill status={task.status} />
                </div>
                <p className="mt-2 text-xs leading-5 text-[#9fb0c2]">{task.detail}</p>
                {task.commands.length > 0 && (
                  <p className="mt-2 text-xs text-fortress-amber">{task.commands.slice(0, 3).join(" | ")}</p>
                )}
              </div>
            ))}
          </div>
        </div>
      ))}
    </div>
  );
}

function IncidentReportPanel({ run, notifyEmail }: { run: PlaybookRunResult | null; notifyEmail: string }) {
  const preview = run?.report?.body?.split("\n").slice(0, 18).join("\n");
  return (
    <div className="rounded border border-fortress-line bg-fortress-panel">
      <div className="border-b border-fortress-line px-5 py-4">
        <h2 className="text-lg font-semibold text-white">Security Incident Report Email</h2>
        <p className="text-sm text-[#9fb0c2]">Recipient: {run?.report?.recipient ?? notifyEmail}</p>
      </div>
      <div className="p-5">
        <div className="grid gap-3 text-sm">
          <Field label="Delivery state" value={run?.notification?.status ?? "ready"} />
          <Field label="Subject" value={run?.report?.subject ?? "Run playbook to generate report"} />
        </div>
        <pre className="mt-4 max-h-80 overflow-auto rounded bg-[#080c12] p-4 text-xs leading-5 text-[#c7d4e2]">
          {preview ?? "After you run the playbook, Nepal Fortress ONE generates a security incident report and sends it through the configured SMTP mail integration."}
        </pre>
      </div>
    </div>
  );
}

function MiniStatus({ icon, label, value }: { icon: ReactNode; label: string; value: number | string }) {
  return (
    <div className="rounded border border-fortress-line bg-[#0b1017] p-3">
      <div className="flex items-center justify-between gap-3">
        <div className="text-fortress-cyan [&_svg]:h-4 [&_svg]:w-4">{icon}</div>
        <span className="text-sm font-semibold text-white">{value}</span>
      </div>
      <p className="mt-2 text-xs text-[#9fb0c2]">{label}</p>
    </div>
  );
}

function StatusPill({ status }: { status: string }) {
  const tone = status.includes("waiting") || status.includes("queued")
    ? "border-fortress-amber text-fortress-amber"
    : status.includes("rejected")
      ? "border-fortress-red text-fortress-red"
      : "border-fortress-green text-fortress-green";
  return <span className={`shrink-0 rounded border px-2 py-1 text-[11px] ${tone}`}>{status.replaceAll("_", " ")}</span>;
}

const defaultPlaybookTasks: PlaybookTask[] = [
  { task_id: "0", task_type: "start", name: "Incident trigger", status: "ready", detail: "Waiting for a high-risk incident run.", commands: [], outputs: {}, timestamp: "" },
  { task_id: "1", task_type: "automation", name: "Normalize and score incident", status: "ready", detail: "Prepare severity, tenant, sector, and risk context.", commands: [], outputs: {}, timestamp: "" },
  { task_id: "2", task_type: "integration", name: "Collect SIEM, XDR, NGFW, and IAM evidence", status: "ready", detail: "Collect correlated evidence across platform telemetry.", commands: ["siem-search-events", "xdr-get-endpoint", "ngfw-log-query"], outputs: {}, timestamp: "" },
  { task_id: "3", task_type: "integration", name: "Enrich IOCs and assets", status: "ready", detail: "Attach threat intelligence, asset criticality, identity, and zone context.", commands: ["threatintel-search", "asset-get"], outputs: {}, timestamp: "" },
  { task_id: "4", task_type: "automation", name: "Map MITRE and blast radius", status: "ready", detail: "Estimate business impact and affected segments.", commands: [], outputs: {}, timestamp: "" },
  { task_id: "5", task_type: "condition", name: "Containment impact decision", status: "ready", detail: "Determine whether approval is required.", commands: [], outputs: {}, timestamp: "" },
  { task_id: "6", task_type: "manual_approval", name: "SOC lead approval", status: "ready", detail: "Approval gate for high-impact containment.", commands: [], outputs: {}, timestamp: "" },
  { task_id: "7", task_type: "condition", name: "Validate policy safety", status: "ready", detail: "Check change safety and emergency window.", commands: [], outputs: {}, timestamp: "" },
  { task_id: "8", task_type: "integration", name: "Block on NGFW and DNS", status: "ready", detail: "Apply network and DNS containment controls.", commands: ["ngfw-security-rule-update", "dns-sinkhole-domain"], outputs: {}, timestamp: "" },
  { task_id: "9", task_type: "integration", name: "Contain endpoint and identity", status: "ready", detail: "Isolate endpoint, revoke sessions, and terminate ZTNA access.", commands: ["xdr-endpoint-isolate", "iam-session-revoke"], outputs: {}, timestamp: "" },
  { task_id: "10", task_type: "integration", name: "Preserve forensics", status: "ready", detail: "Collect triage package and preserve chain of custody.", commands: ["xdr-collect-triage-package"], outputs: {}, timestamp: "" },
  { task_id: "11", task_type: "automation", name: "Verify containment", status: "ready", detail: "Monitor recurrence and validate controls.", commands: [], outputs: {}, timestamp: "" },
  { task_id: "12", task_type: "communication", name: "Email incident report", status: "ready", detail: "Send security incident report to the configured recipient.", commands: ["email-send"], outputs: {}, timestamp: "" },
  { task_id: "13", task_type: "automation", name: "Update case summary", status: "ready", detail: "Update case, executive summary, and timeline.", commands: [], outputs: {}, timestamp: "" }
];

function NgfwTable({ logs }: { logs: NgfwLog[] }) {
  return (
        <div className="rounded border border-fortress-line bg-fortress-panel">
          <div className="border-b border-fortress-line px-5 py-4">
            <h2 className="text-lg font-semibold text-white">Next-Generation Firewall Logs</h2>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full min-w-[920px] text-left text-sm">
              <thead className="bg-[#0b1017] text-xs uppercase text-[#9fb0c2]">
                <tr>
                  <th className="px-4 py-3">Sector</th>
                  <th className="px-4 py-3">Application</th>
                  <th className="px-4 py-3">Flow</th>
                  <th className="px-4 py-3">DPI</th>
                  <th className="px-4 py-3">IPS</th>
                  <th className="px-4 py-3">Action</th>
                  <th className="px-4 py-3">Risk</th>
                </tr>
              </thead>
              <tbody>
                {logs.length === 0 ? (
                  <tr>
                    <td className="px-4 py-8 text-center text-[#9fb0c2]" colSpan={7}>
                      Waiting for real NGFW telemetry from Suricata, Zeek, firewall sensors, or API ingestion.
                    </td>
                  </tr>
                ) : (
                  logs.map((log) => (
                    <tr key={log.event_id} className="border-t border-fortress-line">
                      <td className="px-4 py-3 capitalize">{log.sector.replace("-", " ")}</td>
                      <td className="px-4 py-3">{log.application}</td>
                      <td className="px-4 py-3 text-[#9fb0c2]">{log.src_ip} to {log.dst_ip}</td>
                      <td className="px-4 py-3">{log.dpi?.tls_sni || log.dpi?.file_type || log.dpi?.payload_sha256 || "observed"}</td>
                      <td className="px-4 py-3">{log.ips?.signature || "none"}</td>
                      <td className="px-4 py-3">
                        <span className="rounded border border-fortress-line px-2 py-1">{log.action}</span>
                      </td>
                      <td className="px-4 py-3 font-semibold text-fortress-amber">{log.risk_score}</td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>
  );
}

function PlaybookActivity({ events }: { events: Extract<LiveEvent, { stream: string }>[] }) {
  return (
    <div className="rounded border border-fortress-line bg-fortress-panel">
      <div className="border-b border-fortress-line px-5 py-4">
        <h2 className="text-lg font-semibold text-white">Interactive SOAR Playbook Activity</h2>
      </div>
      <div className="divide-y divide-fortress-line">
        {events.slice(0, 8).map((event, index) => (
          <div className="flex items-center justify-between px-5 py-4" key={index}>
            <div>
              <p className="font-medium text-white">{event.task?.name}</p>
              <p className="text-sm text-[#9fb0c2]">{event.task?.detail}</p>
              {event.task?.commands && event.task.commands.length > 0 && (
                <p className="mt-1 text-xs text-fortress-amber">{event.task.commands.join(" | ")}</p>
              )}
            </div>
            <span className="rounded border border-fortress-line px-3 py-1 text-sm text-fortress-cyan">{event.task?.status}</span>
          </div>
        ))}
        {events.length === 0 && (
          <div className="px-5 py-8 text-center text-[#9fb0c2]">Run a playbook to see approval gates, enrichment, containment, and email notification steps.</div>
        )}
      </div>
    </div>
  );
}

function isPlaybookEvent(event: LiveEvent): event is Extract<LiveEvent, { stream: string }> {
  return "stream" in event && event.stream === "playbook";
}

function NavButton({ active, icon, label, onClick }: { active: boolean; icon: ReactNode; label: string; onClick: () => void }) {
  return (
    <button
      className={`flex items-center gap-2 rounded border px-4 py-2 text-sm ${active ? "border-fortress-cyan bg-[#10242a] text-white" : "border-fortress-line text-[#9fb0c2]"}`}
      onClick={onClick}
    >
      <span className="[&_svg]:h-4 [&_svg]:w-4">{icon}</span>
      {label}
    </button>
  );
}

function Field({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex items-center justify-between rounded border border-fortress-line bg-[#0b1017] px-3 py-2">
      <span className="text-[#9fb0c2]">{label}</span>
      <span className="text-white">{value}</span>
    </div>
  );
}

function Metric({ icon, label, value }: { icon: ReactNode; label: string; value: number }) {
  return (
    <div className="rounded border border-fortress-line bg-fortress-panel p-5">
      <div className="flex items-center justify-between">
        <div className="text-fortress-cyan [&_svg]:h-5 [&_svg]:w-5">{icon}</div>
        <span className="text-2xl font-semibold text-white">{value}</span>
      </div>
      <p className="mt-4 text-sm text-[#9fb0c2]">{label}</p>
    </div>
  );
}
