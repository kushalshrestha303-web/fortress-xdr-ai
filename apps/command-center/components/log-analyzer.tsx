"use client";

import { useMemo, useState } from "react";
import { AlertTriangle, Download, FileText, FileSearch, GitBranch, ShieldCheck, Shield, UploadCloud } from "lucide-react";
import {
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  Line,
  LineChart,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis
} from "recharts";

import { analyzeUploadedLog, reportExportUrl, uploadLogFile } from "@/lib/api";
import type { LogAnalysisResult, ParsedLogEvent } from "@/lib/types";

export function LogAnalyzer({ embedded = false }: { embedded?: boolean }) {
  const [file, setFile] = useState<File | null>(null);
  const [status, setStatus] = useState("ready");
  const [uploadId, setUploadId] = useState<string | null>(null);
  const [events, setEvents] = useState<ParsedLogEvent[]>([]);
  const [analysis, setAnalysis] = useState<LogAnalysisResult | null>(null);

  const highSeverity = useMemo(() => events.filter((event) => ["high", "critical"].includes(event.severity)).length, [events]);

  async function handleUploadAndAnalyze() {
    if (!file) {
      setStatus("select a log file first");
      return;
    }
    setStatus("uploading");
    try {
      const uploaded = await uploadLogFile(file);
      setUploadId(uploaded.upload_id);
      setEvents(uploaded.events as ParsedLogEvent[]);
      setStatus("analyzing");
      const result = await analyzeUploadedLog(uploaded.upload_id);
      setAnalysis(result as LogAnalysisResult);
      setEvents((result as LogAnalysisResult).events);
      setStatus("analysis complete");
    } catch (error) {
      console.error("Log analyzer upload/analyze failed", error);
      setStatus(error instanceof Error ? error.message : "analysis failed");
    }
  }

  const content = (
    <>
      {!embedded && (
      <header className="border-b border-fortress-line bg-[#0b1017]">
        <div className="mx-auto flex max-w-7xl flex-col gap-4 px-6 py-6 md:flex-row md:items-center md:justify-between">
          <div>
            <p className="text-sm uppercase text-fortress-cyan">Nepal Fortress ONE</p>
            <h1 className="mt-1 text-3xl font-semibold text-white">AI Log Attack Analyzer</h1>
          </div>
          <a className="flex items-center gap-2 rounded border border-fortress-line px-4 py-2 text-sm text-[#c7d4e2]" href="/">
            <Shield className="h-4 w-4 text-fortress-cyan" />
            SOC Command Center
          </a>
        </div>
      </header>
      )}

      {embedded && (
        <section className="mx-auto max-w-7xl px-6 pb-5">
          <div className="rounded border border-fortress-line bg-fortress-panel p-5">
            <p className="text-sm uppercase text-fortress-cyan">Fortress AI Brain Module</p>
            <h2 className="mt-1 text-2xl font-semibold text-white">AI Log Attack Analyzer</h2>
            <p className="mt-2 max-w-4xl text-sm text-[#9fb0c2]">
              Upload SOC, firewall, endpoint, Wireshark, CSV, JSON, XLSX, or HTTP logs directly inside Nepal Fortress ONE. The analyzer parses evidence, detects attack patterns, builds an attack flow, and generates an incident report for command-center operations.
            </p>
          </div>
        </section>
      )}

      <section className="mx-auto grid max-w-7xl grid-cols-1 gap-4 px-6 py-6 lg:grid-cols-4">
        <Metric icon={<FileSearch />} label="Parsed Events" value={events.length} />
        <Metric icon={<AlertTriangle />} label="High Severity" value={highSeverity} />
        <Metric icon={<ShieldCheck />} label="Findings" value={analysis?.findings.length ?? 0} />
        <Metric icon={<UploadCloud />} label="Upload State" value={status} text />
      </section>

      <section className="mx-auto grid max-w-7xl grid-cols-1 gap-5 px-6 pb-8 xl:grid-cols-[0.8fr_1.2fr]">
        <div className="rounded border border-fortress-line bg-fortress-panel p-5">
          <h2 className="text-lg font-semibold text-white">Upload Logs</h2>
          <label className="mt-5 flex min-h-44 cursor-pointer flex-col items-center justify-center rounded border border-dashed border-fortress-line bg-[#0b1017] px-4 py-8 text-center">
            <UploadCloud className="h-8 w-8 text-fortress-cyan" />
            <span className="mt-3 text-sm text-[#c7d4e2]">{file ? file.name : "Drop or choose .log, .txt, .csv, .json, .xlsx, .pcapng"}</span>
            <input
              className="hidden"
              type="file"
              accept=".log,.txt,.csv,.json,.xlsx,.pcapng"
              onChange={(event) => setFile(event.target.files?.[0] ?? null)}
            />
          </label>
          <button
            className="mt-5 flex w-full items-center justify-center gap-2 rounded bg-fortress-cyan px-4 py-3 font-semibold text-[#071016]"
            onClick={handleUploadAndAnalyze}
          >
            <FileSearch className="h-4 w-4" />
            Upload and Analyze
          </button>
          <p className="mt-3 text-sm text-fortress-amber">Analyzer state: {status}</p>
          {uploadId && <p className="mt-2 text-xs text-[#9fb0c2]">Upload ID: {uploadId}</p>}
        </div>

        <div className="rounded border border-fortress-line bg-fortress-panel p-5">
          <h2 className="text-lg font-semibold text-white">Detection Summary</h2>
          {analysis ? (
            <div className="mt-4 grid gap-3">
              {analysis.findings.map((finding) => (
                <div className="rounded border border-fortress-line bg-[#0b1017] p-4" key={finding.finding_id}>
                  <div className="flex flex-wrap items-center justify-between gap-3">
                    <h3 className="font-semibold text-white">{finding.attack_type}</h3>
                    <span className="rounded border border-fortress-line px-3 py-1 text-sm text-fortress-amber">{finding.severity} · {Math.round(finding.confidence * 100)}%</span>
                  </div>
                  <p className="mt-2 text-sm text-[#9fb0c2]">{finding.source || "unknown"} to {finding.destination || "unknown"}</p>
                  <p className="mt-2 text-xs text-fortress-cyan">{finding.mitre.join(" | ")}</p>
                </div>
              ))}
              {analysis.findings.length === 0 && <p className="text-sm text-[#9fb0c2]">No confirmed attack detected in this log set.</p>}
            </div>
          ) : (
            <p className="mt-4 text-sm text-[#9fb0c2]">Upload a log to generate attack detections, diagrams, charts, and an incident report.</p>
          )}
        </div>
      </section>

      {analysis && (
        <>
          <DownloadCenter result={analysis} />
          <VisualReport result={analysis} />
          <section className="mx-auto grid max-w-7xl grid-cols-1 gap-5 px-6 pb-8 xl:grid-cols-[1fr_1fr]">
            <AttackDiagram result={analysis} />
            <ReportPreview result={analysis} />
          </section>
          <Charts result={analysis} />
        </>
      )}

      <section className="mx-auto max-w-7xl px-6 pb-10">
        <ParsedTable events={events} />
      </section>
    </>
  );

  if (embedded) {
    return <div className="text-[#e6edf6]">{content}</div>;
  }

  return (
    <main className="min-h-screen bg-fortress-bg text-[#e6edf6]">
      {content}
    </main>
  );
}

function DownloadCenter({ result }: { result: LogAnalysisResult }) {
  const links: Array<{ label: string; detail: string; href: string; primary?: boolean }> = [
    { label: "Visual Report Page", detail: "Best graphic report", href: `/security/log-analyzer/reports/${result.report_id}`, primary: true },
    { label: "PDF Report", detail: "Incident report", href: reportExportUrl(result.report_id, "pdf") },
    { label: "Attack Diagram SVG", detail: "Graphic flow", href: reportExportUrl(result.report_id, "diagram.svg") },
    { label: "Parsed CSV", detail: "Evidence table", href: reportExportUrl(result.report_id, "csv") },
    { label: "Markdown", detail: "SOC notes", href: reportExportUrl(result.report_id, "markdown") }
  ];

  return (
    <section className="mx-auto max-w-7xl px-6 pb-8">
      <div className="rounded border border-fortress-line bg-fortress-panel p-5">
        <div className="flex flex-wrap items-center justify-between gap-4">
          <div>
            <p className="text-sm uppercase text-fortress-cyan">Report Downloads</p>
            <h2 className="mt-1 text-2xl font-semibold text-white">AI Log Attack Analyzer Report Ready</h2>
            <p className="mt-2 text-sm text-[#9fb0c2]">Download the visual incident report, attack graphic, PDF, or raw evidence exports from this completed analysis.</p>
          </div>
          <a
            className="flex items-center gap-2 rounded bg-fortress-cyan px-4 py-3 font-semibold text-[#071016]"
            href={`/security/log-analyzer/reports/${result.report_id}`}
            target="_blank"
            rel="noreferrer"
          >
            <Download className="h-4 w-4" />
            Download Best Visual Report
          </a>
        </div>
        {result.notification && (
          <div className="mt-4 rounded border border-fortress-line bg-[#0b1017] px-4 py-3 text-sm">
            <span className="text-[#9fb0c2]">Email report: </span>
            <span className={result.notification.status === "sent" ? "text-fortress-green" : "text-fortress-amber"}>
              {result.notification.status}
            </span>
            <span className="text-[#9fb0c2]"> to {result.notification.recipient}</span>
          </div>
        )}
        <div className="mt-5 grid grid-cols-1 gap-3 md:grid-cols-5">
          {links.map((link) => (
            <a
              className={`rounded border p-4 ${link.primary ? "border-fortress-cyan bg-[#10242a]" : "border-fortress-line bg-[#0b1017]"}`}
              href={link.href}
              target="_blank"
              rel="noreferrer"
              key={link.label}
            >
              <div className="flex items-center gap-2 text-sm font-semibold text-white">
                <FileText className="h-4 w-4 text-fortress-cyan" />
                {link.label}
              </div>
              <p className="mt-2 text-xs text-[#9fb0c2]">{link.detail}</p>
            </a>
          ))}
        </div>
      </div>
    </section>
  );
}

function VisualReport({ result }: { result: LogAnalysisResult }) {
  const primary = result.findings[0];
  const highestSeverity = primary?.severity ?? "info";
  const risk = primary ? Math.round(primary.confidence * 100) : 0;
  return (
    <section className="mx-auto grid max-w-7xl grid-cols-1 gap-5 px-6 pb-8 xl:grid-cols-[1.05fr_0.95fr]">
      <div className="rounded border border-fortress-line bg-fortress-panel p-5">
        <div className="flex flex-wrap items-start justify-between gap-4">
          <div>
            <p className="text-sm uppercase text-fortress-cyan">Executive Visual Report</p>
            <h2 className="mt-1 text-2xl font-semibold text-white">{result.summary.attack_type}</h2>
            <p className="mt-2 text-sm text-[#9fb0c2]">{String(result.summary.business_impact)}</p>
          </div>
          <div className="rounded border border-fortress-amber bg-[#0b1017] px-4 py-3 text-right">
            <p className="text-xs uppercase text-[#9fb0c2]">AI Confidence</p>
            <p className="text-2xl font-semibold text-fortress-amber">{risk}%</p>
          </div>
        </div>
        <div className="mt-5 grid grid-cols-2 gap-3 lg:grid-cols-4">
          <MiniReportMetric label="Severity" value={highestSeverity} icon={<AlertTriangle />} />
          <MiniReportMetric label="Events" value={result.events.length} icon={<FileSearch />} />
          <MiniReportMetric label="Findings" value={result.findings.length} icon={<ShieldCheck />} />
          <MiniReportMetric label="IOCs" value={result.summary.indicators_of_compromise.length} icon={<GitBranch />} />
        </div>
        <div className="mt-5 rounded border border-fortress-line bg-[#0b1017] p-4">
          <h3 className="text-sm font-semibold text-white">Recommended Mitigation</h3>
          <div className="mt-3 grid gap-2">
            {result.summary.recommended_mitigation.slice(0, 5).map((action) => (
              <div className="rounded border border-fortress-line bg-[#10151d] px-3 py-2 text-sm text-[#c7d4e2]" key={action}>{action}</div>
            ))}
          </div>
        </div>
      </div>
      <div className="rounded border border-fortress-line bg-fortress-panel p-5">
        <h2 className="text-lg font-semibold text-white">Threat Severity Graphic</h2>
        <div className="mt-5 h-72">
          <ResponsiveContainer width="100%" height="100%">
            <BarChart data={result.charts.attack_timeline}>
              <CartesianGrid stroke="#27313f" />
              <XAxis dataKey="attack_type" tick={{ fill: "#9fb0c2", fontSize: 10 }} />
              <YAxis tick={{ fill: "#9fb0c2", fontSize: 11 }} />
              <Tooltip contentStyle={{ background: "#10151d", border: "1px solid #27313f" }} />
              <Bar dataKey="confidence" fill="#f5b84b" radius={[4, 4, 0, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>
    </section>
  );
}

function AttackDiagram({ result }: { result: LogAnalysisResult }) {
  return (
    <div className="rounded border border-fortress-line bg-fortress-panel p-5">
      <div className="flex items-center justify-between gap-3">
        <h2 className="text-lg font-semibold text-white">Attack Flow Diagram</h2>
        <a className="text-sm text-fortress-cyan" href={reportExportUrl(result.report_id, "diagram.svg")}>SVG</a>
      </div>
      <div className="mt-5 flex flex-wrap items-center gap-3">
        {result.diagram.nodes.map((node, index) => (
          <div className="flex items-center gap-3" key={node}>
            <div className="rounded border border-fortress-cyan bg-[#0b1017] px-4 py-3 text-sm text-white">{node}</div>
            {index < result.diagram.nodes.length - 1 && <div className="h-px w-8 bg-fortress-amber" />}
          </div>
        ))}
      </div>
      <pre className="mt-5 overflow-x-auto rounded bg-[#080c12] p-4 text-xs text-[#9fb0c2]">{result.diagram.mermaid}</pre>
    </div>
  );
}

function ReportPreview({ result }: { result: LogAnalysisResult }) {
  const sections = Object.entries(result.report).slice(0, 7);
  return (
    <div className="rounded border border-fortress-line bg-fortress-panel p-5">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <h2 className="text-lg font-semibold text-white">Incident Report</h2>
        <div className="flex gap-2 text-sm">
          <a className="flex items-center gap-1 text-fortress-cyan" href={reportExportUrl(result.report_id, "pdf")}><Download className="h-4 w-4" />PDF</a>
          <a className="text-fortress-cyan" href={reportExportUrl(result.report_id, "html")}>HTML</a>
          <a className="text-fortress-cyan" href={reportExportUrl(result.report_id, "csv")}>CSV</a>
          <a className="text-fortress-cyan" href={reportExportUrl(result.report_id, "markdown")}>MD</a>
        </div>
      </div>
      <div className="mt-4 max-h-[520px] space-y-4 overflow-auto pr-2">
        {sections.map(([title, value]) => (
          <section key={title}>
            <h3 className="text-sm font-semibold text-fortress-amber">{title}</h3>
            <p className="mt-1 text-sm text-[#c7d4e2]">{Array.isArray(value) ? value.slice(0, 4).join(" | ") : String(value)}</p>
          </section>
        ))}
      </div>
    </div>
  );
}

function Charts({ result }: { result: LogAnalysisResult }) {
  return (
    <section className="mx-auto grid max-w-7xl grid-cols-1 gap-5 px-6 pb-8 xl:grid-cols-4">
      <ChartPanel title="Packet Count Over Time">
        <LineChart data={result.charts.packet_count_over_time}>
          <CartesianGrid stroke="#27313f" />
          <XAxis dataKey="time" tick={{ fill: "#9fb0c2", fontSize: 10 }} />
          <YAxis tick={{ fill: "#9fb0c2", fontSize: 11 }} />
          <Tooltip contentStyle={{ background: "#10151d", border: "1px solid #27313f" }} />
          <Line type="monotone" dataKey="count" stroke="#36d7d7" strokeWidth={2} />
        </LineChart>
      </ChartPanel>
      <ChartPanel title="Top Source IPs">
        <BarChart data={result.charts.top_source_ips}>
          <CartesianGrid stroke="#27313f" />
          <XAxis dataKey="ip" tick={{ fill: "#9fb0c2", fontSize: 10 }} />
          <YAxis tick={{ fill: "#9fb0c2", fontSize: 11 }} />
          <Tooltip contentStyle={{ background: "#10151d", border: "1px solid #27313f" }} />
          <Bar dataKey="count" fill="#f5b84b" />
        </BarChart>
      </ChartPanel>
      <ChartPanel title="Protocol Distribution">
        <BarChart data={result.charts.protocol_distribution}>
          <CartesianGrid stroke="#27313f" />
          <XAxis dataKey="protocol" tick={{ fill: "#9fb0c2", fontSize: 10 }} />
          <YAxis tick={{ fill: "#9fb0c2", fontSize: 11 }} />
          <Tooltip contentStyle={{ background: "#10151d", border: "1px solid #27313f" }} />
          <Bar dataKey="count" fill="#36d7d7" />
        </BarChart>
      </ChartPanel>
      <ChartPanel title="Severity Breakdown">
        <PieChart>
          <Pie data={result.charts.severity_breakdown} dataKey="count" nameKey="severity" label>
            {result.charts.severity_breakdown.map((entry, index) => (
              <Cell key={entry.severity} fill={["#36d7d7", "#7ddf64", "#f5b84b", "#ff7a45", "#ff4d6d"][index % 5]} />
            ))}
          </Pie>
          <Tooltip contentStyle={{ background: "#10151d", border: "1px solid #27313f" }} />
        </PieChart>
      </ChartPanel>
    </section>
  );
}

function ChartPanel({ title, children }: { title: string; children: React.ReactElement }) {
  return (
    <div className="rounded border border-fortress-line bg-fortress-panel p-5">
      <h2 className="text-lg font-semibold text-white">{title}</h2>
      <div className="mt-4 h-64">
        <ResponsiveContainer width="100%" height="100%">{children}</ResponsiveContainer>
      </div>
    </div>
  );
}

function ParsedTable({ events }: { events: ParsedLogEvent[] }) {
  return (
    <div className="rounded border border-fortress-line bg-fortress-panel">
      <div className="border-b border-fortress-line px-5 py-4">
        <h2 className="text-lg font-semibold text-white">Parsed Log Evidence</h2>
      </div>
      <div className="overflow-x-auto">
        <table className="w-full min-w-[980px] text-left text-sm">
          <thead className="bg-[#0b1017] text-xs uppercase text-[#9fb0c2]">
            <tr>
              <th className="px-4 py-3">Time</th>
              <th className="px-4 py-3">Source IP</th>
              <th className="px-4 py-3">Destination IP</th>
              <th className="px-4 py-3">Protocol</th>
              <th className="px-4 py-3">Info</th>
              <th className="px-4 py-3">Severity</th>
            </tr>
          </thead>
          <tbody>
            {events.length === 0 ? (
              <tr><td className="px-4 py-8 text-center text-[#9fb0c2]" colSpan={6}>No parsed events yet.</td></tr>
            ) : events.slice(0, 200).map((event) => (
              <tr className="border-t border-fortress-line" key={event.event_id}>
                <td className="px-4 py-3 text-[#9fb0c2]">{event.timestamp}</td>
                <td className="px-4 py-3">{event.source_ip || "-"}</td>
                <td className="px-4 py-3">{event.destination_ip || "-"}</td>
                <td className="px-4 py-3">{event.protocol}</td>
                <td className="max-w-[420px] truncate px-4 py-3">{event.info}</td>
                <td className="px-4 py-3 text-fortress-amber">{event.severity}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function MiniReportMetric({ icon, label, value }: { icon: React.ReactNode; label: string; value: number | string }) {
  return (
    <div className="rounded border border-fortress-line bg-[#0b1017] p-4">
      <div className="flex items-center justify-between gap-3">
        <div className="text-fortress-cyan [&_svg]:h-5 [&_svg]:w-5">{icon}</div>
        <span className="text-lg font-semibold text-white">{value}</span>
      </div>
      <p className="mt-3 text-xs text-[#9fb0c2]">{label}</p>
    </div>
  );
}

function Metric({ icon, label, value, text = false }: { icon: React.ReactNode; label: string; value: number | string; text?: boolean }) {
  return (
    <div className="rounded border border-fortress-line bg-fortress-panel p-5">
      <div className="flex items-center justify-between gap-3">
        <div className="text-fortress-cyan [&_svg]:h-5 [&_svg]:w-5">{icon}</div>
        <span className={`${text ? "text-sm" : "text-2xl"} font-semibold text-white`}>{value}</span>
      </div>
      <p className="mt-4 text-sm text-[#9fb0c2]">{label}</p>
    </div>
  );
}
