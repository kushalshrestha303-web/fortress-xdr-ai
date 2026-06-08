"use client";

import { useEffect, useMemo, useState } from "react";
import type { ReactNode } from "react";
import { AlertTriangle, CheckCircle2, Mail, ShieldAlert, Workflow } from "lucide-react";

import { defaultDesignerPlaybook, mergeRunTasksIntoDesigner } from "./playbookAdapter";
import { ExecutionLogPanel } from "./ExecutionLogPanel";
import { NodeConfigPanel } from "./NodeConfigPanel";
import { NodePalette } from "./NodePalette";
import { PlaybookCanvas } from "./PlaybookCanvas";
import { PlaybookToolbar } from "./PlaybookToolbar";
import type { DesignerEdgeLabel, DesignerNode, DesignerNodeType, DesignerPlaybook, ExecutionLogEntry, PlaybookDesignerProps } from "./playbookTypes";
import { sanitizeDesignerText, validateConnection, validatePlaybook } from "./playbookValidation";

const storageKey = "nepal-fortress-one-playbook-designer";

export function PlaybookDesigner({
  activeRun,
  activeRunId,
  notifyEmail,
  operator,
  runState,
  setNotifyEmail,
  onApprove,
  onReject,
  onRun
}: PlaybookDesignerProps) {
  const [playbook, setPlaybook] = useState<DesignerPlaybook>(() => defaultDesignerPlaybook(notifyEmail));
  const [selectedNodeId, setSelectedNodeId] = useState<string | null>("n-trigger");
  const [connectMode, setConnectMode] = useState(false);
  const [connectSourceId, setConnectSourceId] = useState<string | null>(null);
  const [paletteQuery, setPaletteQuery] = useState("");
  const [zoom, setZoom] = useState(0.78);
  const [pan, setPan] = useState({ x: 30, y: 80 });
  const [logs, setLogs] = useState<ExecutionLogEntry[]>([]);
  const [toast, setToast] = useState("");
  const [contextMenu, setContextMenu] = useState<{ nodeId: string; x: number; y: number } | null>(null);

  useEffect(() => {
    const saved = window.localStorage.getItem(storageKey);
    if (!saved) return;
    try {
      const parsed = JSON.parse(saved) as DesignerPlaybook;
      setPlaybook(parsed);
      setSelectedNodeId(parsed.nodes[0]?.id ?? null);
    } catch {
      setToast("Saved visual playbook could not be loaded.");
    }
  }, []);

  useEffect(() => {
    if (!activeRun?.tasks?.length) return;
    setPlaybook((current) => ({
      ...current,
      nodes: mergeRunTasksIntoDesigner(current.nodes, activeRun.tasks),
      lastRunAt: new Date().toISOString(),
      runHistory: [
        { runId: activeRun.run_id, status: activeRun.status, timestamp: new Date().toISOString() },
        ...current.runHistory
      ].slice(0, 8)
    }));
  }, [activeRun]);

  const selectedNode = playbook.nodes.find((node) => node.id === selectedNodeId) ?? null;
  const warnings = useMemo(() => validatePlaybook(playbook), [playbook]);
  const successRate = playbook.runHistory.length ? Math.round((playbook.runHistory.filter((run) => !run.status.includes("failed")).length / playbook.runHistory.length) * 100) : 100;

  function updatePlaybook(patch: Partial<DesignerPlaybook>) {
    setPlaybook((current) => ({ ...current, ...patch, updatedAt: new Date().toISOString() }));
  }

  function updateNode(nextNode: DesignerNode) {
    updatePlaybook({ nodes: playbook.nodes.map((node) => node.id === nextNode.id ? nextNode : node) });
    if (nextNode.type === "gmailReport" && nextNode.config.emailRecipient) {
      setNotifyEmail(nextNode.config.emailRecipient);
    }
  }

  function addNode(type: DesignerNodeType, x: number, y: number) {
    const id = `n-${Date.now()}`;
    const name = defaultNodeName(type);
    const node: DesignerNode = {
      id,
      type,
      name,
      x,
      y,
      status: "idle",
      config: {
        description: `${name} added from palette.`,
        conditionLogic: type === "condition" ? "risk_score >= 90" : "",
        actionSettings: type === "action" ? "Use existing backend-safe playbook command adapter" : "",
        emailRecipient: type === "gmailReport" ? notifyEmail : "",
        severityThreshold: "critical",
        riskScoreThreshold: 90,
        entityFields: "src_ip, dst_ip, user, domain",
        timeoutSeconds: 900,
        retryCount: 1,
        onSuccessPath: "success",
        onFailurePath: "failure"
      }
    };
    updatePlaybook({ nodes: [...playbook.nodes, node] });
    setSelectedNodeId(id);
  }

  function connect(source: string, target: string, label: DesignerEdgeLabel) {
    const issue = validateConnection(playbook.nodes, { source, target });
    if (issue) {
      setToast(issue);
      return;
    }
    const edge = { id: `${source}-${target}-${label}-${Date.now()}`, source, target, label };
    updatePlaybook({ edges: [...playbook.edges, edge] });
  }

  function deleteNode(nodeId: string) {
    updatePlaybook({
      nodes: playbook.nodes.filter((node) => node.id !== nodeId),
      edges: playbook.edges.filter((edge) => edge.source !== nodeId && edge.target !== nodeId)
    });
    setSelectedNodeId(null);
  }

  function save() {
    const clean = {
      ...playbook,
      name: sanitizeDesignerText(playbook.name),
      description: sanitizeDesignerText(playbook.description),
      updatedAt: new Date().toISOString()
    };
    window.localStorage.setItem(storageKey, JSON.stringify(clean));
    setPlaybook(clean);
    setToast(warnings.length ? `Saved with ${warnings.length} warning(s).` : "Visual playbook saved.");
  }

  async function run() {
    if (warnings.some((warning) => warning.includes("No trigger"))) {
      setToast("Cannot run: add a trigger node first.");
      return;
    }
    const ordered = executionOrder(playbook);
    setLogs([]);
    for (const node of ordered) {
      setPlaybook((current) => ({ ...current, nodes: current.nodes.map((item) => item.id === node.id ? { ...item, status: "running" } : item) }));
      await delay(260);
      setPlaybook((current) => ({ ...current, nodes: current.nodes.map((item) => item.id === node.id ? { ...item, status: "success" } : item) }));
      setLogs((current) => [
        {
          id: `${node.id}-${Date.now()}`,
          timestamp: new Date().toISOString(),
          nodeName: node.name,
          input: node.config.entityFields || "incident context",
          output: node.type === "gmailReport" ? `Prepared report email to ${notifyEmail}` : "completed",
          status: "success"
        },
        ...current
      ]);
    }
    try {
      await onRun();
      setToast("Existing backend playbook executed. Gmail/Brevo incident report preserved.");
    } catch (error) {
      setToast(error instanceof Error ? error.message : "Backend playbook run failed.");
      markLastNodeFailed();
    }
  }

  function markLastNodeFailed() {
    const last = executionOrder(playbook).at(-1);
    if (!last) return;
    setPlaybook((current) => ({ ...current, nodes: current.nodes.map((node) => node.id === last.id ? { ...node, status: "failed" } : node) }));
  }

  return (
    <section className="mx-auto max-w-[1500px] px-6 pb-10">
      <div className="mb-5 grid grid-cols-1 gap-4 lg:grid-cols-4">
        <DesignerMetric icon={<Workflow />} label="Total playbooks" value={1} />
        <DesignerMetric icon={<CheckCircle2 />} label="Active playbooks" value={playbook.status === "active" ? 1 : 0} />
        <DesignerMetric icon={<ShieldAlert />} label="Total runs" value={playbook.runHistory.length + (activeRun ? 1 : 0)} />
        <DesignerMetric icon={<AlertTriangle />} label="Success rate" value={`${successRate}%`} />
      </div>

      <div className="overflow-hidden rounded border border-fortress-line bg-fortress-panel">
        <PlaybookToolbar
          active={playbook.status === "active"}
          canApprove={Boolean(activeRunId && runState === "waiting for approval")}
          connectMode={connectMode}
          onApprove={onApprove}
          onDeactivate={() => updatePlaybook({ status: playbook.status === "active" ? "inactive" : "active" })}
          onFit={() => { setZoom(0.78); setPan({ x: 30, y: 80 }); }}
          onReject={onReject}
          onRun={run}
          onSave={save}
          onToggleConnect={() => { setConnectMode(!connectMode); setConnectSourceId(null); }}
          onZoomIn={() => setZoom((value) => Math.min(1.4, value + 0.1))}
          onZoomOut={() => setZoom((value) => Math.max(0.45, value - 0.1))}
          runState={runState}
        />
        <div className="grid grid-cols-1 gap-4 p-4 xl:grid-cols-[260px_1fr_360px]">
          <NodePalette query={paletteQuery} onQuery={setPaletteQuery} />
          <PlaybookCanvas
            connectMode={connectMode}
            connectSourceId={connectSourceId}
            edges={playbook.edges}
            nodes={playbook.nodes}
            onAddNode={addNode}
            onConnect={connect}
            onContextNode={(nodeId, x, y) => setContextMenu({ nodeId, x, y })}
            onDeleteNode={deleteNode}
            onMoveNode={(nodeId, x, y) => updatePlaybook({ nodes: playbook.nodes.map((node) => node.id === nodeId ? { ...node, x, y } : node) })}
            onPan={setPan}
            onSelectNode={setSelectedNodeId}
            onSetConnectSource={setConnectSourceId}
            pan={pan}
            selectedNodeId={selectedNodeId}
            zoom={zoom}
          />
          <NodeConfigPanel node={selectedNode} onClose={() => setSelectedNodeId(null)} onUpdate={updateNode} />
        </div>
      </div>

      <div className="mt-5 grid grid-cols-1 gap-5 xl:grid-cols-[1.2fr_0.8fr]">
        <ExecutionLogPanel logs={logs} warnings={warnings} />
        <section className="rounded border border-fortress-line bg-fortress-panel">
          <div className="border-b border-fortress-line p-4">
            <h3 className="text-lg font-semibold text-white">Incident Report Delivery</h3>
            <p className="text-sm text-[#9fb0c2]">Existing backend Gmail/Brevo report logic is reused unchanged.</p>
          </div>
          <div className="grid gap-3 p-4 text-sm">
            <Field label="Operator" value={operator} />
            <EditableEmail value={notifyEmail} onChange={setNotifyEmail} />
            <Field label="Delivery state" value={activeRun?.notification?.status ?? "ready"} />
            <Field label="Run ID" value={activeRun?.run_id ?? "not run yet"} />
            <pre className="max-h-72 overflow-auto rounded bg-[#080c12] p-4 text-xs leading-5 text-[#c7d4e2]">
              {activeRun?.report?.body?.split("\n").slice(0, 16).join("\n") ?? "Run Now will call the existing backend playbook and send the incident report to the configured email."}
            </pre>
          </div>
        </section>
      </div>

      {toast && (
        <button className="fixed bottom-5 right-5 z-50 rounded border border-fortress-line bg-[#0b1017] px-4 py-3 text-sm text-white shadow-xl" onClick={() => setToast("")}>{toast}</button>
      )}
      {contextMenu && (
        <div className="fixed z-50 rounded border border-fortress-line bg-[#0b1017] p-2 text-sm shadow-xl" style={{ left: contextMenu.x, top: contextMenu.y }}>
          <button className="block w-full px-3 py-2 text-left text-[#c7d4e2] hover:text-white" onClick={() => { setSelectedNodeId(contextMenu.nodeId); setContextMenu(null); }}>Edit node</button>
          <button className="block w-full px-3 py-2 text-left text-fortress-red" onClick={() => { deleteNode(contextMenu.nodeId); setContextMenu(null); }}>Delete node</button>
        </div>
      )}
    </section>
  );
}

function executionOrder(playbook: DesignerPlaybook): DesignerNode[] {
  const trigger = playbook.nodes.find((node) => node.type === "trigger") ?? playbook.nodes[0];
  if (!trigger) return [];
  const order: DesignerNode[] = [];
  const seen = new Set<string>();
  let current: DesignerNode | undefined = trigger;
  while (current && !seen.has(current.id)) {
    order.push(current);
    seen.add(current.id);
    const edge = playbook.edges.find((item) => item.source === current?.id);
    current = playbook.nodes.find((node) => node.id === edge?.target);
  }
  return order.length ? order : playbook.nodes;
}

function defaultNodeName(type: DesignerNodeType): string {
  return {
    trigger: "New Trigger",
    condition: "New Condition",
    action: "New Action",
    manualApproval: "Manual Approval",
    delay: "Wait",
    notification: "Notification",
    gmailReport: "Gmail Incident Report",
    end: "End"
  }[type];
}

function delay(ms: number) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function DesignerMetric({ icon, label, value }: { icon: ReactNode; label: string; value: number | string }) {
  return (
    <div className="rounded border border-fortress-line bg-fortress-panel p-4">
      <div className="flex items-center justify-between">
        <span className="text-fortress-cyan [&_svg]:h-5 [&_svg]:w-5">{icon}</span>
        <span className="text-2xl font-semibold text-white">{value}</span>
      </div>
      <p className="mt-3 text-sm text-[#9fb0c2]">{label}</p>
    </div>
  );
}

function Field({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded border border-fortress-line bg-[#0b1017] px-3 py-2">
      <span className="text-[#9fb0c2]">{label}</span>
      <p className="mt-1 break-all text-white">{value}</p>
    </div>
  );
}

function EditableEmail({ value, onChange }: { value: string; onChange: (value: string) => void }) {
  return (
    <label className="rounded border border-fortress-line bg-[#0b1017] px-3 py-2">
      <span className="text-[#9fb0c2]">Report email</span>
      <div className="mt-1 flex items-center gap-2">
        <Mail className="h-4 w-4 text-fortress-cyan" />
        <input className="w-full bg-transparent text-white outline-none" value={value} onChange={(event) => onChange(event.target.value)} />
      </div>
    </label>
  );
}
