import type { PlaybookTask } from "@/lib/types";
import type { DesignerEdge, DesignerNode, DesignerPlaybook } from "./playbookTypes";

const now = () => new Date().toISOString();

export function defaultDesignerPlaybook(email: string): DesignerPlaybook {
  return {
    id: "high-risk-incident-response-designer",
    name: "Enterprise High-Risk Incident Response",
    description: "Visual designer adapter for the existing Nepal Fortress ONE high-risk incident playbook.",
    status: "active",
    nodes: [
      node("n-trigger", "trigger", "Incident Trigger", 80, 140, "Critical alert enters SOAR workflow"),
      node("n-score", "action", "Normalize and Score", 330, 110, "Normalize incident context and calculate risk"),
      node("n-condition", "condition", "Containment Impact?", 590, 120, "severity == critical OR sector is protected"),
      node("n-approval", "manualApproval", "SOC Lead Approval", 860, 95, "Approval gate before high-impact containment"),
      node("n-contain", "action", "Contain Assets", 1130, 120, "NGFW, DNS, XDR, IAM and ZTNA containment"),
      node("n-report", "gmailReport", "Gmail Incident Report", 1390, 120, "Send incident report using existing backend mail path", email),
      node("n-end", "end", "Close Case", 1660, 145, "Update case summary and monitoring window")
    ],
    edges: [
      edge("n-trigger", "n-score", "success"),
      edge("n-score", "n-condition", "success"),
      edge("n-condition", "n-approval", "true"),
      edge("n-condition", "n-report", "false"),
      edge("n-approval", "n-contain", "success"),
      edge("n-contain", "n-report", "success"),
      edge("n-report", "n-end", "success")
    ],
    createdAt: now(),
    updatedAt: now(),
    runHistory: []
  };
}

export function mergeRunTasksIntoDesigner(nodes: DesignerNode[], tasks: PlaybookTask[]): DesignerNode[] {
  if (!tasks.length) return nodes;
  const latestByName = new Map(tasks.map((task) => [task.name.toLowerCase(), task.status]));
  return nodes.map((node) => {
    const match = [...latestByName.entries()].find(([name]) => name.includes(node.name.toLowerCase().split(" ")[0]));
    if (!match) return node;
    return { ...node, status: normalizeStatus(match[1]) };
  });
}

function normalizeStatus(status: string) {
  if (status.includes("failed") || status.includes("rejected")) return "failed";
  if (status.includes("waiting") || status.includes("queued")) return "idle";
  if (status.includes("skipped")) return "skipped";
  if (status.includes("running")) return "running";
  return "success";
}

function node(id: string, type: DesignerNode["type"], name: string, x: number, y: number, description: string, email?: string): DesignerNode {
  return {
    id,
    type,
    name,
    x,
    y,
    status: "idle",
    config: {
      description,
      conditionLogic: type === "condition" ? "severity == critical OR risk_score >= 90" : "",
      actionSettings: type === "action" ? "Use existing backend playbook execution service" : "",
      emailRecipient: email,
      severityThreshold: "critical",
      riskScoreThreshold: 90,
      entityFields: "src_ip, dst_ip, user, domain, endpoint_id",
      timeoutSeconds: 900,
      retryCount: 1,
      onSuccessPath: "success",
      onFailurePath: "failure"
    }
  };
}

function edge(source: string, target: string, label: DesignerEdge["label"]): DesignerEdge {
  return { id: `${source}-${target}-${label}`, source, target, label };
}
