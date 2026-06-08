import type { PlaybookRunResult } from "@/lib/types";

export type DesignerNodeType =
  | "trigger"
  | "condition"
  | "action"
  | "manualApproval"
  | "delay"
  | "notification"
  | "gmailReport"
  | "end";

export type DesignerNodeStatus = "idle" | "running" | "success" | "failed" | "skipped";

export type DesignerNodeConfig = {
  description: string;
  conditionLogic?: string;
  actionSettings?: string;
  emailRecipient?: string;
  severityThreshold?: string;
  riskScoreThreshold?: number;
  entityFields?: string;
  timeoutSeconds?: number;
  retryCount?: number;
  onSuccessPath?: string;
  onFailurePath?: string;
};

export type DesignerNode = {
  id: string;
  type: DesignerNodeType;
  name: string;
  x: number;
  y: number;
  status: DesignerNodeStatus;
  config: DesignerNodeConfig;
};

export type DesignerEdgeLabel = "success" | "failure" | "true" | "false" | "escalation";

export type DesignerEdge = {
  id: string;
  source: string;
  target: string;
  label: DesignerEdgeLabel;
};

export type DesignerPlaybook = {
  id: string;
  name: string;
  description: string;
  status: "active" | "inactive";
  nodes: DesignerNode[];
  edges: DesignerEdge[];
  createdAt: string;
  updatedAt: string;
  lastRunAt?: string;
  runHistory: Array<{
    runId: string;
    status: string;
    timestamp: string;
  }>;
};

export type ExecutionLogEntry = {
  id: string;
  timestamp: string;
  nodeName: string;
  input: string;
  output: string;
  status: DesignerNodeStatus;
  error?: string;
};

export type PlaybookDesignerProps = {
  activeRun: PlaybookRunResult | null;
  activeRunId: string | null;
  notifyEmail: string;
  operator: string;
  runState: string;
  setNotifyEmail: (value: string) => void;
  onApprove: () => void;
  onReject: () => void;
  onRun: () => Promise<void>;
};
