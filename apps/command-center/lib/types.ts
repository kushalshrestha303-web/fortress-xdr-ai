export type Sector = "government" | "bank" | "hospital" | "telecom" | "enterprise" | "critical-infrastructure";

export type NgfwLog = {
  event_id: string;
  timestamp: string;
  tenant_id: string;
  sector: Sector;
  sensor_id: string;
  src_ip: string;
  dst_ip: string;
  protocol: string;
  application: string;
  action: "allowed" | "blocked" | "alerted" | "quarantined";
  dpi?: {
    tls_sni?: string;
    http_host?: string;
    file_type?: string;
    payload_sha256?: string;
    user_agent?: string;
  };
  ips?: {
    signature?: string;
    severity?: "info" | "low" | "medium" | "high" | "critical";
    cve?: string;
    blocked?: boolean;
  };
  bytes_in: number;
  bytes_out: number;
  risk_score: number;
  metrics?: {
    dpi_observed: boolean;
    ips_triggered: boolean;
    application_filtered: boolean;
  };
};

export type LiveEvent = NgfwLog | {
  stream: string;
  event_id?: string;
  tenant_id?: string;
  sector?: Sector;
  severity?: string;
  risk_score?: number;
  event_type?: string;
  run_id?: string;
  incident_id?: string;
  task?: {
    name: string;
    status: string;
    detail: string;
    task_id?: string;
    task_type?: string;
    commands?: string[];
    outputs?: Record<string, unknown>;
  };
};

export type PlaybookTask = {
  task_id: string;
  task_type: string;
  name: string;
  status: string;
  detail: string;
  commands: string[];
  outputs: Record<string, unknown>;
  timestamp: string;
};

export type PlaybookRunResult = {
  run_id: string;
  incident_id: string;
  tenant_id: string;
  status: string;
  context: Record<string, unknown>;
  evidence: Array<{ type: string; value: unknown }>;
  notification: {
    status: string;
    recipient: string;
    detail: string;
  };
  report: {
    subject: string;
    recipient: string;
    body: string;
  };
  tasks: PlaybookTask[];
};

export type ParsedLogEvent = {
  event_id: string;
  timestamp: string;
  source_ip?: string | null;
  destination_ip?: string | null;
  protocol: string;
  info: string;
  severity: "info" | "low" | "medium" | "high" | "critical";
  raw: string;
};

export type LogFinding = {
  finding_id: string;
  attack_type: string;
  severity: "low" | "medium" | "high" | "critical";
  confidence: number;
  source?: string | null;
  destination?: string | null;
  evidence: string[];
  mitre: string[];
};

export type LogAnalysisResult = {
  report_id: string;
  upload_id: string;
  created_at: string;
  events: ParsedLogEvent[];
  findings: LogFinding[];
  summary: {
    attack_type: string;
    source?: string | null;
    destination?: string | null;
    business_impact: string;
    recommended_mitigation: string[];
    indicators_of_compromise: string[];
  };
  diagram: {
    mermaid: string;
    nodes: string[];
    edges: Array<{ from: string; to: string; label: string }>;
  };
  charts: {
    packet_count_over_time: Array<{ time: string; count: number }>;
    top_source_ips: Array<{ ip: string; count: number }>;
    protocol_distribution: Array<{ protocol: string; count: number }>;
    severity_breakdown: Array<{ severity: string; count: number }>;
    attack_timeline: Array<{ attack_type: string; severity: string; confidence: number }>;
  };
  report: Record<string, string | unknown[]>;
  notification?: {
    status: string;
    recipient: string;
    detail: string;
  };
  download_links?: {
    visual_page?: string;
    html: string;
    pdf: string;
    diagram_svg: string;
    csv: string;
    markdown: string;
  };
};
