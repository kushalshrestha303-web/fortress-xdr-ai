import type { NgfwLog, PlaybookRunResult } from "@/lib/types";

const DEFAULT_API_URL = "/fortress-api";
const API_URL = process.env.NEXT_PUBLIC_API_URL || DEFAULT_API_URL;

async function expectJson(response: Response, url: string) {
  if (response.ok) {
    return response.json();
  }

  const text = await response.text();
  throw new Error(`${url} failed with ${response.status} ${response.statusText}${text ? `: ${text}` : ""}`);
}

export async function fetchRecentNgfwLogs(): Promise<NgfwLog[]> {
  try {
    const response = await fetch(`${API_URL}/api/v1/ngfw/logs/recent`, { cache: "no-store" });
    if (!response.ok) return [];
    const body = await response.json();
    return body.logs ?? [];
  } catch {
    return [];
  }
}

export async function submitNgfwLog(payload: Record<string, unknown>): Promise<{ accepted: boolean; event_id: string; risk_score: number }> {
  const response = await fetch(`${API_URL}/api/v1/ngfw/logs`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload)
  });
  if (!response.ok) {
    throw new Error(`NGFW ingestion failed with ${response.status}`);
  }
  return response.json();
}

export async function runHighRiskPlaybook(payload: Record<string, unknown>): Promise<PlaybookRunResult> {
  const response = await fetch(`${API_URL}/api/v1/playbooks/high-risk-incident-response/run`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload)
  });
  return expectJson(response, `${API_URL}/api/v1/playbooks/high-risk-incident-response/run`);
}

export async function decidePlaybookRun(runId: string, payload: Record<string, unknown>): Promise<PlaybookRunResult> {
  const response = await fetch(`${API_URL}/api/v1/playbooks/runs/${runId}/decision`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload)
  });
  return expectJson(response, `${API_URL}/api/v1/playbooks/runs/${runId}/decision`);
}

export async function uploadLogFile(file: File): Promise<{ upload_id: string; parsed_events: number; events: unknown[] }> {
  const form = new FormData();
  form.append("file", file);
  try {
    const response = await fetch(`${API_URL}/api/security/logs/upload`, {
      method: "POST",
      body: form
    });
    return expectJson(response, `${API_URL}/api/security/logs/upload`);
  } catch (error) {
    if (error instanceof TypeError) {
      throw new Error(`Backend API is unreachable at ${API_URL}. Start the FastAPI backend on the configured API port, then try again.`);
    }
    throw error;
  }
}

export async function analyzeUploadedLog(uploadId: string) {
  const response = await fetch(`${API_URL}/api/security/logs/analyze`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ upload_id: uploadId })
  });
  return expectJson(response, `${API_URL}/api/security/logs/analyze`);
}

export function reportExportUrl(reportId: string, format: "pdf" | "csv" | "diagram.svg" | "markdown" | "html"): string {
  return `${API_URL}/api/security/reports/${reportId}/export/${format}`;
}

export function streamUrl(): string {
  if (API_URL.startsWith("/")) {
    const origin = typeof window !== "undefined" ? window.location.origin : "http://127.0.0.1:3000";
    return `${origin.replace(/^http/, "ws")}${API_URL}/api/v1/stream`;
  }
  const base = API_URL.replace(/^http/, "ws");
  return `${base}/api/v1/stream`;
}
