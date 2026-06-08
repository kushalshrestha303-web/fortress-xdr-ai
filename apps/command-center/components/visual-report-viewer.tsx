"use client";

import { useEffect, useState } from "react";
import { Download, Shield } from "lucide-react";

import { reportExportUrl } from "@/lib/api";

export function VisualReportViewer({ reportId }: { reportId: string }) {
  const [html, setHtml] = useState("");
  const [status, setStatus] = useState("loading visual report");

  useEffect(() => {
    let cancelled = false;
    fetch(reportExportUrl(reportId, "html"), { cache: "no-store" })
      .then((response) => {
        if (!response.ok) {
          throw new Error(`Report failed with ${response.status}`);
        }
        return response.text();
      })
      .then((body) => {
        if (!cancelled) {
          setHtml(body);
          setStatus("ready");
        }
      })
      .catch((error) => {
        if (!cancelled) {
          setStatus(error instanceof Error ? error.message : "report failed");
        }
      });
    return () => {
      cancelled = true;
    };
  }, [reportId]);

  return (
    <main className="min-h-screen bg-fortress-bg text-[#e6edf6]">
      <header className="border-b border-fortress-line bg-[#0b1017]">
        <div className="mx-auto flex max-w-7xl flex-col gap-4 px-6 py-5 md:flex-row md:items-center md:justify-between">
          <div>
            <p className="text-sm uppercase text-fortress-cyan">Nepal Fortress ONE</p>
            <h1 className="mt-1 text-2xl font-semibold text-white">AI Log Attack Analyzer Visual Report</h1>
            <p className="mt-2 text-sm text-[#9fb0c2]">Report ID: {reportId}</p>
          </div>
          <div className="flex flex-wrap gap-3">
            <a className="flex items-center gap-2 rounded border border-fortress-line px-4 py-2 text-sm text-[#c7d4e2]" href="/">
              <Shield className="h-4 w-4 text-fortress-cyan" />
              SOC Command Center
            </a>
            <a
              className="flex items-center gap-2 rounded bg-fortress-cyan px-4 py-2 text-sm font-semibold text-[#071016]"
              href={reportExportUrl(reportId, "html")}
              target="_blank"
              rel="noreferrer"
            >
              <Download className="h-4 w-4" />
              Open Raw HTML
            </a>
          </div>
        </div>
      </header>
      <section className="mx-auto max-w-7xl px-6 py-6">
        {html ? (
          <iframe
            className="h-[78vh] w-full rounded border border-fortress-line bg-white"
            sandbox=""
            srcDoc={html}
            title="AI Log Attack Analyzer Visual Report"
          />
        ) : (
          <div className="rounded border border-fortress-line bg-fortress-panel p-8 text-center text-[#9fb0c2]">
            {status}
          </div>
        )}
      </section>
    </main>
  );
}
