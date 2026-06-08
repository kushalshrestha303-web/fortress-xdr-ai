export function Reports({ investigation }) {
  if (!investigation) {
    return <section className="panel"><h2>Reports</h2><p>Run an investigation to generate analyst and executive reports.</p></section>;
  }
  return (
    <section className="reports-grid">
      <section className="panel">
        <h2>Analyst Report</h2>
        <DownloadButton filename="fortress-xdr-ai-analyst-report.md" text={investigation.analyst_report} />
        <pre>{investigation.analyst_report}</pre>
      </section>
      <section className="panel">
        <h2>Executive Summary</h2>
        <DownloadButton filename="fortress-xdr-ai-executive-summary.md" text={investigation.executive_summary} />
        {investigation.executive_report && (
          <div className="executive-fields">
            <div>
              <span>Business Impact</span>
              <b>{investigation.executive_report.business_impact}</b>
            </div>
            <div>
              <span>Severity</span>
              <b>{investigation.executive_report.severity}</b>
            </div>
            <div>
              <span>Affected Assets</span>
              <b>{(investigation.executive_report.affected_assets || []).join(", ")}</b>
            </div>
          </div>
        )}
        <pre>{investigation.executive_summary}</pre>
      </section>
    </section>
  );
}

function DownloadButton({ filename, text }) {
  function download() {
    const url = URL.createObjectURL(new Blob([text], { type: "text/markdown" }));
    const link = document.createElement("a");
    link.href = url;
    link.download = filename;
    link.click();
    URL.revokeObjectURL(url);
  }
  return <button onClick={download}>Download Markdown</button>;
}
