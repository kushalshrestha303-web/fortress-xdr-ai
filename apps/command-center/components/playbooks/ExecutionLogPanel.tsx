import type { ExecutionLogEntry } from "./playbookTypes";

export function ExecutionLogPanel({ logs, warnings }: { logs: ExecutionLogEntry[]; warnings: string[] }) {
  return (
    <section className="rounded border border-fortress-line bg-fortress-panel">
      <div className="border-b border-fortress-line p-4">
        <h3 className="text-lg font-semibold text-white">Execution Logs</h3>
        <p className="text-sm text-[#9fb0c2]">Step-by-step visual execution adapter. Backend Gmail report delivery still uses the existing API.</p>
      </div>
      {warnings.length > 0 && (
        <div className="border-b border-fortress-line bg-[#160f08] p-4">
          <p className="text-sm font-semibold text-fortress-amber">Validation warnings</p>
          <ul className="mt-2 list-disc pl-5 text-xs text-[#f5d79a]">
            {warnings.map((warning) => <li key={warning}>{warning}</li>)}
          </ul>
        </div>
      )}
      <div className="max-h-96 overflow-auto">
        {logs.length === 0 ? (
          <div className="p-6 text-center text-sm text-[#9fb0c2]">No execution logs yet. Click Run Now to animate the visual workflow and call the existing backend playbook run.</div>
        ) : (
          logs.map((log) => (
            <div className="grid gap-2 border-b border-fortress-line p-4 text-sm" key={log.id}>
              <div className="flex flex-wrap items-center justify-between gap-2">
                <p className="font-semibold text-white">{log.nodeName}</p>
                <span className={log.status === "failed" ? "text-fortress-red" : log.status === "success" ? "text-fortress-green" : "text-fortress-amber"}>{log.status}</span>
              </div>
              <p className="text-xs text-[#9fb0c2]">{log.timestamp}</p>
              <p className="text-xs text-[#c7d4e2]">Input: {log.input}</p>
              <p className="text-xs text-[#c7d4e2]">Output: {log.output}</p>
              {log.error && <p className="text-xs text-fortress-red">Error: {log.error}</p>}
            </div>
          ))
        )}
      </div>
    </section>
  );
}
