import { Bell, Clock, Diamond, Flag, GitBranch, Mail, MousePointer2, ShieldCheck, Zap } from "lucide-react";
import type { ReactNode } from "react";
import type { DesignerNodeType } from "./playbookTypes";

const nodeTypes: Array<{ type: DesignerNodeType; name: string; description: string; icon: ReactNode }> = [
  { type: "trigger", name: "Trigger Node", description: "Start a playbook from an alert", icon: <Flag /> },
  { type: "condition", name: "Condition Node", description: "Branch on risk, severity, entity", icon: <GitBranch /> },
  { type: "action", name: "Action Node", description: "Run containment or enrichment action", icon: <Zap /> },
  { type: "manualApproval", name: "Manual Approval Node", description: "SOC manager gate", icon: <ShieldCheck /> },
  { type: "delay", name: "Delay/Wait Node", description: "Pause for a timeout or SLA", icon: <Clock /> },
  { type: "notification", name: "Notification Node", description: "Notify stakeholders", icon: <Bell /> },
  { type: "gmailReport", name: "Gmail Incident Report Node", description: "Reuse existing Gmail report sender", icon: <Mail /> },
  { type: "end", name: "End Node", description: "Stop workflow", icon: <Diamond /> }
];

export function NodePalette({ query, onQuery }: { query: string; onQuery: (value: string) => void }) {
  const filtered = nodeTypes.filter((node) => `${node.name} ${node.description}`.toLowerCase().includes(query.toLowerCase()));
  return (
    <aside className="rounded border border-fortress-line bg-fortress-panel">
      <div className="border-b border-fortress-line p-4">
        <h3 className="text-sm font-semibold text-white">Node Palette</h3>
        <div className="mt-3 flex items-center gap-2 rounded border border-fortress-line bg-[#0b1017] px-3 py-2">
          <MousePointer2 className="h-4 w-4 text-fortress-cyan" />
          <input className="w-full bg-transparent text-sm text-white outline-none" placeholder="Search nodes" value={query} onChange={(event) => onQuery(event.target.value)} />
        </div>
      </div>
      <div className="grid gap-2 p-3">
        {filtered.map((node) => (
          <div
            className="cursor-grab rounded border border-fortress-line bg-[#0b1017] p-3 transition hover:border-fortress-cyan"
            draggable
            key={node.type}
            onDragStart={(event) => event.dataTransfer.setData("application/x-playbook-node", node.type)}
            title={node.description}
          >
            <div className="flex items-center gap-2 text-sm font-semibold text-white">
              <span className="text-fortress-cyan [&_svg]:h-4 [&_svg]:w-4">{node.icon}</span>
              {node.name}
            </div>
            <p className="mt-1 text-xs text-[#9fb0c2]">{node.description}</p>
          </div>
        ))}
      </div>
    </aside>
  );
}
