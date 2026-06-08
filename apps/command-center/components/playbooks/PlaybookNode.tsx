import { Bell, Clock, Diamond, Flag, GitBranch, Mail, Pencil, ShieldCheck, Trash2, Zap } from "lucide-react";
import type { MouseEvent, ReactNode } from "react";
import type { DesignerNode, DesignerNodeType } from "./playbookTypes";

const icons: Record<DesignerNodeType, ReactNode> = {
  trigger: <Flag />,
  condition: <GitBranch />,
  action: <Zap />,
  manualApproval: <ShieldCheck />,
  delay: <Clock />,
  notification: <Bell />,
  gmailReport: <Mail />,
  end: <Diamond />
};

const typeLabel: Record<DesignerNodeType, string> = {
  trigger: "Trigger",
  condition: "Condition",
  action: "Action",
  manualApproval: "Manual Approval",
  delay: "Delay/Wait",
  notification: "Notification",
  gmailReport: "Gmail Report",
  end: "End"
};

export function PlaybookNode({
  node,
  selected,
  connectSource,
  onDelete,
  onEdit,
  onMouseDown,
  onSelect
}: {
  node: DesignerNode;
  selected: boolean;
  connectSource: boolean;
  onDelete: () => void;
  onEdit: () => void;
  onMouseDown: (event: MouseEvent<HTMLDivElement>) => void;
  onSelect: () => void;
}) {
  return (
    <div
      className={`absolute w-56 rounded border bg-[#10151d] p-3 shadow-lg transition ${
        selected ? "border-fortress-cyan shadow-cyan-500/20" : "border-fortress-line"
      } ${connectSource ? "ring-2 ring-fortress-amber" : ""} ${node.status === "running" ? "animate-pulse" : ""}`}
      onClick={(event) => {
        event.stopPropagation();
        onSelect();
      }}
      onMouseDown={onMouseDown}
      style={{ left: node.x, top: node.y }}
      title={node.config.description}
    >
      <div className="flex items-start justify-between gap-2">
        <div className="flex items-center gap-2">
          <span className="text-fortress-cyan [&_svg]:h-4 [&_svg]:w-4">{icons[node.type]}</span>
          <div>
            <p className="text-sm font-semibold text-white">{node.name}</p>
            <p className="text-xs text-[#9fb0c2]">{typeLabel[node.type]}</p>
          </div>
        </div>
        <StatusDot status={node.status} />
      </div>
      <p className="mt-3 line-clamp-2 text-xs leading-5 text-[#9fb0c2]">{node.config.description || "No description configured."}</p>
      <div className="mt-3 rounded border border-fortress-line bg-[#0b1017] px-2 py-1 text-[11px] text-[#c7d4e2]">
        {node.type === "gmailReport" ? `Email: ${node.config.emailRecipient || "not set"}` : node.config.conditionLogic || node.config.actionSettings || "Config ready"}
      </div>
      <div className="mt-3 flex justify-end gap-2">
        <button className="rounded border border-fortress-line p-1 text-[#9fb0c2] hover:text-white" onClick={(event) => { event.stopPropagation(); onEdit(); }} title="Edit node">
          <Pencil className="h-3.5 w-3.5" />
        </button>
        <button className="rounded border border-fortress-line p-1 text-fortress-red hover:bg-[#1a0c10]" onClick={(event) => { event.stopPropagation(); onDelete(); }} title="Delete node">
          <Trash2 className="h-3.5 w-3.5" />
        </button>
      </div>
    </div>
  );
}

function StatusDot({ status }: { status: DesignerNode["status"] }) {
  const color = status === "success" ? "bg-fortress-green" : status === "failed" ? "bg-fortress-red" : status === "running" ? "bg-fortress-amber" : status === "skipped" ? "bg-[#657386]" : "bg-[#27313f]";
  return <span className={`mt-1 h-2.5 w-2.5 rounded-full ${color}`} title={status} />;
}
