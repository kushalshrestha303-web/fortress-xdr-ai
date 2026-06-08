import { Activity, Maximize2, Minus, PlayCircle, Plus, Save, ToggleLeft, ToggleRight } from "lucide-react";

export function PlaybookToolbar({
  active,
  canApprove,
  connectMode,
  runState,
  onApprove,
  onDeactivate,
  onFit,
  onReject,
  onRun,
  onSave,
  onToggleConnect,
  onZoomIn,
  onZoomOut
}: {
  active: boolean;
  canApprove: boolean;
  connectMode: boolean;
  runState: string;
  onApprove: () => void;
  onDeactivate: () => void;
  onFit: () => void;
  onReject: () => void;
  onRun: () => void;
  onSave: () => void;
  onToggleConnect: () => void;
  onZoomIn: () => void;
  onZoomOut: () => void;
}) {
  return (
    <div className="flex flex-wrap items-center justify-between gap-3 border-b border-fortress-line bg-[#0b1017] px-4 py-3">
      <div className="flex flex-wrap gap-2">
        <button className="toolbar-primary" onClick={onRun}><PlayCircle className="h-4 w-4" />Run Now</button>
        <button className="toolbar-button" onClick={onSave}><Save className="h-4 w-4" />Save</button>
        <button className="toolbar-button" onClick={onDeactivate}>{active ? <ToggleRight className="h-4 w-4" /> : <ToggleLeft className="h-4 w-4" />}{active ? "Deactivate" : "Activate"}</button>
        <button className={connectMode ? "toolbar-active" : "toolbar-button"} onClick={onToggleConnect}><Activity className="h-4 w-4" />Connect Nodes</button>
      </div>
      <div className="flex flex-wrap gap-2">
        <button className="toolbar-button" onClick={onZoomOut}><Minus className="h-4 w-4" />Zoom</button>
        <button className="toolbar-button" onClick={onZoomIn}><Plus className="h-4 w-4" />Zoom</button>
        <button className="toolbar-button" onClick={onFit}><Maximize2 className="h-4 w-4" />Fit</button>
        <button className="toolbar-success" disabled={!canApprove} onClick={onApprove}>Approve</button>
        <button className="toolbar-danger" disabled={!canApprove} onClick={onReject}>Reject</button>
        <span className="rounded border border-fortress-line px-3 py-2 text-sm text-fortress-amber">{runState}</span>
      </div>
    </div>
  );
}
