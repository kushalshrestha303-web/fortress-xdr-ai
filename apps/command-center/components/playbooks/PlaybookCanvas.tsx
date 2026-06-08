import { useRef, useState } from "react";
import type { MouseEvent } from "react";
import { PlaybookNode } from "./PlaybookNode";
import type { DesignerEdge, DesignerEdgeLabel, DesignerNode, DesignerNodeType } from "./playbookTypes";
import { validateConnection } from "./playbookValidation";

const nodeWidth = 224;
const nodeHeight = 148;

export function PlaybookCanvas({
  connectMode,
  connectSourceId,
  edges,
  nodes,
  pan,
  selectedNodeId,
  zoom,
  onAddNode,
  onConnect,
  onContextNode,
  onDeleteNode,
  onMoveNode,
  onPan,
  onSelectNode,
  onSetConnectSource
}: {
  connectMode: boolean;
  connectSourceId: string | null;
  edges: DesignerEdge[];
  nodes: DesignerNode[];
  pan: { x: number; y: number };
  selectedNodeId: string | null;
  zoom: number;
  onAddNode: (type: DesignerNodeType, x: number, y: number) => void;
  onConnect: (source: string, target: string, label: DesignerEdgeLabel) => void;
  onContextNode: (nodeId: string, x: number, y: number) => void;
  onDeleteNode: (nodeId: string) => void;
  onMoveNode: (nodeId: string, x: number, y: number) => void;
  onPan: (pan: { x: number; y: number }) => void;
  onSelectNode: (nodeId: string | null) => void;
  onSetConnectSource: (nodeId: string | null) => void;
}) {
  const canvasRef = useRef<HTMLDivElement | null>(null);
  const [dragging, setDragging] = useState<{ nodeId: string; dx: number; dy: number } | null>(null);
  const [panning, setPanning] = useState<{ x: number; y: number; startX: number; startY: number } | null>(null);

  function canvasPoint(clientX: number, clientY: number) {
    const rect = canvasRef.current?.getBoundingClientRect();
    return {
      x: ((clientX - (rect?.left ?? 0)) - pan.x) / zoom,
      y: ((clientY - (rect?.top ?? 0)) - pan.y) / zoom
    };
  }

  function handleNodeClick(nodeId: string) {
    if (!connectMode) {
      onSelectNode(nodeId);
      return;
    }
    if (!connectSourceId) {
      onSetConnectSource(nodeId);
      return;
    }
    if (connectSourceId === nodeId) {
      onSetConnectSource(null);
      return;
    }
    const issue = validateConnection(nodes, { source: connectSourceId, target: nodeId });
    if (!issue) onConnect(connectSourceId, nodeId, "success");
    onSetConnectSource(null);
  }

  return (
    <div
      className="relative h-[660px] overflow-hidden rounded border border-fortress-line bg-[#070b10]"
      onClick={() => onSelectNode(null)}
      onContextMenu={(event) => event.preventDefault()}
      onDragOver={(event) => event.preventDefault()}
      onDrop={(event) => {
        event.preventDefault();
        const type = event.dataTransfer.getData("application/x-playbook-node") as DesignerNodeType;
        if (!type) return;
        const point = canvasPoint(event.clientX, event.clientY);
        onAddNode(type, Math.max(20, point.x), Math.max(20, point.y));
      }}
      onMouseDown={(event) => {
        if (event.button !== 1 && !event.altKey) return;
        setPanning({ x: pan.x, y: pan.y, startX: event.clientX, startY: event.clientY });
      }}
      onMouseMove={(event) => {
        if (dragging) {
          const point = canvasPoint(event.clientX, event.clientY);
          onMoveNode(dragging.nodeId, Math.max(0, point.x - dragging.dx), Math.max(0, point.y - dragging.dy));
        }
        if (panning) {
          onPan({ x: panning.x + event.clientX - panning.startX, y: panning.y + event.clientY - panning.startY });
        }
      }}
      onMouseUp={() => {
        setDragging(null);
        setPanning(null);
      }}
      ref={canvasRef}
    >
      <div className="absolute inset-0 opacity-40" style={{ backgroundImage: "linear-gradient(#27313f 1px, transparent 1px), linear-gradient(90deg, #27313f 1px, transparent 1px)", backgroundSize: `${24 * zoom}px ${24 * zoom}px`, backgroundPosition: `${pan.x}px ${pan.y}px` }} />
      <div className="absolute left-3 top-3 z-20 rounded border border-fortress-line bg-[#0b1017] px-3 py-2 text-xs text-[#9fb0c2]">
        Drag palette nodes here. Alt-drag or middle mouse pans. Connect mode links nodes.
      </div>
      <div className="absolute right-3 top-3 z-20 h-28 w-44 rounded border border-fortress-line bg-[#0b1017]/90 p-2">
        <div className="relative h-full w-full overflow-hidden">
          {nodes.map((node) => (
            <span className="absolute h-2 w-3 rounded-sm bg-fortress-cyan" key={node.id} style={{ left: `${Math.min(94, node.x / 18)}%`, top: `${Math.min(88, node.y / 8)}%` }} />
          ))}
        </div>
      </div>
      <div className="absolute origin-top-left" style={{ transform: `translate(${pan.x}px, ${pan.y}px) scale(${zoom})`, width: 2200, height: 1200 }}>
        <svg className="absolute inset-0 h-full w-full overflow-visible">
          {edges.map((edge) => {
            const source = nodes.find((node) => node.id === edge.source);
            const target = nodes.find((node) => node.id === edge.target);
            if (!source || !target) return null;
            const sx = source.x + nodeWidth;
            const sy = source.y + nodeHeight / 2;
            const tx = target.x;
            const ty = target.y + nodeHeight / 2;
            const mid = Math.max(70, Math.abs(tx - sx) / 2);
            return (
              <g key={edge.id}>
                <path d={`M ${sx} ${sy} C ${sx + mid} ${sy}, ${tx - mid} ${ty}, ${tx} ${ty}`} fill="none" stroke="#36d7d7" strokeWidth="2" />
                <text x={(sx + tx) / 2} y={(sy + ty) / 2 - 8} fill="#f5b84b" fontSize="12">{edge.label}</text>
              </g>
            );
          })}
        </svg>
        {nodes.map((node) => (
          <div
            key={node.id}
            onContextMenu={(event) => {
              event.preventDefault();
              onContextNode(node.id, event.clientX, event.clientY);
            }}
          >
            <PlaybookNode
              connectSource={connectSourceId === node.id}
              node={node}
              onDelete={() => onDeleteNode(node.id)}
              onEdit={() => onSelectNode(node.id)}
              onMouseDown={(event: MouseEvent<HTMLDivElement>) => {
                event.stopPropagation();
                const point = canvasPoint(event.clientX, event.clientY);
                setDragging({ nodeId: node.id, dx: point.x - node.x, dy: point.y - node.y });
              }}
              onSelect={() => handleNodeClick(node.id)}
              selected={selectedNodeId === node.id}
            />
          </div>
        ))}
      </div>
    </div>
  );
}
