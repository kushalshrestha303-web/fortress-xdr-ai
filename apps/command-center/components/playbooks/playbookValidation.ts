import type { DesignerEdge, DesignerNode, DesignerPlaybook } from "./playbookTypes";

export function validatePlaybook(playbook: DesignerPlaybook): string[] {
  const warnings: string[] = [];
  const triggerCount = playbook.nodes.filter((node) => node.type === "trigger").length;
  if (triggerCount === 0) warnings.push("No trigger node found.");
  if (triggerCount > 1) warnings.push("Multiple trigger nodes found.");

  const names = new Set<string>();
  for (const node of playbook.nodes) {
    const name = sanitizeDesignerText(node.name).toLowerCase();
    if (names.has(name)) warnings.push(`Duplicate node name: ${node.name}`);
    names.add(name);
    if (!node.config.description.trim()) warnings.push(`${node.name} is missing a description.`);
    if (node.type === "gmailReport" && !node.config.emailRecipient?.includes("@")) {
      warnings.push("Gmail Incident Report node is missing a valid email recipient.");
    }
  }

  for (const node of playbook.nodes) {
    const outgoing = playbook.edges.filter((edge) => edge.source === node.id);
    const incoming = playbook.edges.filter((edge) => edge.target === node.id);
    if (node.type === "end" && outgoing.length > 0) warnings.push("End node must not have outgoing edges.");
    if (node.type !== "trigger" && incoming.length === 0) warnings.push(`Orphan node without incoming edge: ${node.name}`);
  }

  for (const edge of playbook.edges) {
    const message = validateConnection(playbook.nodes, edge);
    if (message) warnings.push(message);
  }

  return warnings;
}

export function validateConnection(nodes: DesignerNode[], edge: Pick<DesignerEdge, "source" | "target">): string | null {
  const source = nodes.find((node) => node.id === edge.source);
  const target = nodes.find((node) => node.id === edge.target);
  if (!source || !target) return "Broken edge references a missing node.";
  if (source.id === target.id) return "A node cannot connect to itself.";
  if (source.type === "end") return "End node cannot have outgoing edges.";
  if (target.type === "trigger") return "Trigger node should start the flow and should not have incoming edges.";
  return null;
}

export function sanitizeDesignerText(value: string): string {
  return value.replace(/[<>]/g, "").slice(0, 500);
}
