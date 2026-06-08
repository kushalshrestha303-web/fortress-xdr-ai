import type { DesignerNode } from "./playbookTypes";
import { sanitizeDesignerText } from "./playbookValidation";

export function NodeConfigPanel({
  node,
  onClose,
  onUpdate
}: {
  node: DesignerNode | null;
  onClose: () => void;
  onUpdate: (node: DesignerNode) => void;
}) {
  if (!node) {
    return (
      <aside className="rounded border border-fortress-line bg-fortress-panel p-5">
        <h3 className="text-lg font-semibold text-white">Node Configuration</h3>
        <p className="mt-2 text-sm text-[#9fb0c2]">Select a node to edit conditions, thresholds, timeouts, retries, and report settings.</p>
      </aside>
    );
  }

  const selected = node;

  function update(patch: Partial<DesignerNode>) {
    onUpdate({ ...selected, ...patch });
  }

  function updateConfig(key: keyof DesignerNode["config"], value: string | number) {
    onUpdate({ ...selected, config: { ...selected.config, [key]: typeof value === "string" ? sanitizeDesignerText(value) : value } });
  }

  return (
    <aside className="rounded border border-fortress-line bg-fortress-panel">
      <div className="flex items-center justify-between border-b border-fortress-line p-4">
        <h3 className="text-lg font-semibold text-white">Node Configuration</h3>
        <button className="text-sm text-[#9fb0c2]" onClick={onClose}>Close</button>
      </div>
      <div className="grid gap-3 p-4 text-sm">
        <Field label="Node name" value={selected.name} onChange={(value) => update({ name: sanitizeDesignerText(value) })} />
        <label>
          <span className="text-[#9fb0c2]">Description</span>
          <textarea className="mt-1 min-h-20 w-full rounded border border-fortress-line bg-[#0b1017] p-2 text-white outline-none" value={selected.config.description} onChange={(event) => updateConfig("description", event.target.value)} />
        </label>
        <Field label="Condition logic" value={selected.config.conditionLogic ?? ""} onChange={(value) => updateConfig("conditionLogic", value)} />
        <Field label="Action settings" value={selected.config.actionSettings ?? ""} onChange={(value) => updateConfig("actionSettings", value)} />
        <Field label="Email/Gmail report recipient" value={selected.config.emailRecipient ?? ""} onChange={(value) => updateConfig("emailRecipient", value)} />
        <Field label="Severity threshold" value={selected.config.severityThreshold ?? ""} onChange={(value) => updateConfig("severityThreshold", value)} />
        <NumberField label="Risk score threshold" value={selected.config.riskScoreThreshold ?? 90} onChange={(value) => updateConfig("riskScoreThreshold", value)} />
        <Field label="IP/domain/user/entity fields" value={selected.config.entityFields ?? ""} onChange={(value) => updateConfig("entityFields", value)} />
        <NumberField label="Timeout seconds" value={selected.config.timeoutSeconds ?? 900} onChange={(value) => updateConfig("timeoutSeconds", value)} />
        <NumberField label="Retry count" value={selected.config.retryCount ?? 1} onChange={(value) => updateConfig("retryCount", value)} />
        <Field label="On success path" value={selected.config.onSuccessPath ?? "success"} onChange={(value) => updateConfig("onSuccessPath", value)} />
        <Field label="On failure path" value={selected.config.onFailurePath ?? "failure"} onChange={(value) => updateConfig("onFailurePath", value)} />
      </div>
    </aside>
  );
}

function Field({ label, value, onChange }: { label: string; value: string; onChange: (value: string) => void }) {
  return (
    <label>
      <span className="text-[#9fb0c2]">{label}</span>
      <input className="mt-1 w-full rounded border border-fortress-line bg-[#0b1017] p-2 text-white outline-none" value={value} onChange={(event) => onChange(event.target.value)} />
    </label>
  );
}

function NumberField({ label, value, onChange }: { label: string; value: number; onChange: (value: number) => void }) {
  return (
    <label>
      <span className="text-[#9fb0c2]">{label}</span>
      <input className="mt-1 w-full rounded border border-fortress-line bg-[#0b1017] p-2 text-white outline-none" type="number" value={value} onChange={(event) => onChange(Number(event.target.value))} />
    </label>
  );
}
