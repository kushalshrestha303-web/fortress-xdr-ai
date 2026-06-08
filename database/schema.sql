CREATE TABLE tenants (
  id UUID PRIMARY KEY,
  name TEXT NOT NULL,
  sector TEXT NOT NULL CHECK (sector IN ('government','bank','hospital','telecom','enterprise','critical-infrastructure')),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE incidents (
  id UUID PRIMARY KEY,
  tenant_id UUID NOT NULL REFERENCES tenants(id),
  severity TEXT NOT NULL CHECK (severity IN ('low','medium','high','critical')),
  status TEXT NOT NULL DEFAULT 'open',
  risk_score INT NOT NULL CHECK (risk_score BETWEEN 0 AND 100),
  title TEXT NOT NULL,
  context JSONB NOT NULL DEFAULT '{}',
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE ngfw_logs (
  event_id UUID PRIMARY KEY,
  tenant_id UUID NOT NULL REFERENCES tenants(id),
  timestamp TIMESTAMPTZ NOT NULL,
  sector TEXT NOT NULL,
  sensor_id TEXT NOT NULL,
  src_ip INET NOT NULL,
  dst_ip INET NOT NULL,
  protocol TEXT NOT NULL,
  application TEXT NOT NULL,
  action TEXT NOT NULL,
  dpi JSONB NOT NULL DEFAULT '{}',
  ips JSONB NOT NULL DEFAULT '{}',
  risk_score INT NOT NULL,
  raw JSONB NOT NULL
);

CREATE TABLE playbook_runs (
  id UUID PRIMARY KEY,
  tenant_id UUID NOT NULL REFERENCES tenants(id),
  incident_id UUID REFERENCES incidents(id),
  playbook_id TEXT NOT NULL,
  status TEXT NOT NULL,
  tasks JSONB NOT NULL DEFAULT '[]',
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

