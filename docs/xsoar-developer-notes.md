# Cortex XSOAR Developer Notes Applied

Sources reviewed:

- [Cortex XSOAR developer welcome](https://xsoar.pan.dev/docs/welcome)
- [Cortex XSOAR concepts](https://xsoar.pan.dev/docs/concepts/concepts)
- [Cortex XSOAR playbook development](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSOAR/6.10/Cortex-XSOAR-Administrator-Guide/Playbook-Development)
- [Demisto content repository](https://github.com/demisto/content)

Vendor-neutral patterns implemented in Nepal Fortress ONE:

- Content packs map to signed integration bundles under `packs/`.
- Integrations expose commands that return human-readable summaries and structured JSON.
- Playbooks are task graphs with automation, integration, condition, communication, remediation, and manual approval tasks.
- Incident context is mutable, auditable, tenant-scoped, and versioned.
- Playbook execution streams task status to the SOC workspace in real time.
- CI/CD should validate schemas, lint integrations, run playbook unit tests, generate docs, and sign releases.

This platform does not clone Cortex XSOAR. It uses comparable SOAR engineering ideas to build an independent Nepal Fortress workflow engine.

