-- M3 schema addition (ADR-0025). The only M3 change: the provider-side handle of a dispatched
-- operation, a Proxmox task UPID. NULL for operations that carry no such handle (SSH templates).
-- Discovery reuses nodes, observations, node_capabilities and providers.

ALTER TABLE operation_intents ADD COLUMN external_ref TEXT;
