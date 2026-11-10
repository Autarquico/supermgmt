-- A node added through the API has its own ssh provider, which holds the node's name, and its Proxmox token is
-- stored by that name (secret://proxmox/<name>). Retiring the node kept both, so no new node could be added under
-- the name, and one that could would have inherited the token. A retired node now gives both up; this does the
-- same for the nodes retired before. The suffix is the one internal/app uses (retiredProviderName).

DELETE FROM secrets
WHERE name IN (
    SELECT 'proxmox/' || n.name FROM nodes AS n JOIN providers AS p ON p.id = n.provider_id
    WHERE p.type = 'ssh' AND p.origin = 'api' AND n.management_state = 'retired'
      AND NOT EXISTS (SELECT 1 FROM nodes AS live WHERE live.name = n.name AND live.management_state <> 'retired'));

UPDATE providers
SET name = name || '~retired-' || id, spec_revision = spec_revision + 1
WHERE type = 'ssh' AND origin = 'api'
  AND EXISTS (SELECT 1 FROM nodes WHERE nodes.provider_id = providers.id)
  AND NOT EXISTS (SELECT 1 FROM nodes WHERE nodes.provider_id = providers.id AND nodes.management_state <> 'retired');
