-- A node added through the API has its own ssh provider, which holds the node's name. Retiring the node kept that
-- provider's name, so no new node could be added under it. A retired node now gives its provider's name up; this
-- frees the names of the nodes retired before. The suffix is the one internal/app uses (retiredProviderName).

UPDATE providers
SET name = name || '~retired-' || id, spec_revision = spec_revision + 1
WHERE type = 'ssh' AND origin = 'api'
  AND EXISTS (SELECT 1 FROM nodes WHERE nodes.provider_id = providers.id)
  AND NOT EXISTS (SELECT 1 FROM nodes WHERE nodes.provider_id = providers.id AND nodes.management_state <> 'retired');
