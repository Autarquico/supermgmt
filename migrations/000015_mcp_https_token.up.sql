-- A local MCP client may be marked at registration so that its token is also accepted on the HTTPS listener of a
-- server (ADR-0044). The marker is part of the approved registration plan and never changes afterwards. Only a local
-- client can carry it: a remote client authenticates with an OAuth access token.

ALTER TABLE mcp_clients ADD COLUMN over_https INTEGER NOT NULL DEFAULT 0
    CHECK (over_https IN (0, 1) AND (over_https = 0 OR origin = 'local'));
