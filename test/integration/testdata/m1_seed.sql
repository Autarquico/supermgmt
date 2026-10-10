-- Rows an M1 (schema 000002) installation holds, used by TestMigrationsM1ToM2KeepsData.
INSERT INTO instances (id, name, created_at) VALUES ('01970000-0000-7000-8000-000000000001', 'home', 1000);

INSERT INTO identities (id, actor_type, issuer, subject, display_name, created_at)
VALUES ('01970000-0000-7000-8000-000000000010', 'human', '', 'local:1000', 'local:1000', 1000),
       ('01970000-0000-7000-8000-000000000011', 'system', '', 'system', 'system', 1000);

INSERT INTO providers (id, type, name, origin, created_at, updated_at)
VALUES ('01970000-0000-7000-8000-000000000020', 'ssh', 'static', 'static', 1000, 1000);

INSERT INTO nodes (id, provider_id, native_id, name, kind, management_state, reachability, metadata_json, created_at, updated_at)
VALUES ('01970000-0000-7000-8000-000000000030', '01970000-0000-7000-8000-000000000020', 'web-1', 'web-1', 'host',
        'managed', 'unknown', '{"note":"kept"}', 1000, 1000);

INSERT INTO jobs (id, type, resource_type, resource_id, actor_id, credential_kind, state, risk, retry_class, scheduled_at, created_at)
VALUES ('01970000-0000-7000-8000-000000000040', 'node.probe', 'node', '01970000-0000-7000-8000-000000000030',
        '01970000-0000-7000-8000-000000000010', 'local_socket', 'succeeded', 'read', 'idempotent', 1000, 1000);

INSERT INTO secrets (id, name, version, envelope_version, kek_id, wrapped_dek, ciphertext, created_at)
VALUES ('01970000-0000-7000-8000-000000000050', 'ssh/default', 1, 1, 'kek-1', x'0102', x'0304', 1000);

INSERT INTO settings (key, value_json, updated_at) VALUES ('active_kek_id', '"kek-1"', 1000);

INSERT INTO interactive_sessions (id, identity_id, node_id, tool, state, created_at)
VALUES ('01970000-0000-7000-8000-000000000060', '01970000-0000-7000-8000-000000000010',
        '01970000-0000-7000-8000-000000000030', 'shell', 'issued', 1000);

INSERT INTO idempotency_records (identity_id, key, method, path, request_hash, status_code, response_json, created_at, expires_at)
VALUES ('01970000-0000-7000-8000-000000000010', 'key-1', 'POST', '/jobs', 'h', 202, '{}', 1000, 2000);
