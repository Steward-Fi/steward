-- Require explicit opt-in before a tenant becomes publicly self-joinable.
ALTER TABLE tenant_configs ALTER COLUMN join_mode SET DEFAULT 'invite';
UPDATE tenant_configs SET join_mode = 'invite' WHERE join_mode = 'open';
