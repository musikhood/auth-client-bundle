-- Example schema for the local user mirror.
--
-- The bundle does not own this table — the consumer creates and migrates it.
-- The columns mirror what `PanelUserInterface` exposes; see also
-- `docs/example-entity.php` for a Doctrine ORM mapping that produces
-- exactly this schema.
--
-- Tested against PostgreSQL 14+. For MySQL 8 swap UUID type for BINARY(16)
-- or CHAR(36), and JSON column type stays the same.

CREATE TABLE users (
    id UUID NOT NULL,
    email VARCHAR(180) NOT NULL,
    display_name VARCHAR(255) DEFAULT NULL,
    roles_for_panel JSON NOT NULL,
    disabled BOOLEAN NOT NULL DEFAULT FALSE,
    last_synced_at TIMESTAMP(0) WITHOUT TIME ZONE NOT NULL,
    PRIMARY KEY (id)
);

CREATE UNIQUE INDEX uniq_users_email ON users (email);
CREATE INDEX idx_users_email ON users (email);

COMMENT ON COLUMN users.id IS '(DC2Type:uuid) — comes from JWT claim user_id, never generated locally.';
COMMENT ON COLUMN users.last_synced_at IS '(DC2Type:datetime_immutable)';
COMMENT ON COLUMN users.roles_for_panel IS 'Panel-scoped role names without the ROLE_ prefix.';
