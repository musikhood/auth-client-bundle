-- Przykładowy schemat tabeli lokalnej kopii użytkownika.
--
-- Paczka nie tworzy tej tabeli — robi to konsument w swojej migracji.
-- Kolumny odpowiadają polom z `PanelUserInterface`. Pełny mapping ORM
-- jest w `docs/example-entity.php`.
--
-- Sprawdzone na PostgreSQL 14+. Dla MySQL 8 zamień UUID na BINARY(16) lub
-- CHAR(36), JSON zostaje bez zmian.

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

COMMENT ON COLUMN users.id IS '(DC2Type:uuid) — pochodzi z claimu user_id w JWT, nie generujemy lokalnie.';
COMMENT ON COLUMN users.last_synced_at IS '(DC2Type:datetime_immutable)';
COMMENT ON COLUMN users.roles_for_panel IS 'Nazwy ról panelu bez prefiksu ROLE_.';
