-- ============================================================
-- ThreatContext-db — schema init script
-- Target: PostgreSQL 18 (container ThreatContext-db)
-- Schema as described in database_description.xml
--
-- docker-compose mount (add to database_tier):
--   volumes:
--     - ./seed.sql:/docker-entrypoint-initdb.d/seed.sql
--     - postgres_data:/var/lib/postgresql/data
--
-- Note: the official postgres image runs every .sql file in
-- /docker-entrypoint-initdb.d/ once, on first creation of the
-- data directory (only when the volume is empty).
-- ============================================================

\set ON_ERROR_STOP on

-- Optional: pgvector for the RAG embedding step.
-- The extension image must be used if you add vector columns:
--   image: pgvector/pgvector:pg18
-- CREATE EXTENSION IF NOT EXISTS vector;

-- ------------------------------------------------------------
-- Schema
-- ------------------------------------------------------------
CREATE TABLE tab_cve (
    id            SERIAL PRIMARY KEY,
    cve_id        TEXT   NOT NULL UNIQUE,   -- e.g. 'CVE-2024-1234'
    exploit_id    INT    NOT NULL,
    ioc_id        INT    NOT NULL,
    platform      TEXT   NOT NULL,          -- platform name (string per XML)
    date_added    DATE   NOT NULL DEFAULT CURRENT_DATE,
    date_modified DATE   NOT NULL DEFAULT CURRENT_DATE
);

CREATE TABLE tab_exploit (
    id              SERIAL PRIMARY KEY,
    exploit_id      INT    NOT NULL UNIQUE,
    exploit_type    TEXT   NOT NULL,        -- e.g. 'remote', 'local', 'dos', 'sql_injection'
    exploit_content TEXT   NOT NULL,        -- exploit source / description (largestring)
    date_added      DATE   NOT NULL DEFAULT CURRENT_DATE,
    date_modified   DATE   NOT NULL DEFAULT CURRENT_DATE
);

CREATE TABLE tab_sample (
    id                SERIAL PRIMARY KEY,
    platform          TEXT  NOT NULL,       -- platform name (string per XML)
    title             TEXT  NOT NULL,
    point_of_interest JSONB,                -- JSON column per XML
    sample_content    TEXT  NOT NULL,       -- raw log sample (largestring)
    date_added        DATE  NOT NULL DEFAULT CURRENT_DATE,
    date_modified    DATE  NOT NULL DEFAULT CURRENT_DATE
);

CREATE TABLE tab_ioc (
    id            SERIAL PRIMARY KEY,
    ioc_id        INT  NOT NULL UNIQUE,
    ioc_content   TEXT NOT NULL,            -- the IoC value(s)
    date_added    DATE NOT NULL DEFAULT CURRENT_DATE,
    date_modified DATE NOT NULL DEFAULT CURRENT_DATE
);

-- ------------------------------------------------------------
-- Indexes for the pipeline's access patterns
-- ------------------------------------------------------------
CREATE INDEX idx_cve_platform     ON tab_cve (platform);
CREATE INDEX idx_sample_platform   ON tab_sample (platform);
CREATE INDEX idx_cve_exploit       ON tab_cve (exploit_id);
CREATE INDEX idx_cve_ioc           ON tab_cve (ioc_id);

-- Foreign-key style constraints (optional, kept as plain indexes above
-- since tab_cve.platform references tab_sample.platform by value, not id)
