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
    cve_id        TEXT   NOT NULL,   -- e.g. 'CVE-2024-1234'
    exploit_id    INT DEFAULT 0,
    ioc_id        INT DEFAULT 0,
    platform      TEXT   NOT NULL,          -- platform name (string per XML)
    cve_source    TEXT NOT NULL DEFAULT 'unprovided',
    date_added    DATE   NOT NULL DEFAULT CURRENT_DATE,
    date_modified DATE   NOT NULL DEFAULT CURRENT_DATE
);

CREATE TABLE tab_exploit (
    id              SERIAL PRIMARY KEY,
    exploit_id      INT    NOT NULL UNIQUE,
    exploit_type    TEXT   NOT NULL,        -- e.g. 'remote', 'local', 'dos', 'sql_injection'
    exploit_content TEXT   NOT NULL,        -- exploit source / description (largestring)
    exploit_source  TEXT NOT NULL DEFAULT 'unprovided',
    date_added      DATE   NOT NULL DEFAULT CURRENT_DATE,
    date_modified   DATE   NOT NULL DEFAULT CURRENT_DATE
);

CREATE TABLE tab_sample (
    id                SERIAL PRIMARY KEY,
    platform          TEXT  NOT NULL,       -- platform name (string per XML)
    title             TEXT  NOT NULL,
    point_of_interest JSONB,                -- JSON column per XML
    sample_content    TEXT  NOT NULL,       -- raw log sample (largestring)
    sample_source     TEXT NOT NULL DEFAULT 'unprovided',
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

CREATE TABLE tab_lexic (
    id            SERIAL PRIMARY KEY,
    category      TEXT NOT NULL,
    value         TEXT NOT NULL
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

-- ------------------------------------------------------------
-- Lexic table fill
-- ------------------------------------------------------------
INSERT INTO tab_lexic (category, value) VALUES
    ('exploit_type','dos'),
    ('exploit_type','hardware'),
    ('exploit_type','local'),
    ('exploit_type','remote'),
    ('exploit_type','webapps'),
    ('sample_platform','aix'),
    ('sample_platform','alpha'),
    ('sample_platform','android'),
    ('sample_platform','arm'),
    ('sample_platform','ashx'),
    ('sample_platform','asp'),
    ('sample_platform','aspx'),
    ('sample_platform','atheos'),
    ('sample_platform','beos'),
    ('sample_platform','bsd'),
    ('sample_platform','bsd_x86'),
    ('sample_platform','cfm'),
    ('sample_platform','cgi'),
    ('sample_platform','freebsd'),
    ('sample_platform','freebsd_x86'),
    ('sample_platform','freebsd_x86-64'),
    ('sample_platform','go'),
    ('sample_platform','hardware'),
    ('sample_platform','hp-ux'),
    ('sample_platform','immunix'),
    ('sample_platform','ios'),
    ('sample_platform','irix'),
    ('sample_platform','java'),
    ('sample_platform','json'),
    ('sample_platform','jsp'),
    ('sample_platform','linux'),
    ('sample_platform','linux_mips'),
    ('sample_platform','linux_sparc'),
    ('sample_platform','linux_x86'),
    ('sample_platform','linux_x86-64'),
    ('sample_platform','lua'),
    ('sample_platform','macos'),
    ('sample_platform','minix'),
    ('sample_platform','multiple'),
    ('sample_platform','netbsd_x86'),
    ('sample_platform','netware'),
    ('sample_platform','nodejs'),
    ('sample_platform','novell'),
    ('sample_platform','openbsd'),
    ('sample_platform','osx'),
    ('sample_platform','osx_ppc'),
    ('sample_platform','palm_os'),
    ('sample_platform','perl'),
    ('sample_platform','php'),
    ('sample_platform','plan9'),
    ('sample_platform','python'),
    ('sample_platform','qnx'),
    ('sample_platform','ruby'),
    ('sample_platform','sco'),
    ('sample_platform','solaris'),
    ('sample_platform','solaris_sparc'),
    ('sample_platform','solaris_x86'),
    ('sample_platform','tru64'),
    ('sample_platform','typescript'),
    ('sample_platform','ultrix'),
    ('sample_platform','unix'),
    ('sample_platform','unixware'),
    ('sample_platform','vxworks'),
    ('sample_platform','watchos'),
    ('sample_platform','windows'),
    ('sample_platform','windows_x86'),
    ('sample_platform','windows_x86-64'),
    ('sample_platform','xml')
