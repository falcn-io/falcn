-- Migration 0002: Enterprise platform tables
-- Supports SQLite (single-node) and PostgreSQL (HA).
-- All timestamps are stored as UTC ISO-8601 strings for SQLite compatibility.

-- ============================================================
-- Users & Organisations
-- ============================================================
CREATE TABLE IF NOT EXISTS organizations (
    id          TEXT        PRIMARY KEY,
    name        TEXT        NOT NULL,
    plan        TEXT        NOT NULL DEFAULT 'free',  -- free | pro | enterprise
    created_at  DATETIME    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at  DATETIME    NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS users (
    id          TEXT        PRIMARY KEY,
    org_id      TEXT        REFERENCES organizations(id) ON DELETE CASCADE,
    email       TEXT        NOT NULL UNIQUE,
    role        TEXT        NOT NULL DEFAULT 'viewer',  -- viewer | analyst | admin | owner
    name        TEXT        NOT NULL DEFAULT '',
    avatar_url  TEXT        NOT NULL DEFAULT '',
    created_at  DATETIME    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at  DATETIME    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_login  DATETIME
);

CREATE INDEX IF NOT EXISTS idx_users_email  ON users(email);
CREATE INDEX IF NOT EXISTS idx_users_org_id ON users(org_id);

-- ============================================================
-- Sessions & API Keys
-- ============================================================
CREATE TABLE IF NOT EXISTS sessions (
    token_hash  TEXT        PRIMARY KEY,   -- SHA-256(token), never store raw token
    user_id     TEXT        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    expires_at  DATETIME    NOT NULL,
    created_at  DATETIME    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    ip_address  TEXT        NOT NULL DEFAULT '',
    user_agent  TEXT        NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_sessions_user_id    ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions(expires_at);

CREATE TABLE IF NOT EXISTS api_keys (
    id          TEXT        PRIMARY KEY,
    key_hash    TEXT        NOT NULL UNIQUE,  -- SHA-256(raw_key)
    user_id     TEXT        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name        TEXT        NOT NULL DEFAULT '',
    scopes      TEXT        NOT NULL DEFAULT '[]',  -- JSON array of permitted scopes
    created_at  DATETIME    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at  DATETIME,
    last_used   DATETIME,
    revoked     INTEGER     NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_api_keys_user_id  ON api_keys(user_id);
CREATE INDEX IF NOT EXISTS idx_api_keys_key_hash ON api_keys(key_hash);

-- ============================================================
-- Audit Log
-- ============================================================
CREATE TABLE IF NOT EXISTS audit_logs (
    id          INTEGER     PRIMARY KEY AUTOINCREMENT,
    user_id     TEXT        REFERENCES users(id) ON DELETE SET NULL,
    org_id      TEXT        REFERENCES organizations(id) ON DELETE SET NULL,
    action      TEXT        NOT NULL,   -- e.g. scan.created, user.login, policy.updated
    resource    TEXT        NOT NULL DEFAULT '',  -- resource type + ID
    details     TEXT        NOT NULL DEFAULT '{}',  -- JSON blob
    ip_address  TEXT        NOT NULL DEFAULT '',
    created_at  DATETIME    NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_audit_logs_user_id    ON audit_logs(user_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_org_id     ON audit_logs(org_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_action     ON audit_logs(action);
CREATE INDEX IF NOT EXISTS idx_audit_logs_created_at ON audit_logs(created_at);

-- ============================================================
-- Policy Violations
-- ============================================================
CREATE TABLE IF NOT EXISTS policy_violations (
    id              INTEGER     PRIMARY KEY AUTOINCREMENT,
    scan_id         TEXT        NOT NULL,
    policy_name     TEXT        NOT NULL,
    policy_rule     TEXT        NOT NULL DEFAULT '',
    package_name    TEXT        NOT NULL,
    package_version TEXT        NOT NULL DEFAULT '',
    severity        TEXT        NOT NULL DEFAULT 'medium',
    details         TEXT        NOT NULL DEFAULT '{}',  -- JSON blob
    created_at      DATETIME    NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_policy_violations_scan_id      ON policy_violations(scan_id);
CREATE INDEX IF NOT EXISTS idx_policy_violations_package_name ON policy_violations(package_name);
CREATE INDEX IF NOT EXISTS idx_policy_violations_created_at   ON policy_violations(created_at);

-- ============================================================
-- LLM Explanation Cache
-- ============================================================
CREATE TABLE IF NOT EXISTS explanations (
    cache_key       TEXT        PRIMARY KEY,  -- explain:{pkg}:{ver}:{threat_type}
    package_name    TEXT        NOT NULL,
    version         TEXT        NOT NULL DEFAULT '',
    threat_type     TEXT        NOT NULL,
    what_text       TEXT        NOT NULL DEFAULT '',
    why_text        TEXT        NOT NULL DEFAULT '',
    impact_text     TEXT        NOT NULL DEFAULT '',
    remediation     TEXT        NOT NULL DEFAULT '',
    confidence      REAL        NOT NULL DEFAULT 0,
    provider_id     TEXT        NOT NULL DEFAULT '',
    created_at      DATETIME    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at      DATETIME    NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_explanations_package  ON explanations(package_name);
CREATE INDEX IF NOT EXISTS idx_explanations_expires  ON explanations(expires_at);

-- ============================================================
-- Schema version tracking
-- ============================================================
INSERT OR IGNORE INTO schema_migrations (version, applied_at)
VALUES ('0002_users', CURRENT_TIMESTAMP);
