package database

import (
	"database/sql"
	"fmt"

	"github.com/sirupsen/logrus"
)

// SchemaMigration represents a single SQLite schema migration step.
// Named SchemaMigration to avoid collision with the Migration type in schema.go.
type SchemaMigration struct {
	Version int
	Name    string
	Up      string
}

// sqliteMigrations is the ordered list of all SQLite schema migrations for the
// embedded scan-persistence store.
var sqliteMigrations = []SchemaMigration{
	{
		Version: 1,
		Name:    "create_schema_versions",
		Up: `CREATE TABLE IF NOT EXISTS schema_versions (
			version     INTEGER PRIMARY KEY,
			name        TEXT NOT NULL,
			applied_at  DATETIME DEFAULT CURRENT_TIMESTAMP
		);`,
	},
	{
		Version: 2,
		Name:    "create_scans",
		Up: `CREATE TABLE IF NOT EXISTS scans (
			id          TEXT PRIMARY KEY,
			package     TEXT NOT NULL,
			name        TEXT NOT NULL,
			registry    TEXT NOT NULL DEFAULT '',
			status      TEXT NOT NULL DEFAULT 'clean',
			threats     INTEGER NOT NULL DEFAULT 0,
			warnings    INTEGER NOT NULL DEFAULT 0,
			duration_ms INTEGER NOT NULL DEFAULT 0,
			created_at  DATETIME DEFAULT CURRENT_TIMESTAMP
		);
		CREATE INDEX IF NOT EXISTS idx_scans_created_at ON scans(created_at DESC);
		CREATE INDEX IF NOT EXISTS idx_scans_name ON scans(name);`,
	},
	{
		Version: 3,
		Name:    "create_threats",
		Up: `CREATE TABLE IF NOT EXISTS scan_threats (
			id          TEXT PRIMARY KEY,
			scan_id     TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
			package     TEXT NOT NULL,
			version     TEXT NOT NULL DEFAULT '',
			type        TEXT NOT NULL,
			severity    TEXT NOT NULL,
			confidence  REAL NOT NULL DEFAULT 0,
			title       TEXT NOT NULL DEFAULT '',
			description TEXT NOT NULL DEFAULT '',
			created_at  DATETIME DEFAULT CURRENT_TIMESTAMP
		);
		CREATE INDEX IF NOT EXISTS idx_scan_threats_scan_id ON scan_threats(scan_id);
		CREATE INDEX IF NOT EXISTS idx_scan_threats_severity ON scan_threats(severity);`,
	},
	{
		Version: 4,
		Name:    "create_audit_log",
		Up: `CREATE TABLE IF NOT EXISTS audit_log (
			id          INTEGER PRIMARY KEY AUTOINCREMENT,
			event       TEXT NOT NULL,
			actor       TEXT NOT NULL DEFAULT 'system',
			resource    TEXT NOT NULL DEFAULT '',
			detail      TEXT NOT NULL DEFAULT '',
			created_at  DATETIME DEFAULT CURRENT_TIMESTAMP
		);
		CREATE INDEX IF NOT EXISTS idx_audit_log_created_at ON audit_log(created_at DESC);`,
	},
	{
		Version: 5,
		Name:    "create_explanations_cache",
		Up: `CREATE TABLE IF NOT EXISTS explanations (
			cache_key    TEXT     PRIMARY KEY,
			package_name TEXT     NOT NULL,
			version      TEXT     NOT NULL DEFAULT '',
			threat_type  TEXT     NOT NULL,
			what_text    TEXT     NOT NULL DEFAULT '',
			why_text     TEXT     NOT NULL DEFAULT '',
			impact_text  TEXT     NOT NULL DEFAULT '',
			remediation  TEXT     NOT NULL DEFAULT '',
			confidence   REAL     NOT NULL DEFAULT 0,
			provider_id  TEXT     NOT NULL DEFAULT '',
			created_at   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			expires_at   DATETIME NOT NULL
		);
		CREATE INDEX IF NOT EXISTS idx_explanations_package ON explanations(package_name);
		CREATE INDEX IF NOT EXISTS idx_explanations_expires  ON explanations(expires_at);`,
	},
}

// RunMigrations applies all pending SQLite migrations against db.
// It is safe to call multiple times; already-applied migrations are skipped.
func RunMigrations(db *sql.DB) error {
	// Bootstrap: ensure the schema_versions table exists first.
	if _, err := db.Exec(sqliteMigrations[0].Up); err != nil {
		return fmt.Errorf("failed to bootstrap migrations table: %w", err)
	}

	for _, m := range sqliteMigrations {
		var count int
		err := db.QueryRow(
			"SELECT COUNT(*) FROM schema_versions WHERE version = ?", m.Version,
		).Scan(&count)
		if err != nil {
			return fmt.Errorf("failed to check migration %d: %w", m.Version, err)
		}
		if count > 0 {
			continue // already applied
		}

		logrus.Infof("Applying SQLite migration %d: %s", m.Version, m.Name)
		if _, err := db.Exec(m.Up); err != nil {
			return fmt.Errorf("migration %d (%s) failed: %w", m.Version, m.Name, err)
		}
		if _, err := db.Exec(
			"INSERT INTO schema_versions (version, name) VALUES (?, ?)",
			m.Version, m.Name,
		); err != nil {
			return fmt.Errorf("failed to record migration %d: %w", m.Version, err)
		}
	}
	return nil
}
