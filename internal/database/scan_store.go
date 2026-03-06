package database

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"fmt"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"github.com/sirupsen/logrus"
)

// ScanRecord represents a persisted scan entry.
type ScanRecord struct {
	ID         string    `json:"id"`
	Package    string    `json:"package"`
	Name       string    `json:"name"`
	Registry   string    `json:"registry"`
	Status     string    `json:"status"`
	Threats    int       `json:"threats"`
	Warnings   int       `json:"warnings"`
	DurationMs int64     `json:"duration_ms"`
	CreatedAt  time.Time `json:"created_at"`
}

// ScanStore provides persistent scan history backed by SQLite.
type ScanStore struct {
	db *sql.DB
}

// NewScanStore opens (or creates) the SQLite database at dbPath and runs all
// pending migrations.  Pass an empty string to use "falcn.db" in the current
// working directory.
func NewScanStore(dbPath string) (*ScanStore, error) {
	if dbPath == "" {
		dbPath = "falcn.db"
	}
	db, err := sql.Open("sqlite3", dbPath+"?_journal_mode=WAL&_foreign_keys=on")
	if err != nil {
		return nil, fmt.Errorf("open db: %w", err)
	}
	// SQLite is single-writer; cap the pool accordingly.
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)

	if err := RunMigrations(db); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("migrate: %w", err)
	}
	return &ScanStore{db: db}, nil
}

// Close releases the underlying database connection.
func (s *ScanStore) Close() error { return s.db.Close() }

// Insert persists a scan record, replacing any existing row with the same ID.
func (s *ScanStore) Insert(r ScanRecord) error {
	_, err := s.db.Exec(
		`INSERT OR REPLACE INTO scans
		 (id, package, name, registry, status, threats, warnings, duration_ms, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		r.ID, r.Package, r.Name, r.Registry,
		r.Status, r.Threats, r.Warnings, r.DurationMs, r.CreatedAt,
	)
	if err != nil {
		logrus.Warnf("ScanStore.Insert: %v", err)
	}
	return err
}

// List returns paginated scan records ordered by created_at DESC.
// It also returns the total number of rows in the table.
// limit is clamped to [1, 200]; a zero or negative limit defaults to 50.
func (s *ScanStore) List(limit, offset int) ([]ScanRecord, int, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}

	var total int
	if err := s.db.QueryRow("SELECT COUNT(*) FROM scans").Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("count scans: %w", err)
	}

	rows, err := s.db.Query(
		`SELECT id, package, name, registry, status, threats, warnings, duration_ms, created_at
		 FROM scans
		 ORDER BY created_at DESC
		 LIMIT ? OFFSET ?`,
		limit, offset,
	)
	if err != nil {
		return nil, 0, fmt.Errorf("query scans: %w", err)
	}
	defer rows.Close()

	var records []ScanRecord
	for rows.Next() {
		var r ScanRecord
		if err := rows.Scan(
			&r.ID, &r.Package, &r.Name, &r.Registry,
			&r.Status, &r.Threats, &r.Warnings, &r.DurationMs, &r.CreatedAt,
		); err != nil {
			return nil, 0, err
		}
		records = append(records, r)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, err
	}
	return records, total, nil
}

// ThreatSummary returns aggregated threat statistics across all persisted scans.
func (s *ScanStore) ThreatSummary() (totalScans, totalThreats, totalWarnings int, err error) {
	err = s.db.QueryRow(
		`SELECT COUNT(*), COALESCE(SUM(threats), 0), COALESCE(SUM(warnings), 0) FROM scans`,
	).Scan(&totalScans, &totalThreats, &totalWarnings)
	return
}

// RecentActivity returns scan and threat counts for the last 24 hours.
func (s *ScanStore) RecentActivity() (scansLast24h, threatsLast24h int, err error) {
	cutoff := time.Now().Add(-24 * time.Hour).Format(time.RFC3339)
	err = s.db.QueryRow(
		`SELECT COUNT(*), COALESCE(SUM(threats), 0)
		 FROM scans
		 WHERE created_at > ?`,
		cutoff,
	).Scan(&scansLast24h, &threatsLast24h)
	return
}

// AvgDurationMs returns the average scan duration in milliseconds.
// Returns 0 when there are no rows.
func (s *ScanStore) AvgDurationMs() (int64, error) {
	var avg sql.NullFloat64
	if err := s.db.QueryRow(`SELECT AVG(duration_ms) FROM scans`).Scan(&avg); err != nil {
		return 0, err
	}
	if !avg.Valid {
		return 0, nil
	}
	return int64(avg.Float64), nil
}

// ScanThreatRecord represents a single detected threat associated with a scan
// stored in the scan_threats SQLite table (distinct from the PostgreSQL ThreatRecord
// in threat_db.go).
type ScanThreatRecord struct {
	ScanID      string    `json:"scan_id"`
	ThreatType  string    `json:"threat_type"`
	Severity    string    `json:"severity"`
	PackageName string    `json:"package_name"`
	Description string    `json:"description"`
	Score       float64   `json:"score"`
	CreatedAt   time.Time `json:"created_at"`
}

// randomHex returns a hex-encoded random ID of the given byte length.
func randomHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// InsertThreat persists an individual threat record linked to a scan.
// The underlying scan_threats table uses the schema from migration 3.
func (s *ScanStore) InsertThreat(t ScanThreatRecord) error {
	_, err := s.db.Exec(
		`INSERT INTO scan_threats (id, scan_id, package, version, type, severity, confidence, title, description, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		randomHex(8), t.ScanID, t.PackageName, "", t.ThreatType, t.Severity,
		t.Score, t.ThreatType, t.Description, t.CreatedAt,
	)
	if err != nil {
		logrus.Warnf("ScanStore.InsertThreat: %v", err)
	}
	return err
}

// ListThreats returns all threat records for a given scan, ordered by confidence descending.
func (s *ScanStore) ListThreats(scanID string) ([]ScanThreatRecord, error) {
	rows, err := s.db.Query(
		`SELECT scan_id, type, severity, package, description, confidence, created_at
		 FROM scan_threats
		 WHERE scan_id = ?
		 ORDER BY confidence DESC`,
		scanID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ScanThreatRecord
	for rows.Next() {
		var t ScanThreatRecord
		if err := rows.Scan(&t.ScanID, &t.ThreatType, &t.Severity, &t.PackageName, &t.Description, &t.Score, &t.CreatedAt); err != nil {
			continue
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// EcosystemStat holds per-registry scan + threat counts.
type EcosystemStat struct {
	Ecosystem string `json:"ecosystem"`
	Scans     int    `json:"count"` // "count" matches the frontend EcosystemStat.count field
	Threats   int    `json:"threats"`
}

// EcosystemStats returns per-registry scan and threat counts.
func (s *ScanStore) EcosystemStats() ([]EcosystemStat, error) {
	rows, err := s.db.Query(
		`SELECT COALESCE(registry, 'unknown'), COUNT(*), COALESCE(SUM(threats), 0)
		 FROM scans
		 WHERE registry != ''
		 GROUP BY registry
		 ORDER BY COUNT(*) DESC
		 LIMIT 10`,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []EcosystemStat
	for rows.Next() {
		var e EcosystemStat
		if err := rows.Scan(&e.Ecosystem, &e.Scans, &e.Threats); err != nil {
			continue
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// TrendPoint holds daily scan and threat counts.
type TrendPoint struct {
	Date    string `json:"date"`
	Threats int    `json:"threats"`
	Scans   int    `json:"scans"`
}

// ThreatTrend returns daily threat and scan counts for the last N days.
func (s *ScanStore) ThreatTrend(days int) ([]TrendPoint, error) {
	if days <= 0 {
		days = 14
	}
	rows, err := s.db.Query(
		`SELECT date(created_at) AS d, COUNT(*), COALESCE(SUM(threats), 0)
		 FROM scans
		 WHERE created_at >= date('now', ? || ' days')
		 GROUP BY d
		 ORDER BY d ASC`,
		fmt.Sprintf("-%d", days),
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []TrendPoint
	for rows.Next() {
		var p TrendPoint
		if err := rows.Scan(&p.Date, &p.Scans, &p.Threats); err != nil {
			continue
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// SeverityBreakdown holds counts of each severity level.
type SeverityBreakdown struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
}

// SeverityStats returns counts of detected threats grouped by severity level.
func (s *ScanStore) SeverityStats() (SeverityBreakdown, error) {
	rows, err := s.db.Query(
		`SELECT severity, COUNT(*) FROM scan_threats GROUP BY severity`,
	)
	if err != nil {
		return SeverityBreakdown{}, err
	}
	defer rows.Close()
	var out SeverityBreakdown
	for rows.Next() {
		var sev string
		var cnt int
		if err := rows.Scan(&sev, &cnt); err != nil {
			continue
		}
		switch sev {
		case "critical":
			out.Critical = cnt
		case "high":
			out.High = cnt
		case "medium":
			out.Medium = cnt
		case "low":
			out.Low = cnt
		}
	}
	return out, rows.Err()
}

// RecentThreat is a threat record shaped for the dashboard and threats list.
// JSON tags match the frontend Threat interface so the struct can be serialised
// directly without a conversion layer.
type RecentThreat struct {
	ID          string              `json:"id"`
	Package     string              `json:"package"`
	Registry    string              `json:"registry"`
	ThreatType  string              `json:"type"`
	Severity    string              `json:"severity"`
	Confidence  float64             `json:"confidence"`
	Title       string              `json:"title"`
	Description string              `json:"description"`
	DetectedAt  time.Time           `json:"detected_at"`
	Explanation *CachedExplanation  `json:"explanation,omitempty"`
}

// CachedExplanation is the LLM-generated explanation embedded in a RecentThreat.
// Field names mirror the frontend ThreatExplanation TypeScript interface.
type CachedExplanation struct {
	What        string  `json:"what"`
	Why         string  `json:"why"`
	Impact      string  `json:"impact"`
	Remediation string  `json:"remediation"`
	Confidence  float64 `json:"confidence"`
	GeneratedBy string  `json:"generated_by,omitempty"`
	CacheHit    bool    `json:"cache_hit"`
}

// scanRecentThreat scans one row that includes the optional LEFT-JOINed
// explanation columns (what_text, why_text, impact_text, remediation,
// e.confidence, e.provider_id — all NULLable).
func scanRecentThreat(row interface {
	Scan(dest ...any) error
}) (RecentThreat, error) {
	var t RecentThreat
	var (
		what, why, impact, remediation, providerID sql.NullString
		explConf                                   sql.NullFloat64
	)
	if err := row.Scan(
		&t.ID, &t.Package, &t.Registry, &t.ThreatType,
		&t.Severity, &t.Confidence, &t.Title, &t.Description, &t.DetectedAt,
		&what, &why, &impact, &remediation, &explConf, &providerID,
	); err != nil {
		return t, err
	}
	if what.Valid && what.String != "" {
		t.Explanation = &CachedExplanation{
			What:        what.String,
			Why:         why.String,
			Impact:      impact.String,
			Remediation: remediation.String,
			Confidence:  explConf.Float64,
			GeneratedBy: providerID.String,
			CacheHit:    true,
		}
	}
	return t, nil
}

// threatListQuery is the shared SELECT for both RecentThreats and ThreatList.
// It LEFT JOINs the explanations cache table so callers get inline AI summaries
// without an extra round-trip.
const threatListQuery = `
	SELECT st.id, st.package, COALESCE(sc.registry,''), st.type,
	       st.severity, st.confidence, st.title, st.description, st.created_at,
	       e.what_text, e.why_text, e.impact_text, e.remediation,
	       e.confidence, e.provider_id
	FROM scan_threats st
	LEFT JOIN scans sc ON sc.id = st.scan_id
	LEFT JOIN explanations e
	       ON e.cache_key = 'explain:' || st.package || ':' || st.version || ':' || st.type
	      AND e.expires_at > CURRENT_TIMESTAMP
	ORDER BY st.created_at DESC`

// RecentThreats returns the most-recently detected threats across all scans,
// with cached AI explanations inlined where available.
func (s *ScanStore) RecentThreats(limit int) ([]RecentThreat, error) {
	if limit <= 0 || limit > 100 {
		limit = 20
	}
	rows, err := s.db.Query(threatListQuery+" LIMIT ?", limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []RecentThreat
	for rows.Next() {
		t, err := scanRecentThreat(rows)
		if err != nil {
			continue
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// ThreatList returns a paginated list of threats with total count,
// with cached AI explanations inlined where available.
func (s *ScanStore) ThreatList(limit, offset int) ([]RecentThreat, int, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}

	var total int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM scan_threats`).Scan(&total); err != nil {
		return nil, 0, err
	}

	rows, err := s.db.Query(threatListQuery+" LIMIT ? OFFSET ?", limit, offset)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var out []RecentThreat
	for rows.Next() {
		t, err := scanRecentThreat(rows)
		if err != nil {
			continue
		}
		out = append(out, t)
	}
	return out, total, rows.Err()
}

// AvgRiskScore returns the mean confidence score across all recorded threats,
// used as a proxy for average ecosystem risk.
func (s *ScanStore) AvgRiskScore() (float64, error) {
	var avg float64
	err := s.db.QueryRow(`SELECT COALESCE(AVG(confidence), 0) FROM scan_threats`).Scan(&avg)
	return avg, err
}

// ─── Explanation cache ────────────────────────────────────────────────────────

// ExplanationRow represents one cached LLM explanation keyed by
// "explain:{package}:{version}:{threat_type}".
type ExplanationRow struct {
	CacheKey    string
	PackageName string
	Version     string
	ThreatType  string
	What        string
	Why         string
	Impact      string
	Remediation string
	Confidence  float64
	ProviderID  string
	ExpiresAt   time.Time
}

// GetExplanation fetches a cached explanation that has not yet expired.
// Returns (nil, nil) when the key is absent or the entry is expired.
func (s *ScanStore) GetExplanation(cacheKey string) (*ExplanationRow, error) {
	var row ExplanationRow
	err := s.db.QueryRow(`
		SELECT cache_key, package_name, version, threat_type,
		       what_text, why_text, impact_text, remediation,
		       confidence, provider_id, expires_at
		FROM   explanations
		WHERE  cache_key = ? AND expires_at > CURRENT_TIMESTAMP`,
		cacheKey,
	).Scan(
		&row.CacheKey, &row.PackageName, &row.Version, &row.ThreatType,
		&row.What, &row.Why, &row.Impact, &row.Remediation,
		&row.Confidence, &row.ProviderID, &row.ExpiresAt,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &row, nil
}

// SaveExplanation upserts a cached explanation row.
func (s *ScanStore) SaveExplanation(row ExplanationRow) error {
	_, err := s.db.Exec(`
		INSERT OR REPLACE INTO explanations
		(cache_key, package_name, version, threat_type,
		 what_text, why_text, impact_text, remediation,
		 confidence, provider_id, expires_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		row.CacheKey, row.PackageName, row.Version, row.ThreatType,
		row.What, row.Why, row.Impact, row.Remediation,
		row.Confidence, row.ProviderID, row.ExpiresAt,
	)
	return err
}

// CleanExpiredExplanations deletes all explanation rows past their TTL.
func (s *ScanStore) CleanExpiredExplanations() (int64, error) {
	res, err := s.db.Exec(`DELETE FROM explanations WHERE expires_at <= CURRENT_TIMESTAMP`)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}
