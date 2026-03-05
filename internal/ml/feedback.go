package ml

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"github.com/sirupsen/logrus"
)

// FeedbackType classifies the nature of a user-reported correction.
type FeedbackType string

const (
	FeedbackFalsePositive FeedbackType = "false_positive" // flagged as malicious but is benign
	FeedbackFalseNegative FeedbackType = "false_negative" // flagged as benign but is malicious
	FeedbackConfirmed     FeedbackType = "confirmed"       // user confirms the threat finding
)

// FeedbackRecord stores one user-submitted correction.
type FeedbackRecord struct {
	ID          int64        `json:"id"`
	PackageName string       `json:"package_name"`
	Registry    string       `json:"registry"`
	Version     string       `json:"version"`
	Type        FeedbackType `json:"type"`
	ModelScore  float64      `json:"model_score"`
	// Features stores the 25-element feature vector as JSON for retraining.
	Features  []float32 `json:"features"`
	Comment   string    `json:"comment"`
	CreatedAt time.Time `json:"created_at"`
}

// FeedbackStore persists user feedback in SQLite for use in retraining.
type FeedbackStore struct {
	db   *sql.DB
	mu   sync.Mutex
	path string
}

// NewFeedbackStore opens (or creates) the SQLite feedback database.
func NewFeedbackStore(dbPath string) (*FeedbackStore, error) {
	if err := os.MkdirAll(filepath.Dir(dbPath), 0o700); err != nil {
		return nil, fmt.Errorf("feedback store: mkdir: %w", err)
	}
	db, err := sql.Open("sqlite3", dbPath+"?_journal_mode=WAL&_busy_timeout=5000")
	if err != nil {
		return nil, fmt.Errorf("feedback store: open db: %w", err)
	}
	store := &FeedbackStore{db: db, path: dbPath}
	if err := store.migrate(); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("feedback store: migrate: %w", err)
	}
	return store, nil
}

func (s *FeedbackStore) migrate() error {
	_, err := s.db.Exec(`
		CREATE TABLE IF NOT EXISTS feedback (
			id           INTEGER PRIMARY KEY AUTOINCREMENT,
			package_name TEXT    NOT NULL,
			registry     TEXT    NOT NULL DEFAULT '',
			version      TEXT    NOT NULL DEFAULT '',
			type         TEXT    NOT NULL,
			model_score  REAL    NOT NULL DEFAULT 0,
			features     TEXT    NOT NULL DEFAULT '[]',
			comment      TEXT    NOT NULL DEFAULT '',
			created_at   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
		);
		CREATE INDEX IF NOT EXISTS idx_feedback_pkg  ON feedback(package_name, registry);
		CREATE INDEX IF NOT EXISTS idx_feedback_type ON feedback(type);
		CREATE INDEX IF NOT EXISTS idx_feedback_ts   ON feedback(created_at);
	`)
	return err
}

// Record saves a feedback entry.
func (s *FeedbackStore) Record(r FeedbackRecord) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	featJSON, err := json.Marshal(r.Features)
	if err != nil {
		featJSON = []byte("[]")
	}

	res, err := s.db.Exec(
		`INSERT INTO feedback (package_name, registry, version, type, model_score, features, comment, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		r.PackageName, r.Registry, r.Version, string(r.Type), r.ModelScore,
		string(featJSON), r.Comment, time.Now().UTC(),
	)
	if err != nil {
		return 0, fmt.Errorf("feedback store: insert: %w", err)
	}
	id, _ := res.LastInsertId()
	logrus.WithFields(logrus.Fields{
		"id":      id,
		"package": r.PackageName,
		"type":    r.Type,
	}).Info("Feedback recorded")
	return id, nil
}

// Stats returns a summary of recorded feedback.
type FeedbackStats struct {
	TotalRecords    int64 `json:"total_records"`
	FalsePositives  int64 `json:"false_positives"`
	FalseNegatives  int64 `json:"false_negatives"`
	Confirmed       int64 `json:"confirmed"`
	Last7DaysCount  int64 `json:"last_7_days_count"`
	NeedsRetrain    bool  `json:"needs_retrain"` // true when false_positives+false_negatives >= threshold
}

// Stats returns aggregate statistics about the feedback store.
func (s *FeedbackStore) Stats() (FeedbackStats, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	var stats FeedbackStats
	row := s.db.QueryRow(`SELECT COUNT(*) FROM feedback`)
	_ = row.Scan(&stats.TotalRecords)

	for _, q := range []struct {
		ft   FeedbackType
		dest *int64
	}{
		{FeedbackFalsePositive, &stats.FalsePositives},
		{FeedbackFalseNegative, &stats.FalseNegatives},
		{FeedbackConfirmed, &stats.Confirmed},
	} {
		row = s.db.QueryRow(`SELECT COUNT(*) FROM feedback WHERE type = ?`, string(q.ft))
		_ = row.Scan(q.dest)
	}

	cutoff := time.Now().UTC().AddDate(0, 0, -7).Format("2006-01-02")
	row = s.db.QueryRow(`SELECT COUNT(*) FROM feedback WHERE created_at >= ?`, cutoff)
	_ = row.Scan(&stats.Last7DaysCount)

	const retrainThreshold = 50
	stats.NeedsRetrain = (stats.FalsePositives + stats.FalseNegatives) >= retrainThreshold

	return stats, nil
}

// ExportTrainingCSV writes all feedback records as a CSV suitable for model retraining.
// Columns match the 25 FEATURE_NAMES + label (0=benign/1=malicious).
func (s *FeedbackStore) ExportTrainingCSV(outputPath string) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	rows, err := s.db.Query(
		`SELECT package_name, type, model_score, features FROM feedback ORDER BY created_at`,
	)
	if err != nil {
		return 0, fmt.Errorf("feedback export: query: %w", err)
	}
	defer rows.Close()

	if err := os.MkdirAll(filepath.Dir(outputPath), 0o700); err != nil {
		return 0, fmt.Errorf("feedback export: mkdir: %w", err)
	}
	f, err := os.Create(outputPath)
	if err != nil {
		return 0, fmt.Errorf("feedback export: create file: %w", err)
	}
	defer f.Close()

	// Header
	header := "log_downloads,maintainer_count,age_days,days_since_update,vuln_count,malware_reports,verified_flags," +
		"has_install_script,install_script_kb,has_preinstall,has_postinstall," +
		"maintainer_change_count,maintainer_velocity,domain_age_days," +
		"executable_binary_count,network_code_files,log_total_files," +
		"entropy_max_file,dependency_delta,log_version_count,days_between_versions," +
		"log_stars,log_forks,namespace_age_days,download_star_anomaly,label\n"
	if _, err := f.WriteString(header); err != nil {
		return 0, err
	}

	count := 0
	for rows.Next() {
		var pkgName, fbType, featJSON string
		var modelScore float64
		if err := rows.Scan(&pkgName, &fbType, &modelScore, &featJSON); err != nil {
			continue
		}

		var features []float32
		_ = json.Unmarshal([]byte(featJSON), &features)
		if len(features) < FeatureVectorSize {
			continue // skip incomplete records
		}

		// label: false_positive → 0 (actually benign), false_negative/confirmed → 1
		label := 0
		switch FeedbackType(fbType) {
		case FeedbackFalseNegative, FeedbackConfirmed:
			label = 1
		}

		line := ""
		for i, v := range features[:FeatureVectorSize] {
			if i > 0 {
				line += ","
			}
			line += fmt.Sprintf("%g", v)
		}
		line += fmt.Sprintf(",%d\n", label)

		if _, err := f.WriteString(line); err != nil {
			return count, err
		}
		count++
	}

	logrus.WithFields(logrus.Fields{
		"count": count,
		"path":  outputPath,
	}).Info("Feedback exported for retraining")
	return count, nil
}

// ModelVersion tracks which model version is active.
type ModelVersion struct {
	Version   string    `json:"version"`
	Path      string    `json:"path"`
	TrainedAt time.Time `json:"trained_at"`
	Metrics   struct {
		F1             float64 `json:"f1"`
		AUC            float64 `json:"auc"`
		FalsePositiveRate float64 `json:"false_positive_rate"`
	} `json:"metrics"`
	IsActive bool `json:"is_active"`
}

// ModelRegistry manages model versioning and A/B testing.
type ModelRegistry struct {
	mu       sync.RWMutex
	versions []ModelVersion
	active   int
	indexPath string
}

// NewModelRegistry loads or initialises a model registry from a JSON index file.
func NewModelRegistry(indexPath string) *ModelRegistry {
	mr := &ModelRegistry{indexPath: indexPath}
	_ = mr.load()
	return mr
}

func (mr *ModelRegistry) load() error {
	data, err := os.ReadFile(mr.indexPath)
	if err != nil {
		return nil // no file yet — start empty
	}
	return json.Unmarshal(data, &mr.versions)
}

func (mr *ModelRegistry) save() error {
	data, err := json.MarshalIndent(mr.versions, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(mr.indexPath, data, 0o600)
}

// Register adds a newly trained model to the registry.
func (mr *ModelRegistry) Register(v ModelVersion) error {
	mr.mu.Lock()
	defer mr.mu.Unlock()
	v.TrainedAt = time.Now().UTC()
	mr.versions = append(mr.versions, v)
	return mr.save()
}

// Promote sets the given version as the active inference model.
func (mr *ModelRegistry) Promote(version string) error {
	mr.mu.Lock()
	defer mr.mu.Unlock()
	found := false
	for i := range mr.versions {
		if mr.versions[i].Version == version {
			mr.versions[i].IsActive = true
			mr.active = i
			found = true
		} else {
			mr.versions[i].IsActive = false
		}
	}
	if !found {
		return fmt.Errorf("model version %q not found in registry", version)
	}
	return mr.save()
}

// ActiveModel returns the path of the currently active model file.
func (mr *ModelRegistry) ActiveModel() (string, bool) {
	mr.mu.RLock()
	defer mr.mu.RUnlock()
	if len(mr.versions) == 0 {
		return "", false
	}
	return mr.versions[mr.active].Path, true
}

// Versions returns all registered model versions (newest last).
func (mr *ModelRegistry) Versions() []ModelVersion {
	mr.mu.RLock()
	defer mr.mu.RUnlock()
	out := make([]ModelVersion, len(mr.versions))
	copy(out, mr.versions)
	return out
}

// Close releases database resources.
func (s *FeedbackStore) Close() error {
	return s.db.Close()
}
