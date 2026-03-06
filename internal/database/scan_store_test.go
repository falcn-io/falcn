package database

import (
	"fmt"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newTestStore creates a temporary ScanStore backed by a fresh SQLite file.
// It registers a cleanup function to close the database when the test ends.
func newTestStore(t *testing.T) *ScanStore {
	t.Helper()
	dir := t.TempDir()
	store, err := NewScanStore(filepath.Join(dir, "test.db"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.db.Close() })
	return store
}

// makeScanRecord builds a ScanRecord with the provided id, name, and threat count.
func makeScanRecord(id, name string, threats int) ScanRecord {
	return ScanRecord{
		ID:         id,
		Package:    name,
		Name:       name,
		Registry:   "npm",
		Status:     "completed",
		Threats:    threats,
		Warnings:   0,
		DurationMs: 150,
		CreatedAt:  time.Now().UTC(),
	}
}

// ─── NewScanStore ─────────────────────────────────────────────────────────────

func TestNewScanStore_CreatesFile(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "new.db")

	store, err := NewScanStore(dbPath)
	require.NoError(t, err)
	require.NotNil(t, store)
	t.Cleanup(func() { _ = store.Close() })
}

func TestNewScanStore_MigrationsRun(t *testing.T) {
	store := newTestStore(t)

	// After NewScanStore the schema_versions table must exist and contain at
	// least the migrations defined in sqliteMigrations.
	var count int
	err := store.db.QueryRow("SELECT COUNT(*) FROM schema_versions").Scan(&count)
	require.NoError(t, err)
	assert.Equal(t, len(sqliteMigrations), count, "expected one row per migration")
}

// ─── Insert / List ────────────────────────────────────────────────────────────

func TestScanStore_Insert_And_List(t *testing.T) {
	store := newTestStore(t)

	records := []ScanRecord{
		makeScanRecord("id-1", "package-a", 0),
		makeScanRecord("id-2", "package-b", 1),
		makeScanRecord("id-3", "package-c", 2),
	}
	for _, r := range records {
		require.NoError(t, store.Insert(r))
	}

	got, total, err := store.List(50, 0)
	require.NoError(t, err)
	assert.Equal(t, 3, total, "expected total == 3")
	assert.Len(t, got, 3, "expected 3 records back")
}

func TestScanStore_Insert_Duplicate(t *testing.T) {
	// INSERT OR REPLACE means inserting the same ID twice must succeed and result
	// in exactly one row (the second write replaces the first).
	store := newTestStore(t)

	r := makeScanRecord("dup-id", "mypkg", 0)
	require.NoError(t, store.Insert(r))

	// Change a field so we can verify the replacement took effect.
	r.Threats = 99
	require.NoError(t, store.Insert(r), "duplicate insert should succeed (replace)")

	got, total, err := store.List(50, 0)
	require.NoError(t, err)
	assert.Equal(t, 1, total, "duplicate insert must not create a second row")
	require.Len(t, got, 1)
	assert.Equal(t, 99, got[0].Threats, "replace must update the existing row")
}

func TestScanStore_List_Pagination(t *testing.T) {
	store := newTestStore(t)

	for i := 0; i < 10; i++ {
		r := makeScanRecord(fmt.Sprintf("id-%02d", i), fmt.Sprintf("pkg-%02d", i), 0)
		// Stagger creation times so the DESC ordering is deterministic.
		r.CreatedAt = time.Now().UTC().Add(time.Duration(i) * time.Second)
		require.NoError(t, store.Insert(r))
	}

	page1, total, err := store.List(3, 0)
	require.NoError(t, err)
	assert.Equal(t, 10, total)
	assert.Len(t, page1, 3)

	page2, _, err := store.List(3, 3)
	require.NoError(t, err)
	assert.Len(t, page2, 3)

	// The two pages must not overlap.
	ids1 := map[string]bool{}
	for _, r := range page1 {
		ids1[r.ID] = true
	}
	for _, r := range page2 {
		assert.False(t, ids1[r.ID], "page 2 must not repeat IDs from page 1")
	}
}

func TestScanStore_List_Empty(t *testing.T) {
	store := newTestStore(t)

	got, total, err := store.List(50, 0)
	require.NoError(t, err)
	assert.Equal(t, 0, total)
	assert.Empty(t, got, "empty store must return empty slice, not nil error")
}

func TestScanStore_List_LimitClamping(t *testing.T) {
	store := newTestStore(t)

	// A limit of 0 should be clamped to the default (50); we insert fewer
	// than 50 rows so we just check no error is returned.
	for i := 0; i < 5; i++ {
		require.NoError(t, store.Insert(makeScanRecord(fmt.Sprintf("clamp-%d", i), "pkg", 0)))
	}

	_, total, err := store.List(0, 0)
	require.NoError(t, err)
	assert.Equal(t, 5, total)
}

// ─── ThreatSummary ────────────────────────────────────────────────────────────

func TestScanStore_ThreatSummary(t *testing.T) {
	store := newTestStore(t)

	data := []struct {
		threats  int
		warnings int
	}{
		{2, 1},
		{0, 3},
		{5, 0},
		{1, 2},
		{0, 0},
	}
	for i, d := range data {
		r := makeScanRecord(fmt.Sprintf("ts-%d", i), "pkg", d.threats)
		r.Warnings = d.warnings
		require.NoError(t, store.Insert(r))
	}

	totalScans, totalThreats, totalWarnings, err := store.ThreatSummary()
	require.NoError(t, err)
	assert.Equal(t, 5, totalScans)
	assert.Equal(t, 8, totalThreats)  // 2+0+5+1+0
	assert.Equal(t, 6, totalWarnings) // 1+3+0+2+0
}

func TestScanStore_ThreatSummary_Empty(t *testing.T) {
	store := newTestStore(t)

	totalScans, totalThreats, totalWarnings, err := store.ThreatSummary()
	require.NoError(t, err)
	assert.Equal(t, 0, totalScans)
	assert.Equal(t, 0, totalThreats)
	assert.Equal(t, 0, totalWarnings)
}

// ─── RecentActivity ───────────────────────────────────────────────────────────

func TestScanStore_RecentActivity(t *testing.T) {
	store := newTestStore(t)

	now := time.Now().UTC()

	// 3 records within the last 24 h
	for i := 0; i < 3; i++ {
		r := makeScanRecord(fmt.Sprintf("recent-%d", i), "pkg", i+1)
		r.CreatedAt = now.Add(-time.Duration(i+1) * time.Hour)
		require.NoError(t, store.Insert(r))
	}
	// 2 records older than 24 h (should be excluded)
	for i := 0; i < 2; i++ {
		r := makeScanRecord(fmt.Sprintf("old-%d", i), "pkg", 0)
		r.CreatedAt = now.Add(-time.Duration(25+i) * time.Hour)
		require.NoError(t, store.Insert(r))
	}

	scans24h, threats24h, err := store.RecentActivity()
	require.NoError(t, err)
	assert.Equal(t, 3, scans24h, "only records from last 24h should be counted")
	// threat sum for recent records: 1+2+3 = 6
	assert.Equal(t, 6, threats24h)
}

// ─── AvgDurationMs ────────────────────────────────────────────────────────────

func TestScanStore_AvgDurationMs_Empty(t *testing.T) {
	store := newTestStore(t)

	avg, err := store.AvgDurationMs()
	require.NoError(t, err)
	assert.Equal(t, int64(0), avg, "empty store must return 0, not an error")
}

func TestScanStore_AvgDurationMs(t *testing.T) {
	store := newTestStore(t)

	durations := []int64{100, 200, 300, 400}
	for i, d := range durations {
		r := makeScanRecord(fmt.Sprintf("dur-%d", i), "pkg", 0)
		r.DurationMs = d
		require.NoError(t, store.Insert(r))
	}

	avg, err := store.AvgDurationMs()
	require.NoError(t, err)
	// Average of 100, 200, 300, 400 = 250
	assert.Equal(t, int64(250), avg)
}

// ─── InsertThreat / ListThreats ───────────────────────────────────────────────

func TestScanStore_InsertThreat_And_ListThreats(t *testing.T) {
	store := newTestStore(t)

	// A scan_threats row references a scan via foreign key; insert the parent first.
	scan := makeScanRecord("scan-001", "mypkg", 1)
	require.NoError(t, store.Insert(scan))

	threat := ScanThreatRecord{
		ScanID:      "scan-001",
		ThreatType:  "typosquatting",
		Severity:    "high",
		PackageName: "mypkg",
		Description: "Suspicious name similarity",
		Score:       0.92,
		CreatedAt:   time.Now().UTC(),
	}
	require.NoError(t, store.InsertThreat(threat))

	threats, err := store.ListThreats("scan-001")
	require.NoError(t, err)
	require.Len(t, threats, 1)
	assert.Equal(t, "scan-001", threats[0].ScanID)
	assert.Equal(t, "typosquatting", threats[0].ThreatType)
	assert.Equal(t, "high", threats[0].Severity)
	assert.InDelta(t, 0.92, threats[0].Score, 0.001)
}

func TestScanStore_ListThreats_Empty(t *testing.T) {
	store := newTestStore(t)

	// Inserting a scan with no threats: ListThreats must return empty slice.
	require.NoError(t, store.Insert(makeScanRecord("scan-no-threat", "pkg", 0)))

	threats, err := store.ListThreats("scan-no-threat")
	require.NoError(t, err)
	assert.Empty(t, threats)
}

func TestScanStore_ListThreats_MultipleOrdered(t *testing.T) {
	store := newTestStore(t)

	require.NoError(t, store.Insert(makeScanRecord("scan-multi", "pkg", 3)))

	scores := []float64{0.3, 0.9, 0.6}
	for i, score := range scores {
		require.NoError(t, store.InsertThreat(ScanThreatRecord{
			ScanID:      "scan-multi",
			ThreatType:  fmt.Sprintf("type-%d", i),
			Severity:    "medium",
			PackageName: "pkg",
			Description: "desc",
			Score:       score,
			CreatedAt:   time.Now().UTC(),
		}))
	}

	threats, err := store.ListThreats("scan-multi")
	require.NoError(t, err)
	require.Len(t, threats, 3)
	// Must come back ordered by confidence DESC.
	assert.GreaterOrEqual(t, threats[0].Score, threats[1].Score)
	assert.GreaterOrEqual(t, threats[1].Score, threats[2].Score)
}

// ─── Concurrency ──────────────────────────────────────────────────────────────

func TestScanStore_ConcurrentInserts(t *testing.T) {
	store := newTestStore(t)

	const goroutines = 10
	const insertsPerGoroutine = 5

	var wg sync.WaitGroup
	wg.Add(goroutines)

	for g := 0; g < goroutines; g++ {
		g := g
		go func() {
			defer wg.Done()
			for i := 0; i < insertsPerGoroutine; i++ {
				id := fmt.Sprintf("g%d-i%d", g, i)
				r := makeScanRecord(id, "pkg", 0)
				if err := store.Insert(r); err != nil {
					t.Errorf("concurrent Insert error: %v", err)
				}
			}
		}()
	}

	wg.Wait()

	_, total, err := store.List(1, 0)
	require.NoError(t, err)
	assert.Equal(t, goroutines*insertsPerGoroutine, total,
		"all concurrent inserts must be persisted")
}

// ─── Large dataset ────────────────────────────────────────────────────────────

func TestScanStore_LargeDataset(t *testing.T) {
	store := newTestStore(t)

	const total = 1000
	for i := 0; i < total; i++ {
		r := makeScanRecord(fmt.Sprintf("large-%04d", i), "pkg", 0)
		require.NoError(t, store.Insert(r))
	}

	got, n, err := store.List(100, 0)
	require.NoError(t, err)
	assert.Equal(t, total, n)
	assert.Len(t, got, 100, "List(100, 0) must return exactly 100 records")
}

// ─── Close ────────────────────────────────────────────────────────────────────

func TestScanStore_Close(t *testing.T) {
	dir := t.TempDir()
	store, err := NewScanStore(filepath.Join(dir, "close.db"))
	require.NoError(t, err)
	require.NoError(t, store.Close())
}
