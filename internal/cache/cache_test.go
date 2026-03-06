package cache

import (
	"context"
	"testing"
	"time"
)

// ─── MemoryCache ───────────────────────────────────────────────────────────────

func TestMemoryCache_SetAndGet(t *testing.T) {
	mc := NewMemoryCache()
	mc.Set("k1", "hello", time.Minute)

	val, ok := mc.Get("k1")
	if !ok {
		t.Fatal("expected cache hit")
	}
	if val != "hello" {
		t.Fatalf("expected 'hello', got %v", val)
	}
}

func TestMemoryCache_MissOnUnknownKey(t *testing.T) {
	mc := NewMemoryCache()
	_, ok := mc.Get("nonexistent")
	if ok {
		t.Fatal("expected cache miss for unknown key")
	}
}

func TestMemoryCache_TTLExpiry(t *testing.T) {
	mc := NewMemoryCache()
	mc.Set("expiring", "value", 50*time.Millisecond)

	time.Sleep(100 * time.Millisecond)

	_, ok := mc.Get("expiring")
	if ok {
		t.Fatal("expected expired entry to be a miss")
	}
}

func TestMemoryCache_Delete(t *testing.T) {
	mc := NewMemoryCache()
	mc.Set("key", "value", time.Minute)
	mc.Delete("key")

	_, ok := mc.Get("key")
	if ok {
		t.Fatal("expected deleted key to be a miss")
	}
}

func TestMemoryCache_Clear(t *testing.T) {
	mc := NewMemoryCache()
	mc.Set("a", 1, time.Minute)
	mc.Set("b", 2, time.Minute)
	mc.Clear()

	for _, k := range []string{"a", "b"} {
		if _, ok := mc.Get(k); ok {
			t.Fatalf("expected key %q to be cleared", k)
		}
	}
}

func TestMemoryCache_CleanupExpired(t *testing.T) {
	mc := NewMemoryCache()
	mc.Set("ephemeral", "gone", 50*time.Millisecond)
	mc.Set("permanent", "stays", time.Minute)

	time.Sleep(100 * time.Millisecond)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // immediately stop after one tick — just verify it doesn't panic

	// CleanupExpired runs in a background goroutine; just make sure it doesn't panic.
	go mc.CleanupExpired(ctx)
	time.Sleep(10 * time.Millisecond)

	// The permanent key should still be accessible.
	if _, ok := mc.Get("permanent"); !ok {
		t.Fatal("permanent key should still exist after cleanup")
	}
}

// ─── CacheIntegration ─────────────────────────────────────────────────────────

func newTestIntegration(t *testing.T) *CacheIntegration {
	t.Helper()
	cfg := &CacheConfig{
		Enabled: true,
		TTL:     time.Minute,
	}
	ci, err := NewCacheIntegration(cfg)
	if err != nil {
		t.Fatalf("NewCacheIntegration: %v", err)
	}
	return ci
}

func TestCacheIntegration_NilConfigError(t *testing.T) {
	_, err := NewCacheIntegration(nil)
	if err == nil {
		t.Fatal("expected error for nil config")
	}
}

func TestCacheIntegration_ExplanationRoundtrip(t *testing.T) {
	ci := newTestIntegration(t)

	type fakeExpl struct{ Text string }
	expl := &fakeExpl{Text: "this is suspicious"}

	ci.SetExplanation("pkg", "1.0.0", "typosquatting", expl)

	got, ok := ci.GetExplanation("pkg", "1.0.0", "typosquatting")
	if !ok {
		t.Fatal("expected cache hit for explanation")
	}
	if got.(*fakeExpl).Text != expl.Text {
		t.Fatalf("explanation mismatch: got %v", got)
	}
}

func TestCacheIntegration_ExplanationKeyMiss(t *testing.T) {
	ci := newTestIntegration(t)
	_, ok := ci.GetExplanation("missing", "0.0.0", "malicious")
	if ok {
		t.Fatal("expected cache miss for unknown explanation")
	}
}

func TestCacheIntegration_DisabledDoesNotStore(t *testing.T) {
	cfg := &CacheConfig{Enabled: false, TTL: time.Minute}
	ci, _ := NewCacheIntegration(cfg)

	// When disabled, CacheScanResult must be a no-op (no error).
	if err := ci.CacheScanResult("key", nil, nil); err != nil {
		t.Fatalf("CacheScanResult with disabled cache returned error: %v", err)
	}

	if _, found, _ := ci.GetCachedScanResult("key"); found {
		t.Fatal("expected no cached result when cache is disabled")
	}
}

func TestCacheIntegration_InvalidateAll(t *testing.T) {
	ci := newTestIntegration(t)
	ci.SetExplanation("a", "1", "t", "expl1")
	ci.SetExplanation("b", "2", "t", "expl2")

	if err := ci.InvalidatePackageCache(""); err != nil {
		t.Fatalf("InvalidatePackageCache: %v", err)
	}

	if _, ok := ci.GetExplanation("a", "1", "t"); ok {
		t.Fatal("expected cache cleared after InvalidatePackageCache('')")
	}
}

func TestCacheIntegration_StartCleanup_ContextCancel(t *testing.T) {
	cfg := &CacheConfig{
		Enabled:         true,
		TTL:             time.Second,
		CleanupInterval: 10 * time.Millisecond,
	}
	ci, _ := NewCacheIntegration(cfg)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		ci.StartCleanup(ctx)
		close(done)
	}()
	cancel()
	select {
	case <-done:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("StartCleanup did not exit after context cancellation")
	}
}

func TestCacheIntegration_GenerateScanKey(t *testing.T) {
	ci := newTestIntegration(t)
	key, err := ci.GenerateScanKey("/path/to/project", []string{"osv", "nvd"}, nil)
	if err != nil {
		t.Fatalf("GenerateScanKey error: %v", err)
	}
	if key == "" {
		t.Fatal("expected non-empty scan key")
	}
}

func TestExplanationKey(t *testing.T) {
	k := ExplanationKey("express", "4.18.0", "typosquatting")
	expected := "explain:express:4.18.0:typosquatting"
	if k != expected {
		t.Fatalf("expected %q, got %q", expected, k)
	}
}
