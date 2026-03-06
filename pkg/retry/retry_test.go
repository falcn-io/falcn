package retry_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/falcn-io/falcn/pkg/retry"
)

// mockServer returns a *httptest.Server that responds with `codes` in sequence,
// then 200 OK for all subsequent requests.
func mockServer(t *testing.T, codes ...int) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := int(calls.Add(1)) - 1 // 0-indexed call number
		if n < len(codes) {
			w.WriteHeader(codes[n])
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	return srv, &calls
}

// callServer is a helper that makes a GET to url and wraps non-200 responses
// in a retry.StatusError so Do() can decide whether to retry.
func callServer(url string) func() error {
	return func() error {
		resp, err := http.Get(url) //nolint:gosec,noctx
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return retry.StatusError(resp.StatusCode, http.ErrNotSupported)
		}
		return nil
	}
}

func TestDo_SucceedsOnFirstAttempt(t *testing.T) {
	srv, calls := mockServer(t) // no codes → always 200
	defer srv.Close()

	err := retry.Do(context.Background(), 3, 10*time.Millisecond, callServer(srv.URL))
	if err != nil {
		t.Fatalf("expected nil, got %v", err)
	}
	if calls.Load() != 1 {
		t.Fatalf("expected 1 call, got %d", calls.Load())
	}
}

func TestDo_RetriesOn503ThenSucceeds(t *testing.T) {
	srv, calls := mockServer(t, 503, 503) // 503, 503, then 200
	defer srv.Close()

	err := retry.Do(context.Background(), 3, 10*time.Millisecond, callServer(srv.URL))
	if err != nil {
		t.Fatalf("expected nil after retry, got %v", err)
	}
	if calls.Load() != 3 {
		t.Fatalf("expected 3 calls, got %d", calls.Load())
	}
}

func TestDo_RetriesOn429(t *testing.T) {
	srv, calls := mockServer(t, 429) // 429, then 200
	defer srv.Close()

	err := retry.Do(context.Background(), 2, 5*time.Millisecond, callServer(srv.URL))
	if err != nil {
		t.Fatalf("expected nil, got %v", err)
	}
	if calls.Load() != 2 {
		t.Fatalf("expected 2 calls, got %d", calls.Load())
	}
}

func TestDo_ExhaustsAllAttempts(t *testing.T) {
	srv, calls := mockServer(t, 503, 503, 503, 503) // always fails
	defer srv.Close()

	err := retry.Do(context.Background(), 3, 5*time.Millisecond, callServer(srv.URL))
	if err == nil {
		t.Fatal("expected error after all attempts exhausted")
	}
	if calls.Load() != 3 {
		t.Fatalf("expected 3 calls, got %d", calls.Load())
	}
}

func TestDo_NoRetryOn400(t *testing.T) {
	srv, calls := mockServer(t, 400) // 400 is not retryable
	defer srv.Close()

	err := retry.Do(context.Background(), 3, 5*time.Millisecond, callServer(srv.URL))
	if err == nil {
		t.Fatal("expected error on 400")
	}
	if calls.Load() != 1 {
		t.Fatalf("expected 1 call (no retry on 400), got %d", calls.Load())
	}
}

func TestDo_ContextCancellation(t *testing.T) {
	srv, _ := mockServer(t, 503, 503, 503, 503)
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	// Cancel after the first failure, before the second retry sleep finishes.
	go func() {
		time.Sleep(30 * time.Millisecond)
		cancel()
	}()

	err := retry.Do(ctx, 5, 50*time.Millisecond, callServer(srv.URL))
	if err == nil {
		t.Fatal("expected error on context cancellation")
	}
}

func TestDo_NilErrorImmediateReturn(t *testing.T) {
	calls := 0
	err := retry.Do(context.Background(), 3, 5*time.Millisecond, func() error {
		calls++
		return nil
	})
	if err != nil {
		t.Fatalf("expected nil, got %v", err)
	}
	if calls != 1 {
		t.Fatalf("expected 1 call, got %d", calls)
	}
}
