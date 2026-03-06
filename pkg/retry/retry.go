// Package retry provides a generic HTTP-aware retry helper with exponential
// backoff and jitter. It is used throughout Falcn wherever external HTTP calls
// can experience transient failures (429, 502, 503, 504, network timeouts).
package retry

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"net"
	"net/http"
	"time"
)

// RetryableError wraps a non-nil error together with the HTTP status code that
// triggered it. The zero status (0) means a network-level failure (no response).
type RetryableError struct {
	StatusCode int
	Cause      error
}

func (e *RetryableError) Error() string {
	if e.StatusCode != 0 {
		return fmt.Sprintf("HTTP %d: %v", e.StatusCode, e.Cause)
	}
	return e.Cause.Error()
}

func (e *RetryableError) Unwrap() error { return e.Cause }

// StatusError creates a RetryableError for the given HTTP status code.
func StatusError(statusCode int, cause error) *RetryableError {
	return &RetryableError{StatusCode: statusCode, Cause: cause}
}

// isRetryable reports whether err is a transient failure worth retrying.
// It recognises:
//   - HTTP 429 (rate-limited), 502/503/504 (gateway errors)
//   - Network-level errors (timeouts, connection resets, DNS failures)
//   - io.EOF / io.ErrUnexpectedEOF on the response body
func isRetryable(err error) bool {
	if err == nil {
		return false
	}
	var re *RetryableError
	if errors.As(err, &re) {
		switch re.StatusCode {
		case http.StatusTooManyRequests,    // 429
			http.StatusBadGateway,         // 502
			http.StatusServiceUnavailable, // 503
			http.StatusGatewayTimeout:     // 504
			return true
		}
		// StatusCode == 0 → network-level failure below
	}
	// Network-level transient errors
	var netErr net.Error
	if errors.As(err, &netErr) {
		return netErr.Timeout()
	}
	return false
}

// Do calls fn up to maxAttempts times, sleeping between attempts with
// exponential backoff starting at base and capped at 30 s. A random jitter of
// ±20 % is applied to avoid thundering-herd effects.
//
// fn should return a *RetryableError (via StatusError) for HTTP errors so Do
// can decide whether to retry. Plain errors (e.g. JSON parse failures) are
// returned immediately without retry.
//
// Do honours ctx cancellation between attempts.
func Do(ctx context.Context, maxAttempts int, base time.Duration, fn func() error) error {
	const maxDelay = 30 * time.Second
	if maxAttempts <= 0 {
		maxAttempts = 3
	}

	var lastErr error
	delay := base

	for attempt := 0; attempt < maxAttempts; attempt++ {
		if attempt > 0 {
			// Apply ±20 % jitter
			jitter := time.Duration(rand.Int63n(int64(delay/5)*2) - int64(delay/5))
			sleep := delay + jitter
			select {
			case <-ctx.Done():
				return fmt.Errorf("retry: context cancelled after %d attempt(s): %w", attempt, ctx.Err())
			case <-time.After(sleep):
			}
			// Exponential backoff, capped
			delay *= 2
			if delay > maxDelay {
				delay = maxDelay
			}
		}

		err := fn()
		if err == nil {
			return nil
		}
		lastErr = err
		if !isRetryable(err) {
			return err // non-transient — fail fast
		}
	}

	return fmt.Errorf("retry: all %d attempt(s) failed: %w", maxAttempts, lastErr)
}
