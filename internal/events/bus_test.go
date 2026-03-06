package events

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	pkgevents "github.com/falcn-io/falcn/pkg/events"
	"github.com/falcn-io/falcn/pkg/logger"
)

// testSubscriber is a simple EventSubscriber implementation for testing.
// mu protects handled and errOnce which are written by the bus goroutine
// and read by the test goroutine.
type testSubscriber struct {
	mu      sync.Mutex
	id      string
	handled []*pkgevents.SecurityEvent
	errOnce bool
}

func (s *testSubscriber) GetID() string { return s.id }

func (s *testSubscriber) Handle(_ context.Context, event *pkgevents.SecurityEvent) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.errOnce {
		s.errOnce = false
		return errors.New("handler error")
	}
	s.handled = append(s.handled, event)
	return nil
}

func (s *testSubscriber) lenHandled() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.handled)
}

func (s *testSubscriber) firstHandledID() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.handled) == 0 {
		return ""
	}
	return s.handled[0].ID
}

func newTestBus() *EventBus {
	log := logger.New()
	return NewEventBus(*log, 100)
}

func newEvent(id string) *pkgevents.SecurityEvent {
	return &pkgevents.SecurityEvent{
		ID:       id,
		Type:     pkgevents.EventTypeThreatDetected,
		Severity: pkgevents.SeverityHigh,
	}
}

// ─── Subscribe / Unsubscribe ─────────────────────────────────────────────────

func TestEventBus_Subscribe(t *testing.T) {
	bus := newTestBus()
	sub := &testSubscriber{id: "sub1"}
	bus.Subscribe(pkgevents.EventTypeThreatDetected, sub)

	bus.mu.RLock()
	count := len(bus.subscribers[pkgevents.EventTypeThreatDetected])
	bus.mu.RUnlock()

	if count != 1 {
		t.Fatalf("expected 1 subscriber, got %d", count)
	}
}

func TestEventBus_Unsubscribe(t *testing.T) {
	bus := newTestBus()
	sub := &testSubscriber{id: "sub1"}
	bus.Subscribe(pkgevents.EventTypeThreatDetected, sub)
	bus.Unsubscribe(pkgevents.EventTypeThreatDetected, "sub1")

	bus.mu.RLock()
	count := len(bus.subscribers[pkgevents.EventTypeThreatDetected])
	bus.mu.RUnlock()

	if count != 0 {
		t.Fatalf("expected 0 subscribers after Unsubscribe, got %d", count)
	}
}

// ─── Publish ─────────────────────────────────────────────────────────────────

func TestEventBus_Publish_QueuesFull(t *testing.T) {
	// Create a bus with a very small queue.
	log := logger.New()
	bus := NewEventBus(*log, 1)

	ctx := context.Background()
	// Fill the queue.
	if err := bus.Publish(ctx, newEvent("e1")); err != nil {
		t.Fatalf("first publish should succeed: %v", err)
	}
	// Next publish should fail (queue full, non-blocking).
	err := bus.Publish(ctx, newEvent("e2"))
	if err == nil {
		t.Fatal("expected error when queue is full")
	}
}

func TestEventBus_Publish_ContextCancelled(t *testing.T) {
	bus := newTestBus()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	// Fill the queue first to force the select to check ctx.Done.
	// With a large queue (100) the first publish still succeeds via the default branch.
	// Just verify the API doesn't panic on cancelled context.
	_ = bus.Publish(ctx, newEvent("e1"))
}

// ─── Start / Stop ─────────────────────────────────────────────────────────────

func TestEventBus_StartStop(t *testing.T) {
	bus := newTestBus()
	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan struct{})
	go func() {
		bus.Start(ctx)
		close(done)
	}()

	cancel()
	select {
	case <-done:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("Start did not exit within 500ms of context cancellation")
	}
}

func TestEventBus_StartIdempotent(t *testing.T) {
	bus := newTestBus()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go bus.Start(ctx)
	time.Sleep(10 * time.Millisecond)

	// Calling Start again should be a no-op (bus is already running).
	done := make(chan struct{})
	go func() {
		bus.Start(ctx) // should return immediately because running=true
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(200 * time.Millisecond):
		t.Fatal("second Start call should return immediately")
	}
}

// ─── Event Delivery ──────────────────────────────────────────────────────────

func TestEventBus_EventDelivery(t *testing.T) {
	bus := newTestBus()
	sub := &testSubscriber{id: "receiver"}
	bus.Subscribe(pkgevents.EventTypeThreatDetected, sub)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go bus.Start(ctx)

	event := newEvent("evt-1")
	if err := bus.Publish(ctx, event); err != nil {
		t.Fatalf("Publish error: %v", err)
	}

	// Give the bus goroutine time to deliver.
	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		if sub.lenHandled() >= 1 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	if sub.lenHandled() == 0 {
		t.Fatal("event was not delivered to subscriber")
	}
	if id := sub.firstHandledID(); id != "evt-1" {
		t.Fatalf("unexpected event ID: %s", id)
	}
}

// ─── Metrics ─────────────────────────────────────────────────────────────────

func TestEventBus_MetricsPublished(t *testing.T) {
	bus := newTestBus()
	ctx := context.Background()

	if err := bus.Publish(ctx, newEvent("m1")); err != nil {
		t.Fatalf("Publish: %v", err)
	}

	bus.metrics.mu.RLock()
	published := bus.metrics.EventsPublished
	bus.metrics.mu.RUnlock()

	if published != 1 {
		t.Fatalf("expected 1 published event, got %d", published)
	}
}

func TestEventBus_Stop_ViaClose(t *testing.T) {
	bus := newTestBus()
	ctx := context.Background()

	done := make(chan struct{})
	var stopped atomic.Bool
	go func() {
		bus.Start(ctx)
		stopped.Store(true)
		close(done)
	}()

	time.Sleep(20 * time.Millisecond)
	close(bus.eventQueue) // simulate Stop() closing the channel

	select {
	case <-done:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("Start did not exit after channel close")
	}
	if !stopped.Load() {
		t.Fatal("Start goroutine should have exited")
	}
}
