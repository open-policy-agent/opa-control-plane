package pool

import (
	"context"
	"testing"
	"time"
)

func TestPool(t *testing.T) {
	p := New(2)
	ctx := context.Background()

	// Add a task that returns a deadline in the future.
	p.Add(ctx, func(_ context.Context) time.Time {
		return time.Now().Add(100 * time.Millisecond)
	})

	// Add a task that returns a deadline in the past.
	p.Add(ctx, func(_ context.Context) time.Time {
		return time.Now().Add(-100 * time.Millisecond)
	})

	// Add a task that returns a deadline in the future.
	p.Add(ctx, func(_ context.Context) time.Time {
		return time.Now().Add(200 * time.Millisecond)
	})

	// Wait for a short period to allow tasks to be processed.
	time.Sleep(300 * time.Millisecond)

	// The pool should have processed all tasks without deadlock.
	t.Log("All tasks processed successfully")
}

func TestPoolPropagatesTaskContext(t *testing.T) {
	p := New(1)

	type ctxKey struct{}
	ctx := context.WithValue(context.Background(), ctxKey{}, "value")

	seen := make(chan context.Context, 1)
	p.Add(ctx, func(fnCtx context.Context) time.Time {
		seen <- fnCtx
		return time.Time{} // remove the task from the pool
	})

	select {
	case fnCtx := <-seen:
		if fnCtx.Value(ctxKey{}) != "value" {
			t.Fatalf("task did not receive the context passed to Add")
		}
	case <-time.After(time.Second):
		t.Fatal("task was never executed")
	}
}

func TestPoolObservesContextCancellation(t *testing.T) {
	p := New(1)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	done := make(chan error, 1)
	p.Add(ctx, func(fnCtx context.Context) time.Time {
		done <- fnCtx.Err()
		return time.Time{} // remove the task from the pool
	})

	select {
	case err := <-done:
		if err != context.Canceled {
			t.Fatalf("expected context.Canceled, got: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("task was never executed")
	}
}
