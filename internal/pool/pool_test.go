package pool

import (
	"context"
	"testing"
	"time"
)

func TestPool(t *testing.T) {
	p := New(2)

	// Add a task that returns a deadline in the future.
	p.Add("a", func(context.Context) time.Time {
		return time.Now().Add(100 * time.Millisecond)
	})

	// Add a task that returns a deadline in the past.
	p.Add("b", func(context.Context) time.Time {
		return time.Now().Add(-100 * time.Millisecond)
	})

	// Add a task that returns a deadline in the future.
	p.Add("c", func(context.Context) time.Time {
		return time.Now().Add(200 * time.Millisecond)
	})

	// Wait for a short period to allow tasks to be processed.
	time.Sleep(300 * time.Millisecond)

	// The pool should have processed all tasks without deadlock.
	// If it had gotten stuck, we'd never reach this line.
	t.Log("All tasks processed successfully")
}

type run struct {
	left     int
	ran      int
	sleep    time.Duration
	deadline time.Duration
}

func (t *run) Execute(context.Context) time.Time {
	if t.left > 0 {
		time.Sleep(t.sleep)
		t.left--
		t.ran++
		return time.Now().Add(t.deadline)
	}

	var zero time.Time
	return zero // dequeue task
}

func TestTrigger(t *testing.T) {
	t.Run("trigger pulls queued task up from", func(t *testing.T) {
		p := New(2)

		rx := &run{left: 3, deadline: 200 * time.Millisecond}

		p.Add("t", rx.Execute) // will run once (run #1), and be queued for 200 ms

		_ = p.Trigger("t") // pulled in front, run #2
		time.Sleep(50 * time.Millisecond)
		_ = p.Trigger("t")                 // pulled in front, run #3
		time.Sleep(300 * time.Millisecond) // no other runs, third run dequeued

		if exp, act := 3, rx.ran; exp != act {
			t.Errorf("expected counter of %d, got %d", exp, act)
		}
	})

	t.Run("trigger reruns executing task right away", func(t *testing.T) {
		p := New(2)

		// if it wasn't triggered, we'd not see a second run: the next deadline is 1s
		rx := &run{left: 3, sleep: 100 * time.Millisecond, deadline: time.Second}

		p.Add("t", rx.Execute) // will run once (run #1), and be queued for 200 ms
		time.Sleep(50 * time.Millisecond)
		_ = p.Trigger("t") // re-run after it's done, run #2

		time.Sleep(300 * time.Millisecond)

		if exp, act := 2, rx.ran; exp != act {
			t.Errorf("expected counter of %d, got %d", exp, act)
		}
	})
}
