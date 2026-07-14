package pool

import (
	"context"
	"slices"
	"sync"
	"time"
)

// Pool executes tasks in order of their deadlines, using a fixed number of goroutines.
// Tasks are added to the pool with a function that returns the next deadline.
// The pool will execute the tasks in the order of their deadlines, ensuring that
// tasks with earlier deadlines are executed before those with later deadlines.
// If a task is added while the pool is waiting for the next task, it will wake up
// the waiting goroutine to process the new task immediately.
type Pool struct {
	mu    sync.Mutex
	tasks []*task
	wait  chan struct{}
	done  chan struct{}
}

type task struct {
	ctx      context.Context
	fn       func(context.Context) time.Time
	deadline time.Time
}

func New(workers int) *Pool {
	pool := &Pool{
		done: make(chan struct{}),
	}

	for range workers {
		go pool.work()
	}

	return pool
}

// Stop signals all worker goroutines to exit. It returns once all workers have stopped.
func (p *Pool) Stop() {
	close(p.done)
}

// Add schedules fn to run in the pool. ctx is retained for the lifetime of the task,
// including any rescheduled executions (fn returning a future deadline), and is passed
// to every invocation of fn instead of a detached background context. Cancelling ctx
// does not interrupt an in-progress call to fn; fn is responsible for observing
// ctx.Done() itself if it needs to abort early.
func (p *Pool) Add(ctx context.Context, fn func(context.Context) time.Time) {
	p.enqueue(&task{ctx: ctx, fn: fn, deadline: time.Now()})
}

// work is the main loop for each worker goroutine.
func (p *Pool) work() {
	for {
		t, ok := p.dequeue()
		if !ok {
			return
		}
		p.enqueue(t.Execute(t.ctx))
	}
}

func (p *Pool) enqueue(t *task) {
	if t.deadline.IsZero() {
		// Task requested removal from the pool.
		return
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	// Maintain the tasks in deadline order.
	p.tasks = append(p.tasks, t)
	slices.SortFunc(p.tasks, func(a, b *task) int {
		return a.deadline.Compare(b.deadline)
	})

	// Wake up any waiting goroutine.
	if p.wait != nil {
		close(p.wait)
		p.wait = nil
	}
}

// dequeue blocks until a task is ready or the pool is stopped.
// Returns (task, true) when a task is ready, or (nil, false) when stopped.
func (p *Pool) dequeue() (*task, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()

	for {
		var t *task
		if len(p.tasks) == 0 {
			t = &task{deadline: time.Now().Add(time.Hour * 24 * 365)} // Default to a far future deadline
		} else {
			t = p.tasks[0]
		}

		if t.deadline.After(time.Now()) {
			// Task is not ready yet, wait for it to be executed or another (potentially earlier) task to arrive.

			if p.wait == nil {
				p.wait = make(chan struct{})
			}

			wait := p.wait

			p.mu.Unlock()

			select {
			case <-time.After(time.Until(t.deadline)):
			case <-wait:
			case <-p.done:
				p.mu.Lock()
				return nil, false
			}

			p.mu.Lock()
			continue
		}

		// The first queued task is ready to be executed, remove it from the queue.
		break
	}

	t := p.tasks[0]
	p.tasks = slices.Delete(p.tasks, 0, 1)
	return t, true
}

func (t *task) Execute(ctx context.Context) *task {
	t.deadline = t.fn(ctx)
	return t
}
