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
}

type task struct {
	fn       func(context.Context) time.Time
	deadline time.Time
}

func New(workers int) *Pool {
	var pool Pool

	for range workers {
		go pool.work()
	}

	return &pool
}

func (p *Pool) Add(fn func(context.Context) time.Time) {
	p.enqueue(&task{fn: fn, deadline: time.Now()})
}

// work is the main loop for each worker goroutine.
func (p *Pool) work() {
	for {
		ctx := context.Background()
		p.enqueue(p.dequeue().Execute(ctx))
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

func (p *Pool) dequeue() *task {
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
			}

			p.mu.Lock()
			continue
		}

		// The first queued task is ready to be executed, remove it from the queue.
		break
	}

	t := p.tasks[0]
	p.tasks = slices.Delete(p.tasks, 0, 1)
	return t
}

func (t *task) Execute(ctx context.Context) *task {
	t.deadline = t.fn(ctx)
	return t
}
