package pool

import (
	"context"
	"fmt"
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
	queue []*task
	reg   map[string]*task
	wait  chan struct{}
}

type task struct {
	name     string
	fn       func(context.Context) time.Time
	deadline time.Time
	rerun    bool
}

func New(workers int) *Pool {
	pool := Pool{reg: make(map[string]*task)}

	for range workers {
		go pool.work()
	}

	return &pool
}

func (p *Pool) Add(name string, fn func(context.Context) time.Time) {
	p.enqueue(&task{name: name, fn: fn, deadline: time.Now()})
}

// work is the main loop for each worker goroutine.
func (p *Pool) work() {
	for {
		ctx := context.Background()
		p.enqueue(p.dequeue().Execute(ctx))
	}
}

// Trigger runs the named task NOW, if it is in the queue, regardless of the
// previous deadline, by pulling it into the front of the queue. If the named
// task is not queued, it's running. In that case, we'll have it override its
// next deadline to NOW, causing an immediate re-run after the current run.
// Subsequent runs will use the deadline returned by the task's `fn`.
func (p *Pool) Trigger(n string) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if i := slices.IndexFunc(p.queue, func(t *task) bool { return t.name == n }); i != -1 {
		p.queue[i].deadline = time.Now()
		p.sortAndWake()
		return nil
	}
	// if it's not in p.queue, it must be running at the moment
	if t, ok := p.reg[n]; ok {
		t.rerun = true
		return nil
	}

	return fmt.Errorf("no task with name %s", n)
}

// sortAndWake is used in multiple places, but always needs to be run
// within a p.mu lock!
func (p *Pool) sortAndWake() {
	// Maintain the tasks in deadline order.
	slices.SortFunc(p.queue, func(a, b *task) int {
		return a.deadline.Compare(b.deadline)
	})

	// Wake up any waiting goroutine.
	if p.wait != nil {
		close(p.wait)
		p.wait = nil
	}
}

func (p *Pool) enqueue(t *task) {
	if t.deadline.IsZero() {
		// Task requested removal from the pool.
		delete(p.reg, t.name)
		return
	}

	p.mu.Lock()
	p.reg[t.name] = t
	p.queue = append(p.queue, t)
	p.sortAndWake()
	p.mu.Unlock()
}

func (p *Pool) dequeue() *task {
	p.mu.Lock()
	defer p.mu.Unlock()

	for {

		var t *task
		if len(p.queue) == 0 {
			t = &task{name: "dummy", deadline: time.Now().Add(time.Hour * 24 * 365)} // Default to a far future deadline
		} else {
			t = p.queue[0]
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

	var t *task
	t, p.queue = p.queue[0], p.queue[1:]
	return t
}

func (t *task) Execute(ctx context.Context) *task {
	t.deadline = t.fn(ctx)
	if t.rerun {
		t.rerun = false
		t.deadline = time.Now()
	}
	return t
}
