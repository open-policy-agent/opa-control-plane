package service

import (
	"bytes"
	"context"
	"time"

	"github.com/open-policy-agent/opa/ast" // nolint:staticcheck
	"github.com/styrainc/opa-control-plane/internal/builder"
	"github.com/styrainc/opa-control-plane/internal/config"
	"github.com/styrainc/opa-control-plane/internal/logging"
	"github.com/styrainc/opa-control-plane/internal/metrics"
	"github.com/styrainc/opa-control-plane/internal/progress"
	"github.com/styrainc/opa-control-plane/internal/s3"
)

var (
	errorDelay = 30 * time.Second
)

// BundleWorker is responsible for constructing a bundle from the source
// dependencies and uploading it to an object storage service. It uses a git
// synchronizer to pull the latest changes from the source repositories,
// constructs a bundle using the builder package, and uploads the resulting
// bundle to an S3-compatible object storage service.
type BundleWorker struct {
	bundleDir     string
	bundleConfig  *config.Bundle
	sourceConfigs config.Sources
	stackConfigs  config.Stacks
	synchronizers []Synchronizer
	sources       []*builder.Source
	storage       s3.ObjectStorage
	changed       chan struct{}
	done          chan struct{}
	singleShot    bool
	log           *logging.Logger
	bar           *progress.Bar
	status        Status
}

type Synchronizer interface {
	Execute(ctx context.Context) error
	Close(ctx context.Context)
}

func NewBundleWorker(bundleDir string, b *config.Bundle, sources []*config.Source, stacks []*config.Stack, logger *logging.Logger, bar *progress.Bar) *BundleWorker {
	return &BundleWorker{
		bundleDir:     bundleDir,
		bundleConfig:  b,
		sourceConfigs: sources,
		stackConfigs:  stacks,
		log:           logger,
		bar:           bar,
		changed:       make(chan struct{}), done: make(chan struct{}),
	}
}

func (worker *BundleWorker) WithSynchronizers(synchronizers []Synchronizer) *BundleWorker {
	worker.synchronizers = synchronizers
	return worker
}

func (worker *BundleWorker) WithSources(sources []*builder.Source) *BundleWorker {
	worker.sources = sources
	return worker
}

func (worker *BundleWorker) WithStorage(storage s3.ObjectStorage) *BundleWorker {
	worker.storage = storage
	return worker
}

func (worker *BundleWorker) WithSingleShot(singleShot bool) *BundleWorker {
	worker.singleShot = singleShot
	return worker
}

func (worker *BundleWorker) Done() bool {
	select {
	case <-worker.done:
		return true
	default:
		return false
	}
}

func (worker *BundleWorker) UpdateConfig(b *config.Bundle, sources []*config.Source, stacks []*config.Stack) {
	if b == nil || !worker.bundleConfig.Equal(b) || !worker.sourceConfigs.Equal(sources) || !worker.stackConfigs.Equal(stacks) {
		worker.changeConfiguration()
	}
}

// Execute runs a bundle synchronization iteration: git sync, bundle construct
// and then push bundles to object storage.
func (w *BundleWorker) Execute(ctx context.Context) time.Time {
	startTime := time.Now()
	w.updateStartMetrics(startTime)
	defer w.updateEndMetrics(startTime)

	defer w.bar.Add(1)

	// If a configuration change was requested, request the worker to be removed from the pool and signal this worker being done.

	if w.configurationChanged() {
		return w.die(ctx)
	}

	// Wipe any old files synchronized during the previous run to avoid deleted files in database/http from reappearing to bundle bundles.
	for _, src := range w.sources {
		if err := src.Wipe(); err != nil {
			w.log.Warnf("failed to remove a directory for bundle %q: %v", w.bundleConfig.Name, err)
			return w.report(ctx, BuildStateInternalError, err)
		}
	}

	for _, synchronizer := range w.synchronizers {
		err := synchronizer.Execute(ctx)
		if err != nil {
			w.log.Warnf("failed to synchronize bundle %q: %v", w.bundleConfig.Name, err)
			return w.report(ctx, BuildStateSyncFailed, err)
		}
	}

	for _, src := range w.sources {
		if err := src.Transform(ctx); err != nil {
			w.log.Warnf("failed to evaluate source %q for bundle %q: %v", src.Name, w.bundleConfig.Name, err)
			return w.report(ctx, BuildStateTransformFailed, err)
		}
	}

	buffer := bytes.NewBuffer(nil)

	b := builder.New().
		WithSources(w.sources).
		WithExcluded(w.bundleConfig.ExcludedFiles).
		WithOutput(buffer)

	err := b.Build(ctx)
	if err != nil {
		w.log.Warnf("failed to build a bundle %q: %v", w.bundleConfig.Name, err)
		return w.report(ctx, BuildStateBuildFailed, err)
	}

	if w.storage != nil {
		if err := w.storage.Upload(ctx, bytes.NewReader(buffer.Bytes())); err != nil {
			w.log.Warnf("failed to upload bundle %q: %v", w.bundleConfig.Name, err)
			return w.report(ctx, BuildStatePushFailed, err)
		}

		w.log.Debugf("Bundle %q built and uploaded.", w.bundleConfig.Name)
		return w.report(ctx, BuildStateSuccess, nil)
	}

	w.log.Debugf("Bundle %q built.", w.bundleConfig.Name)
	return w.report(ctx, BuildStateSuccess, nil)
}

func (w *BundleWorker) report(ctx context.Context, state BuildState, err error) time.Time {
	w.status.State = state
	if err != nil {
		metrics.BundleBuildFailed.WithLabelValues(w.bundleConfig.Name, state.String()).Inc()

		if _, ok := err.(ast.Errors); ok {
			w.status.Message = "Run 'opa build " + w.bundleDir + "' to see errors"
		} else {
			w.status.Message = err.Error()
		}
	}

	if w.singleShot {
		return w.die(ctx)
	}

	return time.Now().Add(errorDelay)
}

func (w *BundleWorker) changeConfiguration() {
	select {
	case <-w.changed:
	default:
		close(w.changed)
	}
}

func (w *BundleWorker) configurationChanged() bool {
	select {
	case <-w.changed:
		return true
	default:
		return false
	}
}

func (w *BundleWorker) die(ctx context.Context) time.Time {
	for _, synchronizer := range w.synchronizers {
		synchronizer.Close(ctx)
	}

	close(w.done)

	var zero time.Time
	return zero
}

func (w *BundleWorker) updateStartMetrics(startTime time.Time) {
	metrics.BundleBuildCount.Inc()
	metrics.LastBundleBuildStart.WithLabelValues(w.bundleConfig.Name).Set(float64(startTime.Unix()))
}

func (w *BundleWorker) updateEndMetrics(startTime time.Time) {
	metrics.BundleBuildDuration.WithLabelValues(w.bundleConfig.Name).Observe(float64(time.Since(startTime).Seconds()))
	metrics.LastBundleBuildEnd.WithLabelValues(w.bundleConfig.Name).Set(float64(time.Now().Unix()))
}
