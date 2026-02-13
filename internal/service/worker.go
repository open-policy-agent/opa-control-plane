package service

import (
	"bytes"
	"cmp"
	"context"
	"time"

	"github.com/open-policy-agent/opa-control-plane/internal/config"
	"github.com/open-policy-agent/opa-control-plane/internal/logging"
	"github.com/open-policy-agent/opa-control-plane/internal/metrics"
	"github.com/open-policy-agent/opa-control-plane/internal/progress"
	"github.com/open-policy-agent/opa-control-plane/internal/s3"
	"github.com/open-policy-agent/opa-control-plane/pkg/builder"
)

var (
	defaultInterval = 30 * time.Second
	errorInterval   = 30 * time.Second
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
	synchronizers []sourceSynchronizer
	sources       []*builder.Source
	storage       s3.ObjectStorage
	changed       chan struct{}
	done          chan struct{}
	singleShot    bool
	log           *logging.Logger
	bar           *progress.Bar
	status        Status
	interval      time.Duration
}

type Synchronizer interface {
	Execute(ctx context.Context) (map[string]any, error)
	Close(ctx context.Context)
}

type sourceSynchronizer struct {
	sync       Synchronizer
	sourceName string
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
		interval: defaultInterval,
	}
}

func (worker *BundleWorker) WithSynchronizers(synchronizers []sourceSynchronizer) *BundleWorker {
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

func (worker *BundleWorker) WithInterval(d config.Duration) *BundleWorker {
	worker.interval = cmp.Or(time.Duration(d), defaultInterval)
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
	startTime := time.Now() // Used for timing metric

	defer w.bar.Add(1)

	// If a configuration change was requested, request the worker to be removed from the pool and signal this worker being done.

	if w.configurationChanged() {
		return w.die(ctx)
	}

	// Wipe any old files synchronized during the previous run to avoid deleted files in database/http from reappearing to bundle bundles.
	for _, src := range w.sources {
		if err := src.Wipe(); err != nil {
			w.log.Warnf("failed to remove a directory for bundle %q: %v", w.bundleConfig.Name, err)
			return w.report(ctx, BuildStateInternalError, startTime, err)
		}
	}

	// Collect source metadata from synchronizers
	sourceMetadata := make(map[string]map[string]any)
	for _, ss := range w.synchronizers {
		metadata, err := ss.sync.Execute(ctx)
		if err != nil {
			w.log.Warnf("failed to synchronize bundle %q: %v", w.bundleConfig.Name, err)
			return w.report(ctx, BuildStateSyncFailed, startTime, err)
		}
		if metadata != nil {
			sourceMetadata[ss.sourceName] = metadata
		}
	}

	for _, src := range w.sources {
		buf, err := src.Transform(ctx)
		if buf != nil && buf.Len() > 0 {
			w.log.Debugf("transform %q: %s", src.Name, buf.String())
		}
		if err != nil {
			w.log.Warnf("failed to evaluate source %q for bundle %q: %v", src.Name, w.bundleConfig.Name, err)
			return w.report(ctx, BuildStateTransformFailed, startTime, err)
		}
	}

	buffer := bytes.NewBuffer(nil)

	b := builder.New().
		WithSources(w.sources).
		WithExcluded(w.bundleConfig.ExcludedFiles).
		WithTarget(w.bundleConfig.Options.Target).
		WithRevision(w.bundleConfig.Revision).
		WithSourceMetadata(sourceMetadata).
		WithOutput(buffer)

	err := b.Build(ctx)
	if err != nil {
		w.log.Warnf("failed to build a bundle %q: %v", w.bundleConfig.Name, err)
		return w.report(ctx, BuildStateBuildFailed, startTime, err)
	}

	if w.storage != nil {
		revision := b.LatestRevision()
		if err := w.storage.Upload(ctx, bytes.NewReader(buffer.Bytes()), revision); err != nil {
			w.log.Warnf("failed to upload bundle %q: %v", w.bundleConfig.Name, err)
			return w.report(ctx, BuildStatePushFailed, startTime, err)
		}

		w.log.Debugf("Bundle %q built and uploaded.", w.bundleConfig.Name)
		return w.report(ctx, BuildStateSuccess, startTime, nil)
	}

	w.log.Debugf("Bundle %q built.", w.bundleConfig.Name)
	return w.report(ctx, BuildStateSuccess, startTime, nil)
}

func (w *BundleWorker) report(ctx context.Context, state BuildState, startTime time.Time, err error) time.Time {
	interval := w.interval
	w.status.State = state
	if err != nil {
		interval = errorInterval // faster retry on error
		w.status.Message = err.Error()
	}

	if state == BuildStateSuccess {
		metrics.BundleBuildSucceeded(w.bundleConfig.Name, state.String(), startTime)
	} else {
		metrics.BundleBuildFailed(w.bundleConfig.Name, state.String())
	}

	if w.singleShot {
		return w.die(ctx)
	}

	return time.Now().Add(interval)
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
	for _, ss := range w.synchronizers {
		ss.sync.Close(ctx)
	}

	close(w.done)

	var zero time.Time
	return zero
}
