package service

import (
	"bytes"
	"cmp"
	"context"
	"errors"
	"io/fs"
	"time"

	"github.com/open-policy-agent/opa-control-plane/internal/config"
	"github.com/open-policy-agent/opa-control-plane/internal/database"
	ocp_fs "github.com/open-policy-agent/opa-control-plane/internal/fs"
	"github.com/open-policy-agent/opa-control-plane/internal/logging"
	"github.com/open-policy-agent/opa-control-plane/internal/metrics"
	"github.com/open-policy-agent/opa-control-plane/internal/progress"
	"github.com/open-policy-agent/opa-control-plane/internal/syncerr"
	"github.com/open-policy-agent/opa-control-plane/pkg/builder"
	ext_os "github.com/open-policy-agent/opa-control-plane/pkg/objectstorage"
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
	storage       ext_os.ObjectStorage
	changed       chan struct{}
	done          chan struct{}
	singleShot    bool
	log           *logging.Logger
	bar           *progress.Bar
	status        Status
	interval      time.Duration
	database      *database.Database
	tenant        string
	metrics       *metrics.Metrics
}

type Synchronizer interface {
	Execute(ctx context.Context) (map[string]any, error)
	Close(ctx context.Context)
}

type sourceSynchronizer struct {
	sync           Synchronizer
	sourceName     string
	sourceType     string // "git", "sql", "http", "s3"
	datasourceName string // For http/s3: the datasource name used as key in metadata
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

func (worker *BundleWorker) WithStorage(storage ext_os.ObjectStorage) *BundleWorker {
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

func (worker *BundleWorker) WithDatabase(database *database.Database) *BundleWorker {
	worker.database = database
	return worker
}

func (worker *BundleWorker) WithTenant(tenant string) *BundleWorker {
	worker.tenant = tenant
	return worker
}

func (worker *BundleWorker) WithMetrics(m *metrics.Metrics) *BundleWorker {
	worker.metrics = m
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
			return w.report(ctx, BuildStateInternalError, BuildPhaseSync, database.SentinelRevision, startTime, err)
		}
	}

	// Collect source metadata from synchronizers and structure by source type
	// Note: Metadata fields to compute are configured at synchronizer construction time
	sourceMetadata := make(map[string]map[string]any)
	for _, ss := range w.synchronizers {
		metadata, err := ss.sync.Execute(ctx)
		if err != nil {
			w.log.Warnf("failed to synchronize bundle %q: %v", w.bundleConfig.Name, err)
			state := BuildStateSyncFailed
			if syncerr.IsUserError(err) {
				state = BuildStateUserError
			}
			return w.report(ctx, state, BuildPhaseSync, database.SentinelRevision, startTime, err)
		}
		if metadata != nil {
			if sourceMetadata[ss.sourceName] == nil {
				sourceMetadata[ss.sourceName] = make(map[string]any)
			}
			// For datasource types (http, s3), nest metadata under datasource name
			// to support multiple datasources of the same type per source:
			//   input.sources["src"].http["ds-name"].hash
			if ss.datasourceName != "" {
				typeMap, ok := sourceMetadata[ss.sourceName][ss.sourceType].(map[string]any)
				if !ok {
					typeMap = make(map[string]any)
					sourceMetadata[ss.sourceName][ss.sourceType] = typeMap
				}
				typeMap[ss.datasourceName] = metadata
			} else {
				sourceMetadata[ss.sourceName][ss.sourceType] = metadata
			}
		}
	}

	for _, src := range w.sources {
		buf, err := src.Transform(ctx)
		if buf != nil && buf.Len() > 0 {
			w.log.Debugf("transform %q: %s", src.Name, buf.String())
		}
		if err != nil {
			w.log.Warnf("failed to evaluate source %q for bundle %q: %v", src.Name, w.bundleConfig.Name, err)
			return w.report(ctx, BuildStateTransformFailed, BuildPhaseTransform, database.SentinelRevision, startTime, err)
		}
	}

	buffer := bytes.NewBuffer(nil)

	_, needsBundleHash, _ := extractRevisionRefs(w.bundleConfig.Revision)

	var resolvedRevision string
	b := builder.New().
		WithSources(w.sources).
		WithExcluded(w.bundleConfig.ExcludedFiles).
		WithTarget(w.bundleConfig.Options.Target).
		WithOutput(buffer).
		WithRevisionFunc(func(fsys fs.FS) (string, error) {
			var bundleHash string
			if needsBundleHash {
				var err error
				bundleHash, err = ocp_fs.HashFS(fsys)
				if err != nil {
					return "", err
				}
			}
			rev, err := resolveRevision(ctx, w.bundleConfig.Revision, sourceMetadata, bundleHash)
			if err != nil {
				return "", err
			}
			resolvedRevision = rev
			return rev, nil
		})

	if w.bundleConfig.Options.Optimization != nil {
		b = b.WithOptimizationLevel(w.bundleConfig.Options.Optimization.Level)
	}

	if err := b.Build(ctx); err != nil {
		w.log.Warnf("failed to build a bundle %q: %v", w.bundleConfig.Name, err)
		return w.report(ctx, BuildStateBuildFailed, BuildPhaseBuild, resolvedRevision, startTime, err)
	}

	if w.storage != nil {
		reader := bytes.NewReader(buffer.Bytes())
		if err := w.storage.Upload(ctx, reader, ext_os.UploadOptions{
			Tenant:    w.tenant,
			Name:      w.bundleConfig.Name,
			Revision:  resolvedRevision,
			TotalSize: reader.Size(),
		}); err != nil {
			if errors.Is(err, ext_os.ErrNotModified) {
				w.log.Debugf("Bundle %q built, not modified.", w.bundleConfig.Name)
				return w.report(ctx, BuildStateSuccess, BuildPhasePush, resolvedRevision, startTime, nil)
			}
			w.log.Warnf("failed to upload bundle %q: %v", w.bundleConfig.Name, err)
			return w.report(ctx, BuildStatePushFailed, BuildPhasePush, resolvedRevision, startTime, err)
		}

		w.log.Debugf("Bundle %q built and uploaded.", w.bundleConfig.Name)
		return w.report(ctx, BuildStateSuccess, BuildPhasePush, resolvedRevision, startTime, nil)
	}

	w.log.Debugf("Bundle %q built.", w.bundleConfig.Name)
	return w.report(ctx, BuildStateSuccess, BuildPhaseBuild, resolvedRevision, startTime, nil)
}

func (w *BundleWorker) report(ctx context.Context, state BuildState, phase BuildPhase, revision string, startTime time.Time, err error) time.Time {
	interval := w.interval
	w.status.State = state
	msg := ""
	if err != nil {
		interval = errorInterval // faster retry on error
		msg = err.Error()
		w.status.Message = msg
	}

	if w.database != nil {
		if _, uerr := w.database.UpsertBundleStatus(ctx, w.tenant, w.bundleConfig.Name,
			revision, phase.String(), state.String(), msg); uerr != nil {
			w.log.Warnf("failed to track bundle status %q: %v", w.bundleConfig.Name, uerr)
		}
	}

	if state == BuildStateSuccess {
		w.metrics.BundleBuildSucceeded(w.bundleConfig.Name, state.String(), startTime)
	} else {
		w.metrics.BundleBuildFailed(w.bundleConfig.Name, state.String())
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
