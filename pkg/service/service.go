package service

import (
	"context"
	"crypto/md5"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"maps"
	"path"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	pkgsync "github.com/open-policy-agent/opa-control-plane/pkg/sync"
	"github.com/open-policy-agent/opa/v1/ast"
	_ "modernc.org/sqlite"

	"github.com/open-policy-agent/opa-control-plane/internal/config"
	"github.com/open-policy-agent/opa-control-plane/internal/database"
	ocp_fs "github.com/open-policy-agent/opa-control-plane/internal/fs"
	"github.com/open-policy-agent/opa-control-plane/internal/gitsync"
	"github.com/open-policy-agent/opa-control-plane/internal/logging"
	"github.com/open-policy-agent/opa-control-plane/internal/migrations"
	"github.com/open-policy-agent/opa-control-plane/internal/pool"
	"github.com/open-policy-agent/opa-control-plane/internal/progress"
	"github.com/open-policy-agent/opa-control-plane/internal/providers"
	"github.com/open-policy-agent/opa-control-plane/internal/s3"
	"github.com/open-policy-agent/opa-control-plane/internal/sqlsync"
	ext_authz "github.com/open-policy-agent/opa-control-plane/pkg/authz"
	"github.com/open-policy-agent/opa-control-plane/pkg/builder"
	pkgconfig "github.com/open-policy-agent/opa-control-plane/pkg/config"
	"github.com/open-policy-agent/opa-control-plane/pkg/metrics"
	ext_os "github.com/open-policy-agent/opa-control-plane/pkg/objectstorage"
)

const (
	internalPrincipal       = "internal"
	defaultTenant           = "default"
	reconfigurationInterval = 15 * time.Second
)

var (
	defaultStackMountPrefix = ast.DefaultRootRef.Append(ast.StringTerm("stacks"))
)

type Service struct {
	config         *config.Root
	rawConfig      []byte
	persistenceDir string
	pool           *pool.Pool
	workers        map[string]*BundleWorker
	readyMutex     sync.Mutex
	ready          bool
	failures       map[string]Status
	database       database.Database
	builtinFS      fs.FS
	singleShot     bool
	report         *Report
	log            *logging.Logger
	noninteractive bool
	migrateDB      bool
	initialized    bool
	storage        ext_os.ObjectStorage
	secretFactory  pkgsync.SecretProviderFactory
	authorizer     ext_authz.Authorizer
	metrics        *metrics.Metrics

	providers *pkgsync.SourceProviderRegistry // custom source types, for providers entries

	builtinsOnce sync.Once
	builtins     *pkgsync.SourceProviderRegistry // built-in source types
	builtinsErr  error
}

type Report struct {
	Bundles map[string]Status
}

type BuildState int
type BuildPhase int

const (
	BuildStateUnknown BuildState = iota
	BuildStateInternalError
	BuildStateConfigError
	BuildStateSuccess
	BuildStateSyncFailed
	BuildStateUserError
	BuildStateTransformFailed
	BuildStateBuildFailed
	BuildStatePushFailed
	BuildStateCancelled
)

const (
	BuildPhaseSync BuildPhase = iota
	BuildPhaseTransform
	BuildPhaseBuild
	BuildPhasePush
)

func (s BuildState) String() string {
	switch s {
	case BuildStateInternalError:
		return "INTERNAL_ERROR"
	case BuildStateConfigError:
		return "CONFIG_ERROR"
	case BuildStateSuccess:
		return "SUCCESS"
	case BuildStateSyncFailed:
		return "SYNC_FAILED"
	case BuildStateUserError:
		return "USER_ERROR"
	case BuildStateTransformFailed:
		return "TRANSFORM_FAILED"
	case BuildStateBuildFailed:
		return "BUILD_FAILED"
	case BuildStatePushFailed:
		return "PUSH_FAILED"
	case BuildStateCancelled:
		return "CANCELLED"
	default:
		return "UNKNOWN"
	}
}

func (s BuildPhase) String() string {
	switch s {
	case BuildPhaseSync:
		return "SYNC"
	case BuildPhaseTransform:
		return "TRANSFORM"
	case BuildPhaseBuild:
		return "BUILD"
	case BuildPhasePush:
		return "PUSH"
	default:
		return "INTERNAL_ERROR"
	}
}

type Status struct {
	State   BuildState
	Message string
}

func New() *Service {
	return &Service{
		pool:           pool.New(10),
		workers:        make(map[string]*BundleWorker),
		failures:       make(map[string]Status),
		noninteractive: true,
		migrateDB:      false,
		providers:      pkgsync.NewSourceProviderRegistry(),
	}
}

// WithSourceProviders sets the registry of source types that can be used in
// sources' providers entries, replacing the service's own (empty) registry.
// The built-in types (git, http, s3) are not part of it: they are configured
// through a source's git and datasources fields.
func (s *Service) WithSourceProviders(reg *pkgsync.SourceProviderRegistry) *Service {
	if reg == nil {
		reg = pkgsync.NewSourceProviderRegistry()
	}
	s.providers = reg
	return s
}

// SourceProviders returns the registry of source types that can be used in
// sources' providers entries.
func (s *Service) SourceProviders() *pkgsync.SourceProviderRegistry {
	return s.providers
}

func (s *Service) WithPersistenceDir(d string) *Service {
	s.persistenceDir = d
	return s
}

func (s *Service) WithAuthorizer(a ext_authz.Authorizer) *Service {
	s.authorizer = a
	s.database = *s.database.WithAuthorizer(a)
	return s
}

func (s *Service) WithMetrics(m *metrics.Metrics) *Service {
	s.metrics = m
	s.database = *s.database.WithMetrics(m)
	return s
}

func (s *Service) WithConfig(config *config.Root) *Service {
	s.config = config
	s.database = *s.database.WithConfig(config.Database)
	return s
}

func (s *Service) WithRawConfig(rawConfig []byte) *Service {
	s.rawConfig = rawConfig
	s.database = *s.database.WithRawRootConfig(rawConfig)
	return s
}

// WithDatabaseConfig configures the database connection from a typed struct
// instead of raw JSON/YAML bytes.
func (s *Service) WithDatabaseConfig(cfg *pkgconfig.DatabaseConfig) *Service {
	if s.config == nil {
		s.config = &config.Root{}
	}
	s.config.Database = config.DatabaseFromPublic(cfg)
	s.database = *s.database.WithConfig(s.config.Database)
	return s
}

func (s *Service) WithBuiltinFS(fs fs.FS) *Service {
	s.builtinFS = fs
	return s
}

func (s *Service) WithSingleShot(singleShot bool) *Service {
	s.singleShot = singleShot
	return s
}

func (s *Service) Database() *database.Database {
	return &s.database
}

func (s *Service) WithLogger(logger *logging.Logger) *Service {
	s.log = logger
	s.database = *s.database.WithLogger(logger)
	return s
}

// WithSlogLogger sets the service logger from a standard *slog.Logger.
func (s *Service) WithSlogLogger(logger *slog.Logger) *Service {
	l := logging.FromSlog(logger)
	s.log = l
	s.database = *s.database.WithLogger(l)
	return s
}

func (s *Service) WithNoninteractive(yes bool) *Service {
	s.noninteractive = yes
	return s
}

func (s *Service) WithMigrateDB(yes bool) *Service {
	s.migrateDB = yes
	return s
}

func (s *Service) WithStorage(storage ext_os.ObjectStorage) *Service {
	s.storage = storage
	return s
}

func (s *Service) WithSecretProviderFactory(factory pkgsync.SecretProviderFactory) *Service {
	s.secretFactory = factory
	return s
}

func (s *Service) Init(ctx context.Context) error {
	if s.initialized {
		return nil
	}
	err := s.initDB(ctx)
	s.initialized = err == nil
	return err
}

func (s *Service) Run(ctx context.Context) error {
	if err := s.Init(ctx); err != nil {
		return err
	}
	defer s.database.CloseDB()
	defer s.pool.Stop()

	s.readyMutex.Lock()
	s.ready = true
	s.readyMutex.Unlock()
	// Launch new workers for new bundles and bundles with updated configuration until it is time to shutdown.

shutdown:
	for {
		s.launchWorkers(ctx)

		for s.singleShot {
			if s.allWorkersDone() {
				break shutdown
			}

			select {
			case <-time.After(100 * time.Millisecond):
			case <-ctx.Done():
				break shutdown
			}
		}

		select {
		case <-time.After(reconfigurationInterval):
		case <-ctx.Done():
			break shutdown
		}
	}

	for _, w := range s.workers {
		w.UpdateConfig(nil, nil, nil)
	}

	if s.singleShot {
		s.report = &Report{
			Bundles: make(map[string]Status, len(s.workers)),
		}
		for _, w := range s.workers {
			s.report.Bundles[w.bundleConfig.Name] = w.status
		}
		maps.Copy(s.report.Bundles, s.failures)
	}

	return nil
}

func (s *Service) Report() *Report {
	return s.report
}

func (s *Service) Ready(context.Context) error {
	s.readyMutex.Lock()
	defer s.readyMutex.Unlock()
	if s.ready {
		return nil
	}
	return errors.New("not ready")
}

func (s *Service) initDB(ctx context.Context) error {
	bar := progress.New(s.noninteractive, -1, "loading configuration")
	defer bar.Finish()

	if s.rawConfig != nil {
		cfg, err := config.Parse(s.rawConfig)
		if err != nil {
			return err
		}
		s.config = cfg
	}

	if s.config != nil {
		for _, src := range s.config.Sources {
			if err := providers.Validate(s.providers, src); err != nil {
				return fmt.Errorf("invalid configuration: %w", err)
			}
		}
	}

	db, err := migrations.New().
		WithConfig(s.config.Database).
		WithLogger(s.log).
		WithMigrate(s.migrateDB).
		WithAuthorizer(s.authorizer).
		WithMetrics(s.metrics).
		Run(ctx)
	if err != nil {
		return err
	}
	s.database = *db

	if err := s.database.UpsertPrincipal(ctx, database.Principal{Id: internalPrincipal, Tenant: defaultTenant, Role: "administrator"}); err != nil {
		return err
	}

	if err := s.database.LoadConfig(ctx, bar, internalPrincipal, defaultTenant, s.config); err != nil {
		return fmt.Errorf("load config failed: %w", err)
	}

	return nil
}

type tenantWorkload struct {
	tenant     string
	bundles    []*config.Bundle
	sourceDefs []*config.Source
	stacks     []*config.Stack
}

// collectTenantWorkloads fetches every tenant's bundles, sources and stacks, and
// derives the set of bundle worker ids that should be running across all tenants.
// ok is false if listing failed for some tenant (already logged), in which case
// launchWorkers should skip this round entirely rather than act on partial data.
func (s *Service) collectTenantWorkloads(ctx context.Context) (workloads []tenantWorkload, activeBundles map[string]struct{}, ok bool) {
	activeBundles = make(map[string]struct{})

	for tenant, err := range s.database.Tenants(ctx) {
		if err != nil {
			s.log.Errorf("error listing tenants: %s", err.Error())
			return nil, nil, false
		}
		tenant := tenant.Name

		bundles, _, err := s.database.ListBundles(ctx, internalPrincipal, tenant, database.ListOptions{Stale: true})
		if err != nil {
			s.log.Errorf("error listing bundles: %s", err.Error())
			return nil, nil, false
		}
		s.log.Debugf("launchWorkers(%s) for %d bundles", tenant, len(bundles))

		sourceDefs, _, err := s.database.ListSources(ctx, internalPrincipal, tenant, database.ListOptions{Stale: true})
		if err != nil {
			s.log.Errorf("error listing sources: %s", err.Error())
			return nil, nil, false
		}

		stacks, _, err := s.database.ListStacks(ctx, internalPrincipal, tenant, database.ListOptions{Stale: true})
		if err != nil {
			s.log.Errorf("error listing stacks: %s", err.Error())
			return nil, nil, false
		}

		workloads = append(workloads, tenantWorkload{tenant: tenant, bundles: bundles, sourceDefs: sourceDefs, stacks: stacks})

		for _, b := range bundles {
			activeBundles[tenant+"_"+b.Name] = struct{}{}
		}
	}

	return workloads, activeBundles, true
}

// retireStaleWorkers drops already-finished workers from bookkeeping and initiates
// shutdown for any worker whose bundle is no longer active in any tenant.
// activeBundles must cover every tenant, not just the one a caller happens to be
// looking at, or it will retire other tenants' still-valid workers.
func (s *Service) retireStaleWorkers(activeBundles map[string]struct{}) {
	for id, w := range s.workers {
		if w.Done() {
			delete(s.workers, id)
			continue
		}

		if _, ok := activeBundles[id]; !ok {
			w.UpdateConfig(nil, nil, nil)
		}
	}
}

// builtinProviders returns the registry of built-in source types (git, http,
// s3). It is kept apart from any user-provided registry, since built-in
// types are configured through a source's git and datasources fields.
func (s *Service) builtinProviders() (*pkgsync.SourceProviderRegistry, error) {
	s.builtinsOnce.Do(func() {
		s.builtins, s.builtinsErr = providers.Builtins(s.metrics)
	})
	return s.builtins, s.builtinsErr
}

func (s *Service) launchWorkers(ctx context.Context) {
	workloads, activeBundles, ok := s.collectTenantWorkloads(ctx)
	if !ok {
		return
	}

	s.retireStaleWorkers(activeBundles)

	failures := make(map[string]Status)

	for _, workload := range workloads {
		tenant := workload.tenant
		bundles := workload.bundles
		sourceDefs := workload.sourceDefs
		stacks := workload.stacks

		sourceDefsByName := make(map[string]*config.Source)
		for _, src := range sourceDefs {
			sourceDefsByName[src.Name] = src
		}

		// Start any new workers for bundles that are in the current configuration but not yet running. Inform any existing
		// workers of the current configuration, which will cause them to shutdown if configuration has changed.
		//
		// For each bundle, create the following directory structure under persistencyDir for the builder to use
		// when constructing bundles:
		//
		// persistenceDir/
		// └── {md5(${tenant}_${bundle.Name})}/
		//     └── sources/
		//         └── {source.Name}/
		//             ├── builtin/           # Built-in source specific files
		//             ├── database/          # Source-specific files from SQL database
		//             ├── datasources/       # Source-specific HTTP datasources
		//             └── repo/              # Source git repository

		bar := progress.New(s.noninteractive, len(bundles), "building and pushing bundles")

		for _, b := range bundles {
			bName := tenant + "_" + b.Name
			if w, ok := s.workers[bName]; ok {
				w.UpdateConfig(b, sourceDefs, stacks)
				continue
			}

			s.log.Debugf("(re)starting worker for bundle: %s (%s)", b.Name, tenant)
			root := newSource(b.Name).AddRequirements(b.Requirements)

			for _, stack := range stacks {
				if stack.Selector.Matches(b.Labels) && !stack.ExcludeSelector.PtrMatches(b.Labels) {
					reqs := make([]config.Requirement, len(stack.Requirements))
					for i, req := range stack.Requirements {
						if !b.Options.NoDefaultStackMount && // per-bundle opt-out not set
							(req.AutoMount == nil || *req.AutoMount) { // per-source override is unset or true
							req.Prefix = addPrefix(defaultStackMountPrefix, stack.Name, req.Prefix)
						}
						reqs[i] = req
					}
					root = root.AddRequirements(reqs)
				}
			}

			deps, overrides, conflicts := getDeps(root.Requirements, sourceDefsByName)
			if len(conflicts) > 0 {
				sorted := slices.Collect(maps.Keys(conflicts))
				sort.Strings(sorted)
				var extra string
				if len(sorted) > 1 {
					extra = fmt.Sprintf(" (along with %d other sources)", len(sorted)-1)
				}
				// NB(sr): As of now, `failures` is only used for single-shot mode, and that's not a
				// multi-tenant use cases (I think). So let's ignore the possibility of clashes for the
				// same bundle name here.
				failures[b.Name] = Status{State: BuildStateConfigError, Message: fmt.Sprintf("requirements on %q (%s) conflict%s", sorted[0], tenant, extra)}
				continue
			}

			// Analyze revision to determine which metadata fields are needed per source
			metadataFields := make(map[string][]string)
			if b.Revision != "" {
				refs, _, err := extractRevisionRefs(b.Revision)
				if err != nil {
					s.log.Debugf("failed to analyze revision references for bundle %q, computing all metadata: %v", b.Name, err)
				} else {
					for _, ref := range refs {
						metadataFields[ref.SourceName] = ref.Fields
					}
				}
			}

			syncs := []sourceSynchronizer{}
			sources := []*builder.Source{&root.Source}
			bundleDir := join(s.persistenceDir, md5sum(bName))
			tenantProvider := s.secretProviderForTenant(ctx, tenant)

			builtins, err := s.builtinProviders()
			if err != nil {
				failures[b.Name] = Status{State: BuildStateInternalError, Message: fmt.Sprintf("built-in source types: %v", err)}
				continue
			}

			var srcErr error
			for _, dep := range deps {
				// NB(sr): dep.Name could contain a `:` which cause build errors in OPA's bundle build machinery
				srcDir := join(bundleDir, "sources", ocp_fs.Escape(dep.Name))

				src := newSource(dep.Name).
					SyncBuiltin(&syncs, dep.Builtin, s.builtinFS, join(srcDir, "builtin")).
					SyncSourceSQL(&syncs, dep.ID, dep.Name, &s.database, join(srcDir, "database"), metadataFields[dep.Name]).
					SyncDatasources(ctx, builtins, &syncs, dep.Name, dep.Datasources, join(srcDir, "datasources"), tenantProvider, metadataFields[dep.Name]).
					SyncGit(ctx, builtins, &syncs, dep.Name, dep.Git, join(srcDir, "repo"), overrides[dep.Name], tenantProvider).
					SyncProviders(ctx, s.providers, &syncs, dep.Name, dep.Providers, join(srcDir, "providers"), tenantProvider, metadataFields[dep.Name], s.log).
					AddRequirements(dep.Requirements)
				if src.err != nil {
					srcErr = fmt.Errorf("source %q: %w", dep.Name, src.err)
					break
				}

				sources = append(sources, &src.Source)
			}
			if srcErr != nil {
				failures[b.Name] = Status{State: BuildStateConfigError, Message: srcErr.Error()}
				continue
			}

			w := NewBundleWorker(bundleDir, b, sourceDefs, stacks, s.log, bar).
				WithSources(sources).
				WithSynchronizers(syncs).
				WithInterval(b.Interval).
				WithSingleShot(s.singleShot).
				WithDatabase(s.Database()).
				WithTenant(tenant).
				WithMetrics(s.metrics)

			if s.storage != nil {
				w.WithStorage(s.storage)
			} else {
				storage, err := s3.New(ctx, b.ObjectStorage)
				if err != nil {
					s.log.Errorf("error creating object storage client: %s", err.Error())
					failures[b.Name] = Status{State: BuildStateConfigError, Message: fmt.Sprintf("object storage: %v", err)}
					continue
				}
				w.WithStorage(storage)
			}

			s.pool.Add(ctx, w.Execute)

			s.workers[bName] = w
		}
	}

	s.failures = failures
}

func (s *Service) secretProviderForTenant(ctx context.Context, tenant string) pkgsync.SecretProvider {
	if s.secretFactory != nil {
		provider, err := s.secretFactory.SecretProviderForTenant(ctx, tenant)
		if err != nil {
			s.log.Warnf("secret provider factory error for tenant %q: %v", tenant, err)
			return nil
		}
		return provider
	}
	return nil
}

func (s *Service) allWorkersDone() bool {
	for _, worker := range s.workers {
		if !worker.Done() {
			return false
		}
	}
	return true
}

func getDeps(rs config.Requirements, byName map[string]*config.Source) ([]*config.Source, map[string]string, map[string]struct{}) {
	var srcs []*config.Source
	visited := make(map[string]struct{})
	var all []config.Requirement
	for len(rs) > 0 {
		next, tail := rs[0], rs[1:]
		all = append(all, next)
		rs = tail
		if next.Source == nil {
			continue
		} else if _, ok := visited[*next.Source]; ok {
			continue
		} else if src, ok := byName[*next.Source]; !ok {
			continue
		} else {
			visited[*next.Source] = struct{}{}
			srcs = append(srcs, src)
			rs = append(rs, src.Requirements...)
		}
	}

	overrides := make(map[string]string)
	conflicts := make(map[string]struct{})

	for _, r := range all {
		if r.Source != nil && r.Git.Commit != nil {
			if x, ok := overrides[*r.Source]; ok && x != *r.Git.Commit {
				conflicts[*r.Source] = struct{}{}
			} else {
				overrides[*r.Source] = *r.Git.Commit
			}
		}
	}

	return srcs, overrides, conflicts
}

type source struct {
	builder.Source

	// err records the first error from setting up the source's
	// synchronizers; later Sync* calls are no-ops once it is set.
	err error
}

// newSync creates the synchronizer for a built-in source type.
func (src *source) newSync(ctx context.Context, builtins *pkgsync.SourceProviderRegistry, t string, p pkgsync.ProviderParams) pkgsync.Synchronizer {
	prov, ok := builtins.Get(t)
	if !ok {
		src.err = fmt.Errorf("unknown source type %q", t)
		return nil
	}
	syncer, err := prov.New(ctx, p)
	if err != nil {
		src.err = fmt.Errorf("%s: %w", t, err)
		return nil
	}
	return syncer
}

func newSource(name string) *source {
	return &source{
		Source: *builder.NewSource(name),
	}
}

func (src *source) addDir(dir string, wipe bool, includedFiles, excludedFiles, metadataFiles []string) {
	_ = src.Source.AddDir(builder.Dir{
		Path:                  filepath.ToSlash(dir),
		Wipe:                  wipe,
		IncludedFiles:         includedFiles,
		ExcludedFiles:         excludedFiles,
		ExcludedMetadataFiles: metadataFiles,
	})
}

func (src *source) addFS(fsys fs.FS) {
	src.Source.AddFS(fsys)
}

func (src *source) SyncGit(ctx context.Context, builtins *pkgsync.SourceProviderRegistry, syncs *[]sourceSynchronizer, sourceName string, git config.Git, repoDir string, reqCommit string, provider pkgsync.SecretProvider) *source {
	if src.err != nil || git.Repo == "" {
		return src
	}
	srcDir := repoDir
	if git.Path != nil {
		srcDir = join(srcDir, *git.Path)
	}
	src.addDir(srcDir, false, git.IncludedFiles, git.ExcludedFiles, gitsync.MetadataFiles)
	if reqCommit != "" {
		git.Commit = &reqCommit
	}
	syncer := src.newSync(ctx, builtins, providers.TypeGit, pkgsync.ProviderParams{
		SourceName:     sourceName,
		Config:         git,
		Dir:            repoDir,
		SecretProvider: provider,
	})
	if syncer == nil {
		return src
	}
	*syncs = append(*syncs, sourceSynchronizer{
		sync:       syncer,
		sourceName: sourceName,
		sourceType: providers.TypeGit,
	})
	return src
}

func (src *source) SyncBuiltin(syncs *[]sourceSynchronizer, builtin *string, fs_ fs.FS, dir string) *source {
	if builtin != nil {
		// NB(sr): If the builtin isn't known, this will end up returning
		// "open .: file does not exist", so we don't check it here.
		sub, _ := fs.Sub(fs_, *builtin)
		src.addFS(sub)
	}
	return src
}

func (src *source) SyncDatasources(ctx context.Context, builtins *pkgsync.SourceProviderRegistry, syncs *[]sourceSynchronizer, sourceName string, datasources []config.Datasource, dir string, provider pkgsync.SecretProvider, metadataFields []string) *source {
	if src.err != nil {
		return src
	}
	for _, datasource := range datasources {
		switch datasource.Type {
		case providers.TypeHTTP, providers.TypeS3:
			syncer := src.newSync(ctx, builtins, datasource.Type, pkgsync.ProviderParams{
				SourceName:     sourceName,
				Name:           datasource.Name,
				Config:         datasource,
				Dir:            join(dir, datasource.Path),
				SecretProvider: provider,
				MetadataFields: metadataFields,
			})
			if syncer == nil {
				return src
			}
			*syncs = append(*syncs, sourceSynchronizer{
				sync:       syncer,
				sourceName: sourceName,
				sourceType: datasource.Type,
				entryName:  datasource.Name,
			})
		}

		if datasource.TransformQuery != "" {
			src.Transforms = append(src.Transforms, builder.Transform{
				Query: datasource.TransformQuery,
				Path:  join(dir, datasource.Path, "data.json"),
			})
		}
	}
	if len(datasources) > 0 {
		src.addDir(dir, true, nil, nil, nil)
	}
	return src
}

// SyncProviders sets up the source's provider entries. Each entry gets its
// own directory under dir, emptied before every sync; the entry's content is
// written to its path within it.
func (src *source) SyncProviders(ctx context.Context, reg *pkgsync.SourceProviderRegistry, syncs *[]sourceSynchronizer, sourceName string, entries config.Providers, dir string, provider pkgsync.SecretProvider, metadataFields []string, log *logging.Logger) *source {
	if src.err != nil {
		return src
	}
	for _, p := range entries {
		prov, cfg, err := providers.ParseEntry(reg, p)
		if err != nil {
			src.err = fmt.Errorf("provider %q: %w", p.Name, err)
			return src
		}
		entryDir := join(dir, ocp_fs.Escape(p.Name))
		contentDir := join(entryDir, p.Path)
		syncer, err := prov.New(ctx, pkgsync.ProviderParams{
			SourceName:     sourceName,
			Name:           p.Name,
			Config:         cfg,
			Dir:            contentDir,
			SecretProvider: provider,
			MetadataFields: metadataFields,
			Logger:         log.Slog(),
		})
		if err != nil {
			src.err = fmt.Errorf("provider %q: %w", p.Name, err)
			return src
		}

		contrib := &contribution{}
		_ = src.Source.AddDir(builder.Dir{
			Path:         filepath.ToSlash(entryDir),
			Wipe:         true,
			Contribution: contrib.get,
		})
		*syncs = append(*syncs, sourceSynchronizer{
			sync:       syncer,
			sourceName: sourceName,
			sourceType: "providers",
			entryName:  p.Name,
			dir:        contentDir,
			contrib:    contrib,
		})
	}
	return src
}

func (src *source) SyncSourceSQL(syncs *[]sourceSynchronizer, sourceID int64, name string, database *database.Database, dir string, metadataFields []string) *source {
	opts := []sqlsync.SQLSyncOption{}
	if len(metadataFields) > 0 {
		opts = append(opts, sqlsync.WithMetadataFields(metadataFields))
	}
	*syncs = append(*syncs, sourceSynchronizer{
		sync:       sqlsync.NewSQLSourceDataSynchronizer(dir, database, sourceID, name, opts...),
		sourceName: name,
		sourceType: "sql",
	})
	src.addDir(dir, true, nil, nil, nil)
	return src
}

func (src *source) AddRequirements(requirements []config.Requirement) *source {
	for _, r := range requirements {
		if r.Source != nil {
			src.Requirements = append(src.Requirements, r)
		}
	}
	return src
}

func md5sum(s string) string {
	h := md5.New()
	h.Write([]byte(s))
	return hex.EncodeToString(h.Sum(nil))
}

// join is used to normalize all paths: where `path.Join()` calls `Clean()` and gives
// us `\`-separated paths on windows, `join` will convert the result back using
// `filepath.ToSlash`.
func join(ps ...string) string {
	return filepath.ToSlash(path.Join(ps...))
}

func addPrefix(prefix ast.Ref, name string, existing string) string {
	pr := prefix.Append(ast.StringTerm(name)).String() // String() takes care of using ["..."] where required
	offset := 0
	if existing == "" {
		return pr
	}
	if strings.HasPrefix(existing, "data.") {
		offset = 5
	}
	return pr + "." + existing[offset:]
}
