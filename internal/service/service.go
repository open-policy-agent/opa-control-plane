package service

import (
	"cmp"
	"context"
	"crypto/md5"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"path"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/open-policy-agent/opa/v1/ast"
	_ "modernc.org/sqlite"

	"github.com/open-policy-agent/opa-control-plane/internal/builder"
	"github.com/open-policy-agent/opa-control-plane/internal/config"
	"github.com/open-policy-agent/opa-control-plane/internal/database"
	ocp_fs "github.com/open-policy-agent/opa-control-plane/internal/fs"
	"github.com/open-policy-agent/opa-control-plane/internal/gitsync"
	"github.com/open-policy-agent/opa-control-plane/internal/httpsync"
	"github.com/open-policy-agent/opa-control-plane/internal/logging"
	"github.com/open-policy-agent/opa-control-plane/internal/migrations"
	"github.com/open-policy-agent/opa-control-plane/internal/pool"
	"github.com/open-policy-agent/opa-control-plane/internal/progress"
	"github.com/open-policy-agent/opa-control-plane/internal/s3"
	"github.com/open-policy-agent/opa-control-plane/internal/sqlsync"
)

const (
	internalPrincipal              = "internal"
	defaultTenant                  = "default"
	reconfigurationInterval        = 15 * time.Second
	defaultReconfigurationInterval = 15 * time.Second
	defaultBuildInterval           = 30 * time.Second
)

var (
	defaultStackMountPrefix = ast.DefaultRootRef.Append(ast.StringTerm("stacks"))
)

type Service struct {
	config                  *config.Root
	persistenceDir          string
	pool                    *pool.Pool
	workers                 map[string]*BundleWorker
	readyMutex              sync.Mutex
	ready                   bool
	failures                map[string]Status
	database                database.Database
	builtinFS               fs.FS
	singleShot              bool
	report                  *Report
	log                     *logging.Logger
	noninteractive          bool
	migrateDB               bool
	initialized             bool
	reconfigurationInterval time.Duration
	buildInterval           time.Duration
}

type Report struct {
	Bundles map[string]Status
}

type BuildState int

const (
	BuildStateInternalError BuildState = iota
	BuildStateConfigError
	BuildStateSuccess
	BuildStateSyncFailed
	BuildStateTransformFailed
	BuildStateBuildFailed
	BuildStatePushFailed
)

func (s BuildState) String() string {
	switch s {
	case BuildStateConfigError:
		return "CONFIG_ERROR"
	case BuildStateSuccess:
		return "SUCCESS"
	case BuildStateSyncFailed:
		return "SYNC_FAILED"
	case BuildStateTransformFailed:
		return "TRANSFORM_FAILED"
	case BuildStateBuildFailed:
		return "BUILD_FAILED"
	case BuildStatePushFailed:
		return "PUSH_FAILED"
	case BuildStateInternalError:
		fallthrough
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
		pool:                    pool.New(10),
		workers:                 make(map[string]*BundleWorker),
		failures:                make(map[string]Status),
		noninteractive:          true,
		migrateDB:               false,
		reconfigurationInterval: defaultReconfigurationInterval,
		buildInterval:           defaultBuildInterval,
	}
}

func (s *Service) WithPersistenceDir(d string) *Service {
	s.persistenceDir = d
	return s
}

func (s *Service) WithConfig(config *config.Root) *Service {
	s.config = config
	s.database = *s.database.WithConfig(config.Database)
	if s.config.Service != nil {
		if s.config.Service.ReconfigurationInterval != nil {
			s.reconfigurationInterval = *s.config.Service.ReconfigurationInterval
		}
		if s.config.Service.BundleRebuildInterval != nil {
			s.buildInterval = *s.config.Service.BundleRebuildInterval
		}
	}
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

func (s *Service) WithNoninteractive(yes bool) *Service {
	s.noninteractive = yes
	return s
}

func (s *Service) WithMigrateDB(yes bool) *Service {
	s.migrateDB = yes
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

			// NB(sr): if a worker fails to shut down, we'll be stuck here forever
			time.Sleep(100 * time.Millisecond)
		}

		select {
		case <-time.After(s.reconfigurationInterval):
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

func (s *Service) TriggerAll(ctx context.Context) error {
	for name := range s.workers {
		return s.Trigger(ctx, name)
	}
	return nil
}

func (s *Service) Trigger(_ context.Context, name string) error {
	err := s.pool.Trigger(name)
	if err != nil {
		s.log.Errorf("trigger bundle build for %s: %v", name, err)
	} else {
		s.log.Debugf("triggered bundle build for %s", name)
	}
	return err
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

	db, err := migrations.New().
		WithConfig(s.config.Database).
		WithLogger(s.log).
		WithMigrate(s.migrateDB).
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

func (s *Service) launchWorkers(ctx context.Context) {
	for tenant, err := range s.database.Tenants(ctx) {
		if err != nil {
			s.log.Errorf("error listing tenants: %s", err.Error())
			return
		}
		tenant := tenant.Name

		bundles, _, err := s.database.ListBundles(ctx, internalPrincipal, tenant, database.ListOptions{})
		if err != nil {
			s.log.Errorf("error listing bundles: %s", err.Error())
			return
		}
		s.log.Debugf("launchWorkers(%s) for %d bundles", tenant, len(bundles))

		sourceDefs, _, err := s.database.ListSources(ctx, internalPrincipal, tenant, database.ListOptions{})
		if err != nil {
			s.log.Errorf("error listing sources: %s", err.Error())
			return
		}

		sourceDefsByName := make(map[string]*config.Source)
		for _, src := range sourceDefs {
			sourceDefsByName[src.Name] = src
		}

		stacks, _, err := s.database.ListStacks(ctx, internalPrincipal, tenant, database.ListOptions{})
		if err != nil {
			s.log.Errorf("error listing stacks: %s", err.Error())
			return
		}

		activeBundles := make(map[string]struct{})
		for _, b := range bundles {
			bName := tenant + "_" + b.Name
			activeBundles[bName] = struct{}{}
		}

		// Remove any worker already shutdown from bookkeeping, as well as initiate shutdown for any bundle (worker) not in the current configuration.
		for id, w := range s.workers {
			if w.Done() {
				delete(s.workers, id)
				continue
			}

			if _, ok := activeBundles[id]; !ok {
				w.UpdateConfig(nil, nil, nil)
			}
		}

		// Start any new workers for bundles that are in the current configuration but not yet running. Inform any existing
		// workers of the current configuration, which will cause them to shutdown if configuration has changed.
		//
		// For each bundle, create the following directory structure under persistenceDir for the builder to use
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
		failures := make(map[string]Status)

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
						if !b.Options.NoDefaultStackMount {
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

			syncs := []Synchronizer{}
			sources := []*builder.Source{&root.Source}
			bundleDir := join(s.persistenceDir, md5sum(bName))

			for _, dep := range deps {
				// NB(sr): dep.Name could contain a `:` which cause build errors in OPA's bundle build machinery
				srcDir := join(bundleDir, "sources", ocp_fs.Escape(dep.Name))

				src := newSource(dep.Name).
					SyncBuiltin(&syncs, dep.Builtin, s.builtinFS, join(srcDir, "builtin")).
					SyncSourceSQL(&syncs, dep.ID, dep.Name, &s.database, join(srcDir, "database")).
					SyncDatasources(&syncs, dep.Datasources, join(srcDir, "datasources")).
					SyncGit(&syncs, dep.Name, dep.Git, join(srcDir, "repo"), overrides[dep.Name]).
					AddRequirements(dep.Requirements)

				sources = append(sources, &src.Source)
			}

			storage, err := s3.New(ctx, b.ObjectStorage)
			if err != nil {
				s.log.Errorf("error creating object storage client: %s", err.Error())
				failures[b.Name] = Status{State: BuildStateConfigError, Message: fmt.Sprintf("object storage: %v", err)}
				continue
			}

			w := NewBundleWorker(bundleDir, b, sourceDefs, stacks, s.log, bar, s.buildInterval).
				WithSources(sources).
				WithSynchronizers(syncs).
				WithStorage(storage).
				WithInterval(b.Interval).
				WithSingleShot(s.singleShot)
			s.pool.Add(b.Name, w.Execute) // TODO(sr): name not unique

			s.workers[bName] = w
		}

		s.failures = failures
	}
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
}

func newSource(name string) *source {
	return &source{
		Source: *builder.NewSource(name),
	}
}

func (src *source) addDir(dir string, wipe bool, includedFiles []string, excludedFiles []string) {
	_ = src.Source.AddDir(builder.Dir{
		Path:          filepath.ToSlash(dir),
		Wipe:          wipe,
		IncludedFiles: includedFiles,
		ExcludedFiles: excludedFiles,
	})
}

func (src *source) addFS(fsys fs.FS) {
	src.Source.AddFS(fsys)
}

func (src *source) SyncGit(syncs *[]Synchronizer, sourceName string, git config.Git, repoDir string, reqCommit string) *source {
	// Q(sr): Why errorDelay if we use this function to report BuildStateSuccess, too?
	if git.Repo != "" {
		srcDir := repoDir
		if git.Path != nil {
			srcDir = join(srcDir, *git.Path)
		}
		src.addDir(srcDir, false, git.IncludedFiles, git.ExcludedFiles)
		if reqCommit != "" {
			git.Commit = &reqCommit
		}
		*syncs = append(*syncs, gitsync.New(repoDir, git, sourceName))
	}

	return src
}

func (src *source) SyncBuiltin(syncs *[]Synchronizer, builtin *string, fs_ fs.FS, dir string) *source {
	if builtin != nil {
		// NB(sr): If the builtin isn't known, this will end up returning
		// "open .: file does not exist", so we don't check it here.
		sub, _ := fs.Sub(fs_, *builtin)
		src.addFS(sub)
	}
	return src
}

func (src *source) SyncDatasources(syncs *[]Synchronizer, datasources []config.Datasource, dir string) *source {
	for _, datasource := range datasources {
		switch datasource.Type {
		case "http":
			url, _ := datasource.Config["url"].(string)
			method, _ := datasource.Config["method"].(string)
			method = cmp.Or(method, "GET")

			body, _ := datasource.Config["body"].(string)
			headers, _ := datasource.Config["headers"].(map[string]any)
			*syncs = append(*syncs, httpsync.New(join(dir, datasource.Path, "data.json"), url, method, body, headers, datasource.Credentials))
		}

		if datasource.TransformQuery != "" {
			src.Transforms = append(src.Transforms, builder.Transform{
				Query: datasource.TransformQuery,
				Path:  join(dir, datasource.Path, "data.json"),
			})
		}
	}
	if len(datasources) > 0 {
		src.addDir(dir, true, nil, nil)
	}
	return src
}

func (src *source) SyncSourceSQL(syncs *[]Synchronizer, sourceID int64, name string, database *database.Database, dir string) *source {
	*syncs = append(*syncs, sqlsync.NewSQLSourceDataSynchronizer(dir, database, sourceID, name))
	src.addDir(dir, true, nil, nil)
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
