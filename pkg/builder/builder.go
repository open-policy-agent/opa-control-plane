package builder

import (
	"bytes"
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/yalue/merged_fs"

	"github.com/open-policy-agent/opa/ast"     // nolint:staticcheck
	"github.com/open-policy-agent/opa/bundle"  // nolint:staticcheck
	"github.com/open-policy-agent/opa/compile" // nolint:staticcheck
	"github.com/open-policy-agent/opa/format"  // nolint:staticcheck
	"github.com/open-policy-agent/opa/rego"    // nolint:staticcheck
	"github.com/open-policy-agent/opa/v1/refactor"
	"github.com/open-policy-agent/opa/v1/topdown"

	ocp_fs "github.com/open-policy-agent/opa-control-plane/internal/fs"
	"github.com/open-policy-agent/opa-control-plane/internal/fs/mountfs"
	ext_config "github.com/open-policy-agent/opa-control-plane/pkg/config"
)

// Source represents a collection of policy and data files with dependencies.
// Sources can depend on other sources via Requirements and apply transformations
// to data files before building.
type Source struct {
	Name         string
	Requirements []ext_config.Requirement
	Transforms   []Transform

	// dirs record the underlying OS directories, used for `Wipe` and `Transform`
	dirs []Dir

	// fses are the fs.FS instances used for building the bundle, with per-source
	// includes/excludes already applied
	fses []sourceFS
}

// sourceFS is one filesystem of a Source, together with what it contributes
// to the bundle beyond its files.
type sourceFS struct {
	fsys         fs.FS
	contribution func() *Contribution
}

func (s *sourceFS) contrib() *Contribution {
	if s.contribution == nil {
		return nil
	}
	return s.contribution()
}

// Contribution describes what a single source directory contributes to the
// bundle beyond its files. It is set per directory so that it only affects the content that produced it, not sibling
// directories of the same Source.
type Contribution struct {
	// Metadata is merged into the bundle manifest's metadata. A top-level key
	// contributed by two different directories is a build error.
	Metadata map[string]any

	// Roots are bundle roots claimed by this directory. They are subject to requirement mounts and to the same
	// overlap checks as roots computed from files.
	Roots []string

	// RegoVersion sets the Rego version (0 or 1) used to parse this directory's
	// policies. Nil leaves the default in place.
	RegoVersion *int
}

// Transform defines a data transformation operation that uses a Rego query to
// process and modify data files within a source.
type Transform struct {
	Query string
	Path  string
}

func NewSource(name string) *Source {
	return &Source{
		Name: name,
	}
}

func (s *Source) Equal(other *Source) bool {
	return s.Name == other.Name &&
		slices.EqualFunc(s.Requirements, other.Requirements, ext_config.Requirement.Equal) &&
		slices.Equal(s.Transforms, other.Transforms)
}

func (s *Source) Wipe() error {
	for _, dir := range s.dirs {
		if dir.Wipe {
			if err := removeDir(dir.Path); err != nil {
				return err
			}
		}
	}
	return nil
}

func (s *Source) AddDir(d Dir) error {
	// We record the Dir struct because we need to know whether we can Wipe().
	// `os.DirFS()` does not read anything until it's used, so it's OK to alter
	// the underlying OS filesystem via Wipe() or when applying the `Transforms`.
	s.dirs = append(s.dirs, d)

	excluded := slices.Concat(d.ExcludedFiles, d.ExcludedMetadataFiles)

	f, err := ocp_fs.NewFilterFS(os.DirFS(d.Path), d.IncludedFiles, excluded)
	if err != nil {
		return err
	}
	s.fses = append(s.fses, sourceFS{fsys: f, contribution: d.Contribution})
	return nil
}

func (s *Source) AddFS(f fs.FS) {
	s.fses = append(s.fses, sourceFS{fsys: f})
}

// Transform applies Rego policies to data, replacing the original content with the
// transformed content.
func (s *Source) Transform(ctx context.Context) (*bytes.Buffer, error) {
	paths := make([]string, len(s.dirs))
	for i, dir := range s.dirs {
		paths[i] = dir.Path
	}
	buf := bytes.Buffer{}

	for _, t := range s.Transforms {
		content, err := os.ReadFile(t.Path)
		if err != nil {
			return nil, err
		}

		var input any
		if err := json.Unmarshal(content, &input); err != nil {
			return nil, fmt.Errorf("failed to unmarshal content: %w", err)
		}

		q, err := rego.New(
			rego.Query(t.Query),
			rego.Load(paths, nil),
			rego.Capabilities(offlineCaps),
			rego.EnablePrintStatements(true),
			rego.PrintHook(topdown.NewPrintHook(&buf)),
		).PrepareForEval(ctx)
		if err != nil {
			return nil, err
		}

		rs, err := q.Eval(ctx, rego.EvalInput(input))
		if err != nil {
			return &buf, err
		}

		value := make([]any, 0)
		for _, result := range rs {
			for _, expr := range result.Expressions {
				if expr.Text == t.Query {
					value = append(value, expr.Value)
				}
			}
		}

		if len(value) == 1 {
			content, err = json.Marshal(value[0])
		} else {
			content, err = json.Marshal(value)
		}
		if err != nil {
			return &buf, err
		}

		if err := os.WriteFile(t.Path, content, 0o644); err != nil {
			return &buf, err
		}
	}

	return &buf, nil
}

type Dir struct {
	Path                  string   // local fs path to source files
	Wipe                  bool     // bit indicates if worker should delete directory before synchronization
	IncludedFiles         []string // inclusion filter on files to load from path
	ExcludedFiles         []string // exclusion filter on files to skip from path
	ExcludedMetadataFiles []string // excludes files that exist in the directory but are not part of its source content (eg. git checkout's .git)

	// Contribution, if set, is called once at the start of every Build to get
	// what this directory contributes to the bundle beyond its files. It may
	// return nil.
	Contribution func() *Contribution
}

type Builder struct {
	sources           []*Source
	output            io.Writer
	excluded          []string
	target            string
	optimizationLevel int
	revision          string
	revisionFunc      func(fs.FS) (string, error)
}

func New() *Builder {
	return &Builder{}
}

func (b *Builder) WithOutput(w io.Writer) *Builder {
	b.output = w
	return b
}

func (b *Builder) WithSources(srcs []*Source) *Builder {
	b.sources = srcs
	return b
}

func (b *Builder) WithExcluded(excluded []string) *Builder {
	b.excluded = excluded
	return b
}

func (b *Builder) WithTarget(target string) *Builder {
	b.target = target
	return b
}

func (b *Builder) WithOptimizationLevel(level int) *Builder {
	b.optimizationLevel = level
	return b
}

func (b *Builder) WithRevision(revision string) *Builder {
	b.revision = revision
	return b
}

// WithRevisionFunc sets a function to compute the revision from the assembled
// bundle filesystem. It is called after FS assembly and before compilation.
func (b *Builder) WithRevisionFunc(fn func(fs.FS) (string, error)) *Builder {
	b.revisionFunc = fn
	return b
}

func (b *Builder) Revision() string {
	return b.revision
}

type PackageConflictErr struct {
	Requirement *Source
	Package     *ast.Package
	rootMap     map[string]*Source
	overlap     []ast.Ref
}

func (err *PackageConflictErr) Error() string {
	// TODO(tsandall): once mounts are available improve to suggest
	lines := []string{fmt.Sprintf("requirement %q contains conflicting %v", err.Requirement.Name, err.Package)}
	for i := range err.overlap {
		if src, ok := err.rootMap[err.overlap[i].String()]; ok {
			lines = append(lines, fmt.Sprintf("- %v from %q", &ast.Package{Path: err.overlap[i]}, src.Name))
		}
	}
	return strings.Join(lines, "\n")
}

type mntSrc struct {
	src    *Source
	mounts []mount
}

type mount struct {
	path, prefix string
}

func (m mntSrc) Equal(other mntSrc) bool {
	return m.src.Equal(other.src) &&
		slices.Equal(m.mounts, other.mounts)
}

type buildSources struct {
	fsys map[string][]fs.FS
}

func newBuildSources() *buildSources {
	return &buildSources{fsys: make(map[string][]fs.FS)}
}

func (bs *buildSources) len() int {
	i := 0
	for j := range bs.fsys {
		i += len(bs.fsys[j])
	}
	return i
}

func (bs *buildSources) fs() map[string]fs.FS {
	fses := make(map[string]fs.FS, bs.len())
	for prefix := range bs.fsys {
		for j, fs_ := range bs.fsys[prefix] {
			mnt := prefix
			if j > 0 || mnt == "" {
				mnt += strconv.Itoa(j)
			}
			fses[mnt] = fs_
		}
	}
	return fses
}

func (bs *buildSources) add(prefix string, fsys fs.FS) {
	prefix = ocp_fs.Escape(prefix)
	_, ok := bs.fsys[prefix]
	if !ok {
		bs.fsys[prefix] = []fs.FS{}
	}
	bs.fsys[prefix] = append(bs.fsys[prefix], fsys)
}

func (b *Builder) Build(ctx context.Context) error {

	sourceMap := make(map[string]*Source, len(b.sources))
	for _, src := range b.sources {
		sourceMap[src.Name] = src
	}

	// Snapshot each directory's contribution once, so every pass over a
	// source sees the same value.
	contribs := map[*sourceFS]*Contribution{}
	for _, src := range b.sources {
		for i := range src.fses {
			c := src.fses[i].contrib()
			if c == nil {
				continue
			}
			if c.RegoVersion != nil && *c.RegoVersion != 0 && *c.RegoVersion != 1 {
				return fmt.Errorf("source %q: unsupported rego version %d", src.Name, *c.RegoVersion)
			}
			contribs[&src.fses[i]] = c
		}
	}

	var existingRoots []ast.Ref

	// NB(sr): We've accumulated all deps already (service.go#getDeps), but we'll
	// process them again here: We're applying the bundle-level exclusion filters,
	// and mount options on data and policy; and they can have an effect on the roots.
	toProcess := []mntSrc{{src: b.sources[0]}}

	buildSources := newBuildSources()
	alreadyProcessed := []mntSrc{}
	rootMap := map[string]*Source{}

	var emptyMntSrcs []mntSrc

	effectiveRegoVersion := ast.RegoV0
	var sourceManifests []bundle.Manifest
	var sourceManifestNames []string // source of each entry in sourceManifests

	// Contributed manifest metadata, and which directory contributed each
	// top-level key.
	metadata := map[string]any{}
	metadataOwner := map[string]*sourceFS{}
	metadataSource := map[string]string{}

	var claimedRoots []claimedRoot
	var fileRoots refSet // roots computed from files only, i.e. without claimed roots

	for len(toProcess) > 0 {
		var next mntSrc
		next, toProcess = toProcess[0], toProcess[1:]
		var newRoots refSet

		for i := range next.src.fses {
			sfs := &next.src.fses[i]
			fs0, err := ocp_fs.NewFilterFS(sfs.fsys, nil, b.excluded)
			if err != nil {
				return err
			}

			contrib := contribs[sfs]

			regoVersion := ast.RegoV0
			if m, ok := readManifest(fs0); ok {
				sourceManifests = append(sourceManifests, m)
				sourceManifestNames = append(sourceManifestNames, next.src.Name)
				if m.RegoVersion != nil && *m.RegoVersion == 1 {
					regoVersion = ast.RegoV1
				}
			}
			if contrib != nil && contrib.RegoVersion != nil {
				// The contribution takes precedence over the directory's .manifest.
				if *contrib.RegoVersion == 1 {
					regoVersion = ast.RegoV1
				} else {
					regoVersion = ast.RegoV0
				}
			}
			if regoVersion == ast.RegoV1 {
				effectiveRegoVersion = ast.RegoV1
			}

			if contrib != nil {
				for _, r := range contrib.Roots {
					ref, err := manifestRootToRef(r)
					if err != nil {
						return fmt.Errorf("source %q: claimed root %q: %w", next.src.Name, r, err)
					}
					if ref = mountRef(ref, next.mounts); ref != nil {
						newRoots.add(ref)
						claimedRoots = append(claimedRoots, claimedRoot{ref: ref, src: next.src.Name})
					}
				}
				for k, v := range contrib.Metadata {
					if owner, ok := metadataOwner[k]; ok {
						if owner != sfs {
							return fmt.Errorf("manifest metadata key %q contributed by both source %q and source %q", k, metadataSource[k], next.src.Name)
						}
						continue
					}
					metadata[k] = v
					metadataOwner[k] = sfs
					metadataSource[k] = next.src.Name
				}
			}

			if len(next.mounts) > 0 {
				// rewrite policies to match mounts
				// rego0 contains only rego files now
				rego0, err := extractAndTransformRego(fs0, next.mounts, regoVersion)
				if err != nil {
					return fmt.Errorf("source %s rego: %w", next.src.Name, err)
				}

				data0, err := applyDataMounts(fs0, next.mounts)
				if err != nil {
					return fmt.Errorf("source %s data: %w", next.src.Name, err)
				}
				fs0 = merged_fs.MergeMultiple(data0, rego0)
			}

			files, err := ocp_fs.FSContainsFiles(fs0)
			if err != nil {
				if errors.Is(err, fs.ErrNotExist) {
					return fmt.Errorf("source %q: directory does not exist", next.src.Name)
				}
				return fmt.Errorf("source %q: %w", next.src.Name, err)
			}
			if !files {
				continue
			}

			buildSources.add(next.src.Name, fs0)

			rs, err := getRegoAndJSONRoots(fs0, regoVersion)
			if err != nil {
				return fmt.Errorf("source %s find roots: %w", next.src.Name, err)
			}
			newRoots.add(rs...)
			fileRoots.add(rs...)
		}

		hasSourceReqs := slices.ContainsFunc(next.src.Requirements, func(r ext_config.Requirement) bool {
			return r.Source != nil
		})
		if len(newRoots.refs) == 0 && len(next.mounts) > 0 && !hasSourceReqs {
			emptyMntSrcs = append(emptyMntSrcs, next)
		}

		for _, root := range newRoots.refs {
			if overlap := rootsOverlap(existingRoots, root); len(overlap) > 0 {
				return &PackageConflictErr{
					Requirement: next.src,
					Package:     &ast.Package{Path: root},
					rootMap:     rootMap,
					overlap:     overlap,
				}
			}
			rootMap[root.String()] = next.src
		}
		existingRoots = append(existingRoots, newRoots.refs...)

		for _, r := range next.src.Requirements {
			if r.Source != nil {
				src, ok := sourceMap[*r.Source]
				if !ok {
					return fmt.Errorf("missing source %q", *r.Source)
				}

				// add mounts from requirement
				this := mntSrc{src: src}
				if r.Path != "" || r.Prefix != "" {
					this.mounts = append(this.mounts, mount{path: r.Path, prefix: r.Prefix})
				}
				this.mounts = append(this.mounts, next.mounts...)

				if !slices.ContainsFunc(alreadyProcessed, this.Equal) {
					toProcess = append(toProcess, this)               // queue it
					alreadyProcessed = append(alreadyProcessed, this) // record "dealt with this"
				}
			}
		}
	}

	// For empty sources with mount prefixes, derive roots so the bundle
	// claims the configured namespaces instead of letting OPA default to
	// roots:[""] (which conflicts with every other bundle). This mirrors
	// applyDataMounts: each mount in the chain applies Sub(path) then
	// Mount(prefix). For an empty source, a non-trivial path selects a
	// subtree that doesn't exist, collapsing the chain to nothing.
	for _, ms := range emptyMntSrcs {
		root := mountRoot(ms.mounts)
		if root == nil {
			continue
		}
		if overlap := rootsOverlap(existingRoots, root); len(overlap) > 0 {
			return &PackageConflictErr{
				Requirement: ms.src,
				Package:     &ast.Package{Path: root},
				rootMap:     rootMap,
				overlap:     overlap,
			}
		}
		rootMap[root.String()] = ms.src
		existingRoots = append(existingRoots, root)
		fileRoots.add(root)
	}

	roots := make([]string, 0, len(existingRoots))
	for _, root := range existingRoots {
		r, _ := root.Ptr()
		roots = append(roots, r)
	}

	// If any source manifest specifies roots, use those. Log if they differ from computed.
	manifestRootsFrom := "" // source whose .manifest roots replaced the computed ones
	for i, m := range sourceManifests {
		if m.Roots != nil {
			manifestRoots := *m.Roots
			computed := make([]string, 0, len(fileRoots.refs))
			for _, root := range fileRoots.refs {
				r, _ := root.Ptr()
				computed = append(computed, r)
			}
			sortedComputed := slices.Clone(computed)
			slices.Sort(sortedComputed)
			sortedManifest := slices.Clone(manifestRoots)
			slices.Sort(sortedManifest)
			if !slices.Equal(sortedComputed, sortedManifest) {
				fmt.Fprintf(os.Stderr, "builder: source manifest roots %v differ from computed roots %v; using manifest roots\n", manifestRoots, computed)
			}
			roots = manifestRoots
			manifestRootsFrom = sourceManifestNames[i]
			break
		}
	}

	// Claimed roots are part of the computed roots, so the replacement above
	// would drop them. Add each one back unless a root already covers it
	// (same root or a parent).
	//
	// A claimed root that is broader than a manifest root (claimed "app",
	// manifest "app/x") can't be added: the bundle's own roots would overlap,
	// which OPA rejects when loading it. Fail the build instead.
	//
	// Claimed roots are reduced to a minimal set first (claimed "lazy/users"
	// and "lazy" is just "lazy"), as computed roots are, and only compared
	// with the roots from before this loop, not with ones it added.
	var minimal refSet
	for _, cr := range claimedRoots {
		minimal.add(cr.ref)
	}
	base := slices.Clone(roots)
	added := map[string]struct{}{}
	for _, cr := range claimedRoots {
		if !slices.ContainsFunc(minimal.refs, func(m ast.Ref) bool { return m.Equal(cr.ref) }) {
			continue // covered by a broader claimed root
		}
		r, err := cr.ref.Ptr() // data.authz.main -> "authz/main"
		if err != nil {
			return fmt.Errorf("source %q: claimed root %v: %w", cr.src, cr.ref, err)
		}
		if _, ok := added[r]; ok {
			continue
		}
		if slices.ContainsFunc(base, func(s string) bool { return rootCovers(s, r) }) {
			continue
		}
		if i := slices.IndexFunc(base, func(s string) bool { return rootCovers(r, s) }); i >= 0 {
			return fmt.Errorf("source %q claims root %q, which overlaps root %q from the .manifest of source %q", cr.src, r, base[i], manifestRootsFrom)
		}
		roots = append(roots, r)
		added[r] = struct{}{}
	}

	fsBuild := mountfs.New(buildSources.fs())
	paths := slices.Collect(maps.Keys(fsBuild))

	if b.revisionFunc != nil {
		revision, err := b.revisionFunc(fsBuild)
		if err != nil {
			return fmt.Errorf("revision: %w", err)
		}
		b.revision = revision
	}

	// If any source manifest specifies a revision, use it as the source of truth.
	for _, m := range sourceManifests {
		if m.Revision != "" {
			if b.revisionFunc != nil {
				fmt.Fprintf(os.Stderr, "builder: source manifest revision %q overrides WithRevisionFunc result; using manifest revision\n", m.Revision)
			}
			b.revision = m.Revision
			break
		}
	}

	target := cmp.Or(b.target, "rego")
	if target == "ir" { // fix naming convention
		target = "plan"
	}

	c := compile.New().
		WithRegoVersion(effectiveRegoVersion).
		WithRoots(roots...).
		WithFS(fsBuild).
		WithTarget(target).
		WithOptimizationLevel(b.optimizationLevel).
		WithRegoAnnotationEntrypoints(true).
		WithPaths(paths...)
	if err := c.Build(ctx); err != nil {
		return fmt.Errorf("build: %w", err)
	}

	result := c.Bundle()
	result.Manifest.SetRegoVersion(effectiveRegoVersion)
	result.Manifest.Revision = b.revision
	if len(metadata) > 0 {
		if result.Manifest.Metadata == nil {
			result.Manifest.Metadata = make(map[string]any, len(metadata))
		}
		maps.Copy(result.Manifest.Metadata, metadata)
	}

	return bundle.Write(b.output, *result)
}

type refSet struct {
	refs []ast.Ref
}

// add inserts each ref into the set while keeping it minimal: no ref in the
// set is a prefix of another. Adding a ref already covered by (a prefix of) an
// existing ref is a no-op; adding a ref that is a prefix of existing refs
// replaces all of them.
func (rs *refSet) add(ns ...ast.Ref) {
next:
	for _, n := range ns {
		// If n is already covered by a shorter existing ref, there's nothing
		// to do for this n.
		for _, r := range rs.refs {
			if n.HasPrefix(r) {
				continue next
			}
		}
		// Otherwise keep every existing ref that n does not subsume, then add
		// n. We must drop all refs n is a prefix of, not just the first:
		// several siblings can be covered by the same shorter prefix.
		kept := rs.refs[:0]
		for _, r := range rs.refs {
			if !r.HasPrefix(n) {
				kept = append(kept, r)
			}
		}
		rs.refs = append(kept, n)
	}
}

// getRegoAndJSONRoots returns the set of roots for the given directories.
// The returned roots are the package paths for rego files and the directories
// holding the JSON files.
// It works on `fs.FS`es and expects filters to already have been applied (via
// `utils.FilterFS`).
func getRegoAndJSONRoots(fsys fs.FS, regoVersion ast.RegoVersion) ([]ast.Ref, error) {
	set := &refSet{}
	if err := fs.WalkDir(fsys, ".", walkSuffixes(func(path string, d fs.DirEntry) error {
		bs, err := fs.ReadFile(fsys, path)
		if err != nil {
			return err
		}

		module, err := ast.ParseModuleWithOpts(path, string(bs), ast.ParserOptions{RegoVersion: regoVersion})
		if err != nil {
			return err
		}

		set.add(module.Package.Path)
		return nil
	}, ".rego")); err != nil {
		return nil, err
	}
	if err := fs.WalkDir(fsys, ".", walkSuffixes(func(p string, d fs.DirEntry) error {
		path := filepath.ToSlash(filepath.Dir(p))

		var keys []*ast.Term
		for path != "" && path != "." {
			dir := filepath.Base(path)
			path = filepath.Dir(path)
			keys = append(keys, ast.StringTerm(dir))
		}

		keys = append(keys, ast.DefaultRootDocument)
		slices.Reverse(keys)
		set.add(keys)
		return nil
	}, ".json", ".yml", ".yaml")); err != nil {
		return nil, err
	}

	return set.refs, nil
}

// NB(sr): Why not glob the suffixes on top of our existing globs? Or make FilterFS take
// a function, so we could reuse it for filtering out the interesting suffixes. Room for
// improvements!
func walkSuffixes(f func(path string, d fs.DirEntry) error, suffixes ...string) fs.WalkDirFunc {
	return func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		ext := filepath.Ext(path)
		if !slices.ContainsFunc(suffixes, func(s string) bool {
			return strings.EqualFold(s, ext)
		}) {
			return nil
		}
		return f(path, d)
	}
}

func rootsOverlap(roots []ast.Ref, root ast.Ref) (result []ast.Ref) {
	for _, other := range roots {
		if other.HasPrefix(root) || root.HasPrefix(other) {
			result = append(result, other)
		}
	}
	return result
}

func removeDir(path string) error {

	if path == "" {
		return nil
	}

	if _, err := os.Stat(path); os.IsNotExist(err) {
		return nil
	}

	files, err := os.ReadDir(path)
	if err != nil {
		return err
	}

	for _, f := range files {
		err := os.RemoveAll(filepath.Join(path, f.Name()))
		if err != nil {
			return err
		}
	}

	return nil
}

func toPath(d string) (string, error) {
	if d == "" || d == "data" {
		return ".", nil
	}
	d = toRefString(d)
	r, err := ast.ParseRef(d)
	if err != nil {
		return "", err
	}
	if !r.HasPrefix(ast.DefaultRootRef) {
		return "", fmt.Errorf("ref %v needs to start with \"%s\"", d, ast.DefaultRootRef)
	}
	return r.Ptr()
}

func toRefString(d string) string {
	if d == "" {
		return "data"
	}
	if strings.HasPrefix(d, "data") {
		return d
	}
	return "data." + d
}

var emptyFS = merged_fs.MergeMultiple()

func extractAndTransformRego(fsys fs.FS, mnts []mount, regoVersion ast.RegoVersion) (fs.FS, error) {
	modules := make(map[string]*ast.Module)
	if err := fs.WalkDir(fsys, ".", walkSuffixes(func(path string, d fs.DirEntry) error {
		bs, err := fs.ReadFile(fsys, path)
		if err != nil {
			return err
		}

		modules[path], err = ast.ParseModuleWithOpts(path, string(bs), ast.ParserOptions{RegoVersion: regoVersion})
		return err
	}, ".rego")); err != nil {
		if errors.Is(err, fs.ErrNotExist) { // no rego files present
			return emptyFS, nil
		}
		return nil, err
	}

	for _, mnt := range mnts {
		from, to := toRefString(mnt.path), toRefString(mnt.prefix)
		replacements := map[string]string{from: to}

		// Here, we do the "path" selection: discard anything not in the selected subtree
		maps.DeleteFunc(modules, func(k string, mod *ast.Module) bool {
			return !mod.Package.Path.HasPrefix(ast.MustParseRef(from))
		})

		res, err := refactor.New().Move(refactor.MoveQuery{
			Modules:       modules,
			SrcDstMapping: replacements,
		})
		if err != nil {
			return nil, fmt.Errorf("refactor: %w", err)
		}
		modules = res.Result
	}

	rendered := make(map[string]string, len(modules))
	for p, m := range modules {
		r, err := format.Ast(m)
		if err != nil {
			return nil, fmt.Errorf("failed to format module %s, %w", p, err)
		}
		rendered[p] = string(r)
	}

	return ocp_fs.MapFS(rendered), nil
}

func applyDataMounts(fsys fs.FS, mnts []mount) (fs.FS, error) {
	// for processing data files, exclude rego
	fs1, err := ocp_fs.NewFilterFS(fsys, nil, []string{"*.rego"})
	if err != nil {
		return nil, err
	}

	// With the data files of this source, for every mount, we'll sub and bind;
	// discarding the rest of the content (if any).
	//
	// In the next iteration (for the next mount), we'll keep doing that, and
	// thereby subsequently deal with all the moving we need.
	for _, mnt := range mnts {
		subPath, err := toPath(mnt.path)
		if err != nil {
			return nil, err
		}
		prefPath, err := toPath(mnt.prefix)
		if err != nil {
			return nil, err
		}

		// check if subPath exists, this source could be for rego only
		_, err = fs1.Open(subPath)
		exists := !errors.Is(err, fs.ErrNotExist)
		if !exists {
			fs1 = emptyFS
			continue // next mount
		}

		// We split into `sub` and `rest`, and bind them to `prefix` and `.` accordingly.
		var sub fs.FS
		if subPath == "." {
			sub = fs1 // no `rest`, but could have prefPath (handled below)
		} else {
			sub, err = fs.Sub(fs1, subPath)
			if err != nil {
				return nil, fmt.Errorf("mount %s:%s: %w", subPath, prefPath, err)
			}
		}

		if prefPath != "." {
			sub = mountfs.New(map[string]fs.FS{prefPath: sub})
		}
		fs1 = sub
	}
	return fs1, nil
}

// manifestRootToRef converts a manifest-style root into a data-prefixed ref.
func manifestRootToRef(root string) (ast.Ref, error) {
	ref := ast.DefaultRootRef.Copy()
	if root == "" {
		return ref, nil
	}
	for seg := range strings.SplitSeq(root, "/") {
		if seg == "" {
			return nil, errors.New("empty path segment")
		}
		ref = append(ref, ast.StringTerm(seg))
	}
	return ref, nil
}

// mountRef applies a mount chain to a claimed root, mirroring what the chain
// does to files: each mount selects the subtree at path and places it under
// prefix. A root inside the selected subtree is moved along with it; a root
// containing the selected subtree becomes the prefix; a root disjoint from it
// is dropped (nil), just like files outside the selected path.
func mountRef(ref ast.Ref, mnts []mount) ast.Ref {
	for _, mnt := range mnts {
		subRef, prefRef := toRef(mnt.path), toRef(mnt.prefix)
		if subRef == nil || prefRef == nil {
			return nil
		}
		switch {
		case ref.HasPrefix(subRef):
			ref = prefRef.Concat(ref[len(subRef):])
		case subRef.HasPrefix(ref):
			ref = prefRef.Copy()
		default:
			return nil
		}
	}
	return ref
}

// claimedRoot is a root claimed through a Contribution, after mounts.
type claimedRoot struct {
	ref ast.Ref
	src string // name of the claiming source
}

// rootCovers reports whether manifest root covers manifest root r, i.e. r is
// root itself or below it ("" covers everything).
func rootCovers(root, r string) bool {
	return root == "" || r == root || strings.HasPrefix(r, root+"/")
}

// mountRoot simulates the mount chain on an empty source to determine the
// effective root namespace. It mirrors applyDataMounts: each mount applies
// Sub(path) then Mount(prefix). For an empty source the "data space" is just
// the root (data). A non-trivial path selects a subtree that doesn't exist,
// collapsing the result to nil.
func mountRoot(mnts []mount) ast.Ref {
	cur := ast.DefaultRootRef.Copy() // [data]
	for _, mnt := range mnts {
		subRef := toRef(mnt.path)
		prefRef := toRef(mnt.prefix)
		if subRef == nil || prefRef == nil {
			return nil
		}

		// Sub: selecting a subtree from an empty source yields nothing
		// unless the virtual cursor is already at or below the sub path.
		// When cur equals DefaultRootRef, a deeper subRef selects content
		// that doesn't exist in an empty source.
		if !cur.HasPrefix(subRef) {
			return nil
		}
		cur = ast.DefaultRootRef.Concat(cur[len(subRef):])

		// Mount: place cur under prefRef.
		cur = prefRef.Concat(cur[1:]) // [1:] drops "data" head from cur
	}

	if cur.Equal(ast.DefaultRootRef) {
		return nil // no effective prefix — would default to root
	}
	return cur
}

// toRef parses a mount path or prefix (e.g. "data.x.y" or "") into an ast.Ref.
// Returns DefaultRootRef for empty/root values.
func toRef(d string) ast.Ref {
	d = toRefString(d)
	r, err := ast.ParseRef(d)
	if err != nil {
		return nil
	}
	if !r.HasPrefix(ast.DefaultRootRef) {
		return nil
	}
	return r
}

var offlineCaps = offlineCapabilities()

func offlineCapabilities() *ast.Capabilities {
	caps := ast.CapabilitiesForThisVersion()
	caps.AllowNet = []string{} // allow _no_ network access
	return caps
}

// readManifest reads a .manifest file from the FS root and returns the parsed
// bundle.Manifest and true, or an empty manifest and false if absent or unparseable.
func readManifest(fsys fs.FS) (bundle.Manifest, bool) {
	content, err := fs.ReadFile(fsys, ".manifest")
	if err != nil {
		return bundle.Manifest{}, false
	}
	var m bundle.Manifest
	if err := json.Unmarshal(content, &m); err != nil {
		return bundle.Manifest{}, false
	}
	return m, true
}
