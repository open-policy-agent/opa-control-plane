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
	"github.com/open-policy-agent/opa/rego"    // nolint:staticcheck
	"github.com/open-policy-agent/opa/v1/refactor"
	"github.com/open-policy-agent/opa/v1/topdown"

	"github.com/open-policy-agent/opa-control-plane/internal/config"
	ocp_fs "github.com/open-policy-agent/opa-control-plane/internal/fs"
	"github.com/open-policy-agent/opa-control-plane/internal/fs/mountfs"
)

type Source struct {
	Name         string
	Requirements []config.Requirement
	Transforms   []Transform

	// dirs record the underlying OS directories, used for `Wipe` and `Transform`
	dirs []Dir

	// fses are the fs.FS instances used for building the bundle, with per-source
	// includes/excludes already applied
	fses []fs.FS
}

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
		slices.EqualFunc(s.Requirements, other.Requirements, config.Requirement.Equal) &&
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

	f, err := ocp_fs.NewFilterFS(os.DirFS(d.Path), d.IncludedFiles, d.ExcludedFiles)
	if err != nil {
		return err
	}
	s.AddFS(f)
	return nil
}

func (s *Source) AddFS(f fs.FS) {
	s.fses = append(s.fses, f)
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
	Path          string   // local fs path to source files
	Wipe          bool     // bit indicates if worker should delete directory before synchronization
	IncludedFiles []string // inclusion filter on files to load from path
	ExcludedFiles []string // exclusion filter on files to skip from path
}

type Builder struct {
	sources  []*Source
	output   io.Writer
	excluded []string
	target   string
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
	var existingRoots []ast.Ref

	// NB(sr): We've accumulated all deps already (service.go#getDeps), but we'll
	// process them again here: We're applying the bundle-level exclusion filters,
	// and mount options on data and policy; and they can have an effect on the roots.
	toProcess := []mntSrc{{src: b.sources[0]}}

	buildSources := newBuildSources()
	alreadyProcessed := []mntSrc{}
	rootMap := map[string]*Source{}

	for len(toProcess) > 0 {
		var next mntSrc
		next, toProcess = toProcess[0], toProcess[1:]
		var newRoots refSet

		for _, fs_ := range next.src.fses {
			fs0, err := ocp_fs.NewFilterFS(fs_, nil, b.excluded)
			if err != nil {
				return err
			}

			if len(next.mounts) > 0 {
				// rewrite policies to match mounts
				// rego0 contains only rego files now
				rego0, err := extractAndTransformRego(fs0, next.mounts)
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
				return fmt.Errorf("source %s check files: %w", next.src.Name, err)
			}
			if !files {
				continue
			}

			buildSources.add(next.src.Name, fs0)

			rs, err := getRegoAndJSONRoots(fs0)
			if err != nil && !errors.Is(err, fs.ErrNotExist) {
				return fmt.Errorf("source %s find roots: %w", next.src.Name, err)
			}
			newRoots.add(rs...)
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

	roots := make([]string, 0, len(existingRoots))
	for _, root := range existingRoots {
		r, _ := root.Ptr()
		roots = append(roots, r)
	}

	fsBuild := mountfs.New(buildSources.fs())
	paths := slices.Collect(maps.Keys(fsBuild))

	target := cmp.Or(b.target, "rego")
	if target == "ir" { // fix naming convention
		target = "plan"
	}

	c := compile.New().
		WithRoots(roots...).
		WithFS(fsBuild).
		WithTarget(target).
		WithRegoAnnotationEntrypoints(true).
		WithPaths(paths...)
	if err := c.Build(ctx); err != nil {
		return fmt.Errorf("build: %w", err)
	}

	result := c.Bundle()
	result.Manifest.SetRegoVersion(ast.RegoV0)
	return bundle.Write(b.output, *result)
}

type refSet struct {
	refs []ast.Ref
}

func (rs *refSet) add(ns ...ast.Ref) {
	for _, n := range ns {
		for i, r := range rs.refs {
			switch {
			case r.HasPrefix(n):
				rs.refs[i] = n
				return
			case n.HasPrefix(r):
				return
			}
		}
		rs.refs = append(rs.refs, n)
	}
}

// getRegoAndJSONRoots returns the set of roots for the given directories.
// The returned roots are the package paths for rego files and the directories
// holding the JSON files.
// It works on `fs.FS`es and expects filters to already have been applied (via
// `utils.FilterFS`).
func getRegoAndJSONRoots(fsys fs.FS) ([]ast.Ref, error) {
	set := &refSet{}
	if err := fs.WalkDir(fsys, ".", walkSuffixes(func(path string, d fs.DirEntry) error {
		bs, err := fs.ReadFile(fsys, path)
		if err != nil {
			return err
		}

		module, err := ast.ParseModule(path, string(bs))
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

func extractAndTransformRego(fsys fs.FS, mnts []mount) (fs.FS, error) {
	modules := make(map[string]*ast.Module)
	if err := fs.WalkDir(fsys, ".", walkSuffixes(func(path string, d fs.DirEntry) error {
		bs, err := fs.ReadFile(fsys, path)
		if err != nil {
			return err
		}

		modules[path], err = ast.ParseModule(path, string(bs))
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
		rendered[p] = m.String()
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

var offlineCaps = offlineCapabilities()

func offlineCapabilities() *ast.Capabilities {
	caps := ast.CapabilitiesForThisVersion()
	caps.AllowNet = []string{} // allow _no_ network access
	return caps
}
