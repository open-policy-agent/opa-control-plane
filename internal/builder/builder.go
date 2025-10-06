package builder

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/open-policy-agent/opa/ast"     // nolint:staticcheck
	"github.com/open-policy-agent/opa/bundle"  // nolint:staticcheck
	"github.com/open-policy-agent/opa/compile" // nolint:staticcheck
	"github.com/open-policy-agent/opa/rego"    // nolint:staticcheck

	"github.com/styrainc/opa-control-plane/internal/config"
	"github.com/styrainc/opa-control-plane/internal/util"
)

type Source struct {
	Name         string
	Dirs         []Dir
	Requirements []config.Requirement
	Transforms   []Transform
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

func (s *Source) Wipe() error {
	for _, dir := range s.Dirs {
		if dir.Wipe {
			if err := removeDir(dir.Path); err != nil {
				return err
			}
		}
	}
	return nil
}

// Transform applies Rego policies to data, replacing the original content with the
// transformed content.
func (s *Source) Transform(ctx context.Context) error {
	paths := make([]string, len(s.Dirs))
	for i, dir := range s.Dirs {
		paths[i] = dir.Path
	}

	for _, t := range s.Transforms {
		content, err := os.ReadFile(t.Path)
		if err != nil {
			return err
		}

		var input any
		if err := json.Unmarshal(content, &input); err != nil {
			return fmt.Errorf("failed to unmarshal content: %w", err)
		}

		q, err := rego.New(
			rego.Query(t.Query),
			rego.Load(paths, nil),
		).PrepareForEval(ctx)
		if err != nil {
			return err
		}

		rs, err := q.Eval(ctx, rego.EvalInput(input))
		if err != nil {
			return err
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
			return err
		}

		if err := os.WriteFile(t.Path, content, 0o644); err != nil {
			return err
		}
	}

	return nil
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

func (b *Builder) Build(ctx context.Context) error {

	var existingRoots []ast.Ref
	// NB(sr): We've accumulated all deps already (service.go#getDeps), but we'll
	// process them again here: We're applying the inclusion/exclusion filters, and
	// they have an effect on the roots.
	toProcess := []*Source{b.sources[0]}

	type build struct {
		prefix string
		fsys   fs.FS
	}
	buildSources := []build{}
	sourceMap := make(map[string]*Source)
	for _, src := range b.sources {
		sourceMap[src.Name] = src
	}

	processed := map[string]struct{}{}
	rootMap := map[string]*Source{}

	for len(toProcess) > 0 {
		var next *Source
		next, toProcess = toProcess[0], toProcess[1:]
		var newRoots []ast.Ref

		for i, srcDir := range next.Dirs {
			fs0, err := util.NewFilterFS(os.DirFS(srcDir.Path),
				srcDir.IncludedFiles,
				slices.Concat(b.excluded, srcDir.ExcludedFiles))
			if err != nil {
				return err
			}

			rs, err := getRegoAndJSONRoots(fs0)
			if err != nil {
				return fmt.Errorf("%v: %w", next.Name, err)
			}
			newRoots = append(newRoots, rs...)
			prefix := next.Name
			if prefix == "" || i > 0 {
				prefix += strconv.Itoa(i)
			}
			prefix = clean(prefix)
			buildSources = append(buildSources, build{prefix: prefix, fsys: fs0})
		}

		for _, root := range newRoots {
			if overlap := rootsOverlap(existingRoots, root); len(overlap) > 0 {
				return &PackageConflictErr{
					Requirement: next,
					Package:     &ast.Package{Path: root},
					rootMap:     rootMap,
					overlap:     overlap,
				}
			}
			rootMap[root.String()] = next
		}
		existingRoots = append(existingRoots, newRoots...)
		for _, r := range next.Requirements {
			if r.Source != nil {
				src, ok := sourceMap[*r.Source]
				if !ok {
					return fmt.Errorf("missing source %q", *r.Source)
				}
				if _, ok := processed[src.Name]; !ok {
					toProcess = append(toProcess, src)
					processed[src.Name] = struct{}{}
				}
			}
		}
	}

	ns := util.Namespace()
	paths := make([]string, 0, len(buildSources))
	for _, src := range buildSources {
		if err := ns.Bind(src.prefix, src.fsys); err != nil {
			return err
		}
		paths = append(paths, src.prefix)
	}

	c := compile.New().
		WithFS(ns).
		WithPaths(paths...)
	if err := c.Build(ctx); err != nil {
		return fmt.Errorf("build: %w", err)
	}

	result := c.Bundle()

	var roots []string
	result.Manifest.Roots = &roots // avoid "" default root

	for _, root := range existingRoots {
		r, err := root.Ptr()
		if err != nil {
			return err
		}
		result.Manifest.AddRoot(r)
	}
	result.Manifest.SetRegoVersion(ast.RegoV0)
	return bundle.Write(b.output, *result)
}

// getRegoAndJSONRoots returns the set of roots for the given directories.
// The returned roots are the package paths for rego files and the directories
// holding the JSON files.
// It works on `fs.FS`es and expects filters to already have been applied (via
// `utils.FilterFS`).
func getRegoAndJSONRoots(fsys fs.FS) ([]ast.Ref, error) {
	set := ast.NewSet()
	if err := fs.WalkDir(fsys, ".", walkSuffixes(func(path string, d fs.DirEntry) error {
		bs, err := fs.ReadFile(fsys, path)
		if err != nil {
			return err
		}

		module, err := ast.ParseModule(path, string(bs))
		if err != nil {
			return err
		}

		set.Add(ast.NewTerm(module.Package.Path))
		return nil
	}, ".rego")); err != nil {
		return nil, err
	}
	if err := fs.WalkDir(fsys, ".", walkSuffixes(func(path string, d fs.DirEntry) error {
		path = filepath.ToSlash(filepath.Dir(path))

		var keys []*ast.Term
		for path != "" && path != "." {
			dir := filepath.Base(path)
			path = filepath.Dir(path)
			keys = append([]*ast.Term{ast.StringTerm(dir)}, keys...)
		}

		keys = append([]*ast.Term{ast.DefaultRootDocument}, keys...)
		set.Add(ast.RefTerm(keys...))
		return nil
	}, ".json", ".yml", ".yaml")); err != nil {
		return nil, err
	}

	sl := set.Slice()
	result := make([]ast.Ref, len(sl))
	for i := range sl {
		result[i] = sl[i].Value.(ast.Ref)
	}

	return result, nil
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
