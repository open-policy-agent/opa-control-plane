// Package builder compiles OPA bundles from multiple sources with namespace isolation.
//
// The builder validates package namespacing (no overlapping packages allowed), merges
// filesystems from different sources, and uses OPA's native compiler to produce optimized bundles.
// It supports source transformations via Rego queries and requirement-based dependency management.
//
// # Basic Usage
//
// Create sources with directories and build a bundle:
//
//	import "github.com/open-policy-agent/opa-control-plane/pkg/builder"
//
//	// Create a source
//	src := builder.NewSource("my-policies")
//	err := src.AddDir(builder.Dir{
//	    Path: "/path/to/policies",
//	    Wipe: false,
//	    IncludedFiles: []string{"*.rego"},
//	    ExcludedFiles: []string{"*_test.rego"},
//	})
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	// Build bundle
//	var output bytes.Buffer
//	b := builder.New().
//	    WithSources([]*builder.Source{src}).
//	    WithOutput(&output).
//	    WithTarget("rego") // or "wasm", "ir"
//
//	if err := b.Build(ctx); err != nil {
//	    log.Fatal(err)
//	}
//
// # Sources and Requirements
//
// Sources can depend on other sources via requirements. Requirements support
// path mounting to avoid namespace conflicts:
//
//	lib := builder.NewSource("library")
//	_ = lib.AddDir(builder.Dir{Path: "/path/to/lib"})
//
//	main := builder.NewSource("main")
//	_ = main.AddDir(builder.Dir{Path: "/path/to/main"})
//	libName := "library"
//	main.Requirements = []builder.Requirement{{
//	    Source: &libName,
//	    Path:   "data.lib",      // Select this subtree from library
//	    Prefix: "data.imported", // Mount it here in the bundle
//	}}
//
//	b := builder.New().
//	    WithSources([]*builder.Source{main, lib}).
//	    WithOutput(&output)
//
//	err := b.Build(ctx)
//
// # Namespace Isolation
//
// The builder enforces strict namespace isolation. Sources with overlapping
// package paths will cause a build error:
//
//	// Source A has: package x.y
//	// Source B has: package x.y.z
//	// Build will fail with PackageConflictErr
//
// Use path mounting in requirements to resolve conflicts by moving one source
// into a different namespace:
//
//	main.Requirements = []builder.Requirement{{
//	    Source: &libName,
//	    Prefix: "data.imported", // Moves conflicting packages under "imported"
//	}}
//
// # Data Transformations
//
// Sources can apply Rego transformations to JSON data files before building:
//
//	src.Transforms = []builder.Transform{{
//	    Query: "data.transform.result", // Rego query to evaluate
//	    Path:  "/path/to/data.json",    // File to transform
//	}}
//
// The transform evaluates the query with the file's JSON as input and
// replaces the file with the query result.
//
// # Build Targets
//
// The builder supports multiple OPA compilation targets:
//   - "rego": Compile to Rego (default)
//   - "wasm": Compile to WebAssembly
//   - "ir" or "plan": Compile to intermediate representation
//
// Set the target with WithTarget:
//
//	b := builder.New().
//	    WithSources(sources).
//	    WithTarget("wasm").
//	    WithOutput(&output)
//
// # File Filtering
//
// Filter files at multiple levels:
//   - Per-source: Use Dir.IncludedFiles and Dir.ExcludedFiles
//   - Per-bundle: Use Builder.WithExcluded to filter across all sources
//
//	b := builder.New().
//	    WithSources(sources).
//	    WithExcluded([]string{"test/**", "*.md"}). // Excludes these patterns from all sources
//	    WithOutput(&output)
//
// # Thread Safety
//
// Builder and Source instances are NOT thread-safe. Each instance should
// be used by a single goroutine. Create separate instances for concurrent builds.
package builder
