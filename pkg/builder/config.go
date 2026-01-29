package builder

// Requirement represents a dependency on another source with optional path mounting.
// It allows sources to include other sources and remap their package namespaces
// to avoid conflicts.
type Requirement struct {
	// Source is the name of the source to include (required)
	Source *string

	// Path selects a subtree from the source (e.g., "data.lib" selects only
	// packages under data.lib). Empty means include everything.
	Path string

	// Prefix remaps the source to a different namespace (e.g., "data.imported"
	// moves all packages under data.imported). Empty means no remapping.
	Prefix string
}

// Equal returns true if two requirements are identical.
func (r Requirement) Equal(other Requirement) bool {
	return ptrEqual(r.Source, other.Source) &&
		r.Path == other.Path &&
		r.Prefix == other.Prefix
}

// Dir represents a directory on the filesystem to be included as a source.
// It supports filtering files via include/exclude patterns and can optionally
// wipe the directory contents before synchronization.
type Dir struct {
	// Path is the local filesystem path to source files (required)
	Path string

	// Wipe indicates if the directory should be deleted before synchronization.
	// Set to false for git repositories (preserves .git directory for incremental updates).
	// Set to true for generated/downloaded data (http, database) that should be refreshed.
	Wipe bool

	// IncludedFiles is an inclusion filter on files to load from the path.
	// Supports glob patterns (e.g., "*.rego", "policies/**/*.rego").
	// Empty means include all files.
	IncludedFiles []string

	// ExcludedFiles is an exclusion filter on files to skip from the path.
	// Supports glob patterns (e.g., "*_test.rego", "temp/**").
	// Applied after IncludedFiles.
	ExcludedFiles []string
}

// Transform applies a Rego query to transform data files before building.
// The query is evaluated with the file's JSON content as input, and the
// result replaces the original file content.
type Transform struct {
	// Query is the Rego query to evaluate (e.g., "data.transform.result")
	Query string

	// Path is the absolute filesystem path to the JSON file to transform
	Path string
}

func ptrEqual[T comparable](a, b *T) bool {
	if a == nil && b == nil {
		return true
	}
	if a == nil || b == nil {
		return false
	}
	return *a == *b
}
