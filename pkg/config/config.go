package config

import (
	"cmp"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"os"
	"reflect"
	"slices"
	"strings"
	"time"

	"github.com/gobwas/glob"
	"github.com/goccy/go-yaml"
	schemareflector "github.com/swaggest/jsonschema-go"

	internalfs "github.com/open-policy-agent/opa-control-plane/internal/fs"
	internalutil "github.com/open-policy-agent/opa-control-plane/pkg/util"
)

// Requirement specifies a dependency on a source (such as a Git repository)
// with optional constraints for how it should be resolved and mounted.
type Requirement struct {
	Source    *string        `json:"source,omitempty"`
	Git       GitRequirement `json:"git,omitzero"`
	Path      string         `json:"path,omitzero"`
	Prefix    string         `json:"prefix,omitzero"`
	AutoMount *bool          `json:"automount,omitempty"`

	_ struct{} `additionalProperties:"false"`
}

// GitRequirement specifies Git-specific constraints for a requirement.
// It allows pinning a dependency to a specific Git commit hash.
type GitRequirement struct {
	Commit *string `json:"commit,omitempty"`

	_ struct{} `additionalProperties:"false"`
}

func (a Requirement) Equal(b Requirement) bool {
	return internalutil.PtrEqual(a.Source, b.Source) &&
		internalutil.PtrEqual(a.Git.Commit, b.Git.Commit) &&
		a.Path == b.Path &&
		a.Prefix == b.Prefix &&
		internalutil.PtrEqual(a.AutoMount, b.AutoMount)
}
func (a Requirement) Compare(b Requirement) int {
	if x := internalutil.PtrCompare(a.Source, b.Source); x != 0 {
		return x
	}
	if x := internalutil.PtrCompare(a.Git.Commit, b.Git.Commit); x != 0 {
		return x
	}
	if x := strings.Compare(a.Path, b.Path); x != 0 {
		return x
	}
	if x := strings.Compare(a.Prefix, b.Prefix); x != 0 {
		return x
	}
	if x := internalutil.BoolPtrCompare(a.AutoMount, b.AutoMount); x != 0 {
		return x
	}
	return 0
}

// Labels is a map of key-value string pairs used for bundle labeling.
type Labels map[string]string

// Duration wraps time.Duration with JSON/YAML string marshaling (e.g. "5m", "0.5s").
type Duration time.Duration

func (d Duration) MarshalJSON() ([]byte, error) {
	return json.Marshal(d.String())
}

func (d *Duration) UnmarshalJSON(data []byte) error {
	var str string
	if err := json.Unmarshal(data, &str); err != nil {
		return err
	}
	val, err := time.ParseDuration(str)
	*d = Duration(val)
	return err
}

func (d *Duration) UnmarshalYAML(bs []byte) error {
	var s string
	if err := yaml.Unmarshal(bs, &s); err != nil {
		return err
	}
	val, err := time.ParseDuration(s)
	*d = Duration(val)
	return err
}

func (d Duration) String() string {
	return time.Duration(d).String()
}

// Requirements is a slice of Requirement.
type Requirements []Requirement

// StringSet is a slice of strings.
type StringSet []string

func (a StringSet) Add(value string) StringSet {
	i, found := slices.BinarySearch(a, value)
	if found {
		return a
	}
	return slices.Insert(a, i, value)
}

// Files is a map of file paths to file contents with base64 JSON/YAML marshaling.
type Files map[string]string

func (f Files) MarshalYAML() (any, error) {
	encodedMap := make(map[string]string)
	for key, value := range f {
		encodedMap[key] = base64.StdEncoding.EncodeToString([]byte(value))
	}
	return encodedMap, nil
}

func (f Files) MarshalJSON() ([]byte, error) {
	v, err := f.MarshalYAML()
	if err != nil {
		return nil, err
	}
	return json.Marshal(v)
}

func (f *Files) UnmarshalYAML(bs []byte) error {
	var m map[string]string
	if err := yaml.Unmarshal(bs, &m); err != nil {
		return err
	}

	return f.unmarshal(m)
}

func (f *Files) UnmarshalJSON(bs []byte) error {
	var m map[string]string
	if err := json.Unmarshal(bs, &m); err != nil {
		return err
	}

	return f.unmarshal(m)
}

func (f *Files) unmarshal(raw map[string]string) error {
	*f = Files{}
	for key, encodedValue := range raw {
		decodedBytes, err := base64.StdEncoding.DecodeString(encodedValue)
		if err != nil {
			return fmt.Errorf("failed to decode value for key %q: %w", key, err)
		}
		(*f)[key] = string(decodedBytes)
	}
	return nil
}

// Optimization configures bundle optimization settings.
type Optimization struct {
	Level int `json:"level,omitzero" enum:"0,1,2"`

	_ struct{} `additionalProperties:"false"`
}

// Options configures bundle build options.
type Options struct {
	NoDefaultStackMount bool          `json:"no_default_stack_mount"`
	Optimization        *Optimization `json:"optimization,omitempty"`
	Target              string        `json:"target,omitzero" enum:"rego,ir,plan,wasm"`

	_ struct{} `additionalProperties:"false"`
}

func (o Options) Empty() bool {
	return o == Options{}
}

// Bundle defines the configuration for an OPA Control Plane Bundle.
type Bundle struct {
	Name          string        `json:"name"`
	Labels        Labels        `json:"labels,omitempty"`
	Revision      string        `json:"revision,omitempty"`
	ObjectStorage ObjectStorage `json:"object_storage,omitzero"`
	Requirements  Requirements  `json:"requirements,omitempty"`
	ExcludedFiles StringSet     `json:"excluded_files,omitempty"`
	Interval      Duration      `json:"rebuild_interval,omitzero"`
	Options       Options       `json:"options,omitzero"`

	_ struct{} `additionalProperties:"false"`
}

func (s *Bundle) UnmarshalJSON(bs []byte) error {
	type rawBundle Bundle
	var raw rawBundle

	if err := json.Unmarshal(bs, &raw); err != nil {
		return fmt.Errorf("failed to decode bundle: %w", err)
	}

	*s = Bundle(raw)
	return s.validate()
}

func (s *Bundle) UnmarshalYAML(bs []byte) error {
	type rawBundle Bundle
	var raw rawBundle

	if err := yaml.Unmarshal(bs, &raw); err != nil {
		return fmt.Errorf("failed to decode bundle: %w", err)
	}

	*s = Bundle(raw)
	return s.validate()
}

func (s *Bundle) validate() error {
	for _, pattern := range s.ExcludedFiles {
		if _, err := glob.Compile(pattern); err != nil {
			return fmt.Errorf("failed to compile excluded file pattern %q: %w", pattern, err)
		}
	}

	return s.ObjectStorage.validate()
}

// Source defines the configuration for an OPA Control Plane Source.
type Source struct {
	ID            int64        `json:"-"`
	Name          string       `json:"name"`
	Builtin       *string      `json:"builtin,omitempty"`
	Git           Git          `json:"git,omitzero"`
	Datasources   Datasources  `json:"datasources,omitempty"`
	EmbeddedFiles Files        `json:"files,omitempty"`
	Directory     string       `json:"directory,omitempty"`
	Paths         StringSet    `json:"paths,omitempty"`
	Requirements  Requirements `json:"requirements,omitempty"`

	// NOTE(sr): additional properties need to be allowed here because we support things like
	//
	// sources:
	//   builtin-entz:
	//     styra.entitlements.v1: entitlements-v1/completions/completions/completions.rego
}

func (s *Source) Requirement() Requirement {
	return Requirement{Source: &s.Name}
}

func (s *Source) SetEmbeddedFile(path string, content string) {
	if s.EmbeddedFiles == nil {
		s.EmbeddedFiles = make(Files)
	}
	s.EmbeddedFiles[path] = content
}

func (s *Source) SetEmbeddedFiles(files map[string]string) {
	s.EmbeddedFiles = nil
	for path, content := range files {
		s.SetEmbeddedFile(path, content)
	}
}

func (s *Source) SetPath(path string) {
	if slices.Contains(s.Paths, path) {
		return
	}

	s.Paths = append(s.Paths, path)
}

func (s *Source) SetDirectory(directory string) {
	s.Directory = directory
}

// Files returns the merged set of embedded files and filesystem files for a source.
func (s *Source) Files() (map[string]string, error) {
	m := make(map[string]string, len(s.EmbeddedFiles))
	maps.Copy(m, s.EmbeddedFiles)

	if len(s.Paths) == 0 {
		return m, nil
	}

	baseDir := cmp.Or(s.Directory, ".") // CWD if unset
	baseFS := os.DirFS(baseDir)
	filteredFS, err := internalfs.NewFilterFS(baseFS, s.Paths, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create filtered filesystem for source %q: %w", s.Name, err)
	}

	if err := fs.WalkDir(filteredFS, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if d.IsDir() {
			return nil
		}

		data, err := fs.ReadFile(filteredFS, path)
		if err != nil {
			return fmt.Errorf("failed to read file %q: %w", path, err)
		}

		m[path] = string(data)
		return nil
	}); err != nil {
		return nil, fmt.Errorf("failed to walk source %q: %w", s.Name, err)
	}

	if len(m) == len(s.EmbeddedFiles) {
		return nil, fmt.Errorf("no files matched patterns for source %q", s.Name)
	}

	return m, nil
}

// Sources is a slice of Source pointers.
type Sources []*Source

// ObjectStorage defines where bundles are stored.
type ObjectStorage struct {
	AmazonS3          *AmazonS3          `json:"aws,omitempty"`
	GCPCloudStorage   *GCPCloudStorage   `json:"gcp,omitempty"`
	AzureBlobStorage  *AzureBlobStorage  `json:"azure,omitempty"`
	FileSystemStorage *FileSystemStorage `json:"filesystem,omitempty"`
	HTTPServer        *HTTPServer        `json:"http_server,omitempty"`
}

func (o *ObjectStorage) validate() error {
	if err := o.AmazonS3.validate(); err != nil {
		return err
	}
	if err := o.GCPCloudStorage.validate(); err != nil {
		return err
	}
	if err := o.AzureBlobStorage.validate(); err != nil {
		return err
	}
	if err := o.FileSystemStorage.validate(); err != nil {
		return err
	}
	return o.HTTPServer.validate()
}

// AmazonS3 defines the configuration for an Amazon S3-compatible object storage.
type AmazonS3 struct {
	Bucket      string     `json:"bucket"`
	Key         string     `json:"key"`
	Region      string     `json:"region,omitempty"`
	Credentials *SecretRef `json:"credentials,omitempty"`
	URL         string     `json:"url,omitempty"` // for test purposes
}

func (a *AmazonS3) validate() error {
	if a == nil {
		return nil
	}

	if a.Bucket == "" {
		return errors.New("amazon s3 bucket is required")
	}

	if a.Key == "" {
		return errors.New("amazon s3 key is required")
	}

	if a.Region == "" {
		return errors.New("amazon s3 region is required")
	}

	return nil
}

// GCPCloudStorage defines the configuration for a Google Cloud Storage bucket.
type GCPCloudStorage struct {
	Project     string     `json:"project"`
	Bucket      string     `json:"bucket"`
	Object      string     `json:"object"`
	Credentials *SecretRef `json:"credentials,omitempty"`
}

func (g *GCPCloudStorage) validate() error {
	if g == nil {
		return nil
	}

	if g.Project == "" {
		return errors.New("gcp cloud storage project is required")
	}

	if g.Bucket == "" {
		return errors.New("gcp cloud storage bucket is required")
	}

	if g.Object == "" {
		return errors.New("gcp cloud storage object is required")
	}

	return nil
}

// AzureBlobStorage defines the configuration for an Azure Blob Storage container.
type AzureBlobStorage struct {
	AccountURL  string     `json:"account_url"`
	Container   string     `json:"container"`
	Path        string     `json:"path"`
	Credentials *SecretRef `json:"credentials,omitempty"`
}

func (a *AzureBlobStorage) validate() error {
	if a == nil {
		return nil
	}

	if a.AccountURL == "" {
		return errors.New("azure blob storage account URL is required")
	}

	if a.Container == "" {
		return errors.New("azure blob storage container is required")
	}

	if a.Path == "" {
		return errors.New("azure blob storage path is required")
	}

	return nil
}

// FileSystemStorage defines the configuration for a local filesystem storage.
type FileSystemStorage struct {
	Path string `json:"path"`
}

func (f *FileSystemStorage) validate() error {
	if f == nil {
		return nil
	}

	if f.Path == "" {
		return errors.New("filesystem storage path is required")
	}

	return nil
}

// HTTPServer defines the configuration for serving bundles directly from OCP's HTTP server.
// When configured, the bundle is held in memory and served at the specified path.
type HTTPServer struct {
	Path string `json:"path"`
}

func (h *HTTPServer) validate() error {
	if h == nil {
		return nil
	}

	if h.Path == "" {
		return errors.New("http server path is required")
	}

	return nil
}

// Git defines the Git synchronization configuration used by OPA Control Plane Sources.
type Git struct {
	Repo          string     `json:"repo"`
	Reference     *string    `json:"reference,omitempty"`
	Commit        *string    `json:"commit,omitempty"`
	Path          *string    `json:"path,omitempty"`
	IncludedFiles StringSet  `json:"included_files,omitempty"`
	ExcludedFiles StringSet  `json:"excluded_files,omitempty"`
	Credentials   *SecretRef `json:"credentials,omitempty"`

	_ struct{} `additionalProperties:"false"`
}

// Datasource defines a data source configuration for an OPA Control Plane Source.
type Datasource struct {
	Name           string         `json:"name"`
	Path           string         `json:"path"`
	Type           string         `json:"type"`
	TransformQuery string         `json:"transform_query,omitempty"`
	Config         map[string]any `json:"config,omitempty"`
	Credentials    *SecretRef     `json:"credentials,omitempty"`

	_ struct{} `additionalProperties:"false"`
}

// Datasources is a slice of Datasource.
type Datasources []Datasource

// SecretRef is a reference to a named secret. External consumers see only
// the secret name; secret resolution is handled internally.
type SecretRef struct {
	Name    string                             `json:"-"`
	resolve func(context.Context) (any, error) // Set internally during config unmarshal.
}

// Resolve retrieves the secret value from the secret store. If no resolver
// was configured (e.g. the config was not loaded through the internal
// unmarshal pipeline), an error is returned.
func (s *SecretRef) Resolve(ctx context.Context) (any, error) {
	if s.resolve == nil {
		return nil, fmt.Errorf("secret %q not found", s.Name)
	}

	return s.resolve(ctx)
}

// SetResolver sets the resolve function for this secret reference. This is
// called by the internal config unmarshal pipeline to wire up secret resolution.
func (s *SecretRef) SetResolver(fn func(context.Context) (any, error)) {
	s.resolve = fn
}

func (s *SecretRef) MarshalYAML() (any, error) {
	if s.Name == "" {
		return nil, nil
	}
	return s.Name, nil
}

func (s *SecretRef) MarshalJSON() ([]byte, error) {
	v, err := s.MarshalYAML()
	if err != nil {
		return nil, err
	}

	return json.Marshal(v)
}

func (s *SecretRef) UnmarshalYAML(bs []byte) error {
	if err := yaml.Unmarshal(bs, &s.Name); err != nil {
		return fmt.Errorf("expected scalar node: %w", err)
	}
	return nil
}

func (s *SecretRef) UnmarshalJSON(bs []byte) error {
	if err := json.Unmarshal(bs, &s.Name); err != nil {
		return fmt.Errorf("failed to unmarshal SecretRef: %w", err)
	}

	return nil
}

// PrepareJSONSchema implements the jsonschema-go Preparer interface.
func (Duration) PrepareJSONSchema(schema *schemareflector.Schema) error {
	schema.Type = nil
	schema.AddType(schemareflector.String)
	return nil
}

// PrepareJSONSchema implements the jsonschema-go Preparer interface.
func (*SecretRef) PrepareJSONSchema(schema *schemareflector.Schema) error {
	schema.Type = nil
	schema.AddType(schemareflector.String)
	return nil
}

// PrepareJSONSchema implements the jsonschema-go Preparer interface.
// This allows a null YAML source like:
//
//	sources:
//	  empty-source:
func (*Source) PrepareJSONSchema(schema *schemareflector.Schema) error {
	schema.AddType(schemareflector.Null)
	return nil
}

// Equal methods for config types.

func (s *Bundle) Equal(other *Bundle) bool {
	return internalutil.FastEqual(s, other, func(s, other *Bundle) bool {
		return s.Name == other.Name &&
			maps.Equal(s.Labels, other.Labels) &&
			s.Revision == other.Revision &&
			s.ObjectStorage.Equal(&other.ObjectStorage) &&
			s.Requirements.Equal(other.Requirements) &&
			s.ExcludedFiles.Equal(other.ExcludedFiles) &&
			s.Interval == other.Interval
	})
}

func (s *Source) Equal(other *Source) bool {
	return internalutil.FastEqual(s, other, func(s, other *Source) bool {
		return s.Name == other.Name &&
			internalutil.PtrEqual(s.Builtin, other.Builtin) &&
			s.Git.Equal(&other.Git) &&
			s.Datasources.Equal(other.Datasources) &&
			s.EmbeddedFiles.Equal(other.EmbeddedFiles) &&
			s.Directory == other.Directory &&
			s.Paths.Equal(other.Paths) &&
			s.Requirements.Equal(other.Requirements)
	})
}

func (a Sources) Equal(b Sources) bool {
	return internalutil.SetEqual(a, b, func(s *Source) string { return s.Name }, (*Source).Equal)
}

func (a Requirements) Equal(b Requirements) bool {
	if len(a) != len(b) {
		return false
	}
	if len(a) > 1 {
		a = slices.Clone(a)
		slices.SortFunc(a, Requirement.Compare)
	}
	if len(b) > 1 {
		b = slices.Clone(b)
		slices.SortFunc(b, Requirement.Compare)
	}
	return slices.EqualFunc(a, b, Requirement.Equal)
}

func (a Files) Equal(b Files) bool {
	return maps.Equal(a, b)
}

func (a StringSet) Equal(b StringSet) bool {
	return internalutil.SetEqual(a, b, func(s string) string { return s }, func(a, b string) bool { return a == b })
}

func (g *Git) Equal(other *Git) bool {
	return internalutil.FastEqual(g, other, func(g, other *Git) bool {
		return internalutil.PtrEqual(g.Reference, other.Reference) &&
			internalutil.PtrEqual(g.Commit, other.Commit) &&
			internalutil.PtrEqual(g.Path, other.Path) &&
			g.Credentials.Equal(other.Credentials) &&
			g.IncludedFiles.Equal(other.IncludedFiles) &&
			g.ExcludedFiles.Equal(other.ExcludedFiles)
	})
}

func (s *SecretRef) Equal(other *SecretRef) bool {
	return internalutil.FastEqual(s, other, func(s, other *SecretRef) bool {
		return s.Name == other.Name
	})
}

func (o *ObjectStorage) Equal(other *ObjectStorage) bool {
	return internalutil.FastEqual(o, other, func(o, other *ObjectStorage) bool {
		return o.AmazonS3.Equal(other.AmazonS3) &&
			o.GCPCloudStorage.Equal(other.GCPCloudStorage) &&
			o.AzureBlobStorage.Equal(other.AzureBlobStorage) &&
			o.FileSystemStorage.Equal(other.FileSystemStorage)
	})
}

func (a *AmazonS3) Equal(other *AmazonS3) bool {
	return internalutil.FastEqual(a, other, func(a, other *AmazonS3) bool {
		return a.Bucket == other.Bucket &&
			a.Key == other.Key &&
			a.Region == other.Region &&
			a.Credentials.Equal(other.Credentials) &&
			a.URL == other.URL
	})
}

func (g *GCPCloudStorage) Equal(other *GCPCloudStorage) bool {
	return internalutil.FastEqual(g, other, func(g, other *GCPCloudStorage) bool {
		return g.Project == other.Project &&
			g.Bucket == other.Bucket &&
			g.Object == other.Object
	})
}

func (a *AzureBlobStorage) Equal(other *AzureBlobStorage) bool {
	return internalutil.FastEqual(a, other, func(a, other *AzureBlobStorage) bool {
		return a.AccountURL == other.AccountURL &&
			a.Container == other.Container &&
			a.Path == other.Path
	})
}

func (f *FileSystemStorage) Equal(other *FileSystemStorage) bool {
	return internalutil.FastEqual(f, other, func(f, other *FileSystemStorage) bool {
		return f.Path == other.Path
	})
}

func (d *Datasource) Equal(other *Datasource) bool {
	return internalutil.FastEqual(d, other, func(d, other *Datasource) bool {
		return d.Name == other.Name &&
			d.Path == other.Path &&
			d.Type == other.Type &&
			d.TransformQuery == other.TransformQuery &&
			reflect.DeepEqual(d.Config, other.Config) &&
			d.Credentials.Equal(other.Credentials)
	})
}

func (a Datasources) Equal(b Datasources) bool {
	return internalutil.SetEqual(a, b, func(ds Datasource) string { return ds.Name }, func(a, b Datasource) bool { return a.Equal(&b) })
}
