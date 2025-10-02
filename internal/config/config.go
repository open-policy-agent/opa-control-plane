package config

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"iter"
	"maps"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"sort"

	"github.com/gobwas/glob"
	"github.com/pkg/errors"
	"github.com/swaggest/jsonschema-go"
	"gopkg.in/yaml.v3"
)

// Internal configuration data structures for OPA Control Plane.

// Metadata contains metadata about the configuration file itself. This
// information is not stored in the database and is only used by the migration
// tooling.
type Metadata struct {
	ExportedFrom string `json:"exported_from" yaml:"exported_from"`
	ExportedAt   string `json:"exported_at" yaml:"exported_at"`
}

// Root is the top-level configuration structure used by OPA Control Plane.
type Root struct {
	Metadata Metadata           `json:"metadata" yaml:"metadata"`
	Bundles  map[string]*Bundle `json:"bundles,omitempty" yaml:"bundles,omitempty"`
	Stacks   map[string]*Stack  `json:"stacks,omitempty" yaml:"stacks,omitempty"`
	Sources  map[string]*Source `json:"sources,omitempty" yaml:"sources,omitempty"`
	Secrets  map[string]*Secret `json:"secrets,omitempty" yaml:"secrets,omitempty"` // Schema validation overrides Secret to object type.
	Tokens   map[string]*Token  `json:"tokens,omitempty" yaml:"tokens,omitempty"`
	Database *Database          `json:"database,omitempty" yaml:"database,omitempty"`
}

// SetSQLitePersistentByDefault sets the database configuration to use a SQLite
// database stored in the given persistence directory if no other database configuration
// exists. This is used for the 'run' command to change its default behavior from other
// commands.
func (r *Root) SetSQLitePersistentByDefault(persistenceDir string) bool {
	if r.Database == nil {
		r.Database = &Database{}
	} else if r.Database.AWSRDS != nil {
		return false
	}

	if r.Database.SQL == nil && r.Database.AWSRDS == nil {
		r.Database.SQL = &SQLDatabase{}
	}

	switch r.Database.SQL.Driver {
	case "", "sqlite3", "sqlite":
		if r.Database.SQL.DSN == "" {
			r.Database.SQL.Driver = "sqlite3"
			r.Database.SQL.DSN = filepath.Join(persistenceDir, "sqlite.db")
		}
		return true
	}
	return false
}

// UnmarshalYAML implements the yaml.Marshaler interface for the Root struct. This
// lets us define OPA Control Plane resources in a more user-friendly way with mappings
// where keys are the resource names. It is also used to inject the secret store
// into each secret reference so that internal callers can resolve secret values
// as needed.
func (r *Root) UnmarshalYAML(node *yaml.Node) error {
	type rawRoot Root // avoid recursive calls to UnmarshalYAML by type aliasing
	var raw rawRoot

	if err := node.Decode(&raw); err != nil {
		return fmt.Errorf("failed to decode Root: %w", err)
	}

	*r = Root(raw) // Assign the unmarshaled data back to the original struct
	return r.unmarshal(r)
}

func (r *Root) UnmarshalJSON(bs []byte) error {
	type rawRoot Root // avoid recursive calls to UnmarshalYAML by type aliasing
	var raw rawRoot

	if err := json.Unmarshal(bs, &raw); err != nil {
		return fmt.Errorf("failed to decode Root: %w", err)
	}

	*r = Root(raw) // Assign the unmarshaled data back to the original struct
	return r.unmarshal(r)
}

func (r *Root) Unmarshal() error {
	return r.unmarshal(r)
}

func (*Root) unmarshal(raw *Root) error {
	for name, token := range raw.Tokens {
		token.Name = name
	}

	for name, secret := range raw.Secrets {
		secret.Name = name
	}

	for name, bundle := range raw.Bundles {
		bundle.Name = name
		if bundle.ObjectStorage.AmazonS3 != nil && bundle.ObjectStorage.AmazonS3.Credentials != nil {
			bundle.ObjectStorage.AmazonS3.Credentials.value = raw.Secrets[bundle.ObjectStorage.AmazonS3.Credentials.Name]
		}
		if bundle.ObjectStorage.AzureBlobStorage != nil && bundle.ObjectStorage.AzureBlobStorage.Credentials != nil {
			bundle.ObjectStorage.AzureBlobStorage.Credentials.value = raw.Secrets[bundle.ObjectStorage.AzureBlobStorage.Credentials.Name]
		}
		if bundle.ObjectStorage.GCPCloudStorage != nil && bundle.ObjectStorage.GCPCloudStorage.Credentials != nil {
			bundle.ObjectStorage.GCPCloudStorage.Credentials.value = raw.Secrets[bundle.ObjectStorage.GCPCloudStorage.Credentials.Name]
		}
	}

	for name, src := range raw.Sources {
		src.Name = name
		if src.Git.Credentials != nil {
			src.Git.Credentials.value = raw.Secrets[src.Git.Credentials.Name]
		}
	}

	for name, stack := range raw.Stacks {
		stack.Name = name
	}

	if raw.Database != nil && raw.Database.AWSRDS != nil && raw.Database.AWSRDS.Credentials != nil {
		raw.Database.AWSRDS.Credentials.value = raw.Secrets[raw.Database.AWSRDS.Credentials.Name]
	}

	return nil
}

func (r *Root) SortedBundles() iter.Seq2[int, *Bundle] {
	return iterator(r.Bundles, func(b *Bundle) string { return b.Name })
}

func (r *Root) SortedSecrets() iter.Seq2[int, *Secret] {
	return iterator(r.Secrets, func(s *Secret) string { return s.Name })
}

func (r *Root) SortedSources() iter.Seq2[int, *Source] {
	return iterator(r.Sources, func(s *Source) string { return s.Name })
}

// Returns sources from the configuration ordered by requirements. Cycles are
// treated as errors. Missing requirements are ignored.
func (r *Root) TopologicalSortedSources() ([]*Source, error) {
	sorter := topologicalSortSources{
		sources:    r.Sources,
		inprogress: make(map[string]struct{}),
		done:       make(map[string]struct{}),
	}

	for _, name := range slices.Sorted(maps.Keys(r.Sources)) {
		src := r.Sources[name]
		if err := sorter.Visit(src); err != nil {
			return nil, err
		}
	}
	return sorter.sorted, nil
}

type topologicalSortSources struct {
	sources    map[string]*Source
	inprogress map[string]struct{}
	done       map[string]struct{}
	sorted     []*Source
}

func (s *topologicalSortSources) Visit(src *Source) error {
	if _, ok := s.inprogress[src.Name]; ok {
		return fmt.Errorf("cycle found on source %q", src.Name)
	}
	if _, ok := s.done[src.Name]; ok {
		return nil
	}
	s.inprogress[src.Name] = struct{}{}
	for _, r := range src.Requirements {
		if r.Source != nil {
			if other, ok := s.sources[*r.Source]; ok {
				if err := s.Visit(other); err != nil {
					return err
				}
			}
		}
	}
	s.done[src.Name] = struct{}{}
	delete(s.inprogress, src.Name)
	s.sorted = append(s.sorted, src)
	return nil
}

func (r *Root) SortedStacks() iter.Seq2[int, *Stack] {
	return iterator(r.Stacks, func(s *Stack) string { return s.Name })
}

func iterator[V any](m map[string]V, name func(v V) string) func(yield func(int, V) bool) {
	names := make([]string, 0, len(m))
	for _, v := range m {
		names = append(names, name(v))
	}

	sort.Strings(names)

	return func(yield func(int, V) bool) {
		for i, name := range names {
			if !yield(i, m[name]) {
				return
			}
		}
	}
}

func (r *Root) Validate() error {
	data, err := json.Marshal(r)
	if err != nil {
		return err
	}

	var config interface{}
	if err := json.Unmarshal(data, &config); err != nil {
		return err
	}

	return rootSchema.Validate(config)
}

// Bundle defines the configuration for a OPA Control Plane Bundle.
type Bundle struct {
	Name          string        `json:"name" yaml:"-"`
	Labels        Labels        `json:"labels,omitempty" yaml:"labels,omitempty"`
	ObjectStorage ObjectStorage `json:"object_storage,omitempty" yaml:"object_storage,omitempty"`
	Requirements  Requirements  `json:"requirements,omitempty" yaml:"requirements,omitempty"`
	ExcludedFiles StringSet     `json:"excluded_files,omitempty" yaml:"excluded_files,omitempty"`
}

type Labels map[string]string

type Requirement struct {
	Source *string        `json:"source,omitempty" yaml:"source,omitempty"`
	Git    GitRequirement `json:"git,omitempty" yaml:"git,omitempty"`
}

type GitRequirement struct {
	Commit *string `json:"commit,omitempty" yaml:"commit,omitempty"`
}

func (a Requirement) Equal(b Requirement) bool {
	return stringPtrEqual(a.Source, b.Source) && stringPtrEqual(a.Git.Commit, b.Git.Commit)
}

type Requirements []Requirement

func (a Requirements) Equal(b Requirements) bool {
	// Ordering of requirements does not matter, so we sort them before comparing.

	if len(a) != len(b) {
		return false
	}

	aCpy := slices.Clone(a)
	bCpy := slices.Clone(b)

	cmp := func(a, b Requirement) int {
		if x := stringPtrCompare(a.Source, b.Source); x != 0 {
			return x
		} else if x := stringPtrCompare(a.Git.Commit, b.Git.Commit); x != 0 {
			return x
		}

		return 0
	}

	slices.SortFunc(aCpy, cmp)
	slices.SortFunc(bCpy, cmp)

	return slices.EqualFunc(aCpy, bCpy, func(a, b Requirement) bool { return a.Equal(b) })
}

type Files map[string]string

func (f Files) Equal(other Files) bool {
	return maps.Equal(f, other)
}

func (f Files) MarshalYAML() (interface{}, error) {
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

func (f *Files) UnmarshalYAML(node *yaml.Node) error {
	var m map[string]string
	if err := node.Decode(&m); err != nil {
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

// MarshalYAML implements the yaml.Marshaler interface for the Bundle struct. This

func (s *Bundle) UnmarshalJSON(bs []byte) error {
	type rawBundle Bundle // avoid recursive calls to UnmarshalJSON by type aliasing
	var raw rawBundle

	if err := json.Unmarshal(bs, &raw); err != nil {
		return fmt.Errorf("failed to decode bundle: %w", err)
	}

	*s = Bundle(raw)
	return s.validate()
}

func (s *Bundle) UnmarshalYAML(node *yaml.Node) error {
	type rawBundle Bundle // avoid recursive calls to UnmarshalJSON by type aliasing
	var raw rawBundle

	if err := node.Decode(&raw); err != nil {
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

func (s *Bundle) Equal(other *Bundle) bool {
	return fastEqual(s, other, func() bool {
		return s.Name == other.Name &&
			maps.Equal(s.Labels, other.Labels) &&
			s.ObjectStorage.Equal(&other.ObjectStorage) &&
			s.Requirements.Equal(other.Requirements) &&
			s.ExcludedFiles.Equal(other.ExcludedFiles)
	})
}

// Source defines the configuration for a OPA Control Plane Source.
type Source struct {
	Name          string       `json:"name" yaml:"-"`
	Builtin       *string      `json:"builtin,omitempty" yaml:"builtin,omitempty"`
	Git           Git          `json:"git,omitempty" yaml:"git,omitempty"`
	Datasources   Datasources  `json:"datasources,omitempty" yaml:"datasources,omitempty"`
	EmbeddedFiles Files        `json:"files,omitempty" yaml:"files,omitempty"`
	Directory     string       `json:"directory,omitempty" yaml:"directory,omitempty"` // Root directory for the source files, used to resolve file paths below.
	Paths         StringSet    `json:"paths,omitempty" yaml:"paths,omitempty"`
	Requirements  Requirements `json:"requirements,omitempty" yaml:"requirements,omitempty"`
}

func (s *Source) Equal(other *Source) bool {
	return fastEqual(s, other, func() bool {
		return s.Name == other.Name &&
			stringPtrEqual(s.Builtin, other.Builtin) &&
			s.Git.Equal(&other.Git) &&
			s.Datasources.Equal(other.Datasources) &&
			s.EmbeddedFiles.Equal(other.EmbeddedFiles) &&
			s.Requirements.Equal(other.Requirements)
	})
}

func (s *Source) Requirement() Requirement {
	return Requirement{Source: &s.Name}
}

func (s *Source) Files() (map[string]string, error) {
	m := make(map[string]string, len(s.EmbeddedFiles))
	maps.Copy(m, s.EmbeddedFiles)

	for _, path := range s.Paths {
		data, err := os.ReadFile(filepath.Join(s.Directory, path))
		if err != nil {
			return nil, fmt.Errorf("failed to read file %q for source %q: %w", path, s.Name, err)
		}

		m[path] = string(data)
	}

	return m, nil
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

type Sources []*Source

func (a Sources) Equal(b Sources) bool {
	return setEqual(a, b, func(s *Source) string { return s.Name }, func(a, b *Source) bool { return a.Equal(b) })
}

// Stack defines the configuration for a OPA Control Plane Stack.
type Stack struct {
	Name            string       `json:"name" yaml:"-"`
	Selector        Selector     `json:"selector" yaml:"selector"` // Schema validation overrides Selector to object of string array values.
	ExcludeSelector *Selector    `json:"exclude_selector,omitempty" yaml:"exclude_selector,omitempty"`
	Requirements    Requirements `json:"requirements,omitempty" yaml:"requirements,omitempty"`
}

func (a *Stack) Equal(other *Stack) bool {
	return fastEqual(a, other, func() bool {
		return a.Name == other.Name && a.Selector.Equal(other.Selector) && a.ExcludeSelector.PtrEqual(other.ExcludeSelector) && a.Requirements.Equal(other.Requirements)
	})
}

type Stacks []*Stack

func (a Stacks) Equal(b Stacks) bool {
	return setEqual(a, b, func(s *Stack) string { return s.Name }, func(a, b *Stack) bool { return a.Equal(b) })
}

type Selector struct {
	s map[string]StringSet
	m map[string][]glob.Glob // Pre-compiled glob patterns for faster matching
}

func MustNewSelector(s map[string]StringSet) Selector {
	ss := Selector{s: make(map[string]StringSet), m: make(map[string][]glob.Glob)}
	for key, value := range s {
		if err := ss.Set(key, value); err != nil {
			panic(err)
		}
	}

	return ss
}

func (*Selector) PrepareJSONSchema(schema *jsonschema.Schema) error {
	str := jsonschema.String.ToSchemaOrBool()

	arr := jsonschema.Array.ToSchemaOrBool()
	arr.TypeObject.ItemsEns().SchemaOrBool = &str

	schema.Type = nil
	schema.AddType(jsonschema.Object)
	schema.AdditionalProperties = &arr

	return nil
}

// Matches checks if the given labels match the selector. Empty selector value matches any label value
func (s *Selector) Matches(labels Labels) bool {
	for expLabel, expValues := range s.m {
		v, ok := labels[expLabel]
		if !ok || (len(expValues) > 0 && !slices.ContainsFunc(expValues, func(ev glob.Glob) bool { return ev.Match(v) })) {
			return false
		}
	}
	return true
}

func (s Selector) Equal(other Selector) bool {
	return maps.EqualFunc(s.s, other.s, func(a, b StringSet) bool { return a.Equal(b) })
}

func (s *Selector) PtrMatches(labels Labels) bool {
	if s == nil {
		return false
	}
	return s.Matches(labels)
}

func (s *Selector) PtrEqual(other *Selector) bool {
	if s == other {
		return true
	} else if s == nil && other != nil {
		return false
	} else if s != nil && other == nil {
		return false
	}
	return s.Equal(*other)
}

func (s Selector) MarshalYAML() (interface{}, error) {
	return maps.Clone(s.s), nil
}

func (s Selector) MarshalJSON() ([]byte, error) {
	x, err := s.MarshalYAML()
	if err != nil {
		return nil, err
	}
	return json.Marshal(x)
}

func (s *Selector) UnmarshalYAML(node *yaml.Node) error {
	raw := make(map[string][]string)
	if err := node.Decode(&raw); err != nil {
		return err
	}

	return s.unmarshal(raw)
}

func (s *Selector) UnmarshalJSON(bs []byte) error {
	raw := make(map[string][]string)
	if err := json.Unmarshal(bs, &raw); err != nil {
		return err
	}

	return s.unmarshal(raw)
}

func (s *Selector) unmarshal(raw map[string][]string) error {
	*s = Selector{s: make(map[string]StringSet), m: make(map[string][]glob.Glob)}
	for key, encodedValue := range raw {
		if err := s.Set(key, encodedValue); err != nil {
			return err
		}
	}
	return nil
}

func (s *Selector) Get(key string) ([]string, bool) {
	s.init()
	v, ok := s.s[key]
	return v, ok
}

func (s *Selector) Keys() []string {
	s.init()
	return slices.Collect(maps.Keys(s.s))
}

func (s *Selector) Set(key string, value []string) error {
	s.init()

	if len(value) > 0 {
		for _, v := range value {
			g, err := glob.Compile(v)
			if err != nil {
				return fmt.Errorf("failed to decode value for key %q: %w", key, err)
			}
			s.m[key] = append(s.m[key], g)
		}
	} else {
		s.m[key] = []glob.Glob{}
	}

	s.s[key] = value
	return nil
}

func (s *Selector) Len() int {
	return len(s.s)
}

func (s *Selector) init() {
	if s.s == nil {
		s.s = make(map[string]StringSet)
		s.m = make(map[string][]glob.Glob)
	}
}

type StringSet []string

func (a StringSet) Equal(b StringSet) bool {
	return setEqual(a, b, func(s string) string { return s }, func(a, b string) bool { return a == b })
}

func (a StringSet) Add(value string) StringSet {
	i := sort.Search(len(a), func(i int) bool { return a[i] >= value })
	if i < len(a) && a[i] == value {
		return a
	}

	return slices.Insert(a, i, value)
}

// Git defines the Git synchronization configuration used by OPA Control Plane Sources.
type Git struct {
	Repo          string     `json:"repo" yaml:"repo"`
	Reference     *string    `json:"reference,omitempty" yaml:"reference,omitempty"`
	Commit        *string    `json:"commit,omitempty" yaml:"commit,omitempty"`
	Path          *string    `json:"path,omitempty" yaml:"path,omitempty"`
	IncludedFiles StringSet  `json:"included_files,omitempty" yaml:"included_files,omitempty"`
	ExcludedFiles StringSet  `json:"excluded_files,omitempty" yaml:"excluded_files,omitempty"`
	Credentials   *SecretRef `json:"credentials,omitempty" yaml:"credentials,omitempty"` // If nil, use the default SSH authentication mechanisms available
	// or no authentication for public repos. Note, JSON schema validation overrides this to string type.
}

func (g *Git) Equal(other *Git) bool {
	return fastEqual(g, other, func() bool {
		return stringPtrEqual(g.Reference, other.Reference) &&
			stringPtrEqual(g.Commit, other.Commit) &&
			stringPtrEqual(g.Path, other.Path) &&
			g.Credentials.Equal(other.Credentials) &&
			g.IncludedFiles.Equal(other.IncludedFiles) &&
			g.ExcludedFiles.Equal(other.ExcludedFiles)
	})
}

type SecretRef struct {
	Name  string `json:"-" yaml:"-"`
	value *Secret
}

func (*SecretRef) PrepareJSONSchema(schema *jsonschema.Schema) error {
	schema.Type = nil
	schema.AddType(jsonschema.String)
	return nil
}

// Resolve retrieves the secret value from the secret store. If the secret is not found, an error is returned.
// If the secret is found, it returns the value as an interface{} which can be further typed as needed.
func (s *SecretRef) Resolve(ctx context.Context) (interface{}, error) {
	if s.value == nil {
		return nil, fmt.Errorf("secret %q not found", s.Name)
	}

	return s.value.Typed(ctx)
}

func (s *SecretRef) MarshalYAML() (interface{}, error) {
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

func (s *SecretRef) UnmarshalYAML(n *yaml.Node) error {
	if n.Kind == yaml.ScalarNode {
		return n.Decode(&s.Name)
	}
	return fmt.Errorf("expected scalar node, got %v", n.Kind)
}

func (s *SecretRef) UnmarshalJSON(bs []byte) error {
	if err := json.Unmarshal(bs, &s.Name); err != nil {
		return fmt.Errorf("failed to unmarshal SecretRef: %w", err)
	}

	return nil
}

func (s *SecretRef) Equal(other *SecretRef) bool {
	return fastEqual(s, other, func() bool {
		return s.Name == other.Name && s.value.Equal(other.value)
	})
}

// Token represents an API token to access the OPA Control Plane APIs.
type Token struct {
	Name   string  `json:"-" yaml:"-"`
	APIKey string  `json:"api_key" yaml:"api_key"`
	Scopes []Scope `json:"scopes" yaml:"scopes"`
}

func (t *Token) Equal(other *Token) bool {
	return fastEqual(t, other, func() bool {
		return t.Name == other.Name && t.APIKey == other.APIKey && scopesEqual(t.Scopes, other.Scopes)
	})
}

type Scope struct {
	Role string `json:"role" yaml:"role" enum:"administrator,viewer,owner,stack_owner"`
}

func scopesEqual(a, b []Scope) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		var found bool
		for j := range b {
			if a[i].Equal(b[j]) {
				found = true
			}
		}
		if !found {
			return false
		}
	}
	return true
}

func (s Scope) Equal(other Scope) bool {
	return s.Role == other.Role
}

func ParseFile(filename string) (root *Root, err error) {
	bs, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file %s: %w", filename, err)
	}

	return Parse(bytes.NewReader(bs))
}

func Parse(r io.Reader) (root *Root, err error) {
	bs, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}

	if err := yaml.Unmarshal(bs, &root); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %w", err)
	}

	if err := root.Validate(); err != nil {
		return nil, err
	}

	return root, nil
}

type ObjectStorage struct {
	AmazonS3          *AmazonS3          `json:"aws,omitempty" yaml:"aws,omitempty"`
	GCPCloudStorage   *GCPCloudStorage   `json:"gcp,omitempty" yaml:"gcp,omitempty"`
	AzureBlobStorage  *AzureBlobStorage  `json:"azure,omitempty" yaml:"azure,omitempty"`
	FileSystemStorage *FileSystemStorage `json:"filesystem,omitempty" yaml:"filesystem,omitempty"`
}

func (o *ObjectStorage) Equal(other *ObjectStorage) bool {
	return fastEqual(o, other, func() bool {
		return o.AmazonS3.Equal(other.AmazonS3) && o.GCPCloudStorage.Equal(other.GCPCloudStorage) && o.AzureBlobStorage.Equal(other.AzureBlobStorage) && o.FileSystemStorage.Equal(other.FileSystemStorage)
	})
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
	return o.FileSystemStorage.validate()
}

// AmazonS3 defines the configuration for an Amazon S3-compatible object storage.
type AmazonS3 struct {
	Bucket      string     `json:"bucket" yaml:"bucket"`
	Key         string     `json:"key" yaml:"key"`
	Region      string     `json:"region,omitempty" yaml:"region,omitempty"`
	Credentials *SecretRef `json:"credentials,omitempty" yaml:"credentials,omitempty"` // If nil, use default credentials chain: environment variables,
	// shared credentials file, ECS or EC2 instance role. More details in s3.go.
	URL string `json:"url,omitempty" yaml:"url,omitempty"` // for test purposes
}

// GCPCloudStorage defines the configuration for a Google Cloud Storage bucket.
type GCPCloudStorage struct {
	Project     string     `json:"project" yaml:"project"`
	Bucket      string     `json:"bucket" yaml:"bucket"`
	Object      string     `json:"object" yaml:"object"`
	Credentials *SecretRef `json:"credentials,omitempty" yaml:"credentials,omitempty"` // If nil, use default credentials chain: environment variables,
	// file created by gcloud auth application-default login, GCE/GKE metadata server. More details in s3.go.
}

// AzureBlobStorage defines the configuration for an Azure Blob Storage container.
type AzureBlobStorage struct {
	AccountURL  string     `json:"account_url" yaml:"account_url"`
	Container   string     `json:"container" yaml:"container"`
	Path        string     `json:"path" yaml:"path"`
	Credentials *SecretRef `json:"credentials,omitempty" yaml:"credentials,omitempty"` // If nil, use default credentials chain: environment variables,
	// managed identity, Azure CLI login. More details in s3.go.
}

// FileSystemStorage defines the configuration for a local filesystem storage.
type FileSystemStorage struct {
	Path string `json:"path" yaml:"path"` // Path to the bundle on the local filesystem.
}

func (a *AmazonS3) Equal(other *AmazonS3) bool {
	return fastEqual(a, other, func() bool {
		return a.Bucket == other.Bucket && a.Key == other.Key && a.Region == other.Region && a.Credentials.Equal(other.Credentials) && a.URL == other.URL
	})
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

func (g *GCPCloudStorage) Equal(other *GCPCloudStorage) bool {
	return fastEqual(g, other, func() bool {
		return g.Project == other.Project && g.Bucket == other.Bucket && g.Object == other.Object
	})
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

func (a *AzureBlobStorage) Equal(other *AzureBlobStorage) bool {
	return fastEqual(a, other, func() bool {
		return a.AccountURL == other.AccountURL && a.Container == other.Container && a.Path == other.Path
	})
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

func (f *FileSystemStorage) Equal(other *FileSystemStorage) bool {
	return fastEqual(f, other, func() bool {
		return f.Path == other.Path
	})
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

type Datasource struct {
	Name           string                 `json:"name" yaml:"name"`
	Path           string                 `json:"path" yaml:"path"`
	Type           string                 `json:"type" yaml:"type"`
	TransformQuery string                 `json:"transform_query,omitempty" yaml:"transform_query,omitempty"`
	Config         map[string]interface{} `json:"config,omitempty" yaml:"config,omitempty"`
	Credentials    *SecretRef             `json:"credentials,omitempty" yaml:"credentials,omitempty"`
}

func (d *Datasource) Equal(other *Datasource) bool {
	return fastEqual(d, other, func() bool {
		return d.Name == other.Name &&
			d.Path == other.Path &&
			d.Type == other.Type &&
			d.TransformQuery == other.TransformQuery &&
			reflect.DeepEqual(d.Config, other.Config) &&
			d.Credentials.Equal(other.Credentials)
	})
}

type Datasources []Datasource

func (a Datasources) Equal(b Datasources) bool {
	return setEqual(a, b, func(ds Datasource) string { return ds.Name }, func(a, b Datasource) bool { return a.Equal(&b) })
}

type Database struct {
	SQL    *SQLDatabase `json:"sql,omitempty" yaml:"sql,omitempty"`
	AWSRDS *AmazonRDS   `json:"aws_rds,omitempty" yaml:"aws_rds,omitempty"`
}

type SQLDatabase struct {
	Driver string `yaml:"driver"`
	DSN    string `yaml:"dsn"`
}

type AmazonRDS struct {
	Region       string     `json:"region" yaml:"region"`
	Endpoint     string     `json:"endpoint" yaml:"endpoint"` // hostname:port
	Driver       string     `json:"driver" yaml:"driver"`     // mysql or postgres
	DatabaseUser string     `json:"database_user" yaml:"database_user"`
	DatabaseName string     `json:"database_name" yaml:"database_name"`
	DSN          string     `json:"dsn" yaml:"dsn"`
	Credentials  *SecretRef `json:"credentials,omitempty" yaml:"credentials,omitempty"`
	// RootCertificates points to PEM-encoded root certificate bundle file. If empty, the default system
	// root CA certificates are used. For RDS, you can download the appropriate bundle for your region
	// from here: https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/UsingWithRDS.SSL.html#UsingWithRDS.SSL.CertificatesAllRegions
	RootCertificates string `json:"root_certificates,omitempty" yaml:"root_certificates,omitempty"`
}

func setEqual[K comparable, V any](a, b []V, key func(V) K, eq func(a, b V) bool) bool {
	m := make(map[K]V, len(a))
	for _, v := range a {
		m[key(v)] = v
	}

	n := make(map[K]V, len(b))
	for _, v := range b {
		n[key(v)] = v
	}

	return maps.EqualFunc(m, n, eq)
}

func stringPtrEqual(a, b *string) bool {
	return fastEqual(a, b, func() bool { return *a == *b })
}

func stringPtrCompare(a, b *string) int {
	if a == nil && b == nil {
		return 0
	}
	if a == nil {
		return -1
	}
	if b == nil {
		return 1
	}

	if *a < *b {
		return -1
	}

	if *a > *b {
		return 1
	}

	return 0
}

func fastEqual[V any](a, b *V, slowEqual func() bool) bool {
	if a == b {
		return true
	}

	if a == nil || b == nil {
		return false
	}

	return slowEqual()
}
