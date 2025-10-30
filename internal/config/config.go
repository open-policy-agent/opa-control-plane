package config

import (
	"cmp"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"iter"
	"maps"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/gobwas/glob"
	"github.com/goccy/go-yaml"
	"github.com/swaggest/jsonschema-go"
)

// Internal configuration data structures for OPA Control Plane.

// Metadata contains metadata about the configuration file itself. This
// information is not stored in the database and is only used by the migration
// tooling.
type Metadata struct {
	ExportedFrom string `json:"exported_from"`
	ExportedAt   string `json:"exported_at"`

	_ struct{} `additionalProperties:"false"`
}

// Root is the top-level configuration structure used by OPA Control Plane.
type Root struct {
	Metadata Metadata           `json:"metadata"`
	Bundles  map[string]*Bundle `json:"bundles,omitempty"`
	Stacks   map[string]*Stack  `json:"stacks,omitempty"`
	Sources  map[string]*Source `json:"sources,omitempty"`
	Secrets  map[string]*Secret `json:"secrets,omitempty"` // Schema validation overrides Secret to object type.
	Tokens   map[string]*Token  `json:"tokens,omitempty"`
	Database *Database          `json:"database,omitempty"`
	Service  *Service           `json:"service,omitempty"`
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
func (r *Root) UnmarshalYAML(bs []byte) error {
	type rawRoot Root // avoid recursive calls to UnmarshalYAML by type aliasing
	var raw rawRoot

	if err := yaml.Unmarshal(bs, &raw); err != nil {
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
	for name := range raw.Tokens {
		raw.Tokens[name] = cmp.Or(raw.Tokens[name], &Token{})
		raw.Tokens[name].Name = name
	}

	for name := range raw.Secrets {
		raw.Secrets[name] = cmp.Or(raw.Secrets[name], &Secret{})
		raw.Secrets[name].Name = name
	}

	for name := range raw.Bundles {
		raw.Bundles[name] = cmp.Or(raw.Bundles[name], &Bundle{})
		raw.Bundles[name].Name = name
		if raw.Bundles[name].ObjectStorage.AmazonS3 != nil && raw.Bundles[name].ObjectStorage.AmazonS3.Credentials != nil {
			raw.Bundles[name].ObjectStorage.AmazonS3.Credentials.value = raw.Secrets[raw.Bundles[name].ObjectStorage.AmazonS3.Credentials.Name]
		}
		if raw.Bundles[name].ObjectStorage.AzureBlobStorage != nil && raw.Bundles[name].ObjectStorage.AzureBlobStorage.Credentials != nil {
			raw.Bundles[name].ObjectStorage.AzureBlobStorage.Credentials.value = raw.Secrets[raw.Bundles[name].ObjectStorage.AzureBlobStorage.Credentials.Name]
		}
		if raw.Bundles[name].ObjectStorage.GCPCloudStorage != nil && raw.Bundles[name].ObjectStorage.GCPCloudStorage.Credentials != nil {
			raw.Bundles[name].ObjectStorage.GCPCloudStorage.Credentials.value = raw.Secrets[raw.Bundles[name].ObjectStorage.GCPCloudStorage.Credentials.Name]
		}
	}

	for name := range raw.Sources {
		raw.Sources[name] = cmp.Or(raw.Sources[name], &Source{})
		raw.Sources[name].Name = name
		if raw.Sources[name].Git.Credentials != nil {
			raw.Sources[name].Git.Credentials.value = raw.Secrets[raw.Sources[name].Git.Credentials.Name]
		}
	}

	for name := range raw.Stacks {
		raw.Stacks[name] = cmp.Or(raw.Stacks[name], &Stack{})
		raw.Stacks[name].Name = name
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

func iterator[V any](m map[string]V, name func(V) string) func(func(int, V) bool) {
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

func Validate(data []byte) error {
	var config any
	if err := yaml.Unmarshal(data, &config); err != nil {
		return err
	}

	return rootSchema.Validate(config)
}

// Bundle defines the configuration for an OPA Control Plane Bundle.
type Bundle struct {
	Name          string        `json:"name"`
	Labels        Labels        `json:"labels,omitempty"`
	ObjectStorage ObjectStorage `json:"object_storage,omitzero"`
	Requirements  Requirements  `json:"requirements,omitempty"`
	ExcludedFiles StringSet     `json:"excluded_files,omitempty"`
	Interval      Duration      `json:"rebuild_interval,omitzero"`

	_ struct{} `additionalProperties:"false"`
}

// Instead of marshaling and unmarshaling as int64 it uses strings, like "5m" or "0.5s".
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

type Labels map[string]string

type Requirement struct {
	Source *string        `json:"source,omitempty"`
	Git    GitRequirement `json:"git,omitzero"`
	Path   string         `json:"path,omitzero"`
	Prefix string         `json:"prefix,omitzero"`
}

type GitRequirement struct {
	Commit *string `json:"commit,omitempty"`
}

func (a Requirement) Equal(b Requirement) bool {
	return stringPtrEqual(a.Source, b.Source) &&
		stringPtrEqual(a.Git.Commit, b.Git.Commit) &&
		a.Path == b.Path &&
		a.Prefix == b.Prefix
}
func (a Requirement) Compare(b Requirement) int {
	if x := stringPtrCompare(a.Source, b.Source); x != 0 {
		return x
	}
	if x := stringPtrCompare(a.Git.Commit, b.Git.Commit); x != 0 {
		return x
	}
	if x := strings.Compare(a.Path, b.Path); x != 0 {
		return x
	}
	if x := strings.Compare(a.Prefix, b.Prefix); x != 0 {
		return x
	}
	return 0
}

type Requirements []Requirement

func (a Requirements) Equal(b Requirements) bool {
	if len(a) != len(b) {
		return false
	}
	// Ordering of requirements does not matter, so we sort copies before comparing if
	// the slices have more than one element.
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

type Files map[string]string

func (f Files) Equal(other Files) bool {
	return maps.Equal(f, other)
}

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

func (s *Bundle) UnmarshalYAML(bs []byte) error {
	type rawBundle Bundle // avoid recursive calls to UnmarshalJSON by type aliasing
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

func (s *Bundle) Equal(other *Bundle) bool {
	return fastEqual(s, other, func(s, other *Bundle) bool {
		return s.Name == other.Name &&
			maps.Equal(s.Labels, other.Labels) &&
			s.ObjectStorage.Equal(&other.ObjectStorage) &&
			s.Requirements.Equal(other.Requirements) &&
			s.ExcludedFiles.Equal(other.ExcludedFiles) &&
			s.Interval == other.Interval
	})
}

// Source defines the configuration for an OPA Control Plane Source.
type Source struct {
	Name          string       `json:"name"`
	Builtin       *string      `json:"builtin,omitempty"`
	Git           Git          `json:"git,omitzero"`
	Datasources   Datasources  `json:"datasources,omitempty"`
	EmbeddedFiles Files        `json:"files,omitempty"`
	Directory     string       `json:"directory,omitempty"` // Root directory for the source files, used to resolve file paths below.
	Paths         StringSet    `json:"paths,omitempty"`
	Requirements  Requirements `json:"requirements,omitempty"`
}

func (s *Source) Equal(other *Source) bool {
	return fastEqual(s, other, func(s, other *Source) bool {
		return s.Name == other.Name &&
			stringPtrEqual(s.Builtin, other.Builtin) &&
			s.Git.Equal(&other.Git) &&
			s.Datasources.Equal(other.Datasources) &&
			s.EmbeddedFiles.Equal(other.EmbeddedFiles) &&
			s.Directory == other.Directory &&
			s.Paths.Equal(other.Paths) &&
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
	return setEqual(a, b, func(s *Source) string { return s.Name }, (*Source).Equal)
}

// Stack defines the configuration for an OPA Control Plane Stack.
type Stack struct {
	Name            string       `json:"name"`
	Selector        Selector     `json:"selector"` // Schema validation overrides Selector to object of string array values.
	ExcludeSelector *Selector    `json:"exclude_selector,omitempty"`
	Requirements    Requirements `json:"requirements,omitempty"`

	_ struct{} `additionalProperties:"false"`
}

func (a *Stack) Equal(other *Stack) bool {
	return fastEqual(a, other, func(a, other *Stack) bool {
		return a.Name == other.Name &&
			a.Selector.Equal(other.Selector) &&
			a.ExcludeSelector.PtrEqual(other.ExcludeSelector) &&
			a.Requirements.Equal(other.Requirements)
	})
}

type Stacks []*Stack

func (a Stacks) Equal(b Stacks) bool {
	return setEqual(a, b, func(s *Stack) string { return s.Name }, (*Stack).Equal)
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
	return maps.EqualFunc(s.s, other.s, StringSet.Equal)
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

func (s Selector) MarshalYAML() (any, error) {
	return maps.Clone(s.s), nil
}

func (s Selector) MarshalJSON() ([]byte, error) {
	x, err := s.MarshalYAML()
	if err != nil {
		return nil, err
	}
	return json.Marshal(x)
}

func (s *Selector) UnmarshalYAML(bs []byte) error {
	raw := make(map[string][]string)
	if err := yaml.Unmarshal(bs, &raw); err != nil {
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
	Repo          string     `json:"repo"`
	Reference     *string    `json:"reference,omitempty"`
	Commit        *string    `json:"commit,omitempty"`
	Path          *string    `json:"path,omitempty"`
	IncludedFiles StringSet  `json:"included_files,omitempty"`
	ExcludedFiles StringSet  `json:"excluded_files,omitempty"`
	Credentials   *SecretRef `json:"credentials,omitempty"` // If nil, use the default SSH authentication mechanisms available
	// or no authentication for public repos. Note, JSON schema validation overrides this to string type.

	_ struct{} `additionalProperties:"false"`
}

func (g *Git) Equal(other *Git) bool {
	return fastEqual(g, other, func(g, other *Git) bool {
		return stringPtrEqual(g.Reference, other.Reference) &&
			stringPtrEqual(g.Commit, other.Commit) &&
			stringPtrEqual(g.Path, other.Path) &&
			g.Credentials.Equal(other.Credentials) &&
			g.IncludedFiles.Equal(other.IncludedFiles) &&
			g.ExcludedFiles.Equal(other.ExcludedFiles)
	})
}

type SecretRef struct {
	Name  string `json:"-"`
	value *Secret
}

// Resolve retrieves the secret value from the secret store. If the secret is not found, an error is returned.
// If the secret is found, it returns the value as an interface{} which can be further typed as needed.
func (s *SecretRef) Resolve(ctx context.Context) (any, error) {
	if s.value == nil {
		return nil, fmt.Errorf("secret %q not found", s.Name)
	}

	return s.value.Typed(ctx)
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

func (s *SecretRef) Equal(other *SecretRef) bool {
	return fastEqual(s, other, func(s, other *SecretRef) bool {
		return s.Name == other.Name && s.value.Equal(other.value)
	})
}

// Token represents an API token to access the OPA Control Plane APIs.
type Token struct {
	Name   string  `json:"-"`
	APIKey string  `json:"api_key"`
	Scopes []Scope `json:"scopes"`

	_ struct{} `additionalProperties:"false"`
}

func (t *Token) Equal(other *Token) bool {
	return fastEqual(t, other, func(t, other *Token) bool {
		return t.Name == other.Name && t.APIKey == other.APIKey && scopesEqual(t.Scopes, other.Scopes)
	})
}

type Scope struct {
	Role string `json:"role" enum:"administrator,viewer,owner,stack_owner"`
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

	return Parse(bs)
}

func Parse(bs []byte) (*Root, error) {
	if err := Validate(bs); err != nil {
		return nil, err
	}

	var root Root
	if err := yaml.Unmarshal(bs, &root); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %w", err)
	}

	return &root, nil
}

type ObjectStorage struct {
	AmazonS3          *AmazonS3          `json:"aws,omitempty"`
	GCPCloudStorage   *GCPCloudStorage   `json:"gcp,omitempty"`
	AzureBlobStorage  *AzureBlobStorage  `json:"azure,omitempty"`
	FileSystemStorage *FileSystemStorage `json:"filesystem,omitempty"`
}

func (o *ObjectStorage) Equal(other *ObjectStorage) bool {
	return fastEqual(o, other, func(o, other *ObjectStorage) bool {
		return o.AmazonS3.Equal(other.AmazonS3) &&
			o.GCPCloudStorage.Equal(other.GCPCloudStorage) &&
			o.AzureBlobStorage.Equal(other.AzureBlobStorage) &&
			o.FileSystemStorage.Equal(other.FileSystemStorage)
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
	Bucket      string     `json:"bucket"`
	Key         string     `json:"key"`
	Region      string     `json:"region,omitempty"`
	Credentials *SecretRef `json:"credentials,omitempty"` // If nil, use default credentials chain: environment variables,
	// shared credentials file, ECS or EC2 instance role. More details in s3.go.
	URL string `json:"url,omitempty"` // for test purposes
}

// GCPCloudStorage defines the configuration for a Google Cloud Storage bucket.
type GCPCloudStorage struct {
	Project     string     `json:"project"`
	Bucket      string     `json:"bucket"`
	Object      string     `json:"object"`
	Credentials *SecretRef `json:"credentials,omitempty"` // If nil, use default credentials chain: environment variables,
	// file created by gcloud auth application-default login, GCE/GKE metadata server. More details in s3.go.
}

// AzureBlobStorage defines the configuration for an Azure Blob Storage container.
type AzureBlobStorage struct {
	AccountURL  string     `json:"account_url"`
	Container   string     `json:"container"`
	Path        string     `json:"path"`
	Credentials *SecretRef `json:"credentials,omitempty"` // If nil, use default credentials chain: environment variables,
	// managed identity, Azure CLI login. More details in s3.go.
}

// FileSystemStorage defines the configuration for a local filesystem storage.
type FileSystemStorage struct {
	Path string `json:"path"` // Path to the bundle on the local filesystem.
}

func (a *AmazonS3) Equal(other *AmazonS3) bool {
	return fastEqual(a, other, func(a, other *AmazonS3) bool {
		return a.Bucket == other.Bucket &&
			a.Key == other.Key &&
			a.Region == other.Region &&
			a.Credentials.Equal(other.Credentials) &&
			a.URL == other.URL
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
	return fastEqual(g, other, func(g, other *GCPCloudStorage) bool {
		return g.Project == other.Project &&
			g.Bucket == other.Bucket &&
			g.Object == other.Object
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
	return fastEqual(a, other, func(a, other *AzureBlobStorage) bool {
		return a.AccountURL == other.AccountURL &&
			a.Container == other.Container &&
			a.Path == other.Path
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
	return fastEqual(f, other, func(f, other *FileSystemStorage) bool {
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
	Name           string         `json:"name"`
	Path           string         `json:"path"`
	Type           string         `json:"type"`
	TransformQuery string         `json:"transform_query,omitempty"`
	Config         map[string]any `json:"config,omitempty"`
	Credentials    *SecretRef     `json:"credentials,omitempty"`

	_ struct{} `additionalProperties:"false"`
}

func (d *Datasource) Equal(other *Datasource) bool {
	return fastEqual(d, other, func(d, other *Datasource) bool {
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
	SQL    *SQLDatabase `json:"sql,omitempty"`
	AWSRDS *AmazonRDS   `json:"aws_rds,omitempty"`
}

type SQLDatabase struct {
	Driver string `yaml:"driver"`
	DSN    string `yaml:"dsn"`
}

type AmazonRDS struct {
	Region       string     `json:"region"`
	Endpoint     string     `json:"endpoint"` // hostname:port
	Driver       string     `json:"driver"`   // mysql or postgres
	DatabaseUser string     `json:"database_user"`
	DatabaseName string     `json:"database_name"`
	DSN          string     `json:"dsn"`
	Credentials  *SecretRef `json:"credentials,omitempty"`
	// RootCertificates points to PEM-encoded root certificate bundle file. If empty, the default system
	// root CA certificates are used. For RDS, you can download the appropriate bundle for your region
	// from here: https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/UsingWithRDS.SSL.html#UsingWithRDS.SSL.CertificatesAllRegions
	RootCertificates string `json:"root_certificates,omitempty"`
}

type Service struct {
	// ApiPrefix prefixes all endpoints (including health and metrics) with its value. It is important to start with `/` and not end with `/`.
	// For example `/my/path` will make health endpoint be accessible under `/my/path/health`
	ApiPrefix string   `json:"api_prefix,omitempty" pattern:"^/([^/].*[^/])?$"`
	_         struct{} `additionalProperties:"false"`
}

func setEqual[K comparable, V any](a, b []V, key func(V) K, eq func(a, b V) bool) bool {
	if len(a) == 1 && len(b) == 1 {
		return eq(a[0], b[0])
	}

	// NB(sr): There's a risk of false positives here, e.g. []struct{n, v string}{ {"foo", "bar"}, {"foo", "baz"} }
	// is setEqual to []struct{n, v string}{ {"foo", "baz"} }
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
	return fastEqual(a, b, func(a, b *string) bool { return *a == *b })
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

func fastEqual[V any](a, b *V, slowEqual func(a, b *V) bool) bool {
	if a == b {
		return true
	}

	if a == nil || b == nil {
		return false
	}

	return slowEqual(a, b)
}
