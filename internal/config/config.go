package config

import (
	"cmp"
	"context"
	"encoding/json"
	"fmt"
	"iter"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"sort"

	"github.com/gobwas/glob"
	"github.com/goccy/go-yaml"

	extconfig "github.com/open-policy-agent/opa-control-plane/pkg/config"
	internalutil "github.com/open-policy-agent/opa-control-plane/pkg/util"
)

// Type aliases for types now defined in pkg/config. These allow internal code
// to continue using the short names (e.g. config.Bundle) while the canonical
// definitions live in the public package.
type (
	BundleStatus      = extconfig.BundleStatus
	Bundle            = extconfig.Bundle
	Source            = extconfig.Source
	Sources           = extconfig.Sources
	Labels            = extconfig.Labels
	Duration          = extconfig.Duration
	Options           = extconfig.Options
	Optimization      = extconfig.Optimization
	ObjectStorage     = extconfig.ObjectStorage
	AmazonS3          = extconfig.AmazonS3
	GCPCloudStorage   = extconfig.GCPCloudStorage
	AzureBlobStorage  = extconfig.AzureBlobStorage
	FileSystemStorage = extconfig.FileSystemStorage
	StringSet         = extconfig.StringSet
	Requirements      = extconfig.Requirements
	Files             = extconfig.Files
	Git               = extconfig.Git
	Datasource        = extconfig.Datasource
	Datasources       = extconfig.Datasources
	SecretRef         = extconfig.SecretRef
	Requirement       = extconfig.Requirement
	GitRequirement    = extconfig.GitRequirement
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

	_ struct{} `additionalProperties:"false"`
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

// wireSecret configures a SecretRef to resolve using the given Secret.
func wireSecret(ref *SecretRef, secret *Secret) {
	if ref == nil || secret == nil {
		return
	}
	s := secret // capture for closure
	ref.SetResolver(func(ctx context.Context) (any, error) {
		return s.Typed(ctx)
	})
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
			wireSecret(raw.Bundles[name].ObjectStorage.AmazonS3.Credentials, raw.Secrets[raw.Bundles[name].ObjectStorage.AmazonS3.Credentials.Name])
		}
		if raw.Bundles[name].ObjectStorage.AzureBlobStorage != nil && raw.Bundles[name].ObjectStorage.AzureBlobStorage.Credentials != nil {
			wireSecret(raw.Bundles[name].ObjectStorage.AzureBlobStorage.Credentials, raw.Secrets[raw.Bundles[name].ObjectStorage.AzureBlobStorage.Credentials.Name])
		}
		if raw.Bundles[name].ObjectStorage.GCPCloudStorage != nil && raw.Bundles[name].ObjectStorage.GCPCloudStorage.Credentials != nil {
			wireSecret(raw.Bundles[name].ObjectStorage.GCPCloudStorage.Credentials, raw.Secrets[raw.Bundles[name].ObjectStorage.GCPCloudStorage.Credentials.Name])
		}
	}

	for name := range raw.Sources {
		raw.Sources[name] = cmp.Or(raw.Sources[name], &Source{})
		raw.Sources[name].Name = name
		if raw.Sources[name].Git.Credentials != nil {
			wireSecret(raw.Sources[name].Git.Credentials, raw.Secrets[raw.Sources[name].Git.Credentials.Name])
		}
	}

	for name := range raw.Stacks {
		raw.Stacks[name] = cmp.Or(raw.Stacks[name], &Stack{})
		raw.Stacks[name].Name = name
	}

	if raw.Database != nil {
		if raw.Database.AWSRDS != nil && raw.Database.AWSRDS.Credentials != nil {
			wireSecret(raw.Database.AWSRDS.Credentials, raw.Secrets[raw.Database.AWSRDS.Credentials.Name])
		}
		if raw.Database.SQL != nil && raw.Database.SQL.Credentials != nil {
			wireSecret(raw.Database.SQL.Credentials, raw.Secrets[raw.Database.SQL.Credentials.Name])
		}
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

// Stack defines the configuration for an OPA Control Plane Stack.
type Stack struct {
	Name            string       `json:"name"`
	Selector        Selector     `json:"selector"` // Schema validation overrides Selector to object of string array values.
	ExcludeSelector *Selector    `json:"exclude_selector,omitempty"`
	Requirements    Requirements `json:"requirements,omitempty"`

	_ struct{} `additionalProperties:"false"`
}

func (a *Stack) Equal(other *Stack) bool {
	return internalutil.FastEqual(a, other, func(a, other *Stack) bool {
		return a.Name == other.Name &&
			a.Selector.Equal(other.Selector) &&
			a.ExcludeSelector.PtrEqual(other.ExcludeSelector) &&
			a.Requirements.Equal(other.Requirements)
	})
}

type Stacks []*Stack

func (a Stacks) Equal(b Stacks) bool {
	return internalutil.SetEqual(a, b, func(s *Stack) string { return s.Name }, (*Stack).Equal)
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
	return maps.EqualFunc(s.s, other.s, extconfig.StringSet.Equal)
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

// Token represents an API token to access the OPA Control Plane APIs.
type Token struct {
	Name   string  `json:"-"`
	APIKey string  `json:"api_key"`
	Scopes []Scope `json:"scopes"`

	_ struct{} `additionalProperties:"false"`
}

func (t *Token) Equal(other *Token) bool {
	return internalutil.FastEqual(t, other, func(t, other *Token) bool {
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
	for i := range b {
		if !slices.ContainsFunc(a, func(x Scope) bool { return x.Equal(b[i]) }) {
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

type Database struct {
	SQL    *SQLDatabase `json:"sql,omitempty"`
	AWSRDS *AmazonRDS   `json:"aws_rds,omitempty"`

	_ struct{} `additionalProperties:"false"`
}

type SQLDatabase struct {
	Driver      string     `json:"driver"`
	DSN         string     `json:"dsn"`
	Credentials *SecretRef `json:"credentials,omitempty"`

	_ struct{} `additionalProperties:"false"`
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

	_ struct{} `additionalProperties:"false"`
}

type Service struct {
	// ApiPrefix prefixes all endpoints (including health and metrics) with its value. It is important to start with `/` and not end with `/`.
	// For example `/my/path` will make health endpoint be accessible under `/my/path/health`
	ApiPrefix string `json:"api_prefix,omitempty" pattern:"^/([^/].*[^/])?$"`

	_ struct{} `additionalProperties:"false"`
}
