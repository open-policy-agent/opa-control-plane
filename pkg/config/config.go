package config

import (
	"strings"

	internalutil "github.com/open-policy-agent/opa-control-plane/internal/util"
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
