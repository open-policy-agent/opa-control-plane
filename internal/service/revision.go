package service

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/rego"
)

// ReferencedSource represents a source that is referenced in the revision expression
type ReferencedSource struct {
	SourceName string
	Fields     []string // e.g., ["hashsum"], ["commit"]
}

// AnalyzeRevisionReferences parses a revision Rego expression and extracts all
// references to input.sources to determine which source metadata is needed.
func AnalyzeRevisionReferences(revision string) ([]ReferencedSource, error) {
	if revision == "" {
		return nil, nil
	}

	query, err := ast.ParseExpr(revision)
	if err != nil {
		return nil, fmt.Errorf("invalid rego query: %w", err)
	}

	references := make(map[string]map[string]bool) // sourceName -> fields

	ast.WalkRefs(query, func(ref ast.Ref) bool {
		// Look for references like: input.sources["foo"].hashsum or input.sources.foo.commit
		if !ref.HasPrefix(ast.InputRootRef) {
			return false
		}

		// Must be at least input.sources.name.field
		if len(ref) < 4 {
			return false
		}

		// Check if ref[1] is "sources"
		if term, ok := ref[1].Value.(ast.String); !ok || string(term) != "sources" {
			return false
		}

		// Extract source name from ref[2]
		var sourceName string
		switch v := ref[2].Value.(type) {
		case ast.String:
			sourceName = string(v)
		case ast.Var:
			// Dynamic reference, can't analyze statically
			return false
		default:
			return false
		}

		// Extract fields from ref[3:]
		if references[sourceName] == nil {
			references[sourceName] = make(map[string]bool)
		}

		for i := 3; i < len(ref); i++ {
			if fieldName, ok := ref[i].Value.(ast.String); ok {
				references[sourceName][string(fieldName)] = true
			}
		}

		return false
	})

	// Convert map to slice
	result := make([]ReferencedSource, 0, len(references))
	for sourceName, fields := range references {
		fieldSlice := make([]string, 0, len(fields))
		for field := range fields {
			fieldSlice = append(fieldSlice, field)
		}
		result = append(result, ReferencedSource{
			SourceName: sourceName,
			Fields:     fieldSlice,
		})
	}

	return result, nil
}

// ResolveRevision evaluates a Rego revision expression with the given source metadata
// and returns the final revision string.
func ResolveRevision(ctx context.Context, revision string, sourceMetadata map[string]map[string]any) (string, error) {
	if revision == "" {
		return "", nil
	}

	input := map[string]any{
		"sources": sourceMetadata,
	}

	query, err := ast.ParseExpr(revision)
	if err != nil {
		return "", fmt.Errorf("invalid rego query: %w", err)
	}

	result, err := evaluateRego(ctx, query, input)
	if err != nil {
		return "", fmt.Errorf("rego evaluation failed: %w", err)
	}
	return result, nil
}

func evaluateRego(ctx context.Context, query *ast.Expr, input map[string]any) (string, error) {
	opts := []func(*rego.Rego){
		rego.ParsedQuery([]*ast.Expr{query}),
		rego.Strict(true),
		rego.Runtime(makeRuntimeInfo()),
	}

	if input != nil {
		opts = append(opts, rego.Input(input))
	}

	rs, err := rego.New(opts...).Eval(ctx)
	if err != nil {
		return "", err
	}

	if len(rs) == 0 {
		return "", errors.New("no results from Rego evaluation")
	}

	if len(rs[0].Expressions) == 0 {
		return "", errors.New("no expressions in result")
	}

	value := rs[0].Expressions[0].Value

	return formatValue(value), nil
}

func makeRuntimeInfo() *ast.Term {
	environ := os.Environ()
	items := make([][2]*ast.Term, 0, len(environ))
	for _, e := range environ {
		key, val, _ := strings.Cut(e, "=")
		items = append(items, [2]*ast.Term{ast.StringTerm(key), ast.StringTerm(val)})
	}

	return ast.NewTerm(ast.NewObject(
		[2]*ast.Term{ast.StringTerm("env"), ast.NewTerm(ast.NewObject(items...))},
	))
}

func formatValue(v any) string {
	switch val := v.(type) {
	case string:
		return val
	case ast.Number:
		return val.String()
	default:
		return fmt.Sprint(v)
	}
}
