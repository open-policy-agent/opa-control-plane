package service

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"os"
	"slices"
	"strings"

	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/rego"
)

// ReferencedSource represents a source that is referenced in the revision expression
type ReferencedSource struct {
	SourceName string
	Fields     []string // e.g., ["hashsum"], ["commit"]
}

func ExtractRevisionRefs(revision string) ([]ReferencedSource, error) {
	if revision == "" {
		return nil, nil
	}

	query, err := ast.ParseExpr(revision)
	if err != nil {
		return nil, fmt.Errorf("invalid rego query: %w", err)
	}

	sourcesRef := ast.InputRootRef.Append(ast.StringTerm("sources"))
	references := make(map[string]map[string]bool)

	ast.WalkRefs(query, func(ref ast.Ref) bool {
		if !ref.HasPrefix(sourcesRef) || len(ref) < 4 {
			return false
		}

		s, ok := ref[2].Value.(ast.String)
		if !ok {
			return false
		}
		sourceName := string(s)

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

	result := make([]ReferencedSource, 0, len(references))
	for sourceName, fields := range references {
		result = append(result, ReferencedSource{
			SourceName: sourceName,
			Fields:     slices.Collect(maps.Keys(fields)),
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
		return "", fmt.Errorf("failed to resolve revision: %w", err)
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
