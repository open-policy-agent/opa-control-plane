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

func extractRevisionRefs(revision string) ([]ReferencedSource, bool, error) {
	if revision == "" {
		return nil, false, nil
	}

	query, err := ast.ParseExpr(revision)
	if err != nil {
		return nil, false, fmt.Errorf("invalid rego query: %w", err)
	}

	sourcesRef := ast.InputRootRef.Append(ast.StringTerm("sources"))
	bundleRef := ast.InputRootRef.Append(ast.StringTerm("bundle"))
	references := make(map[string]map[string]bool)
	needsBundleHash := false

	ast.WalkRefs(query, func(ref ast.Ref) bool {
		if ref.HasPrefix(bundleRef) {
			needsBundleHash = true
			return false
		}

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

	return result, needsBundleHash, nil
}

// resolveRevision evaluates a Rego revision expression with the given source metadata
// and returns the final revision string.
func resolveRevision(ctx context.Context, revision string, sourceMetadata map[string]map[string]any, bundleHash string) (string, error) {
	if revision == "" {
		return "", nil
	}

	input := map[string]any{
		"sources": sourceMetadata,
	}
	if bundleHash != "" {
		input["bundle"] = map[string]any{
			"hash": bundleHash,
		}
	}

	query, err := ast.ParseExpr(revision)
	if err != nil {
		return "", fmt.Errorf("invalid rego query: %w", err)
	}

	result, err := evaluateRego(ctx, query, input, sourceMetadata, bundleHash)
	if err != nil {
		return "", fmt.Errorf("failed to resolve revision: %w", err)
	}
	return result, nil
}

func buildInputSchema(sourceMetadata map[string]map[string]any, bundleHash string) *ast.SchemaSet {
	datasourceEntrySchema := map[string]any{
		"type": "object",
		"properties": map[string]any{
			"hash": map[string]any{"type": "string"},
		},
	}

	sourceProps := make(map[string]any, len(sourceMetadata))
	for sourceName, types := range sourceMetadata {
		props := map[string]any{
			"git": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"commit": map[string]any{"type": "string"},
				},
			},
			"sql": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"hash": map[string]any{"type": "string"},
				},
			},
		}

		// For http and s3, build schema from actual datasource names in metadata
		for _, sourceType := range []string{"http", "s3"} {
			if typeData, ok := types[sourceType].(map[string]any); ok {
				dsProps := make(map[string]any, len(typeData))
				for dsName := range typeData {
					dsProps[dsName] = datasourceEntrySchema
				}
				props[sourceType] = map[string]any{
					"type":       "object",
					"properties": dsProps,
				}
			}
		}

		sourceProps[sourceName] = map[string]any{
			"type":       "object",
			"properties": props,
		}
	}

	schemas := ast.NewSchemaSet()

	properties := map[string]any{
		"sources": map[string]any{
			"type":       "object",
			"properties": sourceProps,
		},
	}
	if bundleHash != "" {
		properties["bundle"] = map[string]any{
			"type": "object",
			"properties": map[string]any{
				"hash": map[string]any{"type": "string"},
			},
		}
	}

	required := []string{"sources"}
	if bundleHash != "" {
		required = append(required, "bundle")
	}

	schemas.Put(ast.SchemaRootRef, map[string]any{
		"$schema":    "http://json-schema.org/draft-07/schema",
		"type":       "object",
		"properties": properties,
		"required":   required,
	})
	return schemas
}

func evaluateRego(ctx context.Context, query *ast.Expr, input map[string]any, sourceMetadata map[string]map[string]any, bundleHash string) (string, error) {
	opts := []func(*rego.Rego){
		rego.ParsedQuery([]*ast.Expr{query}),
		rego.Strict(true),
		rego.Runtime(makeRuntimeInfo()),
	}

	if input != nil {
		opts = append(opts, rego.Input(input))
	}

	if sourceMetadata != nil || bundleHash != "" {
		if sourceMetadata == nil {
			sourceMetadata = make(map[string]map[string]any)
		}
		opts = append(opts, rego.Schemas(buildInputSchema(sourceMetadata, bundleHash)))
	}

	rs, err := rego.New(opts...).Eval(ctx)
	if err != nil {
		return "", err
	}

	if len(rs) == 0 || len(rs[0].Expressions) == 0 {
		return "", errors.New("no results from Rego evaluation")
	}

	return formatValue(rs[0].Expressions[0].Value), nil
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
