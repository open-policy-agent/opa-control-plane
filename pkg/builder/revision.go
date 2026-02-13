package builder

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/open-policy-agent/opa/v1/ast" // NB(sr): We need v1, we want template strings here!
	"github.com/open-policy-agent/opa/v1/rego"
)

func (b *Builder) resolveRevision(ctx context.Context) (string, error) {
	if b.revision == "" {
		return "", nil
	}

	input := map[string]any{
		"sources": b.sourceMetadata,
	}

	query, err := ast.ParseExpr(b.revision)
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
	case int, int64, float64:
		return fmt.Sprintf("%v", val)
	case ast.Number:
		if i, ok := val.Int(); ok {
			return strconv.Itoa(i)
		}
		if f, ok := val.Float64(); ok {
			return fmt.Sprintf("%g", f)
		}
		return val.String()
	default:
		return fmt.Sprintf("%v", val)
	}
}
