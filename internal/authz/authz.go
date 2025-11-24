package authz

import (
	"context"
	"database/sql"
	_ "embed"
	"errors"
	"fmt"
	"maps"
	"sort"
	"strconv"
	"strings"

	"github.com/open-policy-agent/opa/ast"          // nolint:staticcheck
	"github.com/open-policy-agent/opa/dependencies" // nolint:staticcheck
	"github.com/open-policy-agent/opa/rego"         // nolint:staticcheck
)

const cacheSize = 128

//go:embed authz.rego
var src string
var partialCache = newCache(cacheSize)

// Any references to `data` documents in the authorization policy are considered
// references to SQL tables and therefore are marked as unknowns by default. In addition,
// we assume that columns are always referred to via `data.<tablename>.<columnname>`.
//
// This function extracts the unknowns and column references from the policy for the
// partial evaluation and query translation (respectively) below.
var defaultUnknowns, defaultColumnMappings = func() ([]string, map[string]ColumnRef) {

	deps, err := dependencies.Minimal(ast.MustParseModule(src))
	if err != nil {
		panic(err)
	}

	var unknowns []string
	columns := make(map[string]ColumnRef)

	for _, dep := range deps {
		if dep[0].Equal(ast.DefaultRootDocument) {
			table := string(dep[1].Value.(ast.String))
			column := string(dep[2].Value.(ast.String))
			columns[dep.String()] = ColumnRef{Table: table, Column: column}
			unknowns = append(unknowns, dep[:2].String())
		}
	}

	return unknowns, columns
}()

type sqlSelect struct {
	Select []Expr
	From   []sqlTableRef
	Where  sqlWhere
}

type sqlWhere struct {
	expr Expr
}

func (x sqlWhere) And(other Expr) sqlWhere {
	if x.expr == nil {
		return sqlWhere{other}
	}
	return sqlWhere{sqlExprAnd{x.expr, other}}
}

func (x sqlWhere) Or(other Expr) sqlWhere {
	if x.expr == nil {
		return sqlWhere{other}
	}
	return sqlWhere{sqlExprOr{x.expr, other}}
}

func (x sqlWhere) Tables() []sqlTableRef { return x.expr.Tables() }

type ArgFn func(int) string

type Expr interface {
	SQL(ArgFn, []any) (string, []any)
	Tables() []sqlTableRef
}

type sqlExprExists struct {
	Query sqlSelect
}

func (x sqlExprExists) Tables() []sqlTableRef {
	return x.Query.From
}

type sqlExprAnd struct {
	LHS Expr
	RHS Expr
}

func (x sqlExprAnd) Tables() []sqlTableRef {
	return append(x.LHS.Tables(), x.RHS.Tables()...)
}

type sqlExprOr struct {
	LHS Expr
	RHS Expr
}

func (x sqlExprOr) Tables() []sqlTableRef {
	return append(x.LHS.Tables(), x.RHS.Tables()...)
}

type sqlExprEq struct {
	LHS sqlOperand
	RHS sqlOperand
}

func (x sqlExprEq) Tables() []sqlTableRef {
	return append(x.LHS.Tables(), x.RHS.Tables()...)
}

type sqlExprIsNotNull struct {
	Column ColumnRef
}

func (e sqlExprIsNotNull) Tables() []sqlTableRef {
	return e.Column.Tables()
}

type sqlTableRef struct {
	Table string
}

type sqlOperand interface {
	Tables() []sqlTableRef
	SQL(ArgFn, []any) (string, []any)
}

type ColumnRef struct {
	Table  string
	Column string
}

func (c ColumnRef) Tables() []sqlTableRef {
	return []sqlTableRef{{Table: c.Table}}
}

type sqlString struct {
	Value string
}

type sqlInt struct {
	Value int
}

func (x sqlSelect) SQL(fn ArgFn, args []any) (string, []any) {
	tables := make([]string, len(x.From))
	for i := range tables {
		tables[i], args = x.From[i].SQL(fn, args)
	}
	selects := make([]string, len(x.Select))
	for i := range selects {
		selects[i], args = x.Select[i].SQL(fn, args)
	}
	conditions, args := x.Where.expr.SQL(fn, args)
	return "SELECT " + strings.Join(selects, ", ") + " FROM " + strings.Join(tables, ", ") + " WHERE " + conditions, args
}

func (x sqlExprExists) SQL(fn ArgFn, args []any) (string, []any) {
	conditions, args := x.Query.SQL(fn, args)
	return "EXISTS (" + conditions + ")", args
}

func (x sqlExprAnd) SQL(fn ArgFn, args []any) (string, []any) {
	lhs, args := x.LHS.SQL(fn, args)
	rhs, args := x.RHS.SQL(fn, args)
	return lhs + " AND " + rhs, args
}

func (x sqlExprOr) SQL(fn ArgFn, args []any) (string, []any) {
	lhs, args := x.LHS.SQL(fn, args)
	rhs, args := x.RHS.SQL(fn, args)
	return lhs + " OR " + rhs, args
}

func (x sqlExprEq) SQL(fn ArgFn, args []any) (string, []any) {
	lhs, args := x.LHS.SQL(fn, args)
	rhs, args := x.RHS.SQL(fn, args)
	return lhs + "=" + rhs, args
}

func (x sqlExprIsNotNull) SQL(fn ArgFn, args []any) (string, []any) {
	cond, args := x.Column.SQL(fn, args)
	return cond + " IS NOT NULL", args
}
func (x sqlTableRef) SQL(fn ArgFn, args []any) (string, []any) { return x.Table, args }
func (x ColumnRef) SQL(fn ArgFn, args []any) (string, []any)   { return x.Table + "." + x.Column, args }
func (x sqlInt) SQL(fn ArgFn, args []any) (string, []any)      { return strconv.Itoa(x.Value), args }

func (x sqlString) SQL(fn ArgFn, args []any) (string, []any) {
	return fn(len(args)), append(args, x.Value)
}

func (sqlString) Tables() []sqlTableRef { return nil }
func (sqlInt) Tables() []sqlTableRef    { return nil }

type Access struct {
	Principal  string `json:"principal"`
	Tenant     string `json:"tenant"`
	Resource   string `json:"resource"`
	Permission string `json:"permission"`
	Name       string `json:"name,omitempty"`
}

func Check(ctx context.Context, tx *sql.Tx, fn ArgFn, access Access) bool {

	expr, err := Partial(ctx, access, nil)
	if err != nil {
		return false
	}

	var x any
	cond, args := expr.SQL(fn, nil)
	return tx.QueryRowContext(ctx, `SELECT 1 WHERE `+cond, args...).Scan(&x) == nil
}

func Partial(ctx context.Context, access Access, extraColumnMappings map[string]ColumnRef) (Expr, error) {
	return partialCache.Get(access, extraColumnMappings, func() (Expr, error) {
		return partial(ctx, access, extraColumnMappings)
	})
}

func partial(ctx context.Context, access Access, extraColumnMappings map[string]ColumnRef) (Expr, error) {

	extraUnknowns := make([]string, 0, len(extraColumnMappings))
	for k := range extraColumnMappings {
		extraUnknowns = append(extraUnknowns, k)
	}

	pqs, err := rego.New(
		rego.Query("data.authz.allow = true"),
		rego.Module("authz.rego", src),
		rego.Unknowns(append(extraUnknowns, defaultUnknowns...)),
		rego.Input(access),
	).Partial(ctx)
	if err != nil {
		return nil, err
	}

	if len(pqs.Support) > 0 {
		return nil, errors.New("unsupported authorization result (support modules found)")
	}

	cm := columnMapper(defaultColumnMappings)
	if len(extraColumnMappings) > 0 {
		cm = make(columnMapper, len(cm)+len(extraColumnMappings))
		maps.Copy(cm, defaultColumnMappings)
		maps.Copy(cm, extraColumnMappings)
	}

	var w sqlWhere

	for _, b := range pqs.Queries {

		var exists sqlExprExists
		exists.Query.Select = []Expr{sqlInt{Value: 1}}

		for _, expr := range b {
			op := expr.Operator()
			switch op.String() {
			case "eq":
				lhs := cm.toSqlOp(expr.Operand(0))
				rhs := cm.toSqlOp(expr.Operand(1))
				if lhs == nil || rhs == nil {
					return nil, fmt.Errorf("XXX: translation error: eq operands: %v", expr)
				}
				exists.Query.Where = exists.Query.Where.And(sqlExprEq{LHS: lhs, RHS: rhs})
			case "neq":
				if e, ok := cm.trySqlExprIsNotNull(expr.Operand(0), expr.Operand(1)); ok {
					exists.Query.Where = exists.Query.Where.And(e)
				} else if e, ok := cm.trySqlExprIsNotNull(expr.Operand(1), expr.Operand(0)); ok {
					exists.Query.Where = exists.Query.Where.And(e)
				} else {
					return nil, errors.New("XXX: translation error: neq operands")
				}
			default:
				return nil, errors.New("XXX: translation error: expr operator")
			}
		}

		seen := map[sqlTableRef]struct{}{}

		for _, t := range exists.Query.Where.Tables() {
			if t.Table != access.Resource {
				seen[t] = struct{}{}
			}
		}

		for t := range seen {
			exists.Query.From = append(exists.Query.From, t)
		}

		sort.Slice(exists.Query.From, func(i, j int) bool {
			return exists.Query.From[i].Table < exists.Query.From[j].Table
		})

		w = w.Or(exists)
	}

	return w.expr, nil
}

type columnMapper map[string]ColumnRef

func (cm columnMapper) trySqlExprIsNotNull(a, b *ast.Term) (Expr, bool) {
	if r, ok := a.Value.(ast.Ref); ok {
		if _, ok := b.Value.(ast.Null); ok {
			if c, ok := cm.trySqlColumnOperand(r); ok {
				return sqlExprIsNotNull{Column: c}, true
			}
		}
	}
	return sqlExprIsNotNull{}, false
}

func (cm columnMapper) toSqlOp(t *ast.Term) sqlOperand {
	switch tv := t.Value.(type) {
	case ast.Ref:
		if c, ok := cm.trySqlColumnOperand(tv); ok {
			return c
		}
	case ast.String:
		return sqlString{Value: string(tv)}
	}
	return nil
}

func (cm columnMapper) trySqlColumnOperand(ref ast.Ref) (ColumnRef, bool) {
	if c, ok := cm[ref.String()]; ok {
		return c, true
	}
	return ColumnRef{}, false
}
