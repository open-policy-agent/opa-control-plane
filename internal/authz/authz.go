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

	"github.com/open-policy-agent/opa-control-plane/pkg/authz"
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
var defaultUnknowns, defaultColumnMappings = func() ([]string, map[string]authz.SQLColumnRef) {

	deps, err := dependencies.Minimal(ast.MustParseModule(src))
	if err != nil {
		panic(err)
	}

	var unknowns []string
	columns := make(map[string]authz.SQLColumnRef)

	for _, dep := range deps {
		if dep[0].Equal(ast.DefaultRootDocument) {
			table := string(dep[1].Value.(ast.String))
			column := string(dep[2].Value.(ast.String))
			columns[dep.String()] = authz.SQLColumnRef{Table: table, Column: column}
			unknowns = append(unknowns, dep[:2].String())
		}
	}

	return unknowns, columns
}()

type sqlSelect struct {
	Select []authz.Expr
	From   []authz.SQLTableRef
	Where  sqlWhere
}

type sqlWhere struct {
	expr authz.Expr
}

func (x sqlWhere) And(other authz.Expr) sqlWhere {
	if x.expr == nil {
		return sqlWhere{other}
	}
	return sqlWhere{sqlExprAnd{x.expr, other}}
}

func (x sqlWhere) Or(other authz.Expr) sqlWhere {
	if x.expr == nil {
		return sqlWhere{other}
	}
	return sqlWhere{sqlExprOr{x.expr, other}}
}

func (x sqlWhere) Tables() []authz.SQLTableRef { return x.expr.Tables() }

type sqlExprExists struct {
	Query sqlSelect
}

func (x sqlExprExists) Tables() []authz.SQLTableRef {
	return x.Query.From
}

type sqlExprAnd struct {
	LHS authz.Expr
	RHS authz.Expr
}

func (x sqlExprAnd) Tables() []authz.SQLTableRef {
	return append(x.LHS.Tables(), x.RHS.Tables()...)
}

type sqlExprOr struct {
	LHS authz.Expr
	RHS authz.Expr
}

func (x sqlExprOr) Tables() []authz.SQLTableRef {
	return append(x.LHS.Tables(), x.RHS.Tables()...)
}

type sqlExprEq struct {
	LHS sqlOperand
	RHS sqlOperand
}

func (x sqlExprEq) Tables() []authz.SQLTableRef {
	return append(x.LHS.Tables(), x.RHS.Tables()...)
}

type sqlExprIsNotNull struct {
	Column authz.SQLColumnRef
}

func (e sqlExprIsNotNull) Tables() []authz.SQLTableRef {
	return []authz.SQLTableRef{{Table: e.Column.Table}}
}

type sqlOperand interface {
	Tables() []authz.SQLTableRef
	SQL(authz.ArgFn, []any) (string, []any)
}

type sqlString struct {
	Value string
}

type sqlInt struct {
	Value int
}

func (x sqlSelect) SQL(fn authz.ArgFn, args []any) (string, []any) {
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

func (x sqlExprExists) SQL(fn authz.ArgFn, args []any) (string, []any) {
	conditions, args := x.Query.SQL(fn, args)
	return "EXISTS (" + conditions + ")", args
}

func (x sqlExprAnd) SQL(fn authz.ArgFn, args []any) (string, []any) {
	lhs, args := x.LHS.SQL(fn, args)
	rhs, args := x.RHS.SQL(fn, args)
	return lhs + " AND " + rhs, args
}

func (x sqlExprOr) SQL(fn authz.ArgFn, args []any) (string, []any) {
	lhs, args := x.LHS.SQL(fn, args)
	rhs, args := x.RHS.SQL(fn, args)
	return lhs + " OR " + rhs, args
}

func (x sqlExprEq) SQL(fn authz.ArgFn, args []any) (string, []any) {
	lhs, args := x.LHS.SQL(fn, args)
	rhs, args := x.RHS.SQL(fn, args)
	return lhs + "=" + rhs, args
}

func (x sqlExprIsNotNull) SQL(fn authz.ArgFn, args []any) (string, []any) {
	cond, args := x.Column.SQL(fn, args)
	return cond + " IS NOT NULL", args
}

func (x sqlInt) SQL(fn authz.ArgFn, args []any) (string, []any) { return strconv.Itoa(x.Value), args }

func (x sqlString) SQL(fn authz.ArgFn, args []any) (string, []any) {
	return fn(len(args)), append(args, x.Value)
}

func (sqlString) Tables() []authz.SQLTableRef { return nil }
func (sqlInt) Tables() []authz.SQLTableRef    { return nil }

type Access struct {
	principal  string
	tenant     string
	resource   string
	permission string
	name       string
}

func NewAccess() authz.AccessDescriptor {
	return &Access{}
}

func (a *Access) WithPrincipal(principal string) authz.AccessDescriptor {
	a.principal = principal
	return a
}

func (a *Access) WithTenant(tenant string) authz.AccessDescriptor {
	a.tenant = tenant
	return a
}

func (a *Access) WithResource(resource string) authz.AccessDescriptor {
	a.resource = resource
	return a
}

func (a *Access) WithPermission(permission string) authz.AccessDescriptor {
	a.permission = permission
	return a
}

func (a *Access) WithName(name string) authz.AccessDescriptor {
	a.name = name
	return a
}

func (a *Access) ToValue() ast.Value {
	return ast.ObjectTerm(ast.Item(ast.StringTerm("principal"), ast.StringTerm(a.Principal())),
		ast.Item(ast.StringTerm("tenant"), ast.StringTerm(a.Tenant())),
		ast.Item(ast.StringTerm("resource"), ast.StringTerm(a.Resource())),
		ast.Item(ast.StringTerm("permission"), ast.StringTerm(a.Permission())),
		ast.Item(ast.StringTerm("name"), ast.StringTerm(a.Name()))).Value
}

func (a *Access) Principal() string {
	return a.principal
}

func (a *Access) Tenant() string {
	return a.tenant
}

func (a *Access) Resource() string {
	return a.resource
}

func (a *Access) Permission() string {
	return a.permission
}

func (a *Access) Name() string {
	return a.name
}

type OPAuthorizer struct{}

func (a *OPAuthorizer) Check(ctx context.Context, tx *sql.Tx, fn authz.ArgFn, accessDescriptor authz.AccessDescriptor) bool {
	expr, err := a.Partial(ctx, accessDescriptor, nil)
	if err != nil {
		return false
	}

	var x any
	cond, args := expr.SQL(fn, nil)
	return tx.QueryRowContext(ctx, `SELECT 1 WHERE `+cond, args...).Scan(&x) == nil
}

func (*OPAuthorizer) Partial(ctx context.Context, accessDescriptor authz.AccessDescriptor, extraColumnMappings map[string]authz.SQLColumnRef) (authz.Expr, error) {
	access, ok := accessDescriptor.(*Access)
	if !ok {
		return nil, errors.New("unknown access descriptor type")
	}

	return partialCache.Get(*access, extraColumnMappings, func() (authz.Expr, error) {
		return partial(ctx, access, extraColumnMappings)
	})
}

func partial(ctx context.Context, access *Access, extraColumnMappings map[string]authz.SQLColumnRef) (authz.Expr, error) {
	extraUnknowns := make([]string, 0, len(extraColumnMappings))
	for k := range extraColumnMappings {
		extraUnknowns = append(extraUnknowns, k)
	}

	pqs, err := rego.New(
		rego.Query("data.authz.allow = true"),
		rego.Module("authz.rego", src),
		rego.Unknowns(append(extraUnknowns, defaultUnknowns...)),
		rego.ParsedInput(access.ToValue()),
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
		exists.Query.Select = []authz.Expr{sqlInt{Value: 1}}

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

		seen := map[authz.SQLTableRef]struct{}{}

		for _, t := range exists.Query.Where.Tables() {
			if t.Table != access.Resource() {
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

type columnMapper map[string]authz.SQLColumnRef

func (cm columnMapper) trySqlExprIsNotNull(a, b *ast.Term) (authz.Expr, bool) {
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

func (cm columnMapper) trySqlColumnOperand(ref ast.Ref) (authz.SQLColumnRef, bool) {
	if c, ok := cm[ref.String()]; ok {
		return c, true
	}
	return authz.SQLColumnRef{}, false
}
