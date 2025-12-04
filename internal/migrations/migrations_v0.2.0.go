package migrations

// NOTE(sr): Here, we collect the migrations up until version v0.2.0. Consider this file immutable.

import (
	"fmt"
	"io/fs"
	"strings"

	ocp_fs "github.com/open-policy-agent/opa-control-plane/internal/fs"
)

func addBundleOptions(dialect string) fs.FS {
	var stmt string
	switch dialect {
	case "sqlite", "postgresql":
		stmt = `ALTER TABLE bundles ADD options TEXT;`
	case "mysql":
		stmt = `ALTER TABLE bundles ADD options VARCHAR(255)`
	case "cockroachdb": // nothing
	}

	return ocp_fs.MapFS(map[string]string{
		"018_add_bundles_options.up.sql": stmt,
	})
}

func addBundleInterval(dialect string) fs.FS {
	var stmt string
	switch dialect {
	case "sqlite", "postgresql":
		stmt = `ALTER TABLE bundles ADD rebuild_interval TEXT`
	case "mysql":
		stmt = `ALTER TABLE bundles ADD rebuild_interval VARCHAR(255)`
	case "cockroachdb": // nothing
	}

	return ocp_fs.MapFS(map[string]string{
		"017_add_bundles_interval.up.sql": stmt,
	})
}

func addMounts(dialect string) fs.FS {
	var stmtBundles, stmtSources, stmtStacks string
	switch dialect {
	case "sqlite": // NB(sr): sqlite doesn't support adding multiple columns in one statement
		stmtBundles = `ALTER TABLE bundles_requirements ADD prefix TEXT; ALTER TABLE bundles_requirements ADD path TEXT`
		stmtSources = `ALTER TABLE sources_requirements ADD prefix TEXT; ALTER TABLE sources_requirements ADD path TEXT`
		stmtStacks = `ALTER TABLE stacks_requirements ADD prefix TEXT; ALTER TABLE stacks_requirements ADD path TEXT`
	case "postgresql":
		stmtBundles = `ALTER TABLE bundles_requirements ADD prefix TEXT, ADD path TEXT`
		stmtSources = `ALTER TABLE sources_requirements ADD prefix TEXT, ADD path TEXT`
		stmtStacks = `ALTER TABLE stacks_requirements ADD prefix TEXT, ADD path TEXT`
	case "mysql":
		stmtBundles = `ALTER TABLE bundles_requirements ADD prefix VARCHAR(255), ADD path VARCHAR(255)`
		stmtSources = `ALTER TABLE sources_requirements ADD prefix VARCHAR(255), ADD path VARCHAR(255)`
		stmtStacks = `ALTER TABLE stacks_requirements ADD prefix VARCHAR(255), ADD path VARCHAR(255)`
	case "cockroachdb": // nothing
	}

	return ocp_fs.MapFS(map[string]string{
		"014_add_mounts_bundles.up.sql": stmtBundles,
		"015_add_mounts_sources.up.sql": stmtSources,
		"016_add_mounts_stacks.up.sql":  stmtStacks,
	})
}

func initialSchemaFS(dialect string) fs.FS {
	var kind int
	switch dialect {
	case "postgresql":
		kind = postgres
	case "mysql":
		kind = mysql
	case "sqlite":
		kind = sqlite
	case "cockroachdb":
		kind = cockroachdb
	}
	m := make(map[string]string, len(schema))
	for i, tbl := range schema {
		f := fmt.Sprintf("%03d_%s.up.sql", i, tbl.name)
		if kind == cockroachdb {
			m[f] = ""
		} else {
			m[f] = tbl.SQL(kind)
		}
	}
	return ocp_fs.MapFS(m)
}

// schema holds the initial set of database tables, dating back to when database
// migrations were introduced. THESE MAY NOT BE CHANGED, as the migrations machinery
// would fall apart for anyone who already applied these migrations.
// They are the basis of all further migrations. We keep them here because it's
// convenient to lookup the tables and there relations in one place -- the initial
// migrations are generated from for each of the dialects we support.
var schema = []*sqlTable{
	createSQLTable("bundles").
		IntegerPrimaryKeyAutoincrementColumn("id").
		VarCharNonNullUniqueColumn("name").
		TextColumn("labels").
		TextColumn("s3url").
		TextColumn("s3region").
		TextColumn("s3bucket").
		TextColumn("s3key").
		TextColumn("gcp_project").
		TextColumn("gcp_object").
		TextColumn("azure_account_url").
		TextColumn("azure_container").
		TextColumn("azure_path").
		TextColumn("filepath").
		TextColumn("excluded"),
	createSQLTable("sources").
		IntegerPrimaryKeyAutoincrementColumn("id").
		VarCharNonNullUniqueColumn("name").
		TextColumn("builtin").
		TextNonNullColumn("repo").
		TextColumn("ref").
		TextColumn("gitcommit").
		TextColumn("path").
		TextColumn("git_included_files").
		TextColumn("git_excluded_files"),
	createSQLTable("stacks").
		IntegerPrimaryKeyAutoincrementColumn("id").
		VarCharNonNullUniqueColumn("name").
		TextNonNullColumn("selector").
		TextColumn("exclude_selector"),
	createSQLTable("secrets").
		IntegerPrimaryKeyAutoincrementColumn("id").
		VarCharNonNullUniqueColumn("name").
		TextColumn("value"),
	createSQLTable("tokens").
		VarCharPrimaryKeyColumn("name").
		TextNonNullColumn("api_key"),
	createSQLTable("bundles_secrets").
		VarCharNonNullColumn("bundle_name").
		VarCharNonNullColumn("secret_name").
		TextNonNullColumn("ref_type").
		PrimaryKey("bundle_name", "secret_name").
		ForeignKey("bundle_name", "bundles(name)").
		ForeignKey("secret_name", "secrets(name)"),
	createSQLTable("bundles_requirements").
		VarCharNonNullColumn("bundle_name").
		VarCharNonNullColumn("source_name").
		TextColumn("gitcommit").
		PrimaryKey("bundle_name", "source_name").
		ForeignKey("bundle_name", "bundles(name)").
		ForeignKey("source_name", "sources(name)"),
	createSQLTable("stacks_requirements").
		VarCharNonNullColumn("stack_name").
		VarCharNonNullColumn("source_name").
		TextColumn("gitcommit").
		PrimaryKey("stack_name", "source_name").
		ForeignKey("stack_name", "stacks(name)").
		ForeignKey("source_name", "sources(name)"),
	createSQLTable("sources_requirements").
		VarCharNonNullColumn("source_name").
		VarCharNonNullColumn("requirement_name").
		TextColumn("gitcommit").
		PrimaryKey("source_name", "requirement_name").
		ForeignKey("source_name", "sources(name)").
		ForeignKey("requirement_name", "sources(name)"),
	createSQLTable("sources_secrets").
		VarCharNonNullColumn("source_name").
		VarCharNonNullColumn("secret_name").
		TextNonNullColumn("ref_type").
		PrimaryKey("source_name", "secret_name").
		ForeignKey("source_name", "sources(name)").
		ForeignKey("secret_name", "secrets(name)"),
	createSQLTable("sources_data").
		VarCharNonNullColumn("source_name").
		VarCharNonNullColumn("path").
		BlobNonNullColumn("data").
		PrimaryKey("source_name", "path").
		ForeignKey("source_name", "sources(name)"),
	createSQLTable("sources_datasources").
		VarCharNonNullColumn("name").
		VarCharNonNullColumn("source_name").
		VarCharColumn("secret_name").
		TextNonNullColumn("type").
		TextNonNullColumn("path").
		TextNonNullColumn("config").
		TextNonNullColumn("transform_query").
		PrimaryKey("source_name", "name").
		ForeignKey("secret_name", "secrets(name)").
		ForeignKey("source_name", "sources(name)"),
	createSQLTable("principals").
		VarCharPrimaryKeyColumn("id").
		TextNonNullColumn("role").
		TimestampDefaultCurrentTimeColumn("created_at"),
	createSQLTable("resource_permissions").
		VarCharNonNullColumn("name").
		VarCharNonNullColumn("resource").
		VarCharNonNullColumn("principal_id").
		TextColumn("role").
		TextColumn("permission").
		TimestampDefaultCurrentTimeColumn("created_at").
		PrimaryKey("name", "resource").
		ForeignKeyOnDeleteCascade("principal_id", "principals(id)"),
}

const (
	sqlite = iota
	postgres
	mysql
	cockroachdb
)

type sqlColumn struct {
	Name                    string
	Type                    sqlDataType
	AutoIncrementPrimaryKey bool
	PrimaryKey              bool
	Unique                  bool
	NotNull                 bool
	Default                 string
}

type sqlDataType interface {
	SQL(kind int) string
}

type sqlInteger struct{}
type sqlText struct{}
type sqlBlob struct{}
type sqlTimestamp struct{}
type sqlVarChar struct{}

func (sqlInteger) SQL(kind int) string {
	switch kind {
	case sqlite:
		return "INTEGER"
	case postgres, cockroachdb:
		return "INTEGER"
	case mysql:
		return "INT"
	}

	panic("unknown kind")
}

func (sqlText) SQL(_ int) string {
	return "TEXT"
}

func (sqlBlob) SQL(kind int) string {
	switch kind {
	case sqlite:
		return "BLOB"
	case postgres, cockroachdb:
		return "BYTEA"
	case mysql:
		return "BLOB"
	}

	panic("unknown kind")
}

func (sqlTimestamp) SQL(_ int) string {
	return "TIMESTAMP"
}

func (sqlVarChar) SQL(kind int) string {
	switch kind {
	case sqlite:
		return "TEXT"
	case postgres, cockroachdb:
		return "VARCHAR(255)"
	case mysql:
		return "VARCHAR(255)"
	}

	panic("unknown kind")
}

func (c sqlColumn) SQL(kind int) string {
	var parts []string

	if c.AutoIncrementPrimaryKey {
		switch kind {
		case sqlite:
			parts = append(parts, c.Name, sqlInteger{}.SQL(kind))
		case postgres, cockroachdb:
			parts = append(parts, c.Name, "SERIAL")
		case mysql:
			parts = append(parts, c.Name, sqlInteger{}.SQL(kind), "AUTO_INCREMENT")
		}
	} else {
		parts = append(parts, c.Name, c.Type.SQL(kind))
		if c.NotNull {
			parts = append(parts, "NOT NULL")
		}
		if c.Default != "" {
			parts = append(parts, "DEFAULT", c.Default)
		}
	}

	return strings.Join(parts, " ")
}

type sqlForeignKey struct {
	Column          string
	References      string
	OnDeleteCascade bool
}

type sqlConstraint struct {
	Columns []string
}

type sqlTable struct {
	name              string
	columns           []sqlColumn
	primaryKeyColumns []string
	foreignKeys       []sqlForeignKey
	unique            []sqlConstraint
	iteration         string // prefix for constraints
}

func createSQLTable(name string) *sqlTable {
	return &sqlTable{
		name:      name,
		iteration: "ocp_v1",
	}
}
func (t *sqlTable) WithColumn(col sqlColumn) *sqlTable {
	t.columns = append(t.columns, col)
	return t
}

func (t *sqlTable) WithIteration(s string) *sqlTable {
	t.iteration = s
	return t
}

func (t *sqlTable) IntegerPrimaryKeyAutoincrementColumn(name string) *sqlTable {
	t.columns = append(t.columns, sqlColumn{Name: name, Type: sqlInteger{}, AutoIncrementPrimaryKey: true})
	return t
}

func (t *sqlTable) IntegerNonNullColumn(name string) *sqlTable {
	t.columns = append(t.columns, sqlColumn{Name: name, Type: sqlInteger{}, NotNull: true})
	return t
}

func (t *sqlTable) IntegerColumn(name string) *sqlTable {
	t.columns = append(t.columns, sqlColumn{Name: name, Type: sqlInteger{}})
	return t
}

func (t *sqlTable) TextNonNullUniqueColumn(name string) *sqlTable {
	t.columns = append(t.columns, sqlColumn{Name: name, Type: sqlText{}, NotNull: true, Unique: true})
	return t
}

func (t *sqlTable) VarCharNonNullUniqueColumn(name string) *sqlTable {
	t.columns = append(t.columns, sqlColumn{Name: name, Type: sqlVarChar{}, NotNull: true, Unique: true})
	return t
}

func (t *sqlTable) VarCharColumn(name string) *sqlTable {
	t.columns = append(t.columns, sqlColumn{Name: name, Type: sqlVarChar{}})
	return t
}

func (t *sqlTable) TextColumn(name string) *sqlTable {
	t.columns = append(t.columns, sqlColumn{Name: name, Type: sqlText{}})
	return t
}

func (t *sqlTable) TextPrimaryKeyColumn(name string) *sqlTable {
	t.columns = append(t.columns, sqlColumn{Name: name, Type: sqlText{}, PrimaryKey: true})
	return t
}

func (t *sqlTable) VarCharPrimaryKeyColumn(name string) *sqlTable {
	t.columns = append(t.columns, sqlColumn{Name: name, Type: sqlVarChar{}, PrimaryKey: true})
	return t
}

func (t *sqlTable) TextNonNullColumn(name string) *sqlTable {
	t.columns = append(t.columns, sqlColumn{Name: name, Type: sqlText{}, NotNull: true})
	return t
}

func (t *sqlTable) VarCharNonNullColumn(name string) *sqlTable {
	t.columns = append(t.columns, sqlColumn{Name: name, Type: sqlVarChar{}, NotNull: true})
	return t
}

func (t *sqlTable) BlobNonNullColumn(name string) *sqlTable {
	t.columns = append(t.columns, sqlColumn{Name: name, Type: sqlBlob{}, NotNull: true})
	return t
}

func (t *sqlTable) TimestampDefaultCurrentTimeColumn(name string) *sqlTable {
	t.columns = append(t.columns, sqlColumn{Name: name, Type: sqlTimestamp{}, Default: "CURRENT_TIMESTAMP"})
	return t
}

func (t *sqlTable) PrimaryKey(columns ...string) *sqlTable {
	t.primaryKeyColumns = columns
	return t
}

func (t *sqlTable) ForeignKey(column string, references string) *sqlTable {
	t.foreignKeys = append(t.foreignKeys, sqlForeignKey{
		Column:     column,
		References: references,
	})
	return t
}

func (t *sqlTable) Unique(columns ...string) *sqlTable {
	t.unique = append(t.unique, sqlConstraint{
		Columns: columns,
	})
	return t
}

func (t *sqlTable) ForeignKeyOnDeleteCascade(column string, references string) *sqlTable {
	t.foreignKeys = append(t.foreignKeys, sqlForeignKey{
		Column:          column,
		References:      references,
		OnDeleteCascade: true,
	})
	return t
}

func (t *sqlTable) SQL(kind int) string {
	c := make([]string, len(t.columns))
	for i := range t.columns {
		c[i] = t.columns[i].SQL(kind)
	}

	// NOTE(sr): All constraints have names we control. That makes them easier to work
	// with in future migrations: you can remove them during the migration, for example.
	// If we don't control them here, MySQL/Postgres/SQLite/CRDB will pick names for us
	// and they're unlikely to match across all four of them.

	for i := range t.columns {
		if t.columns[i].AutoIncrementPrimaryKey || t.columns[i].PrimaryKey {
			c = append(c, fmt.Sprintf("CONSTRAINT %[1]s_%[2]s_%[3]s_pkey PRIMARY KEY (%[3]s)", t.iteration, t.name, t.columns[i].Name))
		}
		if t.columns[i].Unique {
			c = append(c, fmt.Sprintf("CONSTRAINT %[1]s_%[2]s_%[3]s_unique UNIQUE (%[3]s)", t.iteration, t.name, t.columns[i].Name))
		}
	}

	if len(t.primaryKeyColumns) > 0 {
		c = append(c, fmt.Sprintf("CONSTRAINT %s_%s_%s_pkey PRIMARY KEY (%s)",
			t.iteration,
			t.name,
			strings.Join(t.primaryKeyColumns, "_"),
			strings.Join(t.primaryKeyColumns, ", "),
		))
	}

	for _, fk := range t.foreignKeys {
		// refs look like "table(col)"
		open, closed := strings.Index(fk.References, "("), len(fk.References)-1
		fTbl, fCol := fk.References[:open], fk.References[open+1:closed]
		f := fmt.Sprintf("CONSTRAINT %s_%s_%s_%s_%s_fkey FOREIGN KEY (%s) REFERENCES %s",
			t.iteration,
			t.name, fk.Column, fTbl, fCol,
			fk.Column,
			fk.References,
		)
		if fk.OnDeleteCascade {
			f += " ON DELETE CASCADE"
		}
		c = append(c, f)
	}
	for _, constraint := range t.unique {
		c = append(c, fmt.Sprintf("CONSTRAINT %s_%s_%s_unique UNIQUE (%s)",
			t.iteration,
			t.name,
			strings.Join(constraint.Columns, "_"),
			strings.Join(constraint.Columns, ", ")))
	}
	return `CREATE TABLE IF NOT EXISTS ` + t.name + ` (` + strings.Join(c, ", ") + `);`
}
