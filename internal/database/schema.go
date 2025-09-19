package database

import (
	"fmt"
	"slices"
	"strings"
)

var schema = []sqlTable{
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
		VarCharPrimaryKeyColumn("name").
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
	case postgres:
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
	case postgres:
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
	case postgres:
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
			parts = append(parts, []string{c.Name, sqlInteger{}.SQL(kind), "PRIMARY KEY", "AUTOINCREMENT"}...)
		case postgres:
			parts = append(parts, []string{c.Name, "SERIAL"}...)
		case mysql:
			parts = append(parts, []string{c.Name, sqlInteger{}.SQL(kind), "PRIMARY KEY", "AUTO_INCREMENT"}...)
		}
	} else {
		parts = append(parts, []string{c.Name, c.Type.SQL(kind)}...)

		if c.PrimaryKey {
			parts = append(parts, "PRIMARY KEY")
		}
		if c.NotNull {
			parts = append(parts, "NOT NULL")
		}
		if c.Unique {
			parts = append(parts, "UNIQUE")
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

type sqlTable struct {
	name              string
	columns           []sqlColumn
	primaryKeyColumns []string
	foreignKeys       []sqlForeignKey
}

func createSQLTable(name string) sqlTable {
	return sqlTable{
		name: name,
	}
}

func (t sqlTable) WithColumn(col sqlColumn) sqlTable {
	t.columns = append(t.columns, col)
	return t
}

func (t sqlTable) IntegerPrimaryKeyAutoincrementColumn(name string) sqlTable {
	t.columns = append(t.columns, sqlColumn{Name: name, Type: sqlInteger{}, AutoIncrementPrimaryKey: true})
	return t
}

func (t sqlTable) TextNonNullUniqueColumn(name string) sqlTable {
	t.columns = append(t.columns, sqlColumn{Name: name, Type: sqlText{}, NotNull: true, Unique: true})
	return t
}

func (t sqlTable) VarCharNonNullUniqueColumn(name string) sqlTable {
	t.columns = append(t.columns, sqlColumn{Name: name, Type: sqlVarChar{}, NotNull: true, Unique: true})
	return t
}

func (t sqlTable) VarCharColumn(name string) sqlTable {
	t.columns = append(t.columns, sqlColumn{Name: name, Type: sqlVarChar{}})
	return t
}

func (t sqlTable) TextColumn(name string) sqlTable {
	t.columns = append(t.columns, sqlColumn{Name: name, Type: sqlText{}})
	return t
}

func (t sqlTable) TextPrimaryKeyColumn(name string) sqlTable {
	t.columns = append(t.columns, sqlColumn{Name: name, Type: sqlText{}, PrimaryKey: true})
	return t
}

func (t sqlTable) VarCharPrimaryKeyColumn(name string) sqlTable {
	t.columns = append(t.columns, sqlColumn{Name: name, Type: sqlVarChar{}, PrimaryKey: true})
	return t
}

func (t sqlTable) TextNonNullColumn(name string) sqlTable {
	t.columns = append(t.columns, sqlColumn{Name: name, Type: sqlText{}, NotNull: true})
	return t
}

func (t sqlTable) VarCharNonNullColumn(name string) sqlTable {
	t.columns = append(t.columns, sqlColumn{Name: name, Type: sqlVarChar{}, NotNull: true})
	return t
}

func (t sqlTable) BlobNonNullColumn(name string) sqlTable {
	t.columns = append(t.columns, sqlColumn{Name: name, Type: sqlBlob{}, NotNull: true})
	return t
}

func (t sqlTable) TimestampDefaultCurrentTimeColumn(name string) sqlTable {
	t.columns = append(t.columns, sqlColumn{Name: name, Type: sqlTimestamp{}, Default: "CURRENT_TIMESTAMP"})
	return t
}

func (t sqlTable) PrimaryKey(columns ...string) sqlTable {
	t.primaryKeyColumns = columns
	return t
}

func (t sqlTable) ForeignKey(column string, references string) sqlTable {
	t.foreignKeys = append(t.foreignKeys, sqlForeignKey{
		Column:     column,
		References: references,
	})
	return t
}

func (t sqlTable) ForeignKeyOnDeleteCascade(column string, references string) sqlTable {
	t.foreignKeys = append(t.foreignKeys, sqlForeignKey{
		Column:          column,
		References:      references,
		OnDeleteCascade: true,
	})
	return t
}

func (t sqlTable) SQL(kind int) string {
	c := make([]string, len(t.columns))
	for i := range t.columns {
		c[i] = t.columns[i].SQL(kind)
	}

	if len(t.primaryKeyColumns) > 0 {
		c = append(c, "PRIMARY KEY ("+strings.Join(t.primaryKeyColumns, ", ")+")")
	}

	for _, fk := range t.foreignKeys {
		f := "FOREIGN KEY (" + fk.Column + ") REFERENCES " + fk.References
		if fk.OnDeleteCascade {
			f += " ON DELETE CASCADE"
		}

		c = append(c, f)
	}

	return `CREATE TABLE IF NOT EXISTS ` + t.name + ` (
			` + strings.Join(c, ",\n") + `);`
}

// checkTablePrimaryKey checks if the primary key columns for a table match the schema.
// It serves to validate that the primary key columns specified in the upsert operation are valid.
func checkTablePrimaryKey(table string, primaryKey []string) error {
	for _, t := range schema {
		if t.name == table {
			if len(primaryKey) == 1 {
				for _, col := range t.columns {
					if col.Name == primaryKey[0] && (col.PrimaryKey || col.Unique) {
						return nil
					}
				}

				return fmt.Errorf("primary key column %q not found in table %q", primaryKey[0], table)
			}

			if len(primaryKey) != len(t.primaryKeyColumns) {
				return fmt.Errorf("invalid number of primary key columns for table %q: expected %d, got %d", table, len(t.primaryKeyColumns), len(primaryKey))
			}

			if !slices.Equal(primaryKey, t.primaryKeyColumns) {
				return fmt.Errorf("primary key columns %v do not match expected columns %v for table %q", primaryKey, t.primaryKeyColumns, table)
			}

			return nil
		}
	}

	return fmt.Errorf("table %q not found in schema", table)
}
