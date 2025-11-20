package migrations

import (
	"fmt"
	"io/fs"
	"log"
	"slices"
	"strings"

	ocp_fs "github.com/open-policy-agent/opa-control-plane/internal/fs"
)

// NOTE(sr): We create new tables to drop constraints. It's hard to predict constraint names
// across MySQL and Postgres if they have not been set up at creation time.
// The only tables left untouched from before are:
// - principals
// - resource_permissions
// - tokens

func crossTablesWithIDPKeys(offset int, dialect string) fs.FS {
	m := make(map[string]string, len(v2Tables))
	var kind int
	switch dialect {
	case "postgresql":
		kind = postgres
	case "mysql":
		kind = mysql
	case "sqlite":
		kind = sqlite
	}

	for i, tbl := range v2Tables {
		stmts := make([]string, 6)
		switch kind {
		case mysql, postgres:
			stmts[0], stmts[5] = "BEGIN", "COMMIT"
		case sqlite:
			stmts[0], stmts[5] = "/**/", "/**/"
		}
		stmts[1] = fmt.Sprintf("ALTER TABLE %[1]s RENAME TO %[1]s_old", tbl.name) // rename to old
		stmts[2] = tbl.SQL(kind)                                                  // create new
		stmts[3] = tableCopy(tbl)                                                 // copy data old -> new
		stmts[4] = fmt.Sprintf("DROP TABLE %s_old", tbl.name)                     // delete old

		f := fmt.Sprintf("%03d_%s.up.sql", i+offset, tbl.name)
		m[f] = strings.Join(stmts, ";\n")
	}
	return ocp_fs.MapFS(m)
}

var v2Tables = []sqlTable{
	// entity tables
	createSQLTable("bundles").
		IntegerPrimaryKeyAutoincrementColumn("id").
		VarCharNonNullColumn("name").
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
		VarCharNonNullColumn("name").
		TextColumn("builtin").
		TextNonNullColumn("repo").
		TextColumn("ref").
		TextColumn("gitcommit").
		TextColumn("path").
		TextColumn("git_included_files").
		TextColumn("git_excluded_files"),
	createSQLTable("stacks").
		IntegerPrimaryKeyAutoincrementColumn("id").
		VarCharNonNullColumn("name").
		TextNonNullColumn("selector").
		TextColumn("exclude_selector"),
	createSQLTable("secrets").
		IntegerPrimaryKeyAutoincrementColumn("id").
		VarCharNonNullColumn("name").
		TextColumn("value"),

	// cross tables
	createSQLTable("bundles_secrets").
		IntegerNonNullColumn("bundle_id").
		IntegerNonNullColumn("secret_id").
		TextNonNullColumn("ref_type").
		PrimaryKey("bundle_id", "secret_id").
		ForeignKey("bundle_id", "bundles(id)").
		ForeignKey("secret_id", "secrets(id)"),
	createSQLTable("bundles_requirements").
		IntegerNonNullColumn("bundle_id").
		IntegerNonNullColumn("source_id").
		TextColumn("gitcommit").
		PrimaryKey("bundle_id", "source_id").
		ForeignKey("bundle_id", "bundles(id)").
		ForeignKey("source_id", "sources(id)"),
	createSQLTable("stacks_requirements").
		IntegerNonNullColumn("stack_id").
		IntegerNonNullColumn("source_id").
		TextColumn("gitcommit").
		PrimaryKey("stack_id", "source_id").
		ForeignKey("stack_id", "stacks(id)").
		ForeignKey("source_id", "sources(id)"),
	createSQLTable("sources_requirements").
		IntegerNonNullColumn("source_id").
		IntegerNonNullColumn("requirement_id").
		TextColumn("gitcommit").
		PrimaryKey("source_id", "requirement_id").
		ForeignKey("source_id", "sources(id)").
		ForeignKey("requirement_id", "sources(id)"),
	createSQLTable("sources_secrets").
		IntegerNonNullColumn("source_id").
		IntegerNonNullColumn("secret_id").
		TextNonNullColumn("ref_type").
		PrimaryKey("source_id", "secret_id").
		ForeignKey("source_id", "sources(id)").
		ForeignKey("secret_id", "secrets(id)"),
	createSQLTable("sources_data").
		IntegerNonNullColumn("source_id").
		IntegerNonNullColumn("path").
		BlobNonNullColumn("data").
		PrimaryKey("source_id", "path").
		ForeignKey("source_id", "sources(id)"),
	createSQLTable("sources_datasources").
		IntegerNonNullColumn("name").
		IntegerNonNullColumn("source_id").
		VarCharColumn("secret_id"). // optional
		TextNonNullColumn("type").
		TextNonNullColumn("path").
		TextNonNullColumn("config").
		TextNonNullColumn("transform_query").
		PrimaryKey("source_id", "name").
		ForeignKey("secret_id", "secrets(id)").
		ForeignKey("source_id", "sources(id)"),
}

// This is our model:
// INSERT INTO bundles_secrets (bundle_id, secret_id, ref_type)
// SELECT
//
//	b.id AS bundle_id,
//
//	s.id AS secret_id,
//	bso.ref_type
//
// FROM
//
//	bundles_secrets_old AS bso
//
// JOIN
//
//	bundles AS b ON bso.bundle_name = b.name
//
// JOIN
//
//	secrets AS s ON bso.secret_name = s.name;
func tableCopy(st sqlTable) string {
	cols := make([]string, 0, len(st.columns))
	colsSelect := make([]string, 0, len(st.columns))
	joins := make([]string, 0, len(st.foreignKeys))
	for _, col := range st.columns {
		if col.AutoIncrementPrimaryKey {
			continue
		}
		cols = append(cols, col.Name)
		if idx := slices.IndexFunc(st.foreignKeys, func(f sqlForeignKey) bool { return f.Column == col.Name }); idx != -1 { // lookup IDs by name from old table
			fk := st.foreignKeys[idx]
			fkTbl, _, _ := strings.Cut(fk.References, "(")
			entity, _, _ := strings.Cut(col.Name, "_")
			joinTbl := fmt.Sprintf("%s_%d", fkTbl, idx)
			joins = append(joins, fmt.Sprintf("JOIN %[1]s AS %[2]s ON %[3]s_old.%[4]s_name = %[2]s.name", fkTbl, joinTbl, st.name, entity, idx))
			colsSelect = append(colsSelect, fmt.Sprintf("%s.%s AS %s", joinTbl, "id", col.Name))
			continue
		}
		colsSelect = append(colsSelect, st.name+"_old."+col.Name)
	}
	cpy := fmt.Sprintf(`INSERT INTO %[1]s (%[2]s) SELECT %[3]s FROM %[1]s_old `, st.name, strings.Join(cols, ", "), strings.Join(colsSelect, ", "))
	if len(joins) > 0 {
		cpy += strings.Join(joins, " ")
	}
	log.Println(cpy)
	return cpy
}
