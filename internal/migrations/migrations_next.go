package migrations

import (
	"fmt"
	"io/fs"
	"slices"
	"strings"

	ocp_fs "github.com/open-policy-agent/opa-control-plane/internal/fs"
)

// NOTE(sr): We create new tables to drop constraints. It's hard to predict constraint names
// across MySQL and Postgres if they have not been set up at creation time.
// The only tables left untouched from before are:
// - tokens
// NOTE(sr): We want this to work, or fail, in one step. So this will all be done in a single migration,
// in a single transaction.
// TODO(sr): Let's change a couple of things so that this setup will be lazily evaluated. Most of the
// service startups will not need thesse statements after all.
// NOTE(sr): For cockroachdb, we'll only apply this, and skip all the previous migrations. That's because
// the migrations are particularly hairy to get right on cockroachdb, and we have no need to do that,
// since support for it was merged _after_ those migrations. So there's no cockroachdb-using OCP install
// that would need some data migration.
func crossTablesWithIDPKeys(offset int, dialect string) fs.FS {
	var kind int
	switch dialect {
	case "cockroachdb":
		kind = cockroachdb
	case "postgresql":
		kind = postgres
	case "mysql":
		kind = mysql
	case "sqlite":
		kind = sqlite
	}

	stmts := make([]string, 0, len(v2Tables)*4)
	if kind != sqlite {
		stmts = append(stmts, "BEGIN")
	}
	if kind == cockroachdb {
		stmts = append(stmts, createSQLTable("tokens").WithIteration("ocp_v2").VarCharPrimaryKeyColumn("name").TextNonNullColumn("api_key").SQL(kind))
	}

	for _, tbl := range v2Tables {
		oldName := tbl.name + "_old"
		if tbl.name == "tenants" { // new table
			stmts = append(stmts,
				strings.TrimRight(tbl.SQL(kind), ";"),
				fmt.Sprintf(`INSERT INTO %s (name) VALUES ('default')`, tbl.name),
			)
		} else {
			if kind != cockroachdb {
				stmts = append(stmts, fmt.Sprintf("ALTER TABLE %s RENAME TO %s", tbl.name, oldName)) // rename to old
			}

			stmts = append(stmts, strings.TrimRight(tbl.SQL(kind), ";")) // create new

			if kind != cockroachdb {
				stmts = append(stmts, tableCopy(oldName, tbl)) // copy data old -> new
			}
		}
	}

	if kind != cockroachdb {
		for i := len(v2Tables) - 1; i > 0; i-- { // drop stuff bottom-to-top; ignore first table ("tenants")
			stmts = append(stmts, fmt.Sprintf("DROP TABLE %s_old", v2Tables[i].name)) // delete old
		}
	}
	if kind != sqlite {
		stmts = append(stmts, "COMMIT;")
	}
	f := fmt.Sprintf("%03d_tenants.up.sql", offset)
	return ocp_fs.MapFS(map[string]string{f: strings.Join(stmts, "; ")})
}

var v2Tables = []sqlTable{
	// tenants, new
	createSQLTable("tenants").
		IntegerPrimaryKeyAutoincrementColumn("id").
		VarCharNonNullColumn("name").
		Unique("name"),

	createSQLTable("principals").
		VarCharPrimaryKeyColumn("id").
		IntegerNonNullColumn("tenant_id").
		Unique("tenant_id", "id").
		TextNonNullColumn("role").
		TimestampDefaultCurrentTimeColumn("created_at"),

	// This is backing our ownership logic -- it's referencing other tables in a weak manner:
	// e.g. resource = "bundles", name = "my-bundle". Since all our names are only unique in
	// a single tenant, this table needs to be tenant-indexed, too.
	createSQLTable("resource_permissions").
		VarCharNonNullColumn("name").
		VarCharNonNullColumn("resource").
		VarCharNonNullColumn("principal_id").
		IntegerNonNullColumn("tenant_id").
		TextColumn("role").
		TextColumn("permission").
		TimestampDefaultCurrentTimeColumn("created_at").
		PrimaryKey("name", "resource", "tenant_id").
		ForeignKeyOnDeleteCascade("tenant_id", "tenants(id)").
		ForeignKeyOnDeleteCascade("principal_id", "principals(id)"),

	// entity tables
	createSQLTable("bundles").
		IntegerPrimaryKeyAutoincrementColumn("id").
		IntegerNonNullColumn("tenant_id").
		ForeignKeyOnDeleteCascade("tenant_id", "tenants(id)").
		VarCharNonNullColumn("name").
		Unique("tenant_id", "name").
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
		TextColumn("excluded").
		TextColumn("rebuild_interval").
		TextColumn("options"),
	createSQLTable("sources").
		IntegerPrimaryKeyAutoincrementColumn("id").
		IntegerNonNullColumn("tenant_id").
		ForeignKeyOnDeleteCascade("tenant_id", "tenants(id)").
		VarCharNonNullColumn("name").
		Unique("tenant_id", "name").
		TextColumn("builtin").
		TextNonNullColumn("repo").
		TextColumn("ref").
		TextColumn("gitcommit").
		TextColumn("path").
		TextColumn("git_included_files").
		TextColumn("git_excluded_files"),
	createSQLTable("stacks").
		IntegerPrimaryKeyAutoincrementColumn("id").
		IntegerNonNullColumn("tenant_id").
		ForeignKeyOnDeleteCascade("tenant_id", "tenants(id)").
		Unique("tenant_id", "name").
		VarCharNonNullColumn("name").
		TextNonNullColumn("selector").
		TextColumn("exclude_selector"),
	createSQLTable("secrets").
		IntegerPrimaryKeyAutoincrementColumn("id").
		IntegerNonNullColumn("tenant_id").
		ForeignKeyOnDeleteCascade("tenant_id", "tenants(id)").
		VarCharNonNullColumn("name").
		Unique("tenant_id", "name").
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
		TextColumn("path").
		TextColumn("prefix").
		PrimaryKey("bundle_id", "source_id").
		ForeignKey("bundle_id", "bundles(id)").
		ForeignKey("source_id", "sources(id)"),
	createSQLTable("stacks_requirements").
		IntegerNonNullColumn("stack_id").
		IntegerNonNullColumn("source_id").
		TextColumn("gitcommit").
		TextColumn("path").
		TextColumn("prefix").
		PrimaryKey("stack_id", "source_id").
		ForeignKey("stack_id", "stacks(id)").
		ForeignKey("source_id", "sources(id)"),
	createSQLTable("sources_requirements").
		IntegerNonNullColumn("source_id").
		IntegerNonNullColumn("requirement_id").
		TextColumn("gitcommit").
		TextColumn("path").
		TextColumn("prefix").
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
		VarCharNonNullColumn("path").
		BlobNonNullColumn("data").
		PrimaryKey("source_id", "path").
		ForeignKey("source_id", "sources(id)"),
	createSQLTable("sources_datasources").
		VarCharNonNullColumn("name").
		IntegerNonNullColumn("source_id").
		IntegerColumn("secret_id"). // optional
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
func tableCopy(oldName string, st sqlTable) string {
	cols := make([]string, 0, len(st.columns))
	colsSelect := make([]string, 0, len(st.columns))
	joins := make([]string, 0, len(st.foreignKeys))
	for _, col := range st.columns {
		if col.AutoIncrementPrimaryKey {
			continue
		}
		cols = append(cols, col.Name)
		if col.Name == "tenant_id" {
			colsSelect = append(colsSelect, "(SELECT id FROM tenants WHERE tenants.name = 'default')")
			continue // this one is new
		}
		if col.Name == "principal_id" {
			colsSelect = append(colsSelect, oldName+"."+col.Name)
			continue
		}
		if idx := slices.IndexFunc(st.foreignKeys, func(f sqlForeignKey) bool { return f.Column == col.Name }); idx != -1 { // lookup IDs by name from old table
			fk := st.foreignKeys[idx]
			fkTbl, _, _ := strings.Cut(fk.References, "(")
			entity, _, _ := strings.Cut(col.Name, "_")
			joinTbl := fmt.Sprintf("%s_%d", fkTbl, idx)
			joins = append(joins, fmt.Sprintf("JOIN %[1]s AS %[2]s ON %[3]s.%[4]s_name = %[2]s.name", fkTbl, joinTbl, oldName, entity, idx))
			colsSelect = append(colsSelect, fmt.Sprintf("%s.%s AS %s", joinTbl, "id", col.Name))
			continue
		}
		colsSelect = append(colsSelect, oldName+"."+col.Name)
	}
	cpy := fmt.Sprintf(`INSERT INTO %s (%s) SELECT %s FROM %s %s`,
		st.name,
		strings.Join(cols, ", "),
		strings.Join(colsSelect, ", "),
		oldName,
		strings.Join(joins, " "),
	)
	return cpy
}
