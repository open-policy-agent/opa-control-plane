package migrations

import (
	"fmt"
	"io/fs"
	"slices"
	"strings"

	ocp_fs "github.com/open-policy-agent/opa-control-plane/internal/fs"
)

func addBundlesRevision(offset int, dialect string) fs.FS {
	var stmt string
	switch dialect {
	case "sqlite", "postgresql", "cockroachdb":
		stmt = `ALTER TABLE bundles ADD revision TEXT`
	case "mysql":
		stmt = `ALTER TABLE bundles ADD revision VARCHAR(255)`
	}

	return ocp_fs.MapFS(map[string]string{
		fmt.Sprintf("%03d_add_bundles_revision.up.sql", offset): stmt,
	})
}

func addSourcesGitCredentialsName(offset int, dialect string) fs.FS {
	var stmt string
	switch dialect {
	case "sqlite", "postgresql", "cockroachdb":
		stmt = `ALTER TABLE sources ADD git_credentials_name TEXT`
	case "mysql":
		stmt = `ALTER TABLE sources ADD git_credentials_name VARCHAR(255)`
	}

	return ocp_fs.MapFS(map[string]string{
		fmt.Sprintf("%03d_add_sources_git_credentials_name.up.sql", offset): stmt,
	})
}

func addDatasourcesCredentialsName(offset int, dialect string) fs.FS {
	var stmt string
	switch dialect {
	case "sqlite", "postgresql", "cockroachdb":
		stmt = `ALTER TABLE sources_datasources ADD credentials_name TEXT`
	case "mysql":
		stmt = `ALTER TABLE sources_datasources ADD credentials_name VARCHAR(255)`
	}

	return ocp_fs.MapFS(map[string]string{
		fmt.Sprintf("%03d_add_datasources_credentials_name.up.sql", offset): stmt,
	})
}

func addRequirementsOptions(offset int, dialect string) fs.FS {
	var stmtBundles, stmtSources, stmtStacks string
	switch dialect {
	case "sqlite", "postgresql", "cockroachdb":
		stmtBundles = `ALTER TABLE bundles_requirements ADD options TEXT`
		stmtSources = `ALTER TABLE sources_requirements ADD options TEXT`
		stmtStacks = `ALTER TABLE stacks_requirements ADD options TEXT`
	case "mysql":
		stmtBundles = `ALTER TABLE bundles_requirements ADD options VARCHAR(255)`
		stmtSources = `ALTER TABLE sources_requirements ADD options VARCHAR(255)`
		stmtStacks = `ALTER TABLE stacks_requirements ADD options VARCHAR(255)`
	}

	return ocp_fs.MapFS(map[string]string{
		fmt.Sprintf("%03d_bundles_requirements_add_options.up.sql", offset):   stmtBundles,
		fmt.Sprintf("%03d_sources_requirements_add_options.up.sql", offset+1): stmtSources,
		fmt.Sprintf("%03d_stacks_requirements_add_options.up.sql", offset+2):  stmtStacks,
	})
}

func addBundlesStatuses(offset int, dialect string) fs.FS {
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

	tbl := createSQLTable("bundles_statuses").
		WithIteration("ocp_v2").
		IntegerPrimaryKeyAutoincrementColumn("id").
		IntegerNonNullColumn("tenant_id").
		IntegerNonNullColumn("bundle_id").
		VarCharNonNullColumn("revision").
		TextNonNullColumn("phase").
		TextNonNullColumn("status").
		TextColumn("error_message").
		Unique("tenant_id", "bundle_id", "revision").
		TimestampDefaultCurrentTimeColumn("created_at").
		ForeignKeyOnDeleteCascade("tenant_id", "tenants(id)").
		ForeignKeyOnDeleteCascade("bundle_id", "bundles(id)")

	return ocp_fs.MapFS(map[string]string{
		fmt.Sprintf("%03d_add_bundles_statuses.up.sql", offset): tbl.SQL(kind),
	})
}

// addBundlesStatusesUpdatedAt adds an updated_at column to bundles_statuses so
// callers can tell when a status last changed.
func addBundlesStatusesUpdatedAt(offset int, dialect string) fs.FS {
	var stmtAdd string
	switch dialect {
	case "sqlite", "postgresql", "cockroachdb", "mysql":
		stmtAdd = `ALTER TABLE bundles_statuses ADD updated_at TIMESTAMP`
	}

	stmtBackfill := `UPDATE bundles_statuses SET updated_at = created_at WHERE updated_at IS NULL`

	return ocp_fs.MapFS(map[string]string{
		fmt.Sprintf("%03d_add_bundles_statuses_updated_at.up.sql", offset):        stmtAdd,
		fmt.Sprintf("%03d_backfill_bundles_statuses_updated_at.up.sql", offset+1): stmtBackfill,
	})
}

// fixDatasourcesPrimaryKey widens the primary key of sources_datasources from
// (source_id, name) to (source_id, name, path). Without "path" in the key,
// two datasources sharing the same "name" but different "path" values collapse
// into a single row on upsert, silently dropping one of them.
//
// Each dialect (other than SQLite) can change the primary key in place, so we
// use that instead of a rename/create/copy/drop table rebuild:
//   - postgresql: drop and add the primary key constraint in one statement.
//   - mysql: drop and add the primary key in one statement. "path" first needs
//     a bounded length, since MySQL can't use a TEXT column in a key.
//   - cockroachdb: ALTER PRIMARY KEY is purpose-built for this and runs online.
//     It demotes the old primary key to a secondary unique index named
//     "<table>_source_id_name_key" (verified empirically), which still
//     enforces the old (source_id, name) uniqueness and would defeat the
//     point of this migration, so we drop that index right after.
//
// The current primary key's name, "ocp_v2_sources_datasources_source_id_name_pkey",
// is predictable: the "ocp_v2" table (see crossTablesWithIDPKeys) always names
// its own constraints the same way across dialects (sqlTable.SQL), so postgresql
// can drop it by name; mysql and cockroachdb don't need the name at all.
//
// SQLite has no ALTER TABLE support for primary keys, so for that dialect we
// still rebuild the table: rename it out of the way, recreate it with the new
// key, copy the data across, and drop the renamed-away copy -- all in one
// migration file, which SQLite's migrate driver already wraps in its own
// transaction.
func fixDatasourcesPrimaryKey(offset int, dialect string) fs.FS {
	const table = "sources_datasources"

	var stmt string
	switch dialect {
	case "postgresql":
		stmt = fmt.Sprintf(
			`ALTER TABLE %[1]s DROP CONSTRAINT ocp_v2_%[1]s_source_id_name_pkey, ADD CONSTRAINT ocp_v2_%[1]s_source_id_name_path_pkey PRIMARY KEY (source_id, name, path)`,
			table,
		)

	case "mysql":
		stmt = fmt.Sprintf(
			`ALTER TABLE %s MODIFY path VARCHAR(255) NOT NULL, DROP PRIMARY KEY, ADD PRIMARY KEY (source_id, name, path)`,
			table,
		)

	case "cockroachdb":
		stmt = fmt.Sprintf(
			`ALTER TABLE %[1]s ALTER PRIMARY KEY USING COLUMNS (source_id, name, path); DROP INDEX %[1]s@%[1]s_source_id_name_key`,
			table,
		)

	case "sqlite":
		newTbl := createSQLTable(table).
			WithIteration("ocp_v2_pkfix"). // distinct from "ocp_v2" to avoid clashing with the old table's constraint names while both exist during the migration
			VarCharNonNullColumn("name").
			IntegerNonNullColumn("source_id").
			IntegerColumn("secret_id"). // optional
			TextNonNullColumn("type").
			VarCharNonNullColumn("path"). // part of the primary key; needs a bounded length for consistency with the other dialects
			TextNonNullColumn("config").
			TextNonNullColumn("transform_query").
			TextColumn("credentials_name").
			PrimaryKey("source_id", "name", "path").
			ForeignKey("secret_id", "secrets(id)").
			ForeignKey("source_id", "sources(id)")

		oldName := table + "_old"
		cols := "name, source_id, secret_id, type, path, config, transform_query, credentials_name"

		stmts := []string{
			fmt.Sprintf("ALTER TABLE %s RENAME TO %s", table, oldName),
			strings.TrimRight(newTbl.SQL(sqlite), ";"),
			fmt.Sprintf(`INSERT INTO %s (%s) SELECT %s FROM %s`, table, cols, cols, oldName),
			"DROP TABLE " + oldName,
		}
		stmt = strings.Join(stmts, "; ")
	}

	return ocp_fs.MapFS(map[string]string{
		fmt.Sprintf("%03d_fix_datasources_primary_key.up.sql", offset): stmt,
	})
}

// addSourcesProviders adds the table for sources' `providers:` entries.
// Entries are keyed by name within their source; config holds the entry's
// own (non-reserved) keys as JSON.
func addSourcesProviders(offset int, dialect string) fs.FS {
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

	tbl := createSQLTable("sources_providers").
		WithIteration("ocp_v2").
		VarCharNonNullColumn("name").
		IntegerNonNullColumn("source_id").
		TextNonNullColumn("type").
		TextNonNullColumn("path").
		TextNonNullColumn("config").
		PrimaryKey("source_id", "name").
		ForeignKey("source_id", "sources(id)")

	return ocp_fs.MapFS(map[string]string{
		fmt.Sprintf("%03d_add_sources_providers.up.sql", offset): tbl.SQL(kind),
	})
}

// NOTE(sr): We create new tables to drop constraints. It's hard to predict constraint names
// across MySQL and Postgres if they have not been set up at creation time.
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

var v2Tables = []*sqlTable{
	// tenants, new
	createSQLTable("tenants").
		WithIteration("ocp_v2").
		IntegerPrimaryKeyAutoincrementColumn("id").
		VarCharNonNullColumn("name").
		Unique("name"),

	createSQLTable("tokens").
		WithIteration("ocp_v2").
		VarCharPrimaryKeyColumn("name").
		TextNonNullColumn("api_key"),

	createSQLTable("principals").
		WithIteration("ocp_v2").
		VarCharPrimaryKeyColumn("id").
		IntegerNonNullColumn("tenant_id").
		Unique("tenant_id", "id").
		TextNonNullColumn("role").
		TimestampDefaultCurrentTimeColumn("created_at"),

	// This is backing our ownership logic -- it's referencing other tables in a weak manner:
	// e.g. resource = "bundles", name = "my-bundle". Since all our names are only unique in
	// a single tenant, this table needs to be tenant-indexed, too.
	createSQLTable("resource_permissions").
		WithIteration("ocp_v2").
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
		WithIteration("ocp_v2").
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
		WithIteration("ocp_v2").
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
		WithIteration("ocp_v2").
		IntegerPrimaryKeyAutoincrementColumn("id").
		IntegerNonNullColumn("tenant_id").
		ForeignKeyOnDeleteCascade("tenant_id", "tenants(id)").
		Unique("tenant_id", "name").
		VarCharNonNullColumn("name").
		TextNonNullColumn("selector").
		TextColumn("exclude_selector"),
	createSQLTable("secrets").
		WithIteration("ocp_v2").
		IntegerPrimaryKeyAutoincrementColumn("id").
		IntegerNonNullColumn("tenant_id").
		ForeignKeyOnDeleteCascade("tenant_id", "tenants(id)").
		VarCharNonNullColumn("name").
		Unique("tenant_id", "name").
		TextColumn("value"),

	// cross tables
	createSQLTable("bundles_secrets").
		WithIteration("ocp_v2").
		IntegerNonNullColumn("bundle_id").
		IntegerNonNullColumn("secret_id").
		TextNonNullColumn("ref_type").
		PrimaryKey("bundle_id", "secret_id").
		ForeignKey("bundle_id", "bundles(id)").
		ForeignKey("secret_id", "secrets(id)"),
	createSQLTable("bundles_requirements").
		WithIteration("ocp_v2").
		IntegerNonNullColumn("bundle_id").
		IntegerNonNullColumn("source_id").
		TextColumn("gitcommit").
		TextColumn("path").
		TextColumn("prefix").
		PrimaryKey("bundle_id", "source_id").
		ForeignKey("bundle_id", "bundles(id)").
		ForeignKey("source_id", "sources(id)"),
	createSQLTable("stacks_requirements").
		WithIteration("ocp_v2").
		IntegerNonNullColumn("stack_id").
		IntegerNonNullColumn("source_id").
		TextColumn("gitcommit").
		TextColumn("path").
		TextColumn("prefix").
		PrimaryKey("stack_id", "source_id").
		ForeignKey("stack_id", "stacks(id)").
		ForeignKey("source_id", "sources(id)"),
	createSQLTable("sources_requirements").
		WithIteration("ocp_v2").
		IntegerNonNullColumn("source_id").
		IntegerNonNullColumn("requirement_id").
		TextColumn("gitcommit").
		TextColumn("path").
		TextColumn("prefix").
		PrimaryKey("source_id", "requirement_id").
		ForeignKey("source_id", "sources(id)").
		ForeignKey("requirement_id", "sources(id)"),
	createSQLTable("sources_secrets").
		WithIteration("ocp_v2").
		IntegerNonNullColumn("source_id").
		IntegerNonNullColumn("secret_id").
		TextNonNullColumn("ref_type").
		PrimaryKey("source_id", "secret_id").
		ForeignKey("source_id", "sources(id)").
		ForeignKey("secret_id", "secrets(id)"),
	createSQLTable("sources_data").
		WithIteration("ocp_v2").
		IntegerNonNullColumn("source_id").
		VarCharNonNullColumn("path").
		BlobNonNullColumn("data").
		PrimaryKey("source_id", "path").
		ForeignKey("source_id", "sources(id)"),
	createSQLTable("sources_datasources").
		WithIteration("ocp_v2").
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
func tableCopy(oldName string, st *sqlTable) string {
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
