package database_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	internalconfig "github.com/open-policy-agent/opa-control-plane/internal/config"
	"github.com/open-policy-agent/opa-control-plane/internal/migrations"
	"github.com/open-policy-agent/opa-control-plane/pkg/config"
	"github.com/open-policy-agent/opa-control-plane/pkg/database"
)

func TestSecretCRUD(t *testing.T) {
	ctx := t.Context()
	const principal, tenant = "admin", "default"

	migrated, err := migrations.New().
		WithConfig(&internalconfig.Database{SQL: &internalconfig.SQLDatabase{Driver: "sqlite3", DSN: ":memory:"}}).
		WithMigrate(true).
		Run(ctx)
	require.NoError(t, err)
	t.Cleanup(migrated.CloseDB)

	db, err := database.NewFromDB(migrated.DB(), "sqlite3")
	require.NoError(t, err)
	require.NoError(t, db.UpsertTenantWithPrincipal(ctx, tenant, principal, "administrator"))

	for _, name := range []string{"a", "b", "c"} {
		require.NoError(t, db.UpsertSecret(ctx, principal, tenant, name))
	}
	require.Error(t, db.UpsertSecret(ctx, principal, tenant, ""))

	got, err := db.GetSecret(ctx, principal, tenant, "b")
	require.NoError(t, err)
	require.Equal(t, "b", got.Name)

	var listed []string
	cursor := ""
	for {
		page, next, err := db.ListSecrets(ctx, principal, tenant, 2, cursor)
		require.NoError(t, err)
		for _, s := range page {
			listed = append(listed, s.Name)
		}
		if len(page) < 2 {
			break
		}
		cursor = next
	}
	require.Equal(t, []string{"a", "b", "c"}, listed)

	require.NoError(t, db.DeleteSecret(ctx, principal, tenant, "b"))
	_, err = db.GetSecret(ctx, principal, tenant, "b")
	require.ErrorIs(t, err, database.ErrNotFound)
}

func TestSecretInfo(t *testing.T) {
	ctx := t.Context()
	const principal, tenant = "admin", "default"

	migrated, err := migrations.New().
		WithConfig(&internalconfig.Database{SQL: &internalconfig.SQLDatabase{Driver: "sqlite3", DSN: ":memory:"}}).
		WithMigrate(true).
		Run(ctx)
	require.NoError(t, err)
	t.Cleanup(migrated.CloseDB)

	db, err := database.NewFromDB(migrated.DB(), "sqlite3")
	require.NoError(t, err)
	require.NoError(t, db.UpsertTenantWithPrincipal(ctx, tenant, principal, "administrator"))

	require.NoError(t, db.UpsertSecretInfo(ctx, principal, tenant, &config.SecretInfo{
		Name:     "with-metadata",
		Type:     "basic_auth",
		Metadata: map[string]any{"purpose": "git", "rotated": true},
	}))
	require.NoError(t, db.UpsertSecretInfo(ctx, principal, tenant, &config.SecretInfo{Name: "no-metadata", Type: "token_auth"}))
	require.NoError(t, db.UpsertSecret(ctx, principal, tenant, "name-only"))
	require.Error(t, db.UpsertSecretInfo(ctx, principal, tenant, &config.SecretInfo{}))

	got, err := db.GetSecretInfo(ctx, principal, tenant, "with-metadata")
	require.NoError(t, err)
	require.Equal(t, &config.SecretInfo{
		Name:     "with-metadata",
		Type:     "basic_auth",
		Metadata: map[string]any{"purpose": "git", "rotated": true},
	}, got)

	var listed []*config.SecretInfo
	cursor := ""
	for {
		page, next, err := db.ListSecretInfos(ctx, principal, tenant, 2, cursor)
		require.NoError(t, err)
		listed = append(listed, page...)
		if len(page) < 2 {
			break
		}
		cursor = next
	}
	require.Equal(t, []*config.SecretInfo{
		{Name: "with-metadata", Type: "basic_auth", Metadata: map[string]any{"purpose": "git", "rotated": true}},
		{Name: "no-metadata", Type: "token_auth"},
		{Name: "name-only"},
	}, listed)

	t.Run("updating the info replaces type and metadata", func(t *testing.T) {
		require.NoError(t, db.UpsertSecretInfo(ctx, principal, tenant, &config.SecretInfo{Name: "with-metadata", Type: "token_auth"}))

		got, err := db.GetSecretInfo(ctx, principal, tenant, "with-metadata")
		require.NoError(t, err)
		require.Equal(t, &config.SecretInfo{Name: "with-metadata", Type: "token_auth"}, got)
	})

	t.Run("recording a name only keeps type and metadata", func(t *testing.T) {
		info := &config.SecretInfo{Name: "keep", Type: "basic_auth", Metadata: map[string]any{"purpose": "git"}}
		require.NoError(t, db.UpsertSecretInfo(ctx, principal, tenant, info))
		require.NoError(t, db.UpsertSecret(ctx, principal, tenant, "keep"))

		got, err := db.GetSecretInfo(ctx, principal, tenant, "keep")
		require.NoError(t, err)
		require.Equal(t, info, got)
	})

	t.Run("unknown secret", func(t *testing.T) {
		_, err := db.GetSecretInfo(ctx, principal, tenant, "missing")
		require.ErrorIs(t, err, database.ErrNotFound)
	})
}
