package database_test

import (
	"errors"
	"testing"

	"github.com/testcontainers/testcontainers-go"

	"github.com/open-policy-agent/opa-control-plane/internal/config"
	"github.com/open-policy-agent/opa-control-plane/internal/database"
	"github.com/open-policy-agent/opa-control-plane/internal/migrations"
	"github.com/open-policy-agent/opa-control-plane/internal/test/dbs"
)

func TestDeleteSecretInUse(t *testing.T) {
	ctx := t.Context()

	for databaseType, databaseConfig := range dbs.Configs(t) {
		t.Run(databaseType, func(t *testing.T) {
			t.Parallel()

			var ctr testcontainers.Container
			if databaseConfig.Setup != nil {
				ctr = databaseConfig.Setup(t)
				if databaseConfig.Cleanup != nil {
					t.Cleanup(databaseConfig.Cleanup(t, ctr))
				}
			}

			db, err := migrations.New().
				WithConfig(databaseConfig.Database(t, ctr).Database).
				WithMigrate(true).
				Run(ctx)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(db.CloseDB)

			if err := db.UpsertPrincipal(ctx, principal); err != nil {
				t.Fatal(err)
			}
			if err := db.UpsertSecret(ctx, "admin", tenant, tokenSecret("in-use")); err != nil {
				t.Fatal(err)
			}
			source := &config.Source{
				Name: "uses-secret",
				Git: config.Git{
					Repo:        "https://github.com/example/repo",
					Credentials: &config.SecretRef{Name: "in-use"},
				},
			}
			if err := db.UpsertSource(ctx, "admin", tenant, source); err != nil {
				t.Fatal(err)
			}

			err = db.DeleteSecret(ctx, "admin", tenant, "in-use")
			if !errors.Is(err, database.ErrConflict) {
				t.Fatalf("expected ErrConflict, got %v", err)
			}
		})
	}
}
