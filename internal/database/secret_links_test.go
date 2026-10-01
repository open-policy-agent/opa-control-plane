package database_test

import (
	"testing"

	"github.com/testcontainers/testcontainers-go"

	"github.com/open-policy-agent/opa-control-plane/internal/config"
	"github.com/open-policy-agent/opa-control-plane/internal/migrations"
	"github.com/open-policy-agent/opa-control-plane/internal/test/dbs"
)

func TestSecretReferenceSwitch(t *testing.T) {
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

			t.Run("bundle", func(t *testing.T) {
				for _, name := range []string{"bundle-old-secret", "bundle-new-secret"} {
					if err := db.UpsertSecret(ctx, "admin", tenant, awsSecret(name)); err != nil {
						t.Fatal(err)
					}
				}

				bundle := func(secretName string) *config.Bundle {
					var credentials *config.SecretRef
					if secretName != "" {
						credentials = &config.SecretRef{Name: secretName}
					}
					return &config.Bundle{
						Name: "bundle-secret-switch",
						ObjectStorage: config.ObjectStorage{
							AmazonS3: &config.AmazonS3{
								Bucket:      "bucket",
								Key:         "bundle.tar.gz",
								Region:      "eu-west-1",
								Credentials: credentials,
							},
						},
					}
				}

				if err := db.UpsertBundle(ctx, "admin", tenant, bundle("bundle-old-secret")); err != nil {
					t.Fatal(err)
				}
				if err := db.UpsertBundle(ctx, "admin", tenant, bundle("bundle-new-secret")); err != nil {
					t.Fatal(err)
				}

				got, err := db.GetBundle(ctx, "admin", tenant, "bundle-secret-switch")
				if err != nil {
					t.Fatal(err)
				}
				if got.ObjectStorage.AmazonS3 == nil || got.ObjectStorage.AmazonS3.Credentials == nil {
					t.Fatal("expected bundle credentials")
				}
				if got.ObjectStorage.AmazonS3.Credentials.Name != "bundle-new-secret" {
					t.Errorf("credentials after switch = %q, want %q", got.ObjectStorage.AmazonS3.Credentials.Name, "bundle-new-secret")
				}
				if err := db.DeleteSecret(ctx, "admin", tenant, "bundle-old-secret"); err != nil {
					t.Errorf("delete old, unreferenced secret: %v", err)
				}

				if err := db.UpsertBundle(ctx, "admin", tenant, bundle("")); err != nil {
					t.Fatal(err)
				}
				if err := db.DeleteSecret(ctx, "admin", tenant, "bundle-new-secret"); err != nil {
					t.Errorf("delete removed credentials secret: %v", err)
				}
			})

			t.Run("source", func(t *testing.T) {
				for _, name := range []string{"source-old-secret", "source-new-secret"} {
					if err := db.UpsertSecret(ctx, "admin", tenant, tokenSecret(name)); err != nil {
						t.Fatal(err)
					}
				}

				source := func(secretName string) *config.Source {
					var credentials *config.SecretRef
					if secretName != "" {
						credentials = &config.SecretRef{Name: secretName}
					}
					return &config.Source{
						Name: "source-secret-switch",
						Git: config.Git{
							Repo:        "https://github.com/example/repo",
							Credentials: credentials,
						},
					}
				}

				if err := db.UpsertSource(ctx, "admin", tenant, source("source-old-secret")); err != nil {
					t.Fatal(err)
				}
				if err := db.UpsertSource(ctx, "admin", tenant, source("source-new-secret")); err != nil {
					t.Fatal(err)
				}

				got, err := db.GetSource(ctx, "admin", tenant, "source-secret-switch")
				if err != nil {
					t.Fatal(err)
				}
				if got.Git.Credentials == nil {
					t.Fatal("expected source credentials")
				}
				if got.Git.Credentials.Name != "source-new-secret" {
					t.Errorf("credentials after switch = %q, want %q", got.Git.Credentials.Name, "source-new-secret")
				}
				if err := db.DeleteSecret(ctx, "admin", tenant, "source-old-secret"); err != nil {
					t.Errorf("delete old, unreferenced secret: %v", err)
				}

				if err := db.UpsertSource(ctx, "admin", tenant, source("")); err != nil {
					t.Fatal(err)
				}
				if err := db.DeleteSecret(ctx, "admin", tenant, "source-new-secret"); err != nil {
					t.Errorf("delete removed credentials secret: %v", err)
				}
			})
		})
	}
}

func awsSecret(name string) *config.Secret {
	return &config.Secret{
		Name: name,
		Value: map[string]any{
			"type":              "aws_auth",
			"access_key_id":     name,
			"secret_access_key": "secret",
		},
	}
}

func tokenSecret(name string) *config.Secret {
	return &config.Secret{
		Name: name,
		Value: map[string]any{
			"type":  "token_auth",
			"token": name,
		},
	}
}
