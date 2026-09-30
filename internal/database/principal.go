package database

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"strings"
)

// apiKeyHashPrefix tags the digest with its algorithm, so a later change of
// algorithm can coexist with existing rows.
const apiKeyHashPrefix = "sha256:"

func hashAPIKey(apiKey string) string {
	sum := sha256.Sum256([]byte(apiKey))
	return apiKeyHashPrefix + hex.EncodeToString(sum[:])
}

// BackfillAPIKeyDigests hashes the cleartext API keys earlier versions stored,
// reporting how many rows it rewrote. Skipping rows that already carry a digest
// keeps it idempotent.
func (db *Database) BackfillAPIKeyDigests(ctx context.Context) (int, error) {
	var updated int

	err := tx1(ctx, db, func(tx *sql.Tx) error {
		stale, err := cleartextAPIKeys(ctx, tx)
		if err != nil {
			return err
		}

		// Only once the read is drained: MySQL fails on writes interleaved with an
		// open result set on the same connection.
		query := `UPDATE tokens SET api_key = ` + db.arg(0) + ` WHERE name = ` + db.arg(1)
		for name, apiKey := range stale {
			if _, err := tx.ExecContext(ctx, query, hashAPIKey(apiKey), name); err != nil {
				return fmt.Errorf("failed to hash api key of token %q: %w", name, err)
			}
		}

		updated = len(stale)
		return nil
	})

	return updated, err
}

func cleartextAPIKeys(ctx context.Context, tx *sql.Tx) (map[string]string, error) {
	rows, err := tx.QueryContext(ctx, `SELECT name, api_key FROM tokens`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	stale := map[string]string{}
	for rows.Next() {
		var name, apiKey string
		if err := rows.Scan(&name, &apiKey); err != nil {
			return nil, err
		}
		if !strings.HasPrefix(apiKey, apiKeyHashPrefix) {
			stale[name] = apiKey
		}
	}

	return stale, rows.Err()
}

type Principal struct {
	Id        string
	Role      string
	Tenant    string
	CreatedAt string
}

func (db *Database) UpsertPrincipal(ctx context.Context, principal Principal) error {
	return tx1(ctx, db, func(tx *sql.Tx) error {
		return db.UpsertPrincipalTx(ctx, tx, principal)
	})
}

func (db *Database) UpsertPrincipalTx(ctx context.Context, tx *sql.Tx, principal Principal) error {
	if err := db.upsertNoID(ctx, tx, principal.Tenant, "principals", []string{"id", "role"}, []string{"id"}, principal.Id, principal.Role); err != nil {
		return fmt.Errorf("failed to insert principal: %w", err)
	}
	return nil
}

// UpsertTenantWithPrincipal creates a tenant and its associated principal in a
// single transaction. Both inserts are idempotent.
func (db *Database) UpsertTenantWithPrincipal(ctx context.Context, tenantName, principalID, role string) error {
	return tx1(ctx, db, func(tx *sql.Tx) error {
		return db.UpsertTenantAndPrincipalTx(ctx, tx, tenantName, principalID, role)
	})
}

// UpsertTenantAndPrincipalTx performs the tenant+principal upsert within an existing transaction.
func (db *Database) UpsertTenantAndPrincipalTx(ctx context.Context, tx *sql.Tx, tenantName, principalID, role string) error {
	if err := db.upsertTenantTx(ctx, tx, tenantName); err != nil {
		return err
	}
	if err := db.UpsertPrincipalTx(ctx, tx, Principal{Id: principalID, Role: role, Tenant: tenantName}); err != nil {
		return fmt.Errorf("failed to upsert principal %q for tenant %q: %w", principalID, tenantName, err)
	}
	return nil
}

func (db *Database) upsertTenantTx(ctx context.Context, tx *sql.Tx, tenantName string) error {
	if err := db.upsertRel(ctx, tx, "tenants", []string{"name"}, []string{"name"}, tenantName); err != nil {
		return fmt.Errorf("failed to upsert tenant %q: %w", tenantName, err)
	}
	return nil
}

func (db *Database) GetPrincipalID(ctx context.Context, apiKey string) (string, error) {
	var principalId string
	err := tx1(ctx, db, func(tx *sql.Tx) error {
		query := `SELECT principals.id FROM principals JOIN tokens ON tokens.name = principals.id WHERE tokens.api_key = ` + db.arg(0)
		return tx.QueryRowContext(ctx, query, hashAPIKey(apiKey)).Scan(&principalId)
	})
	return principalId, err
}
