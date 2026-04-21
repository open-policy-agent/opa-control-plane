package database

import (
	"context"
	"database/sql"
	"fmt"
)

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
		if err := db.upsertTenantTx(ctx, tx, tenantName); err != nil {
			return err
		}
		if err := db.UpsertPrincipalTx(ctx, tx, Principal{Id: principalID, Role: role, Tenant: tenantName}); err != nil {
			return fmt.Errorf("failed to upsert principal %q for tenant %q: %w", principalID, tenantName, err)
		}
		return nil
	})
}

func (db *Database) upsertTenantTx(ctx context.Context, tx *sql.Tx, tenantName string) error {
	if err := db.upsertRel(ctx, tx, "tenants", []string{"name"}, []string{"name"}, tenantName); err != nil {
		return fmt.Errorf("failed to upsert tenant %q: %w", tenantName, err)
	}
	return nil
}

func (db *Database) GetPrincipalID(ctx context.Context, apiKey string) (string, error) {
	query := `SELECT principals.id FROM principals JOIN tokens ON tokens.name = principals.id WHERE tokens.api_key = ` + db.arg(0)
	row := db.db.QueryRowContext(ctx, query, apiKey)
	var principalId string
	return principalId, row.Scan(&principalId)
}
