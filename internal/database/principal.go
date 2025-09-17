package database

import (
	"context"
	"database/sql"
	"fmt"
)

type Principal struct {
	Id        string
	Role      string
	CreatedAt string
}

func (db *Database) UpsertPrincipal(ctx context.Context, principal Principal) error {
	return tx1(ctx, db, func(tx *sql.Tx) error {
		return db.UpsertPrincipalTx(ctx, tx, principal)
	})
}

func (db *Database) UpsertPrincipalTx(ctx context.Context, tx *sql.Tx, principal Principal) error {
	if err := db.upsert(ctx, tx, "principals", []string{"id", "role"}, []string{"id"}, principal.Id, principal.Role); err != nil {
		return fmt.Errorf("failed to insert principal: %w", err)
	}

	return nil
}

func (db *Database) GetPrincipalId(ctx context.Context, apiKey string) (string, error) {
	query := `SELECT principals.id FROM principals JOIN tokens ON tokens.name = principals.id WHERE tokens.api_key = ` + db.arg(0)
	row := db.db.QueryRowContext(ctx, query, apiKey)
	var principalId string
	if err := row.Scan(&principalId); err != nil {
		return "", err
	}
	return principalId, nil
}
