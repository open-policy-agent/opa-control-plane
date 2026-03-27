package database

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/open-policy-agent/opa-control-plane/pkg/config"
)

const MaxBundleStatusRetention = 10

// UpsertBundleStatus creates or updates a bundle status record with the given phase and status.
// For a given tenant+bundle+revision combination, only one record exists.
// If a record already exists for the combination, it updates the phase and status.
// Old records beyond the retention limit (MaxBundleStatusRetention) are cleaned up in the same transaction.
func (d *Database) UpsertBundleStatus(ctx context.Context, tenant, bundle, revision, phase, status, errMsg string) (int, error) {
	if revision == "" {
		return 0, errors.New("error inserting bundle status: revision is required")
	}

	var id int
	err := tx1(ctx, d, func(tx *sql.Tx) error {

		bundleID, err := d.lookupID(ctx, tx, tenant, "bundles", bundle)
		if err != nil {
			return fmt.Errorf("error looking up bundle %s: %w", bundle, err)
		}

		resID, err := d.upsertReturning(ctx, true, true, tx, tenant, "bundles_statuses", []string{"bundle_id", "revision", "phase", "status", "error_message"}, []string{"bundle_id", "revision"},
			bundleID, revision, phase, status, errMsg)
		if err != nil {
			return fmt.Errorf("error inserting bundle status: %w", err)
		}
		id = resID

		// Cleanup: keep only the last MaxBundleStatusRetention records per tenant+bundle_id.
		// This runs in the same transaction to ensure consistency.
		//
		// Find the ID of the oldest record we want to keep and then delete everything older.
		var cutoffID int64
		err = tx.QueryRowContext(ctx,
			fmt.Sprintf(
				`SELECT bundles_statuses.id FROM bundles_statuses
				 JOIN tenants ON tenants.id = bundles_statuses.tenant_id
				 WHERE tenants.name = %s AND bundles_statuses.bundle_id = %s
				 ORDER BY bundles_statuses.id DESC
				 LIMIT 1 OFFSET %s`,
				d.arg(0), d.arg(1), d.arg(2),
			),
			tenant, bundleID, MaxBundleStatusRetention-1,
		).Scan(&cutoffID)

		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("error finding cutoff for bundle status cleanup: %w", err)
		}

		// If we found a cutoff, delete all records older than it.
		if err == nil {
			_, err = tx.ExecContext(ctx,
				fmt.Sprintf(
					`DELETE FROM bundles_statuses WHERE bundle_id = %s AND id < %s`,
					d.arg(0), d.arg(1),
				),
				bundleID, cutoffID,
			)
			if err != nil {
				return fmt.Errorf("error cleaning up old bundle statuses: %w", err)
			}
		}

		return nil
	})
	return id, err
}

// GetBundleStatus retrieves a single bundle state record by ID.
func (d *Database) GetBundleStatus(ctx context.Context, id int) (*config.BundleStatus, error) {
	var s config.BundleStatus
	err := tx1(ctx, d, func(tx *sql.Tx) error {
		err := tx.QueryRowContext(ctx,
			`SELECT id, tenant_id, bundle_id, revision, phase, status, error_message, created_at
			 FROM bundles_statuses
			 WHERE id = `+d.arg(0),
			id,
		).Scan(
			&s.ID, &s.TenantID, &s.BundleID, &s.Revision, &s.Phase, &s.Status,
			&s.ErrorMessage, &s.CreatedAt,
		)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return ErrNotFound
			}
			return fmt.Errorf("error querying bundle status by id: %w", err)
		}
		return nil

	})

	return &s, err
}

// GetLatestBundleStatus returns the most recent status record for the given tenant and bundle
// across all revisions. Returns nil and ErrNotFound if no records exist.
func (d *Database) GetLatestBundleStatus(ctx context.Context, principal, tenant, bundle string) (*config.BundleStatus, error) {
	statuses, err := d.ListBundleStatuses(ctx, principal, tenant, bundle, "", 1)
	if err != nil {
		return nil, err
	}

	if len(statuses) == 0 {
		return nil, ErrNotFound
	}

	return statuses[0], nil
}

// ListBundleStatuses returns bundle status records for the given tenant and bundle,
// ordered by bundle status id DESC. If revision is provided, results are filtered by revision.
// If revision is empty, returns records across all revisions.
// A limit of 0 defaults to MaxBundleStatusRetention; values above MaxBundleStatusRetention are capped.
func (d *Database) ListBundleStatuses(ctx context.Context, principal, tenant, bundle, revision string, limit int) ([]*config.BundleStatus, error) {

	// Apply default and cap for limit.
	if limit <= 0 {
		limit = MaxBundleStatusRetention
	}
	if limit > MaxBundleStatusRetention {
		limit = MaxBundleStatusRetention
	}

	var statuses []*config.BundleStatus

	err := tx1(ctx, d, func(tx *sql.Tx) error {
		ad := d.accessFactory().WithPrincipal(principal).WithTenant(tenant).WithResource("bundles_statuses").WithPermission("bundles.statuses.view").WithName(bundle)
		if !d.authorizer.Check(ctx, tx, d.arg, ad) {
			return ErrNotAuthorized
		}

		bundleID, err := d.lookupID(ctx, tx, tenant, "bundles", bundle)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("error looking up bundle %s: %w", bundle, err)
		}

		var query string
		var args []any

		if revision != "" {
			query = fmt.Sprintf(
				`SELECT bundles_statuses.id, tenant_id, bundle_id, revision, phase, status, error_message, created_at
				 FROM bundles_statuses
				 JOIN tenants ON tenants.id = bundles_statuses.tenant_id
				 WHERE tenants.name = %s AND bundle_id = %s AND revision = %s
				 ORDER BY bundles_statuses.id DESC
				 LIMIT %s`,
				d.arg(0), d.arg(1), d.arg(2), d.arg(3),
			)
			args = []any{tenant, bundleID, revision, limit}
		} else {
			query = fmt.Sprintf(
				`SELECT bundles_statuses.id, tenant_id, bundle_id, revision, phase, status, error_message, created_at
				 FROM bundles_statuses
				 JOIN tenants ON tenants.id = bundles_statuses.tenant_id
				 WHERE tenants.name = %s AND bundle_id = %s
				 ORDER BY bundles_statuses.id DESC
				 LIMIT %s`,
				d.arg(0), d.arg(1), d.arg(2),
			)
			args = []any{tenant, bundleID, limit}
		}

		rows, err := tx.Query(query, args...)
		if err != nil {
			return err
		}
		defer rows.Close()

		for rows.Next() {
			var s config.BundleStatus
			if err := rows.Scan(
				&s.ID, &s.TenantID, &s.BundleID, &s.Revision, &s.Phase, &s.Status,
				&s.ErrorMessage, &s.CreatedAt,
			); err != nil {
				return fmt.Errorf("error scanning bundle status: %w", err)
			}
			s.BundleName = bundle
			statuses = append(statuses, &s)
		}
		if err := rows.Err(); err != nil {
			return fmt.Errorf("error iterating bundle statuses: %w", err)
		}
		return nil
	})

	return statuses, err
}
