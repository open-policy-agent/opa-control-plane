package database

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"time"

	"github.com/open-policy-agent/opa-control-plane/internal/metrics"
)

// instrumentedConnector wraps a driver.Connector so every driver.Conn it
// produces records query metrics. Connect is a straight pass-through; the
// returned Conn is wrapped by instrumentedConn (see below).
type instrumentedConnector struct {
	driver.Connector
	metrics *metrics.Metrics
}

func newInstrumentedConnector(inner driver.Connector, m *metrics.Metrics) driver.Connector {
	return instrumentedConnector{Connector: inner, metrics: m}
}

func (c instrumentedConnector) Connect(ctx context.Context) (driver.Conn, error) {
	conn, err := c.Connector.Connect(ctx)
	if err != nil {
		return nil, err
	}
	return wrapConn(conn, c.metrics), nil
}

// instrumentedConn wraps a driver.Conn to record query metrics. Unlike an
// earlier version of this file, it does NOT try to detect which optional
// driver.Conn interfaces (QueryerContext, ExecerContext, Pinger, ...) the
// wrapped conn implements and construct a matching wrapper type — that
// approach requires exhaustively enumerating every combination of ~8
// optional interfaces, and it's easy to silently drop one (as a test here
// caught for driver.Pinger).
//
// Instead, following the pattern used by github.com/XSAM/otelsql (see
// conn.go there), instrumentedConn unconditionally implements every
// optional interface driver.Conn implementations commonly support. Each
// method checks at call time whether the wrapped conn actually implements
// the corresponding interface:
//   - If not, it returns driver.ErrSkip (the sentinel database/sql defines
//     for exactly this situation), which tells database/sql to fall back to
//     the next mechanism (e.g. prepare-then-query) — identical to what
//     would happen without any wrapping.
//   - If so, it forwards the call, recording metrics around it where
//     relevant (QueryContext/ExecContext).
//
// This sidesteps the combinatorial-type problem entirely: there is exactly
// one wrapper type, and no capability is ever silently dropped.
type instrumentedConn struct {
	driver.Conn
	metrics *metrics.Metrics
}

func wrapConn(conn driver.Conn, m *metrics.Metrics) driver.Conn {
	return &instrumentedConn{Conn: conn, metrics: m}
}

var (
	_ driver.Pinger             = (*instrumentedConn)(nil)
	_ driver.Queryer            = (*instrumentedConn)(nil) //nolint:staticcheck
	_ driver.QueryerContext     = (*instrumentedConn)(nil)
	_ driver.Execer             = (*instrumentedConn)(nil) //nolint:staticcheck
	_ driver.ExecerContext      = (*instrumentedConn)(nil)
	_ driver.ConnPrepareContext = (*instrumentedConn)(nil)
	_ driver.ConnBeginTx        = (*instrumentedConn)(nil)
	_ driver.SessionResetter    = (*instrumentedConn)(nil)
	_ driver.NamedValueChecker  = (*instrumentedConn)(nil)
	_ driver.Validator          = (*instrumentedConn)(nil)
)

func (c *instrumentedConn) Ping(ctx context.Context) error {
	pinger, ok := c.Conn.(driver.Pinger)
	if !ok {
		return nil
	}
	return pinger.Ping(ctx)
}

func (c *instrumentedConn) Query(query string, args []driver.Value) (driver.Rows, error) { //nolint:staticcheck
	queryer, ok := c.Conn.(driver.Queryer) //nolint:staticcheck
	if !ok {
		return nil, driver.ErrSkip
	}
	return queryer.Query(query, args)
}

func (c *instrumentedConn) QueryContext(
	ctx context.Context, query string, args []driver.NamedValue,
) (driver.Rows, error) {
	queryer, ok := c.Conn.(driver.QueryerContext)
	if !ok {
		return nil, driver.ErrSkip
	}

	op := metrics.DatabaseOperation(query)
	start := time.Now()
	rows, err := queryer.QueryContext(ctx, query, args)
	if err != nil {
		c.metrics.DatabaseQueryFailed(op)
		return rows, err
	}
	c.metrics.DatabaseQuerySucceeded(op, start)
	return rows, nil
}

func (c *instrumentedConn) Exec(query string, args []driver.Value) (driver.Result, error) { //nolint:staticcheck
	execer, ok := c.Conn.(driver.Execer) //nolint:staticcheck
	if !ok {
		return nil, driver.ErrSkip
	}
	return execer.Exec(query, args)
}

func (c *instrumentedConn) ExecContext(
	ctx context.Context, query string, args []driver.NamedValue,
) (driver.Result, error) {
	execer, ok := c.Conn.(driver.ExecerContext)
	if !ok {
		return nil, driver.ErrSkip
	}

	op := metrics.DatabaseOperation(query)
	start := time.Now()
	res, err := execer.ExecContext(ctx, query, args)
	if err != nil {
		c.metrics.DatabaseQueryFailed(op)
		return res, err
	}
	c.metrics.DatabaseQuerySucceeded(op, start)
	return res, nil
}

// PrepareContext mirrors the fallback database/sql itself would perform if
// the wrapped conn didn't support ConnPrepareContext: call the required
// Prepare method and honor ctx cancellation. Adapted from
// https://github.com/XSAM/otelsql (conn.go), which credits it to
// database/sql's own ctxutil.go.
func (c *instrumentedConn) PrepareContext(ctx context.Context, query string) (driver.Stmt, error) {
	if preparer, ok := c.Conn.(driver.ConnPrepareContext); ok {
		return preparer.PrepareContext(ctx, query)
	}

	stmt, err := c.Conn.Prepare(query)
	if err != nil {
		return nil, err
	}
	select {
	default:
	case <-ctx.Done():
		_ = stmt.Close()
		return nil, ctx.Err()
	}
	return stmt, nil
}

// BeginTx mirrors the fallback database/sql itself would perform if the
// wrapped conn didn't support ConnBeginTx. Adapted from
// https://github.com/XSAM/otelsql (conn.go), which credits it to
// database/sql's own ctxutil.go.
func (c *instrumentedConn) BeginTx(ctx context.Context, opts driver.TxOptions) (driver.Tx, error) {
	if connBeginTx, ok := c.Conn.(driver.ConnBeginTx); ok {
		return connBeginTx.BeginTx(ctx, opts)
	}

	if opts.Isolation != driver.IsolationLevel(sql.LevelDefault) {
		return nil, errors.New("sql: driver does not support non-default isolation level")
	}
	if opts.ReadOnly {
		return nil, errors.New("sql: driver does not support read-only transactions")
	}

	tx, err := c.Conn.Begin() //nolint:staticcheck
	if err != nil {
		return nil, err
	}
	if ctx.Done() != nil {
		select {
		default:
		case <-ctx.Done():
			_ = tx.Rollback()
			return nil, ctx.Err()
		}
	}
	return tx, nil
}

func (c *instrumentedConn) ResetSession(ctx context.Context) error {
	sessionResetter, ok := c.Conn.(driver.SessionResetter)
	if !ok {
		return nil
	}
	return sessionResetter.ResetSession(ctx)
}

func (c *instrumentedConn) CheckNamedValue(nv *driver.NamedValue) error {
	checker, ok := c.Conn.(driver.NamedValueChecker)
	if !ok {
		return driver.ErrSkip
	}
	return checker.CheckNamedValue(nv)
}

func (c *instrumentedConn) IsValid() bool {
	if v, ok := c.Conn.(driver.Validator); ok {
		return v.IsValid()
	}
	return true
}
