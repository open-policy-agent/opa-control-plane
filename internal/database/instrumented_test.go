package database

import (
	"context"
	"database/sql/driver"
	"errors"
	"testing"

	"github.com/open-policy-agent/opa-control-plane/internal/metrics"
	"github.com/prometheus/client_golang/prometheus"
)

// fakeConn is a minimal driver.Conn (Prepare/Close/Begin only). The
// combinator types below each additionally implement one specific optional
// interface, so tests can verify instrumentedConn behaves correctly whether
// or not the wrapped conn supports a given capability.
type fakeConn struct {
	failNext bool
}

func (c *fakeConn) Prepare(string) (driver.Stmt, error) { return nil, errors.New("not implemented") }
func (c *fakeConn) Close() error                        { return nil }
func (c *fakeConn) Begin() (driver.Tx, error)           { return nil, errors.New("not implemented") }

type fakeConnQueryerExecer struct{ *fakeConn }

func (c fakeConnQueryerExecer) QueryContext(
	context.Context, string, []driver.NamedValue,
) (driver.Rows, error) {
	if c.failNext {
		return nil, errors.New("boom")
	}
	return nil, nil
}

func (c fakeConnQueryerExecer) ExecContext(
	context.Context, string, []driver.NamedValue,
) (driver.Result, error) {
	if c.failNext {
		return nil, errors.New("boom")
	}
	return driver.RowsAffected(1), nil
}

type fakeConnPinger struct{ *fakeConn }

func (c fakeConnPinger) Ping(context.Context) error { return nil }

func TestInstrumentedConn_FallsBackWhenUnsupported(t *testing.T) {
	// Neither QueryContext nor ExecContext are implemented by the plain
	// fakeConn, so instrumentedConn must report ErrSkip (not silently
	// succeed, and not panic) so database/sql knows to fall back.
	m := metrics.Init(nil, prometheus.NewRegistry())
	wrapped := wrapConn(&fakeConn{}, m)

	if _, err := wrapped.(driver.QueryerContext).QueryContext(context.Background(), "SELECT 1", nil); !errors.Is(err, driver.ErrSkip) {
		t.Fatalf("QueryContext error = %v, want driver.ErrSkip", err)
	}
	if _, err := wrapped.(driver.ExecerContext).ExecContext(context.Background(), "INSERT INTO t VALUES (1)", nil); !errors.Is(err, driver.ErrSkip) {
		t.Fatalf("ExecContext error = %v, want driver.ErrSkip", err)
	}
}

func TestInstrumentedConn_ForwardsUnrelatedOptionalInterfaces(t *testing.T) {
	// Pinger is never touched by our wrapper; verify it's still forwarded
	// (the earlier, type-switch-based design silently dropped this).
	m := metrics.Init(nil, prometheus.NewRegistry())
	inner := fakeConnPinger{&fakeConn{}}

	wrapped := wrapConn(inner, m)
	if err := wrapped.(driver.Pinger).Ping(context.Background()); err != nil {
		t.Fatalf("expected Ping to be forwarded to the wrapped conn, got error: %v", err)
	}
}

func TestInstrumentedConn_RecordsMetrics(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := metrics.Init(nil, reg)

	base := &fakeConn{}
	wrapped := wrapConn(fakeConnQueryerExecer{base}, m)

	if _, err := wrapped.(driver.QueryerContext).QueryContext(context.Background(), "SELECT 1", nil); err != nil {
		t.Fatal(err)
	}
	base.failNext = true
	if _, err := wrapped.(driver.ExecerContext).ExecContext(context.Background(), "INSERT INTO t VALUES (1)", nil); err == nil {
		t.Fatal("expected error")
	}

	families, err := reg.Gather()
	if err != nil {
		t.Fatal(err)
	}

	var found bool
	for _, f := range families {
		if f.GetName() != "ocp_database_query_count_total" {
			continue
		}
		found = true
		var sawSuccess, sawFailure bool
		for _, metric := range f.GetMetric() {
			labels := map[string]string{}
			for _, l := range metric.GetLabel() {
				labels[l.GetName()] = l.GetValue()
			}
			switch {
			case labels["operation"] == "select" && labels["state"] == "SUCCESS":
				sawSuccess = true
			case labels["operation"] == "insert" && labels["state"] == "FAILED":
				sawFailure = true
			}
		}
		if !sawSuccess {
			t.Error("expected a select/SUCCESS sample")
		}
		if !sawFailure {
			t.Error("expected an insert/FAILED sample")
		}
	}
	if !found {
		t.Fatal("expected ocp_database_query_count_total to be registered")
	}
}

func TestInstrumentedConn_BeginTxFallback(t *testing.T) {
	m := metrics.Init(nil, prometheus.NewRegistry())
	wrapped := wrapConn(&fakeConn{}, m)

	// fakeConn.Begin always errors; BeginTx with default options should fall
	// back to calling it and propagate the error (not panic or hang).
	_, err := wrapped.(driver.ConnBeginTx).BeginTx(context.Background(), driver.TxOptions{})
	if err == nil {
		t.Fatal("expected an error propagated from the fallback Begin() call")
	}

	// Non-default isolation level isn't supported by the fallback path.
	_, err = wrapped.(driver.ConnBeginTx).BeginTx(context.Background(), driver.TxOptions{Isolation: 1})
	if err == nil {
		t.Fatal("expected an error for unsupported isolation level")
	}
}
