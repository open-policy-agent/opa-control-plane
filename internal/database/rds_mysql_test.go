package database

import (
	"testing"
	"time"
)

func TestNewRDSMySQLConfig(t *testing.T) {
	cfg := newRDSMySQLConfig("opa", "db.example.com:3306", "opactl", "custom")

	// A nil Loc makes the driver panic ("missing Location in call to Time.In") the first time a
	// time.Time argument is bound, e.g. when writing bundle status.
	if cfg.Loc == nil {
		t.Fatal("Loc is nil, want UTC")
	}
	if cfg.Loc != time.UTC {
		t.Errorf("Loc = %v, want UTC", cfg.Loc)
	}
	if !cfg.ParseTime {
		t.Error("ParseTime = false, want true")
	}
	if !cfg.MultiStatements {
		t.Error("MultiStatements = false, want true")
	}
	if !cfg.AllowCleartextPasswords {
		t.Error("AllowCleartextPasswords = false, want true")
	}

	if cfg.User != "opa" || cfg.Net != "tcp" || cfg.Addr != "db.example.com:3306" || cfg.DBName != "opactl" || cfg.TLSConfig != "custom" {
		t.Errorf("unexpected connection settings: %+v", cfg)
	}
}
