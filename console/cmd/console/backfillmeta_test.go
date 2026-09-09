package main

import "testing"

func TestBackfillMetaConfigRequiresADSN(t *testing.T) {
	if _, err := parseBackfillMetaConfig(nil); err == nil {
		t.Fatal("expected -dsn to be required")
	}
}

func TestBackfillMetaConfigAcceptsADSN(t *testing.T) {
	cfg, err := parseBackfillMetaConfig([]string{"-dsn", "postgres://x/y"})
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if cfg.DSN != "postgres://x/y" {
		t.Errorf("DSN = %q", cfg.DSN)
	}
}
