package main

import (
	"strings"
	"testing"
)

func TestConfigRejectsAMissingDSN(t *testing.T) {
	_, err := parseConfig([]string{"-blobs", "/tmp/b", "-yr", "/tmp/yr"})
	if err == nil {
		t.Fatal("expected a missing -dsn to be rejected")
	}
	if !strings.Contains(err.Error(), "dsn") {
		t.Fatalf("error should name the missing flag, got: %v", err)
	}
}

func TestConfigRejectsAMissingYr(t *testing.T) {
	// Without yr the console cannot compile a rule, which is its one non-negotiable behaviour.
	_, err := parseConfig([]string{"-dsn", "postgres://x", "-blobs", "/tmp/b"})
	if err == nil {
		t.Fatal("expected a missing -yr to be rejected")
	}
}

func TestConfigAcceptsACompleteInvocation(t *testing.T) {
	cfg, err := parseConfig([]string{
		"-dsn", "postgres://localhost/db", "-blobs", "/var/lib/console/blobs",
		"-yr", "/opt/shellsight/yr", "-addr", ":9000",
	})
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if cfg.Addr != ":9000" || cfg.BlobDir != "/var/lib/console/blobs" {
		t.Fatalf("got %+v", cfg)
	}
}

func TestAddrDefaultsToLocalhost(t *testing.T) {
	// The console holds engagement evidence for every customer. It must not bind 0.0.0.0 by
	// accident; exposing it is a deliberate act.
	cfg, err := parseConfig([]string{"-dsn", "postgres://x", "-blobs", "/tmp/b", "-yr", "/tmp/yr"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(cfg.Addr, "127.0.0.1:") {
		t.Fatalf("default addr is %q, want a 127.0.0.1 bind", cfg.Addr)
	}
}
