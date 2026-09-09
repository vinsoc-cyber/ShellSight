package main

import (
	"strings"
	"testing"
)

func TestPublishConfigRequiresDirVersionAndTarget(t *testing.T) {
	for _, args := range [][]string{
		{"-dsn", "postgres://x", "-blobs", "/tmp/b", "-version", "v1", "-target", "linux-amd64"}, // no -dir
		{"-dsn", "postgres://x", "-blobs", "/tmp/b", "-dir", "/rel", "-target", "linux-amd64"},   // no -version
		{"-dsn", "postgres://x", "-blobs", "/tmp/b", "-dir", "/rel", "-version", "v1"},           // no -target
	} {
		if _, err := parsePublishConfig(args); err == nil {
			t.Errorf("expected %v to be rejected", args)
		}
	}
}

func TestPublishConfigRejectsAnUnknownTarget(t *testing.T) {
	_, err := parsePublishConfig([]string{
		"-dsn", "postgres://x", "-blobs", "/tmp/b", "-dir", "/rel",
		"-version", "v1", "-target", "solaris-sparc",
	})
	if err == nil {
		t.Fatal("expected an unknown target to be rejected")
	}
	if !strings.Contains(err.Error(), "solaris-sparc") {
		t.Fatalf("error should name the bad target, got: %v", err)
	}
}

func TestPublishConfigAcceptsACompleteInvocation(t *testing.T) {
	cfg, err := parsePublishConfig([]string{
		"-dsn", "postgres://x", "-blobs", "/tmp/b", "-dir", "/rel",
		"-version", "v1.0.0-231", "-target", "linux-amd64", "-by", "v.quannh67",
	})
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if cfg.Target != "linux-amd64" || cfg.Version != "v1.0.0-231" || cfg.By != "v.quannh67" {
		t.Fatalf("got %+v", cfg)
	}
}
