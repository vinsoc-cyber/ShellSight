package rules_test

import (
	"bytes"
	"strings"
	"testing"

	"shellsight/cmd/rules"
)

func TestListShowsLayers(t *testing.T) {
	var buf bytes.Buffer
	code := rules.RunWithWriter([]string{"list", "--rules-dir", "testdata/rules"}, &buf)
	if code != 0 {
		t.Fatalf("rules list exited %d", code)
	}
	out := buf.String()
	if !strings.Contains(out, "foundation") || !strings.Contains(out, "own") {
		t.Errorf("rules list output does not contain layer names; got:\n%s", out)
	}
	if !strings.Contains(out, "Memory probe contracts") {
		t.Errorf("rules list output does not contain mem-contracts section; got:\n%s", out)
	}
}

func TestListShowsMemContractsCounts(t *testing.T) {
	var buf bytes.Buffer
	rules.RunWithWriter([]string{"list", "--rules-dir", "testdata/rules"}, &buf)
	out := buf.String()
	// testdata/rules/mem-contracts.json has 1 java contract, 1 type needle, 1 string needle.
	if !strings.Contains(out, "java:") || !strings.Contains(out, "dotnet:") {
		t.Errorf("expected java/dotnet contract counts in list output; got:\n%s", out)
	}
}

func TestNoArgsShowsUsage(t *testing.T) {
	var buf bytes.Buffer
	code := rules.RunWithWriter([]string{}, &buf)
	if code == 0 {
		t.Fatal("expected non-zero exit for no args")
	}
	if !strings.Contains(buf.String(), "usage") {
		t.Errorf("expected usage string; got: %s", buf.String())
	}
}

func TestUnknownSubcmdFails(t *testing.T) {
	var buf bytes.Buffer
	code := rules.RunWithWriter([]string{"bogus"}, &buf)
	if code == 0 {
		t.Fatal("expected non-zero exit for unknown subcommand")
	}
}
