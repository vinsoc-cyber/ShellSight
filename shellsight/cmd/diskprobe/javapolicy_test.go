package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"shellsight/internal/javadisk"
)

func TestJavaDiagnosticPolicyDefaultsWhenOmitted(t *testing.T) {
	got, err := loadJavaOptions("")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, javadisk.DefaultOptions()) {
		t.Fatalf("defaults differ: got=%+v want=%+v", got, javadisk.DefaultOptions())
	}
}

func TestJavaDiagnosticPolicyRejectsInvalidAndOversizedInput(t *testing.T) {
	tests := map[string]string{
		"unknown":   `{"limits":{"unknown_limit":1}}`,
		"negative":  `{"limits":{"max_classes":-1}}`,
		"trailing":  `{"limits":{}} {}`,
		"oversized": strings.Repeat(" ", (64<<10)+1),
	}
	for name, content := range tests {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "policy.json")
			if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := loadJavaOptions(path); err == nil {
				t.Fatal("expected policy error")
			}
		})
	}
}

func TestJavaDiagnosticPolicyFailurePrecedesRulesAndScanning(t *testing.T) {
	policy := filepath.Join(t.TempDir(), "bad.json")
	if err := os.WriteFile(policy, []byte(`{"limits":{"max_classes":-1}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	code := runDiskProbe(context.Background(), []string{"--java-policy", policy, "--rules", filepath.Join(t.TempDir(), "missing")}, strings.NewReader("{}"), &stdout, &stderr)
	if code != exitCoverage || !strings.Contains(stderr.String(), "Java policy") || strings.Contains(stderr.String(), "rules unusable") {
		t.Fatalf("policy must fail first: code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	if stderr.Len() > 1024 {
		t.Fatalf("policy error is not bounded: %d bytes", stderr.Len())
	}
}
