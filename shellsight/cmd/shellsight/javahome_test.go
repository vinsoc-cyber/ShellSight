package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseJavaPaths_filtersBlankAndTrims(t *testing.T) {
	in := "C:\\jdk\\bin\\java.exe\r\n\r\n   D:\\jre\\bin\\java.exe  \r\n"
	got := parseJavaPaths(in)
	want := []string{`C:\jdk\bin\java.exe`, `D:\jre\bin\java.exe`}
	if len(got) != len(want) {
		t.Fatalf("got %d paths %v, want %d %v", len(got), got, len(want), want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("path[%d]=%q want %q", i, got[i], want[i])
		}
	}
}

func TestFirstExistingFile_returnsFirstThatExists(t *testing.T) {
	dir := t.TempDir()
	real := filepath.Join(dir, "java.exe")
	if err := os.WriteFile(real, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	got := firstExistingFile([]string{filepath.Join(dir, "missing.exe"), real})
	if got != real {
		t.Errorf("got %q, want %q", got, real)
	}
	if firstExistingFile([]string{filepath.Join(dir, "nope.exe")}) != "" {
		t.Errorf("expected empty string when none exist")
	}
}
