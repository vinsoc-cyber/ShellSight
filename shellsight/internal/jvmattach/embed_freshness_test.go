package jvmattach

import (
	"archive/zip"
	"bytes"
	"os"
	"path/filepath"
	"sort"
	"testing"
)

// The embedded agent must be the agent the build produced.
//
// WHY THIS TEST EXISTS. internal/jvmattach/agent/javamem-agent.jar is compiled into jvmprobe by
// //go:embed, and it is a SECOND copy of probes/javamem/javamem-agent.jar. Nothing copied it and
// nothing checked it: on 2026-09-01 the embedded copy was found a day stale, so a `go build` would
// have produced a jvmprobe whose in-JVM agent predated the detector change under measurement --
// and the measurement would have described code that was not there. probes/javamem/build.sh now
// performs the copy; this is the gate that catches it being skipped.
//
// It compares ENTRY NAMES, not bytes. Jar builds are not byte-reproducible (zip entries carry
// timestamps), so a byte comparison would fail on an unchanged tree the moment either jar was
// rebuilt. Entry-name equality catches the failure that actually matters: the agent gained, lost or
// renamed a class and the embedded copy did not follow.
func TestEmbeddedAgentMatchesBuiltAgent(t *testing.T) {
	built := filepath.Join("..", "..", "probes", "javamem", "javamem-agent.jar")
	b, err := os.ReadFile(built)
	if err != nil {
		// The built jar is a build output, not a source file. If it is absent there is nothing to
		// compare against and this gate has no opinion -- it must not fail a checkout that has not
		// run probes/javamem/build.sh.
		t.Skipf("no built agent jar to compare against (%v)", err)
	}

	embedded, err := entryNames(agentJar)
	if err != nil {
		t.Fatalf("embedded agent jar is not readable as a zip: %v", err)
	}
	fresh, err := entryNames(b)
	if err != nil {
		t.Fatalf("built agent jar is not readable as a zip: %v", err)
	}

	if len(embedded) != len(fresh) {
		t.Errorf("embedded agent has %d entries, built agent has %d", len(embedded), len(fresh))
	}
	missing := diff(fresh, embedded)
	extra := diff(embedded, fresh)
	if len(missing) > 0 || len(extra) > 0 {
		t.Errorf(`the embedded agent jar is not the built one.

  in the built jar but NOT embedded: %v
  embedded but not in the built jar: %v

Run probes/javamem/build.sh, which copies it into internal/jvmattach/agent/. Shipping without that
gives jvmprobe an in-JVM agent older than the tree it was built from.`, missing, extra)
	}
}

func entryNames(jar []byte) ([]string, error) {
	zr, err := zip.NewReader(bytes.NewReader(jar), int64(len(jar)))
	if err != nil {
		return nil, err
	}
	var out []string
	for _, f := range zr.File {
		out = append(out, f.Name)
	}
	sort.Strings(out)
	return out, nil
}

// diff returns the elements of a that are absent from b.
func diff(a, b []string) []string {
	have := make(map[string]bool, len(b))
	for _, s := range b {
		have[s] = true
	}
	var out []string
	for _, s := range a {
		if !have[s] {
			out = append(out, s)
		}
	}
	return out
}
