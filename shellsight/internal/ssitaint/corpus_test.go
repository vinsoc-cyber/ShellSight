package ssitaint

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Env-gated so the package's own tests stay hermetic. Point these at a directory of .shtml files:
//
//	SSITAINT_MAL_DIR=<dir of known webshells>  -- every file must produce a finding
//	SSITAINT_BEN_DIR=<dir of legitimate pages> -- no file may produce one
//
// The benign set is the point of the whole pass. `ssi_exec_webshell` scores every file in both
// directories 80, so a run over these two directories is the only thing that shows the pass can
// tell them apart.
func TestCorpusDirs(t *testing.T) {
	mal := os.Getenv("SSITAINT_MAL_DIR")
	ben := os.Getenv("SSITAINT_BEN_DIR")
	if mal == "" && ben == "" {
		t.Skip("set SSITAINT_MAL_DIR and/or SSITAINT_BEN_DIR to run")
	}

	scan := func(dir string) (hit []string, miss []string) {
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatalf("read %s: %v", dir, err)
		}
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			name := e.Name()
			low := strings.ToLower(name)
			if !strings.HasSuffix(low, ".shtml") && !strings.HasSuffix(low, ".shtm") {
				continue
			}
			data, err := os.ReadFile(filepath.Join(dir, name))
			if err != nil {
				continue
			}
			if len(Analyze(data)) > 0 {
				hit = append(hit, name)
			} else {
				miss = append(miss, name)
			}
		}
		return hit, miss
	}

	if mal != "" {
		hit, miss := scan(mal)
		t.Logf("MALICIOUS %s: %d flagged, %d missed", mal, len(hit), len(miss))
		for _, m := range miss {
			t.Errorf("false negative: %s produced no finding", m)
		}
	}
	if ben != "" {
		hit, miss := scan(ben)
		t.Logf("BENIGN %s: %d clean, %d flagged", ben, len(miss), len(hit))
		for _, h := range hit {
			t.Errorf("FALSE POSITIVE: %s produced a finding", h)
		}
	}
}
