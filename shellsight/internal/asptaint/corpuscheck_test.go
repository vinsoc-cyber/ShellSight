package asptaint

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// Per-cell coverage over the generated ASP and ASPX corpora, and the false-positive cost on the
// benign pools. Both skip unless pointed at a corpus, so a clean checkout is unaffected.
//
//	ASP_SYNTH=<...>\synthetic\asp   ASPX_SYNTH=<...>\synthetic\aspx   go test ./internal/asptaint/
//	ASP_BENIGN="<dir>;<dir>"                                         go test ./internal/asptaint/
//
// These exist because the package's unit tests all passed while 80 of 92 generated ASP cells scored
// zero. A unit test asserts the shapes someone thought of; a corpus walk finds the ones they did
// not -- here, that the ScriptControl sink only accepted the parenthesised call form and that
// isCodeTemplate silenced every COM sink.

func cellsIn(t *testing.T, root, ext string) (int, int, []string) {
	t.Helper()
	byCell := map[string][2]int{}
	if err := filepath.Walk(root, func(p string, fi os.FileInfo, err error) error {
		if err != nil || fi.IsDir() || !strings.HasSuffix(strings.ToLower(p), ext) {
			return nil
		}
		rel, _ := filepath.Rel(root, p)
		cell := strings.Split(rel, string(os.PathSeparator))[0]
		b, rerr := os.ReadFile(p)
		if rerr != nil {
			return nil
		}
		c := byCell[cell]
		c[1]++
		if len(Analyze(b)) > 0 {
			c[0]++
		}
		byCell[cell] = c
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	cells := make([]string, 0, len(byCell))
	for k := range byCell {
		cells = append(cells, k)
	}
	sort.Strings(cells)
	hit, missed := 0, []string(nil)
	for _, c := range cells {
		if byCell[c][0] > 0 {
			hit++
		} else {
			missed = append(missed, c)
		}
	}
	return hit, len(cells), missed
}

func reportCorpus(t *testing.T, envVar, ext, label string) {
	t.Helper()
	root := os.Getenv(envVar)
	if root == "" {
		t.Skipf("%s not set", envVar)
	}
	hit, total, missed := cellsIn(t, root, ext)
	t.Logf("%s: %d/%d cells detected", label, hit, total)
	for _, m := range missed {
		t.Logf("    MISS %s", m)
	}
}

func TestGeneratedAspCorpusCoverage(t *testing.T) {
	reportCorpus(t, "ASP_SYNTH", ".asp", "asp")
}

func TestGeneratedAspxCorpusCoverage(t *testing.T) {
	reportCorpus(t, "ASPX_SYNTH", ".aspx", "aspx")
}

// The FP figure is what decides whether a recall gain is worth having. This project declined its
// file-manager discriminator at precision 0.053, and the ASP rule set exists to beat an incumbent
// that flags 53.53% of benign ASP files.
func TestBenignAspFalsePositives(t *testing.T) {
	roots := os.Getenv("ASP_BENIGN")
	if roots == "" {
		t.Skip("ASP_BENIGN not set")
	}
	total, flagged := 0, 0
	var hits []string
	for _, root := range strings.Split(roots, ";") {
		if root == "" {
			continue
		}
		filepath.Walk(root, func(p string, fi os.FileInfo, err error) error {
			if err != nil || fi.IsDir() {
				return nil
			}
			switch strings.ToLower(filepath.Ext(p)) {
			case ".asp", ".aspx", ".inc", ".asa", ".ashx", ".asmx":
			default:
				return nil
			}
			b, rerr := os.ReadFile(p)
			if rerr != nil || len(b) == 0 {
				return nil
			}
			total++
			if f := Analyze(b); len(f) > 0 {
				flagged++
				if len(hits) < 25 {
					hits = append(hits, p+"  ->  "+f[0].Evidence)
				}
			}
			return nil
		})
	}
	t.Logf("BENIGN asp-family: %d flagged of %d files", flagged, total)
	for _, h := range hits {
		t.Logf("    FP %s", h)
	}
}
