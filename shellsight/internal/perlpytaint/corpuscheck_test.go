package perlpytaint

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"shellsight/internal/deobfuscate"
)

// Per-cell coverage over the generated corpora, and the false-positive cost on benign trees.
//
// Both skip unless pointed at a corpus, so a clean checkout is unaffected -- the corpus is 24 GB and
// gitignored. They exist because the package's own unit tests all passed while 21 of 63 generated
// python cells scored zero: the folding produced correct bytes and `deobfuscate.Run`'s reveal gate
// discarded them. Only a walk of the corpus through the REAL chain shows that.
//
//	PY_SYNTH=<...>\synthetic\python  PL_SYNTH=<...>\synthetic\perl  go test ./internal/perlpytaint/
//	BENIGN_TREES="python=<dir>;perl=<dir>"                          go test ./internal/perlpytaint/
//
// Measured 2026-09-05: python 33/63 -> 60/63 cells, benign 0/4,725 unchanged.

// runChain analyses the raw bytes AND every decoded layer, exactly as the mirror scan does.
// Analysing only the raw bytes measures the wrong thing: the whole point of the folding pass is
// that the raw bytes do not contain the sink.
func runChain(b []byte, lang string) bool {
	if len(Analyze(b, lang)) > 0 {
		return true
	}
	for _, l := range deobfuscate.Run(b).Layers {
		if len(Analyze(l.Data, lang)) > 0 {
			return true
		}
	}
	return false
}

func walkCells(t *testing.T, root, ext, lang string) (int, int, []string) {
	t.Helper()
	byCell := map[string][2]int{}
	if err := filepath.Walk(root, func(p string, fi os.FileInfo, err error) error {
		if err != nil || fi.IsDir() || !strings.HasSuffix(p, ext) {
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
		if runChain(b, lang) {
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

func reportCells(t *testing.T, envVar, ext, lang string) {
	t.Helper()
	root := os.Getenv(envVar)
	if root == "" {
		t.Skipf("%s not set", envVar)
	}
	hit, total, missed := walkCells(t, root, ext, lang)
	t.Logf("%s: %d/%d cells detected", lang, hit, total)
	for _, m := range missed {
		t.Logf("    MISS %s", m)
	}
}

func TestGeneratedPythonCorpusCoverage(t *testing.T) { reportCells(t, "PY_SYNTH", ".py", "python") }
func TestGeneratedPerlCorpusCoverage(t *testing.T)   { reportCells(t, "PL_SYNTH", ".pl", "perl") }

// False-positive cost THROUGH THE DECODE CHAIN, which is the dimension the package's existing
// `TestTaintFalsePositiveCostOnTheBenignPools` cannot see: that test calls Analyze on the RAW bytes
// only, so an FP introduced by a folded or decoded layer is invisible to it. Widening the fold pass
// creates exactly that risk, so it needs its own measurement rather than an assumption that the
// existing one covers it.
//
// A recall gain that raises the false-positive rate is not a gain: this project declined its
// file-manager discriminator at precision 0.053 for exactly that reason, and the whole v1 claim is
// a precision claim.
func TestBenignFalsePositivesThroughDecodeChain(t *testing.T) {
	spec := os.Getenv("BENIGN_TREES") // "lang=root;lang=root"
	if spec == "" {
		t.Skip("BENIGN_TREES not set")
	}
	for _, part := range strings.Split(spec, ";") {
		bits := strings.SplitN(part, "=", 2)
		if len(bits) != 2 {
			continue
		}
		lang, root := bits[0], bits[1]
		ext := ".py"
		if lang == "perl" {
			ext = ".pl"
		}
		total, flagged := 0, 0
		var hits []string
		filepath.Walk(root, func(p string, fi os.FileInfo, err error) error {
			if err != nil || fi.IsDir() || !strings.HasSuffix(strings.ToLower(p), ext) {
				return nil
			}
			b, rerr := os.ReadFile(p)
			if rerr != nil || len(b) == 0 {
				return nil
			}
			total++
			if runChain(b, lang) {
				flagged++
				if len(hits) < 12 {
					hits = append(hits, p)
				}
			}
			return nil
		})
		t.Logf("BENIGN %s: %d flagged of %d", lang, flagged, total)
		for _, h := range hits {
			t.Logf("    FP %s", h)
		}
	}
}
