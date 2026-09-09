package rules_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"shellsight/cmd/rules"
)

// mkLayers builds a rules tree with the given files, keyed "layer/name.yar" -> body.
func mkLayers(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "rules")
	for _, l := range []string{"foundation", "own", "custom"} {
		if err := os.MkdirAll(filepath.Join(dir, l), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	mc, err := os.ReadFile(filepath.Join("testdata", "rules", "mem-contracts.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "mem-contracts.json"), mc, 0o644); err != nil {
		t.Fatal(err)
	}
	for rel, body := range files {
		if err := os.WriteFile(filepath.Join(dir, filepath.FromSlash(rel)), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func read(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return string(b)
}

// export --include-custom puts the custom layer in the bundle, but import replaced only
// {foundation, own} — so the layer was extracted to .staged-import and deleted with it, while the
// command printed "import: OK". The documented air-gapped workflow could back custom rules up and
// never restore them, which is worse than having no backup at all.
func TestImportInstallsTheCustomLayerFromTheBundle(t *testing.T) {
	src := mkLayers(t, map[string]string{
		"foundation/f.yar": "rule f {condition: false}\n",
		"own/o.yar":        "rule o {condition: false}\n",
		"custom/site.yar":  "rule MY_SITE_RULE {condition: false}\n",
	})
	bundle := filepath.Join(t.TempDir(), "b.tar.gz")

	var buf strings.Builder
	if code := rules.RunWithWriter([]string{"export", "--rules-dir", src, "--out", bundle, "--include-custom"}, &buf); code != 0 {
		t.Fatalf("export failed: %s", buf.String())
	}

	dst := mkLayers(t, map[string]string{
		"foundation/f.yar": "rule f_old {condition: false}\n",
		"own/o.yar":        "rule o_old {condition: false}\n",
	})
	buf.Reset()
	if code := rules.RunWithWriter([]string{"import", "--rules-dir", dst, bundle}, &buf); code != 0 {
		t.Fatalf("import failed: %s", buf.String())
	}

	got := read(t, filepath.Join(dst, "custom", "site.yar"))
	if !strings.Contains(got, "MY_SITE_RULE") {
		t.Fatalf("the bundle's custom rule must be installed, got %q\noutput:\n%s", got, buf.String())
	}
	// The vendor layers still replace wholesale.
	if !strings.Contains(read(t, filepath.Join(dst, "foundation", "f.yar")), "rule f ") {
		t.Error("foundation must be replaced by the bundle")
	}
}

// custom is operator-owned and may hold rules from several sources, so it MERGES rather than
// replacing: a local rule the bundle does not mention must survive. foundation and own are
// vendor-managed and keep replacing wholesale.
func TestImportMergesCustomAndKeepsLocalRules(t *testing.T) {
	src := mkLayers(t, map[string]string{
		"foundation/f.yar": "rule f {condition: false}\n",
		"custom/site.yar":  "rule FROM_BUNDLE {condition: false}\n",
	})
	bundle := filepath.Join(t.TempDir(), "b.tar.gz")
	var buf strings.Builder
	if code := rules.RunWithWriter([]string{"export", "--rules-dir", src, "--out", bundle, "--include-custom"}, &buf); code != 0 {
		t.Fatalf("export failed: %s", buf.String())
	}

	dst := mkLayers(t, map[string]string{
		"custom/local-only.yar": "rule LOCAL_ONLY {condition: false}\n",
		"custom/site.yar":       "rule LOCAL_SITE_VERSION {condition: false}\n",
	})
	buf.Reset()
	rules.RunWithWriter([]string{"import", "--rules-dir", dst, bundle}, &buf)

	if !strings.Contains(read(t, filepath.Join(dst, "custom", "local-only.yar")), "LOCAL_ONLY") {
		t.Error("a local custom rule absent from the bundle must survive the import")
	}
	if !strings.Contains(read(t, filepath.Join(dst, "custom", "site.yar")), "FROM_BUNDLE") {
		t.Error("a same-named custom rule should be updated from the bundle")
	}
}

// A bundle exported WITHOUT --include-custom must leave the operator's rules completely alone.
func TestImportWithoutCustomInBundleLeavesLocalCustomIntact(t *testing.T) {
	src := mkLayers(t, map[string]string{"foundation/f.yar": "rule f {condition: false}\n"})
	bundle := filepath.Join(t.TempDir(), "b.tar.gz")
	var buf strings.Builder
	rules.RunWithWriter([]string{"export", "--rules-dir", src, "--out", bundle}, &buf)

	dst := mkLayers(t, map[string]string{"custom/mine.yar": "rule MINE {condition: false}\n"})
	buf.Reset()
	rules.RunWithWriter([]string{"import", "--rules-dir", dst, bundle}, &buf)

	if !strings.Contains(read(t, filepath.Join(dst, "custom", "mine.yar")), "MINE") {
		t.Fatal("a bundle with no custom layer must not disturb local custom rules")
	}
}

// Whatever it does to the operator-owned layer, it has to say so.
func TestImportReportsWhatItDidToCustom(t *testing.T) {
	src := mkLayers(t, map[string]string{"custom/site.yar": "rule S {condition: false}\n"})
	bundle := filepath.Join(t.TempDir(), "b.tar.gz")
	var buf strings.Builder
	rules.RunWithWriter([]string{"export", "--rules-dir", src, "--out", bundle, "--include-custom"}, &buf)

	dst := mkLayers(t, nil)
	buf.Reset()
	rules.RunWithWriter([]string{"import", "--rules-dir", dst, bundle}, &buf)
	if !strings.Contains(buf.String(), "custom") {
		t.Fatalf("import must report that it touched the custom layer:\n%s", buf.String())
	}
}
