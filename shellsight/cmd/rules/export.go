package rules

import (
	"archive/tar"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

func runExport(args []string, w io.Writer) int {
	dir := rulesDir(args)
	out := "shellsight-rules.tar.gz"
	includeCustom := false
	for i, a := range args {
		if a == "--out" && i+1 < len(args) {
			out = args[i+1]
		}
		if a == "--include-custom" {
			includeCustom = true
		}
	}
	layers := []string{"foundation", "own"}
	if includeCustom {
		layers = append(layers, "custom")
	}
	if err := createTarGz(out, dir, layers); err != nil {
		fmt.Fprintln(w, "export:", err)
		return 1
	}
	fmt.Fprintf(w, "export: written to %s\n", out)
	return 0
}

func runImport(args []string, w io.Writer) int {
	dir := rulesDir(args)
	bundle := ""
	for _, a := range args {
		if !strings.HasPrefix(a, "--") {
			bundle = a
		}
	}
	if bundle == "" {
		fmt.Fprintln(w, "import: missing bundle path")
		return 1
	}
	staged := filepath.Join(dir, ".staged-import")
	if err := extractTarGzTo(bundle, staged); err != nil {
		fmt.Fprintln(w, "import: extract failed:", err)
		return 1
	}
	// foundation and own are vendor-managed: replace them wholesale.
	for _, layer := range []string{"foundation", "own"} {
		src := filepath.Join(staged, layer)
		dst := filepath.Join(dir, layer)
		if _, err := os.Stat(src); err == nil {
			os.RemoveAll(dst)   //nolint:errcheck
			os.Rename(src, dst) //nolint:errcheck
		}
	}
	// custom is OPERATOR-owned, and was previously skipped entirely: a bundle exported with
	// --include-custom had its custom layer extracted here and then deleted with the staging dir,
	// while this command printed "OK". The documented air-gapped workflow could therefore back up
	// an analyst's rules and never restore them.
	//
	// It merges rather than replacing, because the layer can legitimately hold rules from several
	// sources: same-named files are updated from the bundle, anything the bundle does not mention
	// is left alone. Replacing wholesale would destroy local work on the target host — the same
	// class of silent loss being fixed here.
	if n, err := mergeCustomLayer(filepath.Join(staged, "custom"), filepath.Join(dir, "custom")); err != nil {
		fmt.Fprintln(w, "import: custom layer merge failed:", err)
		return 1
	} else if n > 0 {
		fmt.Fprintf(w, "import: merged %d rule file(s) into the custom layer (local rules kept)\n", n)
	}
	// Import mem-contracts.json if the bundle contains it.
	mcSrc := filepath.Join(staged, "mem-contracts.json")
	if _, err := os.Stat(mcSrc); err == nil {
		os.Rename(mcSrc, filepath.Join(dir, "mem-contracts.json")) //nolint:errcheck
	}
	os.RemoveAll(staged) //nolint:errcheck
	fmt.Fprintln(w, "import: OK — rules updated from bundle")
	return 0
}

func createTarGz(dest, rulesDir string, layers []string) error {
	f, err := os.Create(dest)
	if err != nil {
		return err
	}
	defer f.Close()
	gz := gzip.NewWriter(f)
	tw := tar.NewWriter(gz)
	for _, layer := range layers {
		src := filepath.Join(rulesDir, layer)
		filepath.WalkDir(src, func(p string, d os.DirEntry, err error) error { //nolint:errcheck
			if err != nil || d.IsDir() {
				return nil
			}
			rel, _ := filepath.Rel(rulesDir, p)
			rel = filepath.ToSlash(rel)
			data, err := os.ReadFile(p)
			if err != nil {
				return nil
			}
			tw.WriteHeader(&tar.Header{Name: rel, Size: int64(len(data)), Mode: 0644}) //nolint:errcheck
			tw.Write(data)                                                             //nolint:errcheck
			return nil
		})
	}
	// mem-contracts.json is always bundled so recipients can update probe rules without rebuilding.
	if data, err := os.ReadFile(filepath.Join(rulesDir, "mem-contracts.json")); err == nil {
		tw.WriteHeader(&tar.Header{Name: "mem-contracts.json", Size: int64(len(data)), Mode: 0644}) //nolint:errcheck
		tw.Write(data)                                                                              //nolint:errcheck
	}
	tw.Close() //nolint:errcheck
	gz.Close() //nolint:errcheck
	return nil
}

func extractTarGzTo(src, destDir string) error {
	f, err := os.Open(src)
	if err != nil {
		return err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return err
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		if strings.Contains(hdr.Name, "..") {
			continue // path traversal guard
		}
		dest := filepath.Join(destDir, filepath.FromSlash(hdr.Name))
		os.MkdirAll(filepath.Dir(dest), 0755) //nolint:errcheck
		out, err := os.Create(dest)
		if err != nil {
			return err
		}
		io.Copy(out, tr) //nolint:errcheck
		out.Close()
	}
	return nil
}

// mergeCustomLayer copies each file from a bundle's custom layer into the operator's, overwriting
// same-named files and leaving everything else untouched. Returns how many files were written.
// A missing source layer is not an error — most bundles carry no custom rules.
func mergeCustomLayer(src, dst string) (int, error) {
	entries, err := os.ReadDir(src)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil
		}
		return 0, err
	}
	if err := os.MkdirAll(dst, 0o755); err != nil {
		return 0, err
	}
	n := 0
	for _, e := range entries {
		if e.IsDir() {
			continue // the custom layer is flat; ignore anything nested rather than walking a bundle's tree
		}
		body, err := os.ReadFile(filepath.Join(src, e.Name()))
		if err != nil {
			return n, err
		}
		if err := os.WriteFile(filepath.Join(dst, e.Name()), body, 0o644); err != nil {
			return n, err
		}
		n++
	}
	return n, nil
}
