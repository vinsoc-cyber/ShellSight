package rules

import (
	"archive/zip"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

func runUpdate(args []string, w io.Writer) int {
	dir := rulesDir(args)
	offline := ""
	for i, a := range args {
		if a == "--offline" && i+1 < len(args) {
			offline = args[i+1]
		}
	}

	staged := filepath.Join(dir, "foundation", ".staged")
	if err := os.MkdirAll(staged, 0755); err != nil {
		fmt.Fprintln(w, "update: cannot create staged dir:", err)
		return 1
	}

	if offline != "" {
		fmt.Fprintln(w, "update: importing from offline bundle:", offline)
		if err := extractZipTo(offline, staged); err != nil {
			fmt.Fprintln(w, "update: extract failed:", err)
			return 1
		}
	} else {
		fmt.Fprintln(w, "update: fetching latest YARA Forge release...")
		url, tag, err := latestYaraForgeURL()
		if err != nil {
			fmt.Fprintln(w, "update: cannot fetch latest release:", err)
			return 1
		}
		fmt.Fprintf(w, "update: downloading %s (%s)...\n", tag, url)
		zipPath := filepath.Join(staged, "yara-forge-rules.zip")
		if err := downloadFile(url, zipPath); err != nil {
			fmt.Fprintln(w, "update: download failed:", err)
			return 1
		}
		if err := extractZipTo(zipPath, staged); err != nil {
			fmt.Fprintln(w, "update: extract failed:", err)
			return 1
		}
		os.WriteFile(filepath.Join(staged, "VERSION"), []byte(tag), 0644) //nolint:errcheck
	}

	active := filepath.Join(dir, "foundation", "yara-forge")
	os.RemoveAll(active) //nolint:errcheck
	if err := os.Rename(staged, active); err != nil {
		fmt.Fprintln(w, "update: activation failed:", err)
		return 1
	}
	fmt.Fprintln(w, "update: OK — foundation rules updated")
	return 0
}

func latestYaraForgeURL() (url, tag string, err error) {
	resp, err := http.Get("https://api.github.com/repos/YARAHQ/yara-forge/releases/latest") //nolint:noctx
	if err != nil {
		return
	}
	defer resp.Body.Close()
	var rel struct {
		TagName string `json:"tag_name"`
		Assets  []struct {
			Name               string `json:"name"`
			BrowserDownloadURL string `json:"browser_download_url"`
		} `json:"assets"`
	}
	if err = json.NewDecoder(resp.Body).Decode(&rel); err != nil {
		return
	}
	tag = rel.TagName
	for _, a := range rel.Assets {
		if strings.Contains(a.Name, "full") && strings.HasSuffix(a.Name, ".zip") {
			url = a.BrowserDownloadURL
			return
		}
	}
	err = fmt.Errorf("no full rules ZIP found in release %s", tag)
	return
}

func downloadFile(url, dest string) error {
	resp, err := http.Get(url) //nolint:noctx
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	f, err := os.Create(dest)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = io.Copy(f, resp.Body)
	return err
}

func extractZipTo(zipPath, destDir string) error {
	r, err := zip.OpenReader(zipPath)
	if err != nil {
		return err
	}
	defer r.Close()
	for _, f := range r.File {
		dest := filepath.Join(destDir, f.Name)
		if !strings.HasPrefix(filepath.Clean(dest), filepath.Clean(destDir)+string(os.PathSeparator)) {
			continue // zip slip guard
		}
		if f.FileInfo().IsDir() {
			os.MkdirAll(dest, 0755) //nolint:errcheck
			continue
		}
		os.MkdirAll(filepath.Dir(dest), 0755) //nolint:errcheck
		rc, err := f.Open()
		if err != nil {
			return err
		}
		out, err := os.Create(dest)
		if err != nil {
			rc.Close()
			return err
		}
		io.Copy(out, rc) //nolint:errcheck
		out.Close()
		rc.Close()
	}
	return nil
}
