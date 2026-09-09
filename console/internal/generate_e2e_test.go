package console_test

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"shellsightconsole/internal/blob"
	"shellsightconsole/internal/consoletest"
	"shellsightconsole/internal/httpapi"
	"shellsightconsole/internal/rules"
	"shellsightconsole/internal/ruleset"
	"shellsightconsole/internal/store"
)

// The release's own declaration of what each view needs, INLINED rather than produced by running
// `shellsight components`.
//
// The trade the plan names: running the scanner couples this test to a built binary and to a
// cross-compiled target, while inlining risks the document drifting from what the scanner really
// emits. Inlining wins here because the drift is caught elsewhere -- agentgen.LoadComponents
// refuses any schema_version but "1", and the scanner's own package-time
// verify_release_declaration checks a real release's document against its real archive -- whereas
// a test that shells out to a binary fails for reasons that have nothing to do with generation.
//
// It is the linux-amd64 document, copied from the scanner's real output: `always` is the
// orchestrator alone, disk declares two binaries and rules:true, java-mem declares one binary and
// rules:false. That second view is the memory-only shape G3 requires a test for; dotnet-mem is
// deliberately not used, because Plan 1 recorded that its ~137 runtime DLLs are undeclared.
const linuxDeclaration = `{
  "schema_version": "1",
  "target": "linux-amd64",
  "release": "v1.0.0-231",
  "always": ["shellsight"],
  "views": {
    "disk": {
      "binaries": ["diskprobe", "third_party/yara-x/yr"],
      "data": ["kb/rules/foundation", "kb/rules/own"],
      "rules": true
    },
    "java-mem": {
      "binaries": ["jvmprobe"],
      "rules": false
    }
  }
}
`

func TestPublishFreezeGenerateDownload(t *testing.T) {
	dsn := os.Getenv("CONSOLE_TEST_DSN")
	if dsn == "" {
		t.Skip("CONSOLE_TEST_DSN not set")
	}
	yr := consoletest.FindYr()
	if yr == "" {
		t.Skip("no yr binary found; set CONSOLE_TEST_YR")
	}

	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	if _, err := pool.Exec(ctx, `DROP SCHEMA public CASCADE; CREATE SCHEMA public;`); err != nil {
		t.Fatal(err)
	}
	if err := store.Migrate(ctx, pool); err != nil {
		t.Fatal(err)
	}

	st := store.NewPG(pool)
	blobs := blob.New(t.TempDir())

	// 1. Publish a release. Every file's bytes go into the blob store under their own hash, which
	//    is what `console publish` does -- assembly is then a lookup, never a download.
	//
	//    The last four rows exist so the G8 check below has something it can catch. Two of them are
	//    the disk view's declared `data` entries verbatim: in a release built by package.sh those
	//    are DIRECTORIES and release_files has no row for either, so a build that wrongly staged
	//    them would be refused as "this release does not hold it" -- and the archive check would
	//    pass for the wrong reason, which is exactly the inertness this plan recorded for Task 2.
	//    Present as rows, staging them succeeds and only the assertion can refuse the result.
	contents := map[string]string{
		"components.json":         linuxDeclaration,
		"shellsight":              "ELF orchestrator, not really",
		"diskprobe":               "ELF diskprobe, not really",
		"third_party/yara-x/yr":   "ELF yr, not really",
		"jvmprobe":                "ELF jvmprobe, not really",
		"kb/rules/foundation":     `rule Foundation { condition: true }`,
		"kb/rules/own":            `rule Own { condition: true }`,
		"kb/rules/own/acme.yar":   `rule Acme { condition: true }`,
		"kb/rules/own/other.yara": `rule Other { condition: true }`,
	}
	var files []store.ReleaseFile
	for path, body := range contents {
		key, err := blobs.Put([]byte(body))
		if err != nil {
			t.Fatal(err)
		}
		files = append(files, store.ReleaseFile{Path: path, SHA256: key})
	}
	releaseID, err := st.PublishRelease(ctx,
		store.Release{Version: "v1.0.0-231", Target: "linux-amd64", PublishedBy: "v.quannh67"},
		files)
	if err != nil {
		t.Fatalf("publish: %v", err)
	}

	// 2. Author a rule and freeze a set from it, so there is a real compiled .yarc in the blob
	//    store rather than bytes this test invented.
	compiler := rules.NewCompiler(yr)
	ruleSvc := rules.NewService(st, compiler, rules.NewLibraryResolver(st))
	setSvc := ruleset.NewService(st, blobs, compiler)
	ruleID, err := ruleSvc.Create(ctx, "custom",
		`rule e2e_generate { strings: $a = "eval(" condition: $a }`, "php", "v.quannh67")
	if err != nil {
		t.Fatalf("create rule: %v", err)
	}
	setID, err := st.CreateRuleSet(ctx, "e2e-generate-set", "v.quannh67")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.SetSelection(ctx, setID, store.Selection{Rules: []int64{ruleID}}); err != nil {
		t.Fatal(err)
	}
	yarcHash, err := setSvc.Freeze(ctx, setID, 1, "v.quannh67")
	if err != nil {
		t.Fatalf("freeze: %v", err)
	}

	// The clock is held still. generated_at is stamped by the handler, it is an input to the build
	// id, and agent.json is inside the archive -- so without pinning it, step 6's "the same request
	// twice" holds only when both requests land in the same clock second and the test is a coin
	// toss with a very biased coin.
	at := time.Date(2026, 9, 4, 11, 22, 33, 0, time.UTC)
	api := httpapi.NewBuildAPIWithClock(st, blobs, func() time.Time { return at })
	srv := httptest.NewServer(api.Routes())
	defer srv.Close()

	// 3. Generate a disk agent.
	disk := postBuild(t, srv.URL, map[string]any{
		"release_id": releaseID, "rule_set_id": setID, "views": []string{"disk"},
	})

	// 4. Download it, and check the bytes against the hash the build row recorded. This is the
	//    seam: the record says what was handed out, and the download is served by that hash.
	body, hdr := download(t, srv.URL, disk.ID)
	sum := sha256.Sum256(body)
	if got := hex.EncodeToString(sum[:]); got != disk.SHA256 {
		t.Fatalf("downloaded bytes hash to %s, the build row records %s", got, disk.SHA256)
	}
	if hdr.Get("X-Agent-SHA256") != disk.SHA256 {
		t.Errorf("X-Agent-SHA256 = %q, want %s", hdr.Get("X-Agent-SHA256"), disk.SHA256)
	}
	if int64(len(body)) != disk.SizeBytes {
		t.Errorf("downloaded %d bytes, the row records %d", len(body), disk.SizeBytes)
	}

	// 5. What the archive holds, and what it must not.
	entries := unzip(t, body)
	for _, want := range []string{
		"shellsight", "diskprobe", "third_party/yara-x/yr",
		"rules/set.yarc", "agent.json", "manifest.json",
	} {
		if _, ok := entries[want]; !ok {
			t.Errorf("the disk archive is missing %s; it holds %v", want, names(entries))
		}
	}
	// G8/D5: a generated agent ships the COMPILED rule set and no YARA source. The declaration's
	// `data` entries for a rules view name the layers the .yarc replaces, not files to stage -- so
	// a build that staged them would ship the rule tree it exists to avoid shipping.
	for name := range entries {
		if strings.HasSuffix(name, ".yar") || strings.HasSuffix(name, ".yara") ||
			strings.HasPrefix(name, "kb/rules/") {
			t.Errorf("the disk archive carries YARA source: %s", name)
		}
	}

	// 6. The agent.json INSIDE the zip names the frozen set's real blob, and the archive carries
	//    exactly those bytes.
	//
	//    Only an end-to-end test can see this. Each unit test knows one half: the generator is
	//    handed a []byte and told it is a rule set, and the store is asked for a hash. A build
	//    whose configuration points at a different blob than the one it carries is the failure this
	//    whole plan exists to prevent, and it lives in the seam between them.
	cfg := agentConfig(t, entries["agent.json"])
	set, err := st.GetRuleSet(ctx, setID)
	if err != nil {
		t.Fatal(err)
	}
	if set.YarcSHA256 != yarcHash {
		t.Fatalf("the store records %s for the frozen set, Freeze returned %s", set.YarcSHA256, yarcHash)
	}
	if cfg.RuleSet.YarcSHA256 != yarcHash {
		t.Errorf("agent.json names yarc_sha256 %s, the frozen set's blob is %s",
			cfg.RuleSet.YarcSHA256, yarcHash)
	}
	carried := sha256.Sum256(entries[cfg.RuleSet.Yarc])
	if got := hex.EncodeToString(carried[:]); got != cfg.RuleSet.YarcSHA256 {
		t.Errorf("%s in the archive hashes to %s, agent.json says %s",
			cfg.RuleSet.Yarc, got, cfg.RuleSet.YarcSHA256)
	}
	if cfg.RuleSet.Name != "e2e-generate-set" || cfg.RuleSet.Version != 1 {
		t.Errorf("agent.json names rule set %q v%d", cfg.RuleSet.Name, cfg.RuleSet.Version)
	}
	if cfg.Release != "v1.0.0-231" {
		t.Errorf("agent.json records release %q, the release published as v1.0.0-231", cfg.Release)
	}
	if cfg.BuildID != disk.BuildID {
		t.Errorf("agent.json carries build id %q, the row records %q", cfg.BuildID, disk.BuildID)
	}
	// The provenance INSIDE the archive comes from the handler's clock and the request's actor
	// header. Asserting the literal instant is what makes the pinned clock a gate rather than a
	// convenience: with the real clock read at this format's one-second resolution, two POSTs a
	// few milliseconds apart still agree, so step 7 alone cannot tell a pinned clock from an
	// unpinned one -- measured.
	//
	// Note the two clocks are not the same one. agent.json's generated_at is a.now(), from the
	// console process; the build ROW's generated_at is Postgres now(), because create leaves the
	// column to COALESCE($8, now()). They can disagree, and only the archive's is reproducible.
	if cfg.GeneratedAt != "2026-09-04T11:22:33Z" {
		t.Errorf("agent.json generated_at = %q, want the pinned instant", cfg.GeneratedAt)
	}
	if cfg.GeneratedBy != "v.quannh67" || disk.GeneratedBy != "v.quannh67" {
		t.Errorf("attribution did not reach the archive and the row: agent.json %q, row %q",
			cfg.GeneratedBy, disk.GeneratedBy)
	}

	// 7. The same request again is the same artefact -- G6 through the API, not only in the
	//    package. A second row would mean two agents an analyst cannot tell apart.
	again := postBuild(t, srv.URL, map[string]any{
		"release_id": releaseID, "rule_set_id": setID, "views": []string{"disk"},
	})
	if again.BuildID != disk.BuildID || again.SHA256 != disk.SHA256 {
		t.Errorf("the same request produced %s/%s then %s/%s",
			disk.BuildID, disk.SHA256, again.BuildID, again.SHA256)
	}
	if again.ID != disk.ID {
		t.Errorf("the same request recorded two rows, %d and %d", disk.ID, again.ID)
	}

	// 8. A memory-only build carries no YARA at all: no compiled set, no yr, no rule set named.
	//    This is the split G3 asks for, and the shape spec 10 names.
	mem := postBuild(t, srv.URL, map[string]any{
		"release_id": releaseID, "rule_set_id": nil, "views": []string{"java-mem"},
	})
	memBody, _ := download(t, srv.URL, mem.ID)
	memEntries := unzip(t, memBody)
	for _, want := range []string{"shellsight", "jvmprobe", "agent.json", "manifest.json"} {
		if _, ok := memEntries[want]; !ok {
			t.Errorf("the java-mem archive is missing %s; it holds %v", want, names(memEntries))
		}
	}
	for name := range memEntries {
		if strings.HasPrefix(name, "rules/") || strings.HasSuffix(name, "/yr") || name == "yr" {
			t.Errorf("the java-mem archive carries %s, which no memory view scans with", name)
		}
	}
	if _, ok := memEntries["diskprobe"]; ok {
		t.Error("the java-mem archive carries diskprobe, a probe no selected view runs")
	}
	memCfg := agentConfig(t, memEntries["agent.json"])
	if memCfg.RuleSet.Yarc != "" || memCfg.RuleSet.YarcSHA256 != "" || memCfg.RuleSet.Name != "" {
		t.Errorf("the java-mem agent.json names a rule set: %+v", memCfg.RuleSet)
	}
	if len(memCfg.Views) != 1 || memCfg.Views[0] != "java-mem" {
		t.Errorf("the java-mem agent.json declares views %v", memCfg.Views)
	}
	// Different views are a different artefact, or the record layer would return one for the other.
	if mem.BuildID == disk.BuildID {
		t.Errorf("a disk build and a java-mem build share the id %s", mem.BuildID)
	}

	// 9. And it was audited, once per distinct build. Without this the console can hand out an
	//    agent it has no record of having handed out.
	rows, err := pool.Query(ctx,
		`SELECT subject FROM audit_log WHERE action='agent.generate' ORDER BY id`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	generated := map[string]bool{}
	for rows.Next() {
		var subject string
		if err := rows.Scan(&subject); err != nil {
			t.Fatal(err)
		}
		generated[subject] = true
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if !generated[disk.BuildID] || !generated[mem.BuildID] {
		t.Errorf("agent.generate audit covers %v, want %s and %s",
			generated, disk.BuildID, mem.BuildID)
	}
}

func postBuild(t *testing.T, base string, req map[string]any) store.Build {
	t.Helper()
	raw, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	httpReq, err := http.NewRequest(http.MethodPost, base+"/api/builds", bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	// Attribution, not authentication -- but it has to reach the archive, so it is sent here
	// rather than left to default to "unknown".
	httpReq.Header.Set("X-Console-Actor", "v.quannh67")
	resp, err := http.DefaultClient.Do(httpReq)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("POST /api/builds %s: status %d, want 201: %s", raw, resp.StatusCode, body)
	}
	var got store.Build
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatal(err)
	}
	return got
}

func download(t *testing.T, base string, id int64) ([]byte, http.Header) {
	t.Helper()
	resp, err := http.Get(base + "/api/builds/" + strconv.FormatInt(id, 10) + "/download")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("download build %d: status %d: %s", id, resp.StatusCode, body)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "application/zip" {
		t.Errorf("content type %q, want application/zip", ct)
	}
	return body, resp.Header
}

func unzip(t *testing.T, body []byte) map[string][]byte {
	t.Helper()
	zr, err := zip.NewReader(bytes.NewReader(body), int64(len(body)))
	if err != nil {
		t.Fatalf("the download is not a zip: %v", err)
	}
	out := map[string][]byte{}
	for _, f := range zr.File {
		rc, err := f.Open()
		if err != nil {
			t.Fatal(err)
		}
		content, err := io.ReadAll(rc)
		rc.Close()
		if err != nil {
			t.Fatal(err)
		}
		out[f.Name] = content
	}
	return out
}

// agentJSON is the fields this test reads out of the generated agent.json. Declared here rather
// than imported: the console cannot import the scanner's agentcfg, and reading the document as a
// document is the point -- it is what the scanner will do on the host.
type agentJSON struct {
	SchemaVersion string   `json:"schema_version"`
	BuildID       string   `json:"build_id"`
	Views         []string `json:"views"`
	RuleSet       struct {
		Name       string `json:"name"`
		Version    int    `json:"version"`
		Yarc       string `json:"yarc"`
		YarcSHA256 string `json:"yarc_sha256"`
	} `json:"rule_set"`
	GeneratedAt string `json:"generated_at"`
	GeneratedBy string `json:"generated_by"`
	Release     string `json:"release"`
}

func agentConfig(t *testing.T, raw []byte) agentJSON {
	t.Helper()
	if len(raw) == 0 {
		t.Fatal("the archive holds no agent.json")
	}
	var cfg agentJSON
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatalf("agent.json is not valid JSON: %v\n%s", err, raw)
	}
	if cfg.SchemaVersion != "1" {
		t.Errorf("agent.json declares schema_version %q", cfg.SchemaVersion)
	}
	return cfg
}

func names(entries map[string][]byte) []string {
	out := make([]string, 0, len(entries))
	for name := range entries {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}
