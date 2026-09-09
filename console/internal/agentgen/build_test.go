package agentgen

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func diskRequest() Request {
	return Request{
		Files:         diskRelease(),
		Views:         []string{"disk"},
		Release:       "v1.0.0-488-gdd02888",
		RuleSetName:   "sweep-acme",
		RuleSetVer:    3,
		ResolvedRules: 5872,
		Yarc:          []byte("compiled rule blob"),
		OutputFormat:  "json",
		Priority:      "low",
		GeneratedAt:   "2026-09-04T12:00:00Z",
		GeneratedBy:   "v.quannh67",
	}
}

func entries(t *testing.T, archive []byte) map[string][]byte {
	t.Helper()
	zr, err := zip.NewReader(bytes.NewReader(archive), int64(len(archive)))
	if err != nil {
		t.Fatalf("output is not a zip: %v", err)
	}
	out := map[string][]byte{}
	for _, f := range zr.File {
		rc, err := f.Open()
		if err != nil {
			t.Fatal(err)
		}
		var buf bytes.Buffer
		if _, err := buf.ReadFrom(rc); err != nil {
			t.Fatal(err)
		}
		rc.Close()
		out[f.Name] = buf.Bytes()
	}
	return out
}

// Spec 10: a disk build contains yr and rules/set.yarc and NO YARA source.
func TestADiskBuildCarriesYrAndTheCompiledSetAndNoRuleText(t *testing.T) {
	got, err := Build(diskRequest())
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	files := entries(t, got.Archive)
	for _, want := range []string{"shellsight", "diskprobe", "third_party/yara-x/yr", RulesPath,
		AgentPath, ManifestPath} {
		if _, ok := files[want]; !ok {
			t.Errorf("archive is missing %q; it holds %d entries", want, len(files))
		}
	}
	if string(files[RulesPath]) != "compiled rule blob" {
		t.Errorf("%s = %q", RulesPath, files[RulesPath])
	}
	for name := range files {
		if strings.HasSuffix(name, ".yar") || strings.HasSuffix(name, ".yara") ||
			strings.HasPrefix(name, "kb/rules/") {
			t.Errorf("archive carries YARA source at %q, violating G8/D5", name)
		}
	}
}

// Spec 10 and G3: a memory-only build contains neither yr nor rules/. This is the test that makes
// "the split is implemented" a fact rather than a claim about the future.
func TestAMemoryOnlyBuildCarriesNeitherYrNorRules(t *testing.T) {
	req := diskRequest()
	req.Files = fakeFiles{
		"components.json": []byte(linuxComponents),
		"shellsight":      []byte("orchestrator bytes"),
		"jvmprobe":        []byte("jvm probe bytes"),
	}
	req.Views = []string{"java-mem"}
	// A memory-only build takes no rule set at all, so the caller supplies none.
	req.Yarc = nil
	req.RuleSetName, req.RuleSetVer, req.ResolvedRules = "", 0, 0

	got, err := Build(req)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	files := entries(t, got.Archive)
	for name := range files {
		if strings.Contains(name, "yara-x") || strings.HasPrefix(name, "rules/") {
			t.Errorf("a memory-only archive carries %q", name)
		}
	}
	if _, ok := files["jvmprobe"]; !ok {
		t.Error("archive is missing jvmprobe")
	}
	var cfg map[string]any
	if err := json.Unmarshal(files[AgentPath], &cfg); err != nil {
		t.Fatal(err)
	}
	rs, _ := cfg["rule_set"].(map[string]any)
	if rs["yarc"] != "" {
		t.Errorf("agent.json names a rule blob this build does not carry: %v", rs)
	}
}

// The manifest must describe the archive it is in, or it is decoration.
func TestTheManifestMatchesEveryFileActuallyInTheArchive(t *testing.T) {
	got, err := Build(diskRequest())
	if err != nil {
		t.Fatal(err)
	}
	files := entries(t, got.Archive)
	var m struct {
		Files map[string]string `json:"files"`
	}
	if err := json.Unmarshal(files[ManifestPath], &m); err != nil {
		t.Fatal(err)
	}
	if len(m.Files) != len(files)-1 {
		t.Errorf("manifest lists %d files, archive holds %d (excluding the manifest itself)",
			len(m.Files), len(files)-1)
	}
	for name, body := range files {
		if name == ManifestPath {
			continue
		}
		sum := sha256.Sum256(body)
		if m.Files[name] != hex.EncodeToString(sum[:]) {
			t.Errorf("%s: manifest says %q, archive content hashes to %q",
				name, m.Files[name], hex.EncodeToString(sum[:]))
		}
	}
}

// G6, end to end.
//
// The two builds are separated by a DEMONSTRATED clock tick, and that separation is the whole
// difference between this test and the one the plan specified. Measured 2026-09-04: with
// time.Now() hashed into deriveBuildID -- the mutation the plan calls "the one to actually run" --
// the plan's version survived 3 of 12 full-suite runs, because two adjacent Builds of a four-file
// archive fit inside one wall-clock tick on this host (~1ms; 199 distinct RFC3339Nano values in
// 200ms). A gate that fires three times in four is a coin flip a future change gets to toss.
//
// The tick only covers a sub-second clock read. The gate that covers ANY of them, on every run and
// with no waiting, is TestTheBuildIDIsAPinnedFunctionOfTheRequest below.
func TestTwoBuildsOfTheSameRequestAreByteIdentical(t *testing.T) {
	a, err := Build(diskRequest())
	if err != nil {
		t.Fatal(err)
	}
	waitForTheWallClockToAdvance(t)
	b, err := Build(diskRequest())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a.Archive, b.Archive) {
		t.Fatalf("archives differ (%d vs %d bytes); G6 requires identical inputs to reproduce",
			len(a.Archive), len(b.Archive))
	}
	if a.BuildID != b.BuildID {
		t.Errorf("BuildID is not derived from the inputs: %q then %q", a.BuildID, b.BuildID)
	}
	if a.SHA256 != b.SHA256 {
		t.Errorf("SHA256 differs: %q vs %q", a.SHA256, b.SHA256)
	}
}

// waitForTheWallClockToAdvance blocks until time.Now() reports a value it did not report before,
// so anything reading a clock inside Build must read a different one on the next call.
func waitForTheWallClockToAdvance(t *testing.T) {
	t.Helper()
	was := time.Now().UTC().Format(time.RFC3339Nano)
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().UTC().Format(time.RFC3339Nano) == was {
		if time.Now().After(deadline) {
			t.Fatalf("the wall clock has not moved past %s in two seconds, so this test cannot tell a "+
				"fixed instant from a clock read", was)
		}
		time.Sleep(100 * time.Microsecond)
	}
}

// The build id is a pinned function of the request, and pinning it is what makes the clock and the
// random-number generator unusable inside Build.
//
// Every other determinism test compares two builds to each other, so it can only catch a varying
// input if the variation happens to land between them -- measured above at 3-in-4, not 1. This one
// compares against a value written down on 2026-09-04, so ANY clock read, at any resolution, and
// any random source, fails it on every run.
//
// The archive's SHA-256 is deliberately NOT pinned alongside it: flate's output is stable within a
// Go release but is not a documented cross-version constant, so that value would fail a toolchain
// upgrade that changed nothing about the agent. The id hashes only strings this package controls.
//
// If a change to deriveBuildID's inputs is intended, update the constant and say why in the commit.
// A surprise here is the derivation moving without anyone deciding to move it.
func TestTheBuildIDIsAPinnedFunctionOfTheRequest(t *testing.T) {
	const want = "b-5a5390c6220b"
	got, err := Build(diskRequest())
	if err != nil {
		t.Fatal(err)
	}
	if got.BuildID != want {
		t.Errorf("BuildID = %q, want %q; either deriveBuildID's inputs changed on purpose -- in "+
			"which case update this constant -- or something outside the request is reaching into it",
			got.BuildID, want)
	}
}

// Different inputs must not collide on a build id, or the record cannot identify the artefact.
func TestADifferentSelectionGetsADifferentBuildID(t *testing.T) {
	a, err := Build(diskRequest())
	if err != nil {
		t.Fatal(err)
	}
	other := diskRequest()
	other.RuleSetVer = 4
	b, err := Build(other)
	if err != nil {
		t.Fatal(err)
	}
	if a.BuildID == b.BuildID {
		t.Error("a different rule-set version produced the same build id")
	}
}

// Two targets whose declarations name the identical paths must not collide on a build id.
//
// This is not hypothetical and it is not covered by the test above. agent.json records the release
// VERSION, and a version string alone is not unique across targets -- (version, target) is the
// natural key in `releases`. linux-amd64 and linux-arm64 carry the same component paths with
// different machine code in them, so with the target left out of the derivation the same id would
// name two agents that cannot run on each other's processor.
func TestTwoTargetsWithTheSamePathsGetDifferentBuildIDs(t *testing.T) {
	arm := diskRequest()
	armFiles := diskRelease()
	armDoc := strings.Replace(linuxComponents, "linux-amd64", "linux-arm64", 1)
	if armDoc == linuxComponents {
		t.Fatal("fixture did not change; the target is not where this test thinks it is")
	}
	armFiles["components.json"] = []byte(armDoc)
	arm.Files = armFiles

	amd64, err := Build(diskRequest())
	if err != nil {
		t.Fatal(err)
	}
	arm64, err := Build(arm)
	if err != nil {
		t.Fatal(err)
	}
	if amd64.BuildID == arm64.BuildID {
		t.Errorf("linux-amd64 and linux-arm64 both produced %q: the target is not in the derivation, "+
			"so one id names two agents for two processors", amd64.BuildID)
	}
}

// G7. The UI already promises this in SelectionEditor.tsx:99-104.
func TestARuleSetResolvingToZeroRulesIsRefused(t *testing.T) {
	req := diskRequest()
	req.ResolvedRules = 0
	_, err := Build(req)
	if err == nil {
		t.Fatal("a rule set applying no rules must be refused: the agent would detect nothing")
	}
	if !strings.Contains(err.Error(), "no rules") {
		t.Errorf("the message must say why: %v", err)
	}
}

// A disk build with no compiled blob would carry an agent.json naming a rules/set.yarc that is not
// in the archive -- the scanner would then fail on the host for a reason created here.
func TestADiskBuildWithNoCompiledBlobIsRefused(t *testing.T) {
	req := diskRequest()
	req.Yarc = nil
	_, err := Build(req)
	if err == nil {
		t.Fatal("a rules-needing build with no compiled blob must be refused")
	}
	if !strings.Contains(err.Error(), "frozen") {
		t.Errorf("the message should point at freezing the set: %v", err)
	}
}

// A memory-only build handed a rule set is a caller mistake, and staging it would contradict the
// agent.json this same function writes.
func TestAMemoryOnlyBuildGivenARuleSetIsRefused(t *testing.T) {
	req := diskRequest()
	req.Files = fakeFiles{
		"components.json": []byte(linuxComponents),
		"shellsight":      []byte("o"),
		"jvmprobe":        []byte("j"),
	}
	req.Views = []string{"java-mem"}
	if _, err := Build(req); err == nil {
		t.Fatal("a build carrying no YARA must not be given a rule set")
	}
}

// Two builds differing only in the baked scope are different artefacts: agent.json differs, and
// agent.json is inside the archive. If the id ignored the scope they would share one and hash
// differently, and RecordBuild would refuse the second as a collision -- rejecting a legitimate
// build for a reason that is not true.
func TestADifferentBakedScopeGetsADifferentBuildID(t *testing.T) {
	a := diskRequest()
	a.ScanScope = []string{"/var/www"}
	b := diskRequest()
	b.ScanScope = []string{"/srv/http"}

	ra, err := Build(a)
	if err != nil {
		t.Fatal(err)
	}
	rb, err := Build(b)
	if err != nil {
		t.Fatal(err)
	}
	if ra.BuildID == rb.BuildID {
		t.Error("two builds with different baked scopes produced the same build id")
	}
	if ra.SHA256 == rb.SHA256 {
		t.Error("their archives are identical, so the scope did not reach agent.json")
	}
}

// And the scope actually lands in the config the agent reads.
func TestTheBakedScopeReachesAgentJSON(t *testing.T) {
	req := diskRequest()
	req.ScanScope = []string{"/var/www", "/srv/http"}
	got, err := Build(req)
	if err != nil {
		t.Fatal(err)
	}
	var cfg struct {
		ScanScope []string `json:"scan_scope"`
	}
	if err := json.Unmarshal(got.AgentJSON, &cfg); err != nil {
		t.Fatal(err)
	}
	if len(cfg.ScanScope) != 2 || cfg.ScanScope[0] != "/var/www" {
		t.Errorf("agent.json scan_scope = %v", cfg.ScanScope)
	}
}
