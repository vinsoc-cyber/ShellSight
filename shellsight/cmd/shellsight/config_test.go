package main

import (
	"encoding/json"
	"flag"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"shellsight/internal/agentcfg"
	"shellsight/internal/finding"
)

// The precedence C3 specifies: explicit CLI options > agent.json > built-in defaults.
//
// Every test below drives the resolvers directly rather than through a scan, because that is the
// only way to assert the ladder without also asserting a probe registry, a run folder and an exit
// code. Several of them build a Config that Load would reject -- a Present:false config carrying a
// specified value, an enum member that does not exist -- on purpose: the ladder has to be safe on
// its own terms, not merely because the loader upstream happens to be strict today.
//
// Every path expectation is built with filepath.Join and never as a literal. A `C:\agent\...`
// string would fail on Linux against a correct implementation, which is the test lying about the
// code rather than the other way round.

func TestCLIWinsOverTheConfig(t *testing.T) {
	// An operator overriding a view set on a live engagement must not be silently overruled by the
	// build's own config.
	got := resolveViews("disk", true, agentcfg.Config{Present: true, Views: []string{"java-mem"}}, "disk,java-mem")
	if got != "disk" {
		t.Errorf("views = %q, want the CLI value", got)
	}
}

func TestTheConfigWinsOverDefaults(t *testing.T) {
	got := resolveViews("", false, agentcfg.Config{Present: true, Views: []string{"disk"}}, "disk,java-mem")
	if got != "disk" {
		t.Errorf("views = %q, want the config value", got)
	}
}

func TestDefaultsApplyWithNoConfigAndNoFlag(t *testing.T) {
	got := resolveViews("", false, agentcfg.Config{}, "disk,java-mem")
	if got != "disk,java-mem" {
		t.Errorf("views = %q, want the built-in default", got)
	}
}

func TestAFlagSetToTheDefaultValueStillCounts(t *testing.T) {
	// The subtle one. -views defaults to the built-in set, so comparing the flag's VALUE to the
	// default cannot tell "the operator typed it" from "nobody passed it". Whether the flag was
	// SET is the only reliable signal, which is why resolveViews takes it explicitly.
	got := resolveViews("disk,java-mem", true,
		agentcfg.Config{Present: true, Views: []string{"disk"}}, "disk,java-mem")
	if got != "disk,java-mem" {
		t.Errorf("views = %q, want the explicitly-typed CLI value even though it equals the default", got)
	}
}

func TestAConfigThatIsNotPresentCannotSupplyViews(t *testing.T) {
	// Present is checked BEFORE the field, not instead of it. "No agent.json at all" and "an
	// agent.json that named nothing" are different facts and only Present separates them, so a
	// resolver reading the field alone lets a config that does not exist choose the view set.
	got := resolveViews("", false, agentcfg.Config{Views: []string{"java-mem"}}, "disk,java-mem")
	if got != "disk,java-mem" {
		t.Errorf("views = %q, want the built-in default: there is no config to read", got)
	}
}

func TestAConfigThatIsNotPresentCarriesNothing(t *testing.T) {
	// Present before the field once more, and this is the reading where getting it wrong is worst.
	// A configuration that does not exist has no view list, so the answer is nil -- "excludes
	// nothing". Reading the field alone would let a configuration nobody could load declare views
	// ABSENT, and a declared absence does not set `incomplete`: the scan would report every
	// capability as out of scope, cleanly, and exit 0.
	if got := carriedViews(agentcfg.Config{Views: []string{"disk"}}); got != nil {
		t.Errorf("carriedViews = %v, want nil: there is no configuration to read", got)
	}
	// A Present configuration stating no views is answered the same way. agentcfg.Load refuses that
	// configuration, so this is the belt to its braces -- and an empty set here would mean "carries
	// nothing", which is the one answer that turns a scan into a report about nothing.
	if got := carriedViews(agentcfg.Config{Present: true}); got != nil {
		t.Errorf("carriedViews = %v, want nil for a configuration that states no views", got)
	}
	// The ordinary case: a build that declares what it carries.
	got := carriedViews(agentcfg.Config{Present: true, Views: []string{"disk", "java-mem"}})
	if strings.Join(got, ",") != "disk,java-mem" {
		t.Errorf("carriedViews = %v, want the configuration's own view set", got)
	}
}

func TestABlobFromTheConfigIsResolvedBesideIt(t *testing.T) {
	// agent.json's yarc path is relative to the agent directory, because the console writes the
	// config without knowing where the analyst will unpack it.
	agentDir := t.TempDir()
	got, err := resolveRulesBlob("", "",
		agentcfg.Config{Present: true, RuleSet: agentcfg.RuleSet{Yarc: "rules/set.yarc"}}, agentDir)
	if err != nil {
		t.Fatalf("resolveRulesBlob: %v", err)
	}
	if want := filepath.Join(agentDir, "rules", "set.yarc"); got != want {
		t.Errorf("blob = %q, want %q resolved against the agent directory", got, want)
	}
}

func TestAnExplicitBlobFlagWinsOverTheConfig(t *testing.T) {
	mine := filepath.Join(t.TempDir(), "mine.yarc")
	got, err := resolveRulesBlob(mine, "",
		agentcfg.Config{Present: true, RuleSet: agentcfg.RuleSet{Yarc: "rules/set.yarc"}}, t.TempDir())
	if err != nil {
		t.Fatalf("resolveRulesBlob: %v", err)
	}
	if got != mine {
		t.Errorf("blob = %q, want the CLI value %q", got, mine)
	}
}

func TestAnOperatorsBlobIsNotContainedToTheAgentDirectory(t *testing.T) {
	// The deliberate asymmetry, and the reason containment is applied where it is. A human on the
	// console typed this path, and an IR sweep legitimately scans with a rule set staged on another
	// volume. Containment guards the value the FILE supplies -- the one nobody chose.
	elsewhere := filepath.Join(t.TempDir(), "staged", "set.yarc")
	got, err := resolveRulesBlob(elsewhere, "", agentcfg.Config{}, t.TempDir())
	if err != nil {
		t.Fatalf("an operator's own -rules-blob must be honoured, got error: %v", err)
	}
	if got != elsewhere {
		t.Errorf("blob = %q, want %q", got, elsewhere)
	}
}

func TestNoBlobAnywhereLeavesItEmpty(t *testing.T) {
	got, err := resolveRulesBlob("", "", agentcfg.Config{}, t.TempDir())
	if err != nil {
		t.Fatalf("resolveRulesBlob: %v", err)
	}
	if got != "" {
		t.Errorf("blob = %q, want empty so the rules tree is used", got)
	}
}

func TestAConfigThatIsNotPresentCannotSupplyABlob(t *testing.T) {
	got, err := resolveRulesBlob("", "",
		agentcfg.Config{RuleSet: agentcfg.RuleSet{Yarc: "rules/set.yarc"}}, t.TempDir())
	if err != nil {
		t.Fatalf("resolveRulesBlob: %v", err)
	}
	if got != "" {
		t.Errorf("blob = %q, want empty: there is no config to read", got)
	}
}

// A config's yarc path that leaves the agent directory is refused, and refused with an ERROR rather
// than by falling back to the built-in rules.
//
// agent.json is read on a host under investigation, which is to say a host where an intruder may
// have edited it. filepath.Join calls Clean, so it does not neutralise `..`: joining the agent
// directory with "../../../etc/passwd" resolves cleanly OUT of it. Falling back silently would let
// a tampered config downgrade the sweep to a rule set nobody chose, which is the failure diskprobe
// refuses one layer down for -rules versus -rules-blob.
func TestAConfigBlobCannotEscapeTheAgentDirectory(t *testing.T) {
	agentDir := filepath.Join(t.TempDir(), "agent")
	escapes := []struct {
		name string
		yarc string
	}{
		{"parent traversal", filepath.Join("..", "..", "..", "etc", "passwd")},
		{"traversal buried mid-path", filepath.Join("a", "..", "..", "b")},
		{"the parent itself", ".."},
		{"a sibling directory", filepath.Join("..", "sibling", "set.yarc")},
		// The one a bare strings.HasPrefix compare lets through: "<tmp>/agentEVIL/x.yarc" starts
		// with "<tmp>/agent" as a STRING while sitting outside the directory entirely. Containment
		// has to be checked at a separator boundary, not as a prefix.
		{"a sibling whose name extends the agent directory's", filepath.Join("..", "agentEVIL", "x.yarc")},
		// Resolves exactly to the agent directory. A compiled rule set is a file; a path naming the
		// directory itself is not one, and it is not "inside" it either.
		{"the agent directory itself", filepath.Join("rules", "..")},
		// Rooted rather than relative. The config states a path relative to an agent directory whose
		// location it cannot know, so a rooted value is not a relocatable one -- and joining it
		// anyway would silently reinterpret it as a different path than the one written.
		{"rooted", string(filepath.Separator) + filepath.Join("etc", "x.yarc")},
	}
	for _, c := range escapes {
		got, err := resolveRulesBlob("", "",
			agentcfg.Config{Present: true, RuleSet: agentcfg.RuleSet{Yarc: c.yarc}}, agentDir)
		if err == nil {
			t.Errorf("%s: yarc %q resolved to %q, want an error", c.name, c.yarc, got)
			continue
		}
		if got != "" {
			t.Errorf("%s: returned %q alongside its error; a refused path must not also be handed on",
				c.name, got)
		}
		// The operator is standing on the host and has to be told which field and which value to
		// fix. strconv.Quote rather than the raw string, because the message prints untrusted
		// config text with %q -- a Windows path's separators come back escaped, and a raw compare
		// would fail here against an implementation doing the right thing.
		if !strings.Contains(err.Error(), strconv.Quote(c.yarc)) {
			t.Errorf("%s: error %q does not name the offending value %q", c.name, err, c.yarc)
		}
		if !strings.Contains(err.Error(), "rule_set.yarc") {
			t.Errorf("%s: error %q does not name the field it came from", c.name, err)
		}
	}
}

// The minimum agent.json Load accepts. Kept minimal on purpose: these tests are about which file
// gets read, not about what is in it, and agentcfg's own suite already pins the parsing.
const minimalConfig = `{"schema_version":"1","views":["disk"]}`

func TestAConfigBesideTheBinaryIsPickedUpWithNoFlag(t *testing.T) {
	dir := t.TempDir()
	writeConfig(t, filepath.Join(dir, "agent.json"), minimalConfig)
	cfg, path, err := loadAgentConfig("", dir)
	if err != nil {
		t.Fatalf("loadAgentConfig: %v", err)
	}
	if !cfg.Present {
		t.Error("cfg.Present = false, want the config beside the binary to be read")
	}
	if want := filepath.Join(dir, "agent.json"); path != want {
		t.Errorf("path = %q, want %q", path, want)
	}
}

func TestNoConfigBesideTheBinaryIsNormalAndNotAnError(t *testing.T) {
	// A scanner run by hand has no agent.json. It must fall back to built-in defaults rather than
	// refuse to start.
	cfg, _, err := loadAgentConfig("", t.TempDir())
	if err != nil {
		t.Fatalf("an absent config beside the binary must not be an error: %v", err)
	}
	if cfg.Present {
		t.Error("cfg.Present = true with no config on disk")
	}
}

func TestAConfigNamedWithTheFlagIsRead(t *testing.T) {
	staged := filepath.Join(t.TempDir(), "staged.json")
	writeConfig(t, staged, minimalConfig)
	cfg, path, err := loadAgentConfig(staged, t.TempDir())
	if err != nil {
		t.Fatalf("loadAgentConfig: %v", err)
	}
	if !cfg.Present || path != staged {
		t.Errorf("Present = %v, path = %q, want the file -config named", cfg.Present, path)
	}
}

func TestAConfigNamedWithTheFlagThatIsNotThereIsAnError(t *testing.T) {
	// The asymmetry that matters. Absence is normal when nobody asked for a config and is a typo
	// when somebody did -- and falling back silently for the typo runs a scan with a view set and a
	// rule set nobody asked for, while the operator believes they pointed at one.
	missing := filepath.Join(t.TempDir(), "typo.json")
	_, _, err := loadAgentConfig(missing, t.TempDir())
	if err == nil {
		t.Fatal("a -config that does not exist must not silently become a default scan")
	}
	if !strings.Contains(err.Error(), missing) {
		t.Errorf("error %q does not name the path the operator typed", err)
	}
}

func writeConfig(t *testing.T, path, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestTheAgentDirectoryIsWhereTheConfigWasReadFrom(t *testing.T) {
	// Which directory a config's relative paths resolve against. With no -config the config sits
	// beside the binary and this is exeDir(); with -config naming one staged elsewhere, its paths
	// follow it rather than resolving against a binary directory the file says nothing about.
	dir := t.TempDir()
	if got := agentDirFor(filepath.Join(dir, "agent.json")); got != dir {
		t.Errorf("agentDirFor = %q, want %q", got, dir)
	}
}

func TestTheAgentDirectoryItselfIsNeverARuleSet(t *testing.T) {
	// Driven at containedJoin rather than through resolveRulesBlob because of where it has to hold:
	// AT THE FILESYSTEM ROOT the separator-boundary compare cannot catch this on its own. The base
	// already ends in a separator there, so "the directory itself" satisfies a HasPrefix(base+sep)
	// check and would be handed on as the rule blob -- the scanner told to compile a drive.
	for _, base := range []string{string(filepath.Separator), filepath.Join(t.TempDir(), "agent")} {
		got, err := containedJoin("rule_set.yarc", base, ".")
		if err == nil {
			t.Errorf("containedJoin(%q, \".\") = %q, want an error: it names the directory, not a "+
				"compiled rule set inside it", base, got)
		}
	}
}

func TestAConfigBlobThatLegitimatelyNestsStillResolves(t *testing.T) {
	agentDir := filepath.Join(t.TempDir(), "agent")
	fine := []struct {
		yarc string
		want string
	}{
		{filepath.Join("rules", "set.yarc"), filepath.Join(agentDir, "rules", "set.yarc")},
		{"set.yarc", filepath.Join(agentDir, "set.yarc")},
		{filepath.Join("a", "b", "c.yarc"), filepath.Join(agentDir, "a", "b", "c.yarc")},
		// Descends and comes back. It never leaves, so refusing it would be the containment check
		// mistaking Clean's output for an escape.
		{filepath.Join("rules", "..", "set.yarc"), filepath.Join(agentDir, "set.yarc")},
	}
	for _, c := range fine {
		got, err := resolveRulesBlob("", "",
			agentcfg.Config{Present: true, RuleSet: agentcfg.RuleSet{Yarc: c.yarc}}, agentDir)
		if err != nil {
			t.Errorf("yarc %q: %v", c.yarc, err)
			continue
		}
		if got != c.want {
			t.Errorf("yarc %q resolved to %q, want %q", c.yarc, got, c.want)
		}
	}
}

// Settling the question Task 3 left open. `scan -rules-dir X -rules-blob Y` used to be accepted and
// silently split: the disk view took the blob and ignored -rules-dir, while mem-contracts.json kept
// following -rules-dir. diskprobe refuses that same pair one layer down, for the reason its own
// comment gives -- "silently preferring one when both are given is how an agent ends up scanning
// with rules nobody chose".
func TestBothRuleSourcesOnTheCommandLineAreRefused(t *testing.T) {
	blob := filepath.Join(t.TempDir(), "set.yarc")
	dir := filepath.Join(t.TempDir(), "site-rules")
	got, err := resolveRulesBlob(blob, dir, agentcfg.Config{}, t.TempDir())
	if err == nil {
		t.Fatalf("blob = %q, want -rules-dir and -rules-blob together to be refused", got)
	}
	if !strings.Contains(err.Error(), "-rules-dir") || !strings.Contains(err.Error(), "-rules-blob") {
		t.Errorf("error %q must name both flags so the operator knows which pair to drop", err)
	}
}

func TestAnExplicitRulesDirSuppressesTheConfigsBlob(t *testing.T) {
	// C3 from the other side. -rules-dir is an explicit CLI statement about which rules to scan
	// with; letting the config's blob win over it would let agent.json overrule the operator for
	// the disk view, which is the precedence backwards.
	got, err := resolveRulesBlob("", filepath.Join(t.TempDir(), "site-rules"),
		agentcfg.Config{Present: true, RuleSet: agentcfg.RuleSet{Yarc: "rules/set.yarc"}}, t.TempDir())
	if err != nil {
		t.Fatalf("resolveRulesBlob: %v", err)
	}
	if got != "" {
		t.Errorf("blob = %q, want empty so the operator's -rules-dir is what the disk view scans with", got)
	}
}

// The two settings the console bakes as the build's DEFAULT rather than its law (spec 6.6). They
// are enumerations in agent.json and booleans on the command line, so their ladder has a mapping
// step the view set does not.

func TestAnExplicitJSONFlagBeatsTheConfig(t *testing.T) {
	got, err := resolveJSONOutput(true, true,
		agentcfg.Config{Present: true, OutputFormat: agentcfg.Choice{Value: agentcfg.OutputFormatText, Specified: true}})
	if err != nil {
		t.Fatalf("resolveJSONOutput: %v", err)
	}
	if !got {
		t.Error("json = false, want the CLI value")
	}
}

func TestTurningASettingOffOnTheCommandLineBeatsAConfigThatTurnedItOn(t *testing.T) {
	// -json=false against a config saying "json". The flag's VALUE here is the same as its
	// registered default, so only flagWasSet can tell that the operator asked for it -- which is
	// why the bool resolvers take that signal instead of comparing values.
	got, err := resolveJSONOutput(false, true,
		agentcfg.Config{Present: true, OutputFormat: agentcfg.Choice{Value: agentcfg.OutputFormatJSON, Specified: true}})
	if err != nil {
		t.Fatalf("resolveJSONOutput: %v", err)
	}
	if got {
		t.Error("json = true, want the operator's -json=false to win over the config")
	}
}

func TestTheConfigsOutputFormatBeatsTheBuiltInDefault(t *testing.T) {
	on, err := resolveJSONOutput(false, false,
		agentcfg.Config{Present: true, OutputFormat: agentcfg.Choice{Value: agentcfg.OutputFormatJSON, Specified: true}})
	if err != nil {
		t.Fatalf("resolveJSONOutput: %v", err)
	}
	if !on {
		t.Error(`json = false, want the config's "json" to beat the built-in default`)
	}
	// "text" is a CHOICE, not silence. It happens to agree with today's built-in default, and it
	// must still be read as the config choosing -- otherwise a build that deliberately baked the
	// current default is silently re-pointed the day that default changes.
	off, err := resolveJSONOutput(true, false,
		agentcfg.Config{Present: true, OutputFormat: agentcfg.Choice{Value: agentcfg.OutputFormatText, Specified: true}})
	if err != nil {
		t.Fatalf("resolveJSONOutput: %v", err)
	}
	if off {
		t.Error(`json = true, want the config's "text" to be read as a choice, not as silence`)
	}
}

func TestAnUnspecifiedSettingLeavesTheBuiltInDefault(t *testing.T) {
	got, err := resolveJSONOutput(false, false, agentcfg.Config{Present: true, Views: []string{"disk"}})
	if err != nil {
		t.Fatalf("resolveJSONOutput: %v", err)
	}
	if got {
		t.Error("json = true, want the built-in default: this config named no output_format")
	}
}

func TestAConfigThatIsNotPresentCannotSupplyABakedSetting(t *testing.T) {
	// Present before Specified again. Config{} and a config that named neither field both leave
	// Choice zero, so a resolver reading Specified alone cannot tell them apart -- and a
	// hand-constructed value would then let a config that does not exist choose the output format.
	got, err := resolveJSONOutput(false, false,
		agentcfg.Config{OutputFormat: agentcfg.Choice{Value: agentcfg.OutputFormatJSON, Specified: true}})
	if err != nil {
		t.Fatalf("resolveJSONOutput: %v", err)
	}
	if got {
		t.Error("json = true, want the built-in default: there is no config to read")
	}
}

func TestProcessPriorityRunsTheSameLadder(t *testing.T) {
	low, err := resolveLowPriority(false, false,
		agentcfg.Config{Present: true, ProcessPriority: agentcfg.Choice{Value: agentcfg.ProcessPriorityLow, Specified: true}})
	if err != nil {
		t.Fatalf("resolveLowPriority: %v", err)
	}
	if !low {
		t.Error(`low-priority = false, want the config's "low"`)
	}
	normal, err := resolveLowPriority(true, false,
		agentcfg.Config{Present: true, ProcessPriority: agentcfg.Choice{Value: agentcfg.ProcessPriorityNormal, Specified: true}})
	if err != nil {
		t.Fatalf("resolveLowPriority: %v", err)
	}
	if normal {
		t.Error(`low-priority = true, want the config's "normal" to be read as a choice`)
	}
	overridden, err := resolveLowPriority(false, true,
		agentcfg.Config{Present: true, ProcessPriority: agentcfg.Choice{Value: agentcfg.ProcessPriorityLow, Specified: true}})
	if err != nil {
		t.Fatalf("resolveLowPriority: %v", err)
	}
	if overridden {
		t.Error("low-priority = true, want the operator's -low-priority=false to win")
	}
}

// Nothing enforces that these enumerations stay one-to-one with the booleans they feed. A third
// output_format would Load cleanly under a later schema and then reach a resolver that can only say
// true or false -- and silently picking a side is how the agent ends up in a mode nobody chose.
//
// The Configs here are hand-built because today's Load rejects these values outright. That is the
// point: the mapping has to fail loudly on its own, not only because the loader upstream is strict.
func TestASettingTheFlagCannotExpressIsRefusedRatherThanGuessed(t *testing.T) {
	if got, err := resolveJSONOutput(false, false,
		agentcfg.Config{Present: true, OutputFormat: agentcfg.Choice{Value: "sarif", Specified: true}}); err == nil {
		t.Errorf("json = %v with no error, want output_format \"sarif\" refused", got)
	} else if !strings.Contains(err.Error(), "output_format") || !strings.Contains(err.Error(), "sarif") {
		t.Errorf("error %q must name the field and the value", err)
	}
	if got, err := resolveLowPriority(false, false,
		agentcfg.Config{Present: true, ProcessPriority: agentcfg.Choice{Value: "realtime", Specified: true}}); err == nil {
		t.Errorf("low-priority = %v with no error, want process_priority \"realtime\" refused", got)
	} else if !strings.Contains(err.Error(), "process_priority") || !strings.Contains(err.Error(), "realtime") {
		t.Errorf("error %q must name the field and the value", err)
	}
}

func TestAnUnmappableSettingIsStillOverridableFromTheCommandLine(t *testing.T) {
	// The flag is checked first, so an operator standing on the host can still run the scan while a
	// config this build no longer understands sits beside the binary. Refusing even then would turn
	// a stale config into an unrunnable agent with no way past it.
	got, err := resolveJSONOutput(true, true,
		agentcfg.Config{Present: true, OutputFormat: agentcfg.Choice{Value: "sarif", Specified: true}})
	if err != nil {
		t.Fatalf("an explicit flag must not be blocked by an unmappable config value: %v", err)
	}
	if !got {
		t.Error("json = false, want the CLI value")
	}
}

// The WIRING, not the ladder. Every resolver above can be exactly right while runScan still reads
// the raw flag standing beside it, and no test of a pure function can see that. These two drive
// runScan itself, which is the only place the two can be told apart.
//
// Not covered here, and deliberately: the -low-priority use site. Killing that one requires the
// true branch to run, and lowprio.Reduce puts THIS process into background mode (Windows) or raises
// its niceness (Linux, where it cannot be lowered again without privilege) for the remainder of the
// suite, with no restore in the package's API. Verified by hand against the built binary instead.

func TestRunScanTakesItsViewSetFromTheConfig(t *testing.T) {
	// The config's only view is not a view, so nothing is runnable and the run is refused. A runScan
	// that read *views instead would see the built-in default set here, and would go and scan.
	cfgPath := filepath.Join(t.TempDir(), "agent.json")
	writeConfig(t, cfgPath, `{"schema_version":"1","views":["nope-not-a-view"]}`)
	if got := runScan([]string{"-config", cfgPath, "-out", t.TempDir()}); got != 1 {
		t.Errorf("runScan = %d, want 1: the config declares one view and it is not one", got)
	}
}

func TestRunScanTakesItsOutputFormatFromTheConfig(t *testing.T) {
	// json mode prints the report path as the only stdout line; text mode prints a verdict line. The
	// config asks for json and no flag says otherwise, so the config's choice is what must show up.
	//
	// The scan itself fails -- there is no diskprobe beside a test binary -- which is fine and is
	// what keeps this fast. What is being asserted is which of the two lines got printed.
	cfgPath := filepath.Join(t.TempDir(), "agent.json")
	writeConfig(t, cfgPath, `{"schema_version":"1","views":["disk"],"output_format":"json"}`)
	out := captureStdout(t, func() {
		runScan([]string{"-config", cfgPath, "-out", t.TempDir()})
	})
	if !strings.Contains(out, "report.json") || strings.Contains(out, "verdict=") {
		t.Errorf("stdout = %q, want the report path json mode prints, not the text verdict line", out)
	}

	// And the operator turning it off wins, which is the -json=false case the ladder exists for.
	out = captureStdout(t, func() {
		runScan([]string{"-config", cfgPath, "-json=false", "-out", t.TempDir()})
	})
	if !strings.Contains(out, "verdict=") {
		t.Errorf("stdout = %q, want the text verdict line: -json=false beats the config", out)
	}
}
func TestRunScanStatesTheViewsTheBuildDoesNotCarry(t *testing.T) {
	// The WIRING again, and the one whose failure would be SILENT. carriedViews can be exactly
	// right while runScan hands selectProbes a nil, and no test of a pure function can see it: the
	// symptom is a report that simply does not mention the views this build left out, which reads
	// exactly like a scanner that has never heard of them. That silence is what C4 exists to make
	// impossible, so it is asserted from the report itself rather than from the selection.
	//
	// The scan fails -- there is no diskprobe beside a test binary -- which is fine and is what
	// keeps this fast. What is asserted is what the report SAYS about the views the configuration
	// did not declare.
	cfgPath := filepath.Join(t.TempDir(), "agent.json")
	writeConfig(t, cfgPath, `{"schema_version":"1","views":["disk"],"output_format":"json"}`)
	out := captureStdout(t, func() {
		runScan([]string{"-config", cfgPath, "-out", t.TempDir()})
	})

	reportPath := strings.TrimSpace(out)
	raw, err := os.ReadFile(reportPath)
	if err != nil {
		t.Fatalf("reading the report json mode printed (%q): %v", reportPath, err)
	}
	var rep finding.Report
	if err := json.Unmarshal(raw, &rep); err != nil {
		t.Fatal(err)
	}
	covered := map[string]finding.Coverage{}
	for _, c := range rep.Coverage {
		covered[c.View] = c
	}

	// Every view that can exist on THIS platform and that the configuration did not declare.
	// Derived from the table rather than listed, so the assertion cannot rot when a capability is
	// added and so it says the same thing on both platforms.
	for _, s := range registryFor(runtime.GOOS) {
		if s.View == "disk" {
			continue
		}
		c, ok := covered[s.View]
		if !ok {
			t.Errorf("%s is absent from the report; this build does not carry it and must SAY so "+
				"rather than stay silent", s.View)
			continue
		}
		if c.Status != finding.CovNA {
			t.Errorf("%s status = %q, want %q -- a view this build never shipped did not fail, it "+
				"was never included, and an operator reading %q would be reading an incident",
				s.View, c.Status, finding.CovNA, c.Status)
		}
		if !strings.Contains(c.Reason, "not included in this build") {
			t.Errorf("%s reason = %q, want the build named as the reason", s.View, c.Reason)
		}
	}
	// And the view it DOES carry was attempted. Without this a build set that excluded everything
	// would satisfy the loop above while examining nothing.
	if c := covered["disk"]; c.Status == finding.CovNA {
		t.Errorf("disk = %q (%s), want it attempted: the configuration declares it", c.Status, c.Reason)
	}
}

func TestRunScanReportsADeclaredViewWhoseComponentIsMissing(t *testing.T) {
	// The third state, end to end, through the real binary's own code path: agent.json declares a
	// view, the component is not beside the binary, and the question is what report.json says.
	// Before this it said nothing -- five coverage records and no row for the declared view, with
	// the only trace a stderr warning calling a view the table holds "unknown", and stderr is not
	// in the report.
	//
	// The view is DISCOVERED rather than named, so the test says the same thing on both platforms:
	// beside a test binary the optional companions are all absent, which is dotnet-mem-x86 on
	// Windows (and java-mem too on a host with no JRE) and java-mem on Linux.
	reg := probeRegistryIn(exeDir(), runtime.GOOS, "", "")
	missing := ""
	for _, spec := range registryFor(runtime.GOOS) {
		// disk is never Optional, so it stays registered and keeps the run runnable -- without one
		// runnable view runScan refuses before any report is written.
		if spec.View == "disk" {
			continue
		}
		if _, ok := reg[spec.View]; !ok {
			missing = spec.View
			break
		}
	}
	if missing == "" {
		t.Skipf("every optional component for %s is present beside this test binary, so there is "+
			"no missing-component case to exercise here", runtime.GOOS)
	}

	cfgPath := filepath.Join(t.TempDir(), "agent.json")
	writeConfig(t, cfgPath, `{"schema_version":"1","views":["disk","`+missing+`"],"output_format":"json"}`)
	out := captureStdout(t, func() {
		runScan([]string{"-config", cfgPath, "-out", t.TempDir()})
	})
	raw, err := os.ReadFile(strings.TrimSpace(out))
	if err != nil {
		t.Fatalf("reading the report json mode printed (%q): %v", strings.TrimSpace(out), err)
	}
	var rep finding.Report
	if err := json.Unmarshal(raw, &rep); err != nil {
		t.Fatal(err)
	}

	var cov finding.Coverage
	var found bool
	for _, c := range rep.Coverage {
		if c.View == missing {
			cov, found = c, true
		}
	}
	if !found {
		t.Fatalf("%s is declared in agent.json and has no coverage record in report.json at all; "+
			"the report carries %d records: %+v", missing, len(rep.Coverage), rep.Coverage)
	}
	if cov.Status == finding.CovNA {
		t.Fatalf("%s = %q (%s); the build DECLARES it and its component is absent, which is a broken "+
			"package, not a coverage choice -- and n/a does not set `incomplete`",
			missing, cov.Status, cov.Reason)
	}
	if cov.Status != finding.CovFailed {
		t.Fatalf("%s status = %q (%s), want %q", missing, cov.Status, cov.Reason, finding.CovFailed)
	}
	// And the reason names the component, from the table. `failed` alone is what an exec error also
	// produces, so without this the record could be right by accident -- and an operator reading
	// "fork/exec: the system cannot find the file specified" on a customer's host has to guess which
	// file, while the table already knows.
	want := mustSpec(t, missing).binariesFor(runtime.GOOS)
	var named bool
	for _, b := range want {
		if strings.Contains(cov.Reason, b) {
			named = true
		}
	}
	if !named {
		t.Errorf("%s reason = %q, want it to name one of the components the table declares for it "+
			"on %s (%v)", missing, cov.Reason, runtime.GOOS, want)
	}
	// Over-determined here -- the disk view fails too, because there is no diskprobe beside a test
	// binary -- and asserted anyway, because a report that is not incomplete after this would mean
	// the record stopped counting. That the record sets it ON ITS OWN is asserted in
	// TestADeclaredViewWithNoComponentIsFailedInTheEmittedReport, which puts nothing else in the run.
	if !rep.Verdict.Incomplete {
		t.Error("report is not incomplete, but a declared view was never examined")
	}
}

// captureStdout collects what fn writes to os.Stdout. The reader runs in its own goroutine so a
// write larger than the pipe buffer cannot deadlock the test against itself.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	saved := os.Stdout
	os.Stdout = writer
	collected := make(chan string, 1)
	go func() {
		var buffer strings.Builder
		io.Copy(&buffer, reader)
		collected <- buffer.String()
	}()
	fn()
	os.Stdout = saved
	writer.Close()
	out := <-collected
	reader.Close()
	return out
}

func TestFlagWasSetDistinguishesTypedFromDefaulted(t *testing.T) {
	newSet := func() (*flag.FlagSet, *string) {
		fs := flag.NewFlagSet("scan", flag.ContinueOnError)
		views := fs.String("views", "disk,java-mem", "")
		fs.Bool("json", false, "")
		return fs, views
	}

	fs, views := newSet()
	if err := fs.Parse(nil); err != nil {
		t.Fatal(err)
	}
	if flagWasSet(fs, "views") {
		t.Error("views reported as set when nothing was passed")
	}
	if *views != "disk,java-mem" {
		t.Errorf("views = %q, want the registered default", *views)
	}

	// Typed, and typed as the default. The value is identical to the case above, so a resolver
	// comparing values would call this one "not set" too.
	fs, views = newSet()
	if err := fs.Parse([]string{"-views", "disk,java-mem"}); err != nil {
		t.Fatal(err)
	}
	if !flagWasSet(fs, "views") {
		t.Error("views reported as unset when the operator typed the default value")
	}
	if *views != "disk,java-mem" {
		t.Errorf("views = %q, want the typed value", *views)
	}
	if flagWasSet(fs, "json") {
		t.Error("json reported as set when only -views was passed")
	}

	// A bool set to its own default, which is the -json=false case the ladder depends on.
	fs, _ = newSet()
	if err := fs.Parse([]string{"-json=false"}); err != nil {
		t.Fatal(err)
	}
	if !flagWasSet(fs, "json") {
		t.Error("json reported as unset when the operator typed -json=false")
	}
}

// The baked scan scope, and the reason it is a DEFAULT rather than a bound.
func TestAnOperatorsPathBeatsTheBakedScope(t *testing.T) {
	cfg := agentcfg.Config{Present: true, ScanScope: []string{"/var/www"}}
	if got := resolveScanScope("/srv/http", true, cfg); got != "/srv/http" {
		t.Errorf("resolveScanScope = %q; -path must win over a baked scope", got)
	}
}

func TestTheBakedScopeIsUsedWhenNoPathWasTyped(t *testing.T) {
	cfg := agentcfg.Config{Present: true, ScanScope: []string{"/var/www", "/srv/http"}}
	if got := resolveScanScope("", false, cfg); got != "/var/www,/srv/http" {
		t.Errorf("resolveScanScope = %q, want the joined baked scope", got)
	}
}

// -path "" is an operator saying "ignore the baked scope, auto-discover". The flag's VALUE cannot
// tell that apart from not passing it, which is why the whole ladder branches on flagSet: reading
// the value alone would let a build's scope silently override a human who explicitly cleared it.
func TestClearingPathExplicitlyDefeatsTheBakedScope(t *testing.T) {
	cfg := agentcfg.Config{Present: true, ScanScope: []string{"/var/www"}}
	if got := resolveScanScope("", true, cfg); got != "" {
		t.Errorf("resolveScanScope = %q; an explicitly cleared -path must mean auto-discover", got)
	}
}

func TestAConfigThatIsNotPresentSuppliesNoScope(t *testing.T) {
	cfg := agentcfg.Config{ScanScope: []string{"/var/www"}}
	if got := resolveScanScope("", false, cfg); got != "" {
		t.Errorf("resolveScanScope = %q; a config that does not exist cannot supply a scope", got)
	}
}

func TestNoScopeAnywhereMeansAutoDiscover(t *testing.T) {
	if got := resolveScanScope("", false, agentcfg.Config{Present: true}); got != "" {
		t.Errorf("resolveScanScope = %q, want empty so the disk view auto-discovers", got)
	}
}

// The WIRING, not the resolver. Reverting runScan's use site to read *paths -- which makes the
// baked scope inert -- passed every resolveScanScope test above, because those assert on a pure
// function and a pure function cannot tell you whether anything calls it. Same defect shape this
// repo hit in Task 6, where four tests asserted on a struct and stayed green under a mutation that
// inverted their meaning.
//
// Asserted through the emitted report's own target spec, which is what the disk probe is handed.
func TestRunScanTakesItsScanScopeFromTheConfig(t *testing.T) {
	scope := t.TempDir()
	cfgPath := filepath.Join(t.TempDir(), "agent.json")
	writeConfig(t, cfgPath, `{"schema_version":"1","views":["disk"],"scan_scope":[`+
		strconv.Quote(filepath.ToSlash(scope))+`]}`)

	out := t.TempDir()
	// The scan itself fails -- there is no diskprobe beside a test binary -- which is fine and keeps
	// this fast. The report is still written, and it records the webroots the run was given.
	runScan([]string{"-config", cfgPath, "-out", out})

	rep := readOnlyReport(t, out)
	// Compared against what the config SAID, slash for slash. The scanner uses a configured path
	// verbatim rather than normalising it, which is right: os.Stat accepts either form on Windows,
	// and rewriting an operator's path would make the report describe something they did not write.
	want := filepath.ToSlash(scope)
	if len(rep.Scan.Webroots) != 1 || rep.Scan.Webroots[0] != want {
		t.Fatalf("report webroots = %v, want the config's baked scope %q\n"+
			"a runScan reading *paths instead would have recorded none and auto-discovered",
			rep.Scan.Webroots, want)
	}
}

// And the operator's -path still wins once the wiring is real.
func TestRunScanLetsAnOperatorsPathBeatTheBakedScope(t *testing.T) {
	baked, typed := t.TempDir(), t.TempDir()
	cfgPath := filepath.Join(t.TempDir(), "agent.json")
	writeConfig(t, cfgPath, `{"schema_version":"1","views":["disk"],"scan_scope":[`+
		strconv.Quote(filepath.ToSlash(baked))+`]}`)

	out := t.TempDir()
	runScan([]string{"-config", cfgPath, "-path", typed, "-out", out})

	rep := readOnlyReport(t, out)
	if len(rep.Scan.Webroots) != 1 || rep.Scan.Webroots[0] != typed {
		t.Fatalf("report webroots = %v, want the typed -path %q", rep.Scan.Webroots, typed)
	}
}

// readOnlyReport reads the report.json out of the single run folder under out.
func readOnlyReport(t *testing.T, out string) finding.Report {
	t.Helper()
	entries, err := os.ReadDir(out)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(out, e.Name(), "report.json"))
		if err != nil {
			t.Fatal(err)
		}
		var rep finding.Report
		if err := json.Unmarshal(raw, &rep); err != nil {
			t.Fatal(err)
		}
		return rep
	}
	t.Fatalf("no run folder under %s", out)
	return finding.Report{}
}
