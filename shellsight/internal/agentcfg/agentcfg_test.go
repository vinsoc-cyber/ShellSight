package agentcfg

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

const complete = `{
  "schema_version": "1",
  "build_id": "b-7f3a91",
  "views": ["disk"],
  "rule_set": { "name": "sweep-acme", "version": 3,
                "yarc": "rules/set.yarc",
                "yarc_sha256": "aeabf48ad4390ab86aae9ec4dbcccb5fd331f93d36bc6b45b4966b0166149353" },
  "output_format": "json",
  "process_priority": "low",
  "generated_at": "2026-09-03T19:41:56Z",
  "generated_by": "v.quannh67",
  "release": "v1.0.0-384-gd4bcc6b"
}`

func write(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "agent.json")
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadReadsTheWholeConfig(t *testing.T) {
	got, err := Load(write(t, complete))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if got.SchemaVersion != "1" {
		t.Errorf("SchemaVersion = %q", got.SchemaVersion)
	}
	if got.BuildID != "b-7f3a91" {
		t.Errorf("BuildID = %q", got.BuildID)
	}
	if len(got.Views) != 1 || got.Views[0] != "disk" {
		t.Errorf("Views = %v, want [disk]", got.Views)
	}
	if got.RuleSet.Yarc != "rules/set.yarc" {
		t.Errorf("RuleSet.Yarc = %q", got.RuleSet.Yarc)
	}
	if got.RuleSet.Name != "sweep-acme" || got.RuleSet.Version != 3 {
		t.Errorf("RuleSet = %+v", got.RuleSet)
	}
	// Every remaining field is checked too, because a wrong json tag on one of them is invisible
	// to a test that only samples: the field stays zero and nothing errors.
	if got.RuleSet.YarcSHA256 != "aeabf48ad4390ab86aae9ec4dbcccb5fd331f93d36bc6b45b4966b0166149353" {
		t.Errorf("RuleSet.YarcSHA256 = %q", got.RuleSet.YarcSHA256)
	}
	if got.GeneratedAt != "2026-09-03T19:41:56Z" {
		t.Errorf("GeneratedAt = %q", got.GeneratedAt)
	}
	if got.GeneratedBy != "v.quannh67" {
		t.Errorf("GeneratedBy = %q", got.GeneratedBy)
	}
	if got.Release != "v1.0.0-384-gd4bcc6b" {
		t.Errorf("Release = %q", got.Release)
	}
	// Both baked settings, taken from the spec's canonical agent.json (6.1). A wrong json tag on
	// either is otherwise invisible: the field stays unspecified, no gate fires, and the caller
	// falls through to a built-in default while the file on disk says something else.
	if got.OutputFormat != (Choice{Value: OutputFormatJSON, Specified: true}) {
		t.Errorf("OutputFormat = %+v", got.OutputFormat)
	}
	if got.ProcessPriority != (Choice{Value: ProcessPriorityLow, Specified: true}) {
		t.Errorf("ProcessPriority = %+v", got.ProcessPriority)
	}
}

func TestLoadOnAMissingFileReportsAbsenceNotFailure(t *testing.T) {
	// A scanner run by hand has no agent.json, and that is the normal case today. Absence must be
	// distinguishable from a broken file, because one falls back to defaults and the other must not.
	got, err := Load(filepath.Join(t.TempDir(), "nope.json"))
	if err != nil {
		t.Fatalf("a missing config is not an error: %v", err)
	}
	if got.Present {
		t.Error("Present is true for a file that does not exist")
	}
	if len(got.Views) != 0 {
		t.Errorf("Views = %v, want empty so the caller keeps its defaults", got.Views)
	}
}

func TestLoadOnAPresentFileSaysSo(t *testing.T) {
	got, err := Load(write(t, complete))
	if err != nil {
		t.Fatal(err)
	}
	if !got.Present {
		t.Error("Present is false for a file that exists and parsed")
	}
}

func TestAPathThatCannotBeReadIsAnErrorNotAbsence(t *testing.T) {
	// The asymmetry from the other side, and the one an implementation is most likely to get wrong
	// by collapsing every read failure into "no config". Only ErrNotExist means absence; a
	// directory in the config's place, a permission denial, or an I/O error on the host under
	// investigation are all configs that may exist and could not be read.
	//
	// A directory is the portable way to provoke that: os.ReadFile fails on one on every OS this
	// ships to, and never with ErrNotExist.
	got, err := Load(t.TempDir())
	if err == nil {
		t.Fatalf("expected an unreadable path to fail, got %+v", got)
	}
	if got.Present {
		t.Error("Present is true for a config that could not be read")
	}
}

func TestMalformedJSONFailsLoudly(t *testing.T) {
	// The failure that matters most. A build whose config cannot be read must NOT silently fall
	// back to defaults: it would scan with the full default view set and a rule tree nobody chose,
	// and report success. Louder is the only safe direction.
	path := write(t, "{ this is not json")
	_, err := Load(path)
	if err == nil {
		t.Fatal("expected a malformed config to fail")
	}
	// Assert the parse branch is what rejected it, not merely that something did. A failed parse
	// leaves a zero Config, which also trips the schema-version gate -- so "an error came back"
	// would still hold with the parse error swallowed, and this test would pass proving nothing.
	var syntax *json.SyntaxError
	if !errors.As(err, &syntax) {
		t.Errorf("error does not wrap the JSON parse failure: %v", err)
	}
	// An operator sweeping a host has to be told which file is the bad one.
	if !strings.Contains(err.Error(), path) {
		t.Errorf("error does not name the file: %v", err)
	}
}

func TestAnEmptyConfigFileFailsLoudly(t *testing.T) {
	// What a generation interrupted mid-write leaves behind. The file EXISTS, so the
	// absence-means-defaults path must not claim it.
	if _, err := Load(write(t, "")); err == nil {
		t.Fatal("expected an empty config file to fail")
	}
}

func TestTrailingBytesAfterTheConfigFailLoudly(t *testing.T) {
	// The whole file has to parse, not a valid prefix of it. agent.json is read off a host that
	// may be compromised; accepting a good prefix would let appended bytes ride along unread.
	if _, err := Load(write(t, complete+"\n{\"views\":[\"java-mem\"]}")); err == nil {
		t.Fatal("expected trailing bytes after the config object to fail")
	}
}

func TestAnUnknownSchemaVersionFailsLoudly(t *testing.T) {
	// Same reasoning. A newer console writing a config this agent cannot interpret must stop the
	// scan, not produce one whose settings were half-understood.
	_, err := Load(write(t, `{"schema_version":"99","views":["disk"]}`))
	if err == nil {
		t.Fatal("expected an unknown schema_version to fail")
	}
	// This config parses and declares a view, so the version gate is the only thing that can
	// reject it. Naming the version found is what tells an operator the agent is older than its
	// config rather than broken.
	if !strings.Contains(err.Error(), "99") {
		t.Errorf("error does not name the version found: %v", err)
	}
}

func TestAMissingSchemaVersionFailsLoudly(t *testing.T) {
	// An absent version must not be read as "1 by default". A config that never claimed to follow
	// this schema would otherwise be interpreted under it.
	if _, err := Load(write(t, `{"views":["disk"]}`)); err == nil {
		t.Fatal("expected a config with no schema_version to fail")
	}
}

func TestAConfigWithNoViewsFailsLoudly(t *testing.T) {
	// views is the declaration the whole absence-is-declared property rests on. A config that
	// omits it cannot be distinguished from one that meant "no views", and a scan of nothing that
	// reports success is the exact failure this design exists to prevent.
	//
	// All three spellings of "nothing" are rejected, not just the omitted one: an empty array and
	// an explicit null are what a generator with a bug in its view split actually writes.
	for name, body := range map[string]string{
		"omitted": `{"schema_version":"1","build_id":"b-1"}`,
		"empty":   `{"schema_version":"1","build_id":"b-1","views":[]}`,
		"null":    `{"schema_version":"1","build_id":"b-1","views":null}`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := Load(write(t, body)); err == nil {
				t.Fatal("expected a config with no views to fail")
			}
		})
	}
}

func TestAMemoryOnlyConfigCarriesNoRuleSet(t *testing.T) {
	// G8: a memory-only agent ships no compiled rules at all, so its config has no rule_set.
	// Refusing that would make the view split (G3) unrepresentable in the very file that declares
	// it, so the absence has to parse cleanly.
	got, err := Load(write(t, `{"schema_version":"1","build_id":"b-2","views":["java-mem","native-mem"]}`))
	if err != nil {
		t.Fatalf("a config with no rule_set is legal for a memory-only build: %v", err)
	}
	if len(got.Views) != 2 || got.Views[0] != "java-mem" || got.Views[1] != "native-mem" {
		t.Errorf("Views = %v", got.Views)
	}
	if got.RuleSet != (RuleSet{}) {
		t.Errorf("RuleSet = %+v, want the zero value", got.RuleSet)
	}
}

func TestUnknownFieldsAreToleratedForForwardCompatibility(t *testing.T) {
	// A later console may add fields this agent does not know. Within the same schema_version that
	// must not be fatal, or every config change would strand deployed agents.
	got, err := Load(write(t, `{"schema_version":"1","build_id":"b-3","views":["disk"],"future_thing":{"a":1}}`))
	if err != nil {
		t.Fatalf("an unknown field within a known schema version is not an error: %v", err)
	}
	if len(got.Views) != 1 {
		t.Errorf("Views = %v", got.Views)
	}
	// The known fields around the unknown one still have to land. A bare no-error check would pass
	// just as happily if the unknown field had derailed the rest of the object.
	if got.BuildID != "b-3" {
		t.Errorf("BuildID = %q", got.BuildID)
	}
}

// padTo builds a syntactically complete config of exactly n bytes by padding a field the schema does
// not know. Size fixtures have to be valid JSON everywhere except their length, or the parse gate
// rejects them and the size test passes proving nothing.
func padTo(t *testing.T, n int) string {
	t.Helper()
	const prefix = `{"schema_version":"1","build_id":"b-4","views":["disk"],"pad":"`
	const suffix = `"}`
	if n < len(prefix)+len(suffix) {
		t.Fatalf("cannot build a valid config of only %d bytes", n)
	}
	return prefix + strings.Repeat("A", n-len(prefix)-len(suffix)) + suffix
}

func TestADuplicateKeyIsRejectedRatherThanSilentlyTakingTheLast(t *testing.T) {
	// Measured against the code Task 4 shipped: `{"schema_version":"99","views":["a"],
	// "schema_version":"1"}` loaded clean, as SchemaVersion "1" with Present true. encoding/json
	// keeps the LAST value for a repeated key, so the version gate is bypassable by appending a
	// second copy of the key it checks. On a host where an intruder may have edited this file, that
	// is the gate defeating itself.
	//
	// internal/corpus rejects duplicate keys for the same reason -- ValidateStrictJSONText,
	// internal/corpus/io.go:339, raised by the walk at io.go:451.
	path := write(t, `{"schema_version":"99","views":["disk"],"schema_version":"1"}`)
	got, err := Load(path)
	if err == nil {
		t.Fatalf("expected a repeated key to fail, got %+v", got)
	}
	// Naming the key is what makes this test about the duplicate. Both halves of the duplicate are
	// individually legal configs, so "an error came back" cannot say which gate rejected it.
	if !strings.Contains(err.Error(), `"schema_version"`) {
		t.Errorf("error does not name the repeated key: %v", err)
	}
	if !strings.Contains(err.Error(), path) {
		t.Errorf("error does not name the file: %v", err)
	}
	if got.Present {
		t.Error("Present is true for a config that was rejected")
	}
}

func TestADuplicateKeyInsideRuleSetIsRejectedToo(t *testing.T) {
	// Measured: `"rule_set":{"name":"x","name":"y"}` loaded as Name "y". A top-level-only walk would
	// leave this open, and rule_set is the worst place to leave it -- it names the compiled rules a
	// scan will use, so a silently-winning second value is a scan run with rules nobody chose.
	//
	// The walk is recursive rather than two levels deep for the same reason internal/corpus's is
	// (io.go:430): the depth at which a config may be tampered with is not a thing this package
	// gets to assume.
	path := write(t, `{"schema_version":"1","views":["disk"],"rule_set":{"name":"x","name":"y"}}`)
	got, err := Load(path)
	if err == nil {
		t.Fatalf("expected a repeated key inside rule_set to fail, got %+v", got)
	}
	if !strings.Contains(err.Error(), `"name"`) {
		t.Errorf("error does not name the repeated key: %v", err)
	}
}

func TestAConfigAboveTheSizeCapFailsLoudly(t *testing.T) {
	// Measured: Load used os.ReadFile, which is unbounded, and a 3 MiB agent.json loaded clean.
	// agent.json is read at the START of a sweep on a host under investigation, so an oversized
	// file, a FIFO, or a device node in its place exhausts or stalls the scan before any scanning
	// happens -- and both this tool and the incumbent are already known to lose a whole scan to a
	// FIFO. internal/corpus bounds its reads for the same reason (io.go:302).
	//
	// The fixture is valid JSON with a legal schema_version and a legal view, and exactly ONE byte
	// over the cap. Both halves matter: valid so the parse gate cannot be what rejects it, and one
	// byte over so that with the size gate removed the bounded read truncates nothing and the
	// document still parses. A fatter fixture would be rejected by the parse gate instead and this
	// test would pass proving nothing -- the same hazard TestMalformedJSONFailsLoudly above is
	// hardened against, arriving here from the opposite direction.
	body := padTo(t, maxConfigBytes+1)
	path := write(t, body)
	got, err := Load(path)
	if err == nil {
		t.Fatalf("expected a config above the cap to fail, got %+v", got)
	}
	// Both numbers, or "too big" is unactionable: the operator cannot tell a config a byte over the
	// line from a device node.
	if !strings.Contains(err.Error(), strconv.Itoa(maxConfigBytes)) {
		t.Errorf("error does not name the cap: %v", err)
	}
	if !strings.Contains(err.Error(), strconv.Itoa(len(body))) {
		t.Errorf("error does not name the size seen: %v", err)
	}
	if !strings.Contains(err.Error(), path) {
		t.Errorf("error does not name the file: %v", err)
	}
}

func TestAConfigAtTheSizeCapStillLoads(t *testing.T) {
	// The cap from the side that costs recall. A bounded read is easy to write one byte short, and a
	// cap that rejects at exactly its own value would reject a config the documented limit says is
	// legal. This is the only test here that fails if the bound is too TIGHT.
	got, err := Load(write(t, padTo(t, maxConfigBytes)))
	if err != nil {
		t.Fatalf("a config of exactly the cap is legal: %v", err)
	}
	if len(got.Views) != 1 || got.Views[0] != "disk" {
		t.Errorf("Views = %v, want [disk]", got.Views)
	}
}

func TestAViewNameThatNamesNoViewIsRejected(t *testing.T) {
	// Measured: views:[""] passed the len(Views) > 0 gate, so the config declared a view COUNT of
	// one and a view SET of nothing. The whitespace-only spelling is what a generator writes when it
	// interpolates a variable that was never set.
	//
	// views is the declaration the whole absence-is-declared property rests on, so a name that
	// declares nothing has to be rejected, not trimmed away: a config we do not understand must not
	// be repaired into one we do.
	for name, body := range map[string]string{
		"empty":           `{"schema_version":"1","views":[""]}`,
		"whitespace-only": `{"schema_version":"1","views":["  \t "]}`,
		"second-of-two":   `{"schema_version":"1","views":["disk",""]}`,
	} {
		t.Run(name, func(t *testing.T) {
			path := write(t, body)
			got, err := Load(path)
			if err == nil {
				t.Fatalf("expected a view name that names no view to fail, got %+v", got)
			}
			if !strings.Contains(err.Error(), "views[") {
				t.Errorf("error does not locate the offending entry: %v", err)
			}
		})
	}
}

func TestAViewNameContainingACommaIsRejected(t *testing.T) {
	// The subtle one, and it is not cosmetic. The CLI path joins this list with a comma, so
	// views:["disk,java-mem"] becomes TWO views on the command line while staying ONE opaque string
	// to the declared-absence check. The same field would mean two different things one layer apart,
	// and the coverage record -- the thing that makes a reported absence trustworthy -- would be the
	// half that is wrong.
	path := write(t, `{"schema_version":"1","views":["disk,java-mem"]}`)
	got, err := Load(path)
	if err == nil {
		t.Fatalf("expected a comma-bearing view name to fail, got %+v", got)
	}
	// Naming the offender is the difference between "your config is bad" and "line up your views".
	if !strings.Contains(err.Error(), "disk,java-mem") {
		t.Errorf("error does not name the offending view: %v", err)
	}
}

func TestBothBakedSettingsParseTheirRecognisedValues(t *testing.T) {
	// The mapping stated once, because the flags are booleans and these fields are not. The config
	// carries an enum where the CLI carries a bool -- -json (cmd/shellsight/main.go:92) and
	// -low-priority (:99) -- because an enum can grow a third value and a bool cannot:
	//
	//	output_format    "json" -> -json true          "text"   -> -json false
	//	process_priority "low"  -> -low-priority true  "normal" -> -low-priority false
	//
	// Each recognised spelling has to land on its own state. The two fields are independent, so a
	// config that bakes one and leaves the other to the host is checked as well: reading one
	// field's silence off the other's value is exactly the mistake a shared parse makes.
	for name, testCase := range map[string]struct {
		body     string
		format   Choice
		priority Choice
	}{
		"both, json and low": {
			body:     `{"schema_version":"1","views":["disk"],"output_format":"json","process_priority":"low"}`,
			format:   Choice{Value: OutputFormatJSON, Specified: true},
			priority: Choice{Value: ProcessPriorityLow, Specified: true},
		},
		"both, text and normal": {
			body:     `{"schema_version":"1","views":["disk"],"output_format":"text","process_priority":"normal"}`,
			format:   Choice{Value: OutputFormatText, Specified: true},
			priority: Choice{Value: ProcessPriorityNormal, Specified: true},
		},
		"format alone": {
			body:   `{"schema_version":"1","views":["disk"],"output_format":"text"}`,
			format: Choice{Value: OutputFormatText, Specified: true},
		},
		"priority alone": {
			body:     `{"schema_version":"1","views":["disk"],"process_priority":"low"}`,
			priority: Choice{Value: ProcessPriorityLow, Specified: true},
		},
	} {
		t.Run(name, func(t *testing.T) {
			got, err := Load(write(t, testCase.body))
			if err != nil {
				t.Fatalf("load: %v", err)
			}
			if got.OutputFormat != testCase.format {
				t.Errorf("OutputFormat = %+v, want %+v", got.OutputFormat, testCase.format)
			}
			if got.ProcessPriority != testCase.priority {
				t.Errorf("ProcessPriority = %+v, want %+v", got.ProcessPriority, testCase.priority)
			}
		})
	}
}

func TestSilenceIsDistinguishableFromChoosingWhatTheDefaultAlreadyIs(t *testing.T) {
	// The property the precedence ladder rests on, and the one a single bool cannot hold.
	//
	// "text" and "normal" are the analyst CHOOSING the thing the scanner already defaults to; an
	// absent field is the analyst not choosing at all. Only the second may lose to the built-in
	// default. Modelled as one bool, false would mean both -- and a build that deliberately baked
	// today's default would be silently re-pointed the day that default changes.
	silent, err := Load(write(t, `{"schema_version":"1","views":["disk"]}`))
	if err != nil {
		t.Fatalf("a config that bakes neither setting is legal: %v", err)
	}
	if silent.OutputFormat.Specified {
		t.Errorf("OutputFormat reads as chosen for a config that never mentions it: %+v", silent.OutputFormat)
	}
	if silent.ProcessPriority.Specified {
		t.Errorf("ProcessPriority reads as chosen for a config that never mentions it: %+v", silent.ProcessPriority)
	}

	chosen, err := Load(write(t, `{"schema_version":"1","views":["disk"],"output_format":"text","process_priority":"normal"}`))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if !chosen.OutputFormat.Specified || !chosen.ProcessPriority.Specified {
		t.Fatalf("an explicitly chosen default does not read as chosen: %+v %+v",
			chosen.OutputFormat, chosen.ProcessPriority)
	}
	// The comparison the caller will make. If these two configs are indistinguishable here, the
	// ladder has nothing to branch on however carefully it is written.
	if silent.OutputFormat == chosen.OutputFormat {
		t.Error(`an unset output_format is indistinguishable from an explicit "text"`)
	}
	if silent.ProcessPriority == chosen.ProcessPriority {
		t.Error(`an unset process_priority is indistinguishable from an explicit "normal"`)
	}
}

func TestAnUnrecognisedBakedSettingIsRejectedNamingTheFieldAndTheValue(t *testing.T) {
	// Rejected, not coerced. Coercing "realtime" to normal leaves the agent running at a priority
	// nobody chose while its config says otherwise, and the operator reading that config afterwards
	// is reading a description of a scan that did not happen (spec 6.1).
	//
	// Case is significant, so the case variant is a rejection and not a second spelling. The empty
	// and whitespace-padded values are what a generator writes when it interpolates a variable that
	// was never set -- measured on this package's own views field, where views:[""] once passed
	// every gate. They must not be read as silence: the key is present, so the config states a
	// value, and that value is not one of the field's.
	for name, testCase := range map[string]struct{ body, field, value string }{
		"unknown format":      {`{"schema_version":"1","views":["disk"],"output_format":"yaml"}`, "output_format", "yaml"},
		"unknown priority":    {`{"schema_version":"1","views":["disk"],"process_priority":"realtime"}`, "process_priority", "realtime"},
		"case variant":        {`{"schema_version":"1","views":["disk"],"output_format":"JSON"}`, "output_format", "JSON"},
		"empty format":        {`{"schema_version":"1","views":["disk"],"output_format":""}`, "output_format", ""},
		"whitespace priority": {`{"schema_version":"1","views":["disk"],"process_priority":" low "}`, "process_priority", " low "},
	} {
		t.Run(name, func(t *testing.T) {
			path := write(t, testCase.body)
			got, err := Load(path)
			if err == nil {
				t.Fatalf("expected %s = %q to fail, got %+v", testCase.field, testCase.value, got)
			}
			// The field, or the operator standing on the host cannot tell which of the two to fix.
			if !strings.Contains(err.Error(), testCase.field) {
				t.Errorf("error does not name the field: %v", err)
			}
			// The value, quoted, so an empty or space-padded one is visible at all.
			if !strings.Contains(err.Error(), strconv.Quote(testCase.value)) {
				t.Errorf("error does not name the offending value: %v", err)
			}
			if !strings.Contains(err.Error(), path) {
				t.Errorf("error does not name the file: %v", err)
			}
			if got.Present {
				t.Error("Present is true for a config that was rejected")
			}
		})
	}
}

func TestARepeatedBakedSettingKeyIsRejected(t *testing.T) {
	// Confirmed rather than assumed. The duplicate-key walk is generic and recursive, so it ought to
	// cover keys added after it was written -- but "ought to" is the kind of claim that walk exists
	// to disprove, and encoding/json keeps the LAST value for a repeated key. Unwalked, a build's
	// priority would be settable by appending one line to the file that declares it.
	//
	// Both spellings in each fixture are individually legal, which is what keeps this test about the
	// duplicate: no other gate here can reject either half.
	for field, body := range map[string]string{
		"output_format":    `{"schema_version":"1","views":["disk"],"output_format":"json","output_format":"text"}`,
		"process_priority": `{"schema_version":"1","views":["disk"],"process_priority":"low","process_priority":"normal"}`,
	} {
		t.Run(field, func(t *testing.T) {
			got, err := Load(write(t, body))
			if err == nil {
				t.Fatalf("expected a repeated %s to fail, got %+v", field, got)
			}
			if !strings.Contains(err.Error(), strconv.Quote(field)) {
				t.Errorf("error does not name the repeated key: %v", err)
			}
		})
	}
}

func TestANullBakedSettingIsTheSameAsAnAbsentOne(t *testing.T) {
	// The contract for the shape a generator actually emits: a Go console marshalling an unset
	// optional writes null rather than omitting the key, so null has to say what an omitted key
	// says -- nothing was baked, the host decides.
	//
	// This is the only spelling of "nothing" that is accepted, and the line is deliberate. null is
	// JSON's own absence of a value; "" is a value, and not one of the field's, so it is rejected
	// above.
	got, err := Load(write(t, `{"schema_version":"1","views":["disk"],"output_format":null,"process_priority":null}`))
	if err != nil {
		t.Fatalf("a null baked setting is the absence of one: %v", err)
	}
	if got.OutputFormat.Specified || got.ProcessPriority.Specified {
		t.Errorf("null read as a choice: %+v %+v", got.OutputFormat, got.ProcessPriority)
	}
}

func TestABakedSettingThatIsNotAStringIsRejected(t *testing.T) {
	// A console emitting the flag's own type -- output_format:true, a priority as a number -- must
	// fail rather than land as the zero string. The zero string reads as silence, and silence is the
	// one state that lets the built-in default win, so a wrong-typed value quietly becoming silence
	// is the coercion these fields are specified to refuse.
	for name, body := range map[string]string{
		"boolean format":   `{"schema_version":"1","views":["disk"],"output_format":true}`,
		"numeric priority": `{"schema_version":"1","views":["disk"],"process_priority":5}`,
		"object format":    `{"schema_version":"1","views":["disk"],"output_format":{"value":"json"}}`,
	} {
		t.Run(name, func(t *testing.T) {
			got, err := Load(write(t, body))
			if err == nil {
				t.Fatalf("expected a non-string baked setting to fail, got %+v", got)
			}
			if !strings.Contains(err.Error(), "string") {
				t.Errorf("error does not say what shape was expected: %v", err)
			}
		})
	}
}

// TestAConfigSurvivesARoundTripThroughJSON pins the property the console depends on: what this
// package writes is what it reads.
//
// Before Choice had a MarshalJSON, marshalling a Config emitted
// "output_format":{"Value":"json","Specified":true} while Load accepted only "output_format":"json".
// The type parsed one shape and wrote another, so a console generating agent.json from it would have
// produced a file the scanner rejects at the first thing it does on the host.
func TestAConfigSurvivesARoundTripThroughJSON(t *testing.T) {
	first, err := Load(write(t, complete))
	if err != nil {
		t.Fatalf("load: %v", err)
	}

	encoded, err := json.Marshal(first)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	second, err := Load(write(t, string(encoded)))
	if err != nil {
		t.Fatalf("the config this package wrote is one it will not read: %v\n%s", err, encoded)
	}

	// Present is json:"-" and describes the read, not the document, so it is equal by construction
	// and compared here only so a future field cannot slip through unchecked.
	if !reflect.DeepEqual(first, second) {
		t.Errorf("round trip changed the config:\n first  = %+v\n second = %+v", first, second)
	}
}

func TestAnUnspecifiedChoiceMarshalsAsNullSoItReadsBackAsSilence(t *testing.T) {
	encoded, err := json.Marshal(Choice{})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	// Not `""`: an empty string is a value the field does not recognise, and Load rejects it. null is
	// the spelling that means nothing was chosen.
	if string(encoded) != "null" {
		t.Errorf("an unspecified choice marshalled as %s, want null", encoded)
	}

	var back Choice
	if err := json.Unmarshal(encoded, &back); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if back.Specified {
		t.Error("null read back as a specified choice")
	}
}

// A path containing a comma would arrive as two paths that are each wrong, because the scanner
// joins this list with one to build -path. Same reason a view name cannot contain one.
func TestAScanScopePathContainingACommaIsRejected(t *testing.T) {
	doc := strings.Replace(complete, `"views": [`, `"scan_scope": ["/var/www,/srv"], "views": [`, 1)
	if doc == complete {
		t.Fatal("fixture did not change; the views key is not where this test thinks it is")
	}
	_, err := Load(write(t, doc))
	if err == nil {
		t.Fatal("a scan_scope path containing a comma must be rejected")
	}
	if !strings.Contains(err.Error(), "comma") {
		t.Errorf("the error must say why: %v", err)
	}
}

func TestABlankScanScopePathIsRejected(t *testing.T) {
	doc := strings.Replace(complete, `"views": [`, `"scan_scope": ["  "], "views": [`, 1)
	if _, err := Load(write(t, doc)); err == nil {
		t.Fatal("a blank scan_scope entry must be rejected")
	}
}

// Absent is legal and means the build bakes no scope, so the host auto-discovers.
func TestAnAbsentScanScopeIsLegal(t *testing.T) {
	got, err := Load(write(t, complete))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(got.ScanScope) != 0 {
		t.Errorf("ScanScope = %v, want empty for a config that bakes none", got.ScanScope)
	}
}
