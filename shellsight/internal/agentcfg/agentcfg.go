// Package agentcfg reads an agent's build configuration.
//
// A generated agent carries agent.json stating which views it was built with and which compiled
// rule set it holds. The scanner reads it so a trimmed build can report the views it does not carry
// as "not included in this build" rather than as failures.
//
// It also states the output format and process priority the build was generated to prefer. Those
// two are the build's DEFAULT rather than its law -- the host flag still wins -- so what this
// package reports about them is whether the config chose at all, separately from what it chose.
//
// A leaf package: stdlib only. cmd/shellsight is the intended caller, and keeping it
// dependency-free means the parsing rules below are testable without a scanner.
//
// The precedence this feeds is explicit CLI options > agent.json > built-in defaults, and it is
// applied by the caller: this package only reports what the file said.
//
// agent.json is read by a binary running on a host under investigation, which is to say a host where
// an intruder may have edited it. Everything below treats it as untrusted input: bounded before it
// is read, rejected when it says a thing twice, rejected when it declares a view name that is not
// shaped like one. Rejected, never repaired -- a config we do not understand must not be quietly
// turned into one we do, because the scan that follows is then a scan nobody chose.
//
// SHAPED like one is the limit, and it is a deliberate one. This package is a stdlib-only leaf, so
// it cannot see the scanner's capability table and cannot know that "dotnet-mem-x64" names nothing.
// What it rejects is a name that could never be a view whatever the table held: blank, or carrying
// the comma the scanner joins this list with. Whether a well-shaped name is a REAL view is decided
// where the table lives, in cmd/shellsight, and a build declaring one that is not gets a failed
// coverage record saying so -- never silence, and never a clean report.
package agentcfg

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
)

// SchemaVersion is the only version this scanner can interpret.
const SchemaVersion = "1"

// maxConfigBytes bounds the read of agent.json.
//
// The file is a handful of fields -- the complete fixture in the tests is under 400 bytes -- so
// 64 KiB is over 150x anything a console could legitimately write, while staying small enough that
// an oversized file, a FIFO, or a device node left in the config's place costs one bounded read
// rather than exhausting or stalling the sweep before any scanning happens. The 64 MiB cap in
// internal/corpus (io.go:19) is the precedent for having a cap at all and is three orders of
// magnitude too generous here: that number sizes a corpus document, not a build manifest.
//
// The gate is the bounded READ and not a size check on os.Stat, because a FIFO or a device node
// stats as 0 bytes and would walk straight past one. Both this scanner and the incumbent are
// already known to lose an entire scan to a FIFO on the path they were pointed at.
const maxConfigBytes = 64 << 10

// RuleSet identifies the compiled rule set a build carries.
//
// A memory-only build has none -- it ships no YARA rules at all (G8) -- so the zero value is a
// legal state, not a missing one.
type RuleSet struct {
	Name       string `json:"name"`
	Version    int    `json:"version"`
	Yarc       string `json:"yarc"`
	YarcSHA256 string `json:"yarc_sha256"`
}

// Recognised values for the two settings the console bakes into a build.
//
// They are enumerations where the flags they feed are booleans -- -json (cmd/shellsight/main.go:92)
// and -low-priority (:99) -- because an enum can grow a third value and a bool cannot. The mapping
// is one-to-one today:
//
//	output_format    "json" -> -json true          "text"   -> -json false
//	process_priority "low"  -> -low-priority true  "normal" -> -low-priority false
const (
	OutputFormatJSON = "json"
	OutputFormatText = "text"

	ProcessPriorityLow    = "low"
	ProcessPriorityNormal = "normal"
)

// A Choice is an enumerated setting the console may bake into a build, or leave to the host.
//
// Silence and a stated default are NOT the same thing, and one bool cannot hold both. An
// output_format of "text" is the analyst choosing the format the scanner already defaults to; an
// absent output_format is the analyst not choosing at all. The caller's ladder -- flag, else config,
// else built-in default -- may let only the second lose to the built-in default. Encoded into the
// value, a build that deliberately baked today's default would be silently re-pointed the day that
// default changes.
//
// So presence is carried BESIDE the value rather than inside it, for the same reason Config carries
// Present: a zero value has to stay distinguishable from a value that happens to be zero.
type Choice struct {
	// Value is what the config said, once Load has accepted it as one of the field's recognised
	// values. It is "" exactly when Specified is false.
	Value string
	// Specified is true when the key was present and named a value.
	Specified bool
}

// UnmarshalJSON accepts a JSON string, and treats null as the absence of one.
//
// null is the one spelling of "nothing" that is not an error here: it is JSON's own absence of a
// value, and it is what a generator marshalling an unset optional writes, so it says exactly what an
// omitted key says. An empty or unknown STRING is the opposite -- a value that is present and is not
// one of the field's -- and Load rejects it. This method cannot: it is not told which field it is
// being read into, so it does not know that field's members.
//
// Any other JSON type is rejected rather than defaulted. Defaulted, it would land as the zero string
// and read as silence -- and silence is the one state that lets the built-in default win, so a
// mistyped value would quietly become a setting nobody chose.
func (c *Choice) UnmarshalJSON(data []byte) error {
	if bytes.Equal(bytes.TrimSpace(data), []byte("null")) {
		return nil
	}
	var value string
	if err := json.Unmarshal(data, &value); err != nil {
		// The offending text is bounded but need not be short -- an object here could be most of
		// the file -- so it is truncated to keep the message readable on a console.
		return fmt.Errorf("a baked setting must be a JSON string, got %.32s", data)
	}
	c.Value = value
	c.Specified = true
	return nil
}

// MarshalJSON writes the shape UnmarshalJSON reads: the bare string, or null when nothing was
// chosen.
//
// Without it, encoding/json marshals the struct itself -- {"Value":"json","Specified":true} -- which
// Load then rejects, correctly, as not a JSON string. A type that cannot read back what it writes is
// a trap for the console, which is precisely the program that generates agent.json.
//
// null rather than "" for the unspecified case, because "" is a value the field does not recognise
// and Load rejects it. null is the spelling that means nothing was chosen, which is what round-trips.
func (c Choice) MarshalJSON() ([]byte, error) {
	if !c.Specified {
		return []byte("null"), nil
	}
	return json.Marshal(c.Value)
}

// Config is what a generated agent declares about itself.
type Config struct {
	// Present distinguishes "no agent.json" from "an agent.json that said nothing". A scanner run
	// by hand has no config, which is normal and must fall back to defaults; a config that exists
	// and is unreadable must not.
	//
	// json:"-" so the file cannot set it: presence is a fact about the filesystem, and a config
	// that could assert its own is a config that could lie about it.
	Present bool `json:"-"`

	SchemaVersion string   `json:"schema_version"`
	BuildID       string   `json:"build_id"`
	Views         []string `json:"views"`
	// ScanScope is the webroot list the build prefers, and it is a DEFAULT rather than a bound:
	// -path overrides it, and an empty list means auto-discover. Baked because an analyst who
	// already knows the customer's layout should not have to retype it on every host; overridable
	// because the layout usually is not knowable when the agent is built, and with the analysis
	// layers locked scope is the only speed lever an operator has on the box.
	//
	// It CANNOT restrict anything. A tampered agent.json can widen the scan as easily as narrow it,
	// so this is a convenience, not a containment control -- decided deliberately 2026-09-04.
	ScanScope []string `json:"scan_scope"`
	RuleSet       RuleSet  `json:"rule_set"`

	// OutputFormat and ProcessPriority are the analyst's choice baked as the build's DEFAULT, not
	// its law: the host flag still wins (spec 6.6). Enumerations rather than the booleans the flags
	// use, so a third value stays expressible -- and so that choosing today's default stays
	// distinguishable from not choosing.
	OutputFormat    Choice `json:"output_format"`
	ProcessPriority Choice `json:"process_priority"`

	GeneratedAt string `json:"generated_at"`
	GeneratedBy string `json:"generated_by"`
	Release     string `json:"release"`
}

// Load reads path. A file that is absent yields a zero Config with Present false and no error; a
// file that is present but unusable is an error.
//
// The asymmetry is deliberate. Falling back to defaults when a config cannot be read would make a
// build scan with the full default view set and whatever rules happen to be beside the binary, then
// report success -- a scan nobody configured, presented as the one they asked for. Failing is the
// only safe direction.
//
// Only ErrNotExist counts as absence. Every other read failure -- a directory in the config's
// place, a permission denial, an I/O error on the host under investigation -- is a config that may
// exist and could not be read, and takes the failing path.
func Load(path string) (Config, error) {
	raw, err := readBounded(path)
	if errors.Is(err, os.ErrNotExist) {
		return Config{}, nil
	}
	if err != nil {
		return Config{}, fmt.Errorf("reading %s: %w", path, err)
	}

	var c Config
	if err := json.Unmarshal(raw, &c); err != nil {
		return Config{}, fmt.Errorf("%s is not valid JSON: %w", path, err)
	}
	if err := rejectDuplicateKeys(raw); err != nil {
		return Config{}, fmt.Errorf("%s %w", path, err)
	}
	// Unknown FIELDS are tolerated -- json.Unmarshal ignores them -- so a later console can add
	// one without stranding deployed agents. An unknown SCHEMA VERSION is not: it means fields
	// this agent does understand may have changed meaning.
	if c.SchemaVersion != SchemaVersion {
		return Config{}, fmt.Errorf("%s declares schema_version %q; this scanner understands %q",
			path, c.SchemaVersion, SchemaVersion)
	}
	if len(c.Views) == 0 {
		return Config{}, fmt.Errorf("%s declares no views; a build must state what it carries", path)
	}
	// Every entry has to be a view NAME, not merely a string. Measured on the code this replaces:
	// views:[""] passed the length gate above, declaring a view count of one and a view set of
	// nothing -- and views is the declaration the whole absence-is-declared property rests on.
	//
	// The comma rule is the one that is not cosmetic. The CLI path joins this list with a comma, so
	// views:["disk,java-mem"] would be TWO views there while staying ONE opaque string to the
	// declared-absence check: the same field meaning two different things one layer apart, with the
	// coverage record -- the thing that makes a reported absence trustworthy -- on the wrong side.
	//
	// Rejected rather than trimmed or split, and naming the offender, because the operator is
	// standing on the host and has to be told which entry to fix.
	for index, view := range c.Views {
		if strings.TrimSpace(view) == "" {
			return Config{}, fmt.Errorf("%s declares views[%d] = %q, which names no view",
				path, index, view)
		}
		if strings.Contains(view, ",") {
			return Config{}, fmt.Errorf(
				"%s declares views[%d] = %q; a view name cannot contain a comma, because the scanner joins this list with one",
				path, index, view)
		}
	}
	for index, scope := range c.ScanScope {
		if strings.TrimSpace(scope) == "" {
			return Config{}, fmt.Errorf("%s declares scan_scope[%d] = %q, which names no path",
				path, index, scope)
		}
		// Same reason as a view name: the scanner joins this list with a comma to build -path, so a
		// path containing one would arrive as two paths that are each wrong.
		if strings.Contains(scope, ",") {
			return Config{}, fmt.Errorf(
				"%s declares scan_scope[%d] = %q; a path cannot contain a comma, because the scanner joins this list with one",
				path, index, scope)
		}
	}
	// The two settings the console bakes as the build's DEFAULT rather than its law: the host flag
	// still wins (spec 6.6). An unrecognised value is rejected rather than dropped, because a
	// dropped one leaves the file on disk describing a build the host is not running.
	if err := validateChoice(path, "output_format", c.OutputFormat,
		OutputFormatJSON, OutputFormatText); err != nil {
		return Config{}, err
	}
	if err := validateChoice(path, "process_priority", c.ProcessPriority,
		ProcessPriorityLow, ProcessPriorityNormal); err != nil {
		return Config{}, err
	}
	c.Present = true
	return c, nil
}

// validateChoice rejects a value the field does not define, naming the file, the field, the value,
// and what the field does accept.
//
// Rejected rather than coerced to the field's default. Coercion would leave the agent running at a
// priority nobody chose while its config says otherwise, and an operator reading that config
// afterwards would be reading a description of a scan that did not happen -- the class of silent
// disagreement a declared build exists to prevent.
//
// Case is significant: "JSON" is rejected, not folded. A case-insensitive read would be a second,
// quieter spelling of a field whose whole job is to say exactly one thing, and this package repairs
// nothing it does not understand.
//
// An unspecified field states no value, so there is nothing here to reject: silence is legal, and it
// is what lets the caller's built-in default win.
func validateChoice(path, field string, choice Choice, allowed ...string) error {
	if !choice.Specified {
		return nil
	}
	for _, value := range allowed {
		if choice.Value == value {
			return nil
		}
	}
	quoted := make([]string, len(allowed))
	for index, value := range allowed {
		quoted[index] = strconv.Quote(value)
	}
	return fmt.Errorf("%s declares %s = %q, which is not one of %s",
		path, field, choice.Value, strings.Join(quoted, ", "))
}

// readBounded reads at most maxConfigBytes from path, reporting anything longer as an error rather
// than truncating it. Truncating would hand the parser a prefix of a config and let it succeed on
// half a file.
//
// os.Open's error comes back unwrapped so Load can still tell ErrNotExist -- absence, and normal --
// from every other read failure.
func readBounded(path string) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	// One byte past the cap, so a file sitting exactly on it still loads and a file one byte over
	// is distinguishable from one that fit.
	data, err := io.ReadAll(&io.LimitedReader{R: file, N: maxConfigBytes + 1})
	if err != nil {
		return nil, err
	}
	if len(data) > maxConfigBytes {
		// Stat the OPEN HANDLE, not the path: on a host under investigation, whatever sits at that
		// path by now need not be the file that was just read. A stream or a device node reports 0
		// here, and that is the useful answer -- set against "exceeds the cap" it tells the
		// operator the path is not a plain file at all.
		seen := "an unknown number of"
		if info, statErr := file.Stat(); statErr == nil {
			seen = strconv.FormatInt(info.Size(), 10)
		}
		return nil, fmt.Errorf("exceeds the %d-byte cap for an agent config; stat reports %s bytes",
			maxConfigBytes, seen)
	}
	return data, nil
}

// rejectDuplicateKeys errors on any object in the document that names the same key twice.
//
// encoding/json silently keeps the LAST value for a repeated key. Measured on the code this
// replaces: {"schema_version":"99","views":["disk"],"schema_version":"1"} loaded clean as version
// "1", so the version gate in Load was switchable off by appending a second copy of the very key it
// checks; {"rule_set":{"name":"x","name":"y"}} loaded as "y", which is the same trick pointed at the
// compiled rules a scan will use. A gate that can be disabled from inside the file it guards is not
// a gate. internal/corpus rejects duplicate keys for the same reason (ValidateStrictJSONText,
// io.go:339, raised by the walk at io.go:451).
//
// The walk is recursive rather than top-level-plus-rule_set: the depth at which a config may have
// been tampered with is not something this package gets to assume, and the recursion is bounded by
// maxConfigBytes above.
//
// It runs AFTER json.Unmarshal has accepted the document, which is what makes it single-purpose: on
// a document already known to parse, a token error is unreachable and a duplicate key is the only
// thing it can report. Run first, it would become the gate that rejects malformed JSON as well --
// and a gate that catches two faults is a gate whose tests cannot say which one they caught.
func rejectDuplicateKeys(raw []byte) error {
	return walkForDuplicateKeys(json.NewDecoder(bytes.NewReader(raw)))
}

func walkForDuplicateKeys(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, structured := token.(json.Delim)
	if !structured {
		return nil
	}
	switch delimiter {
	case '{':
		seen := make(map[string]bool)
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return fmt.Errorf("has a JSON object key that is not a string: %v", keyToken)
			}
			if seen[key] {
				return fmt.Errorf("repeats the JSON object key %q, and the later value would silently win", key)
			}
			seen[key] = true
			if err := walkForDuplicateKeys(decoder); err != nil {
				return err
			}
		}
	case '[':
		for decoder.More() {
			if err := walkForDuplicateKeys(decoder); err != nil {
				return err
			}
		}
	}
	// Consume the closing delimiter so the caller is left positioned on the next value.
	if _, err := decoder.Token(); err != nil {
		return err
	}
	return nil
}
