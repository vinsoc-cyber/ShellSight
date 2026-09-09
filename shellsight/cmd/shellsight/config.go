package main

import (
	"flag"
	"fmt"
	"path/filepath"
	"strings"

	"shellsight/internal/agentcfg"
)

// Precedence: explicit CLI options > agent.json > built-in defaults (C3).
//
// These are separate pure functions rather than inline branches so the precedence is assertable
// without building a scan. Getting it backwards would let a build's own config silently overrule an
// operator on a live engagement, which is the opposite of what an override is for.
//
// Every one of them checks cfg.Present BEFORE the field it reads. "No agent.json at all" and "an
// agent.json that named neither field" both leave the field zero, and only Present separates them --
// so a resolver reading the field alone lets a config that does not exist choose the setting.

// resolveViews picks the view set. flagSet reports whether -views was actually passed, which the
// flag's VALUE cannot tell you: -views defaults to the built-in set, so an operator who types the
// default is indistinguishable from one who typed nothing unless the caller tracks it.
func resolveViews(flagValue string, flagSet bool, cfg agentcfg.Config, builtinDefault string) string {
	if flagSet {
		return flagValue
	}
	if cfg.Present && len(cfg.Views) > 0 {
		return strings.Join(cfg.Views, ",")
	}
	return builtinDefault
}

// resolveScanScope picks the webroot list: -path if the operator typed one, else the build's baked
// scope, else empty, which the disk view reads as auto-discover.
//
// flagSet rather than flagValue != "", for the reason the whole file uses it: an operator who types
// -path "" is saying "ignore the baked scope and auto-discover", and the VALUE alone cannot tell
// that apart from not passing the flag. Reading it as "not set" would let a build's scope quietly
// override a human who explicitly cleared it.
//
// The scope is a DEFAULT, never a bound. agent.json can widen the scan as easily as narrow it, so
// this is convenience rather than containment -- see agentcfg.Config.ScanScope.
func resolveScanScope(flagValue string, flagSet bool, cfg agentcfg.Config) string {
	if flagSet {
		return flagValue
	}
	if cfg.Present && len(cfg.ScanScope) > 0 {
		return strings.Join(cfg.ScanScope, ",")
	}
	return ""
}

// carriedViews is the set of views the build DECLARES it carries, or nil when no build declared
// anything.
//
// nil and empty are different answers and the caller reads them differently: nil excludes nothing,
// while an empty set would declare every view absent. So Present is checked BEFORE the field, as
// everything in this file does, and a Present configuration that somehow states no views is
// answered nil as well. agentcfg.Load already refuses that configuration, but "excludes nothing" is
// the safe direction to be wrong in; the other one turns a configuration nobody could read into a
// scan that reports every capability as out of scope, cleanly, and exits 0.
//
// Separate from resolveViews on purpose. That one answers "what was REQUESTED", which an explicit
// -views overrules. This one answers "what does this build CARRY", which nothing on the command
// line can change: an operator naming a view cannot put a component into a package that does not
// ship one.
func carriedViews(cfg agentcfg.Config) []string {
	if !cfg.Present || len(cfg.Views) == 0 {
		return nil
	}
	return cfg.Views
}

// resolveRulesBlob picks the compiled rule set, and settles what `-rules-dir X -rules-blob Y` means.
//
// The pair is REFUSED, as diskprobe refuses it one layer down (cmd/diskprobe/main.go) and for the
// reason its comment gives: "silently preferring one when both are given is how an agent ends up
// scanning with rules nobody chose". Until now scan accepted the pair and split it -- the disk view
// took the blob and ignored -rules-dir, while mem-contracts.json kept following -rules-dir -- which
// is that same silent preferring, just spread across two views instead of one.
//
// An explicit -rules-dir therefore also SUPPRESSES a blob the config supplies. That is C3 read from
// the other side: -rules-dir is an explicit CLI statement about which rules to scan with, so letting
// agent.json's blob win over it would put the file above the operator for the disk view.
//
// The config's path is relative to the agent directory, because the console writes agent.json
// without knowing where it will be unpacked. That value is CONTAINED to that directory; an
// operator's -rules-blob is deliberately not. See containedJoin for why the containment exists and
// why the asymmetry is the right way round.
func resolveRulesBlob(blobFlag, rulesDirFlag string, cfg agentcfg.Config, agentDir string) (string, error) {
	if blobFlag != "" && rulesDirFlag != "" {
		return "", fmt.Errorf("-rules-dir and -rules-blob are mutually exclusive: a build scans with " +
			"a rule tree or with a compiled rule set, and preferring one silently is how a scan ends " +
			"up using rules nobody chose")
	}
	// A human on the console typed this one, and an IR sweep legitimately scans with a rule set
	// staged on another volume, so it is taken as given.
	if blobFlag != "" {
		return blobFlag, nil
	}
	// The operator named a rule TREE. Reporting no blob is what makes that tree the thing the disk
	// view scans with, config or no config.
	if rulesDirFlag != "" {
		return "", nil
	}
	if cfg.Present && cfg.RuleSet.Yarc != "" {
		return containedJoin("rule_set.yarc", agentDir, cfg.RuleSet.Yarc)
	}
	// No blob anywhere: the rule tree beside the binary is used, which is the hand-run default.
	return "", nil
}

// containedJoin resolves rel inside baseDir, refusing any value that does not stay there. what names
// the field being resolved, so the operator standing on the host is told which one to fix.
//
// filepath.Join calls Clean, so it does NOT neutralise `..`: Join(agentDir, "../../../etc/passwd")
// resolves cleanly out of the agent directory. agent.json is read on a host under investigation --
// which is to say a host where an intruder may have edited it -- so an unchecked value here points
// the scanner's rule blob anywhere on the filesystem.
//
// The check is a separator BOUNDARY, not a string prefix. A bare strings.HasPrefix compare accepts
// "<base>EVIL/x.yarc" as living under "<base>", because it does as a string and does not as a path.
//
// Refused with an ERROR, never by falling back to the built-in rules. A silent fallback would let a
// tampered config downgrade the sweep to a rule set nobody chose while reporting success, which is
// the failure this containment exists to prevent, reintroduced one line below the check.
//
// The offending value is printed with %q rather than raw: it is untrusted text from the config, and
// quoting is what keeps a control character or a terminal escape sequence inside it from reaching a
// console as anything but visible text.
func containedJoin(what, baseDir, rel string) (string, error) {
	if rel == "" {
		return "", fmt.Errorf("%s names no path", what)
	}
	// A rooted value is not a relocatable one. The config states a path relative to an agent
	// directory whose location it cannot know, so joining a rooted value would silently reinterpret
	// it as a different path than the one written -- Join("C:\\agent", "/etc/x.yarc") is
	// "C:\\agent\\etc\\x.yarc", which is neither what the file said nor an error.
	if isRooted(rel) {
		return "", fmt.Errorf("%s is %q, a rooted path; it must be relative to the agent directory %s",
			what, rel, baseDir)
	}
	base, err := filepath.Abs(baseDir)
	if err != nil {
		return "", fmt.Errorf("resolving the agent directory %s: %w", baseDir, err)
	}
	target, err := filepath.Abs(filepath.Join(base, rel))
	if err != nil {
		return "", fmt.Errorf("resolving %s %q against the agent directory: %w", what, rel, err)
	}
	// A compiled rule set is a file. A value resolving to the directory itself names no file, and is
	// not "inside" it either -- so it is refused here rather than left to fail later as a read of a
	// directory.
	if target == base {
		return "", fmt.Errorf("%s is %q, which resolves to the agent directory %s itself rather than "+
			"to a file inside it", what, rel, base)
	}
	prefix := base
	if !strings.HasSuffix(prefix, string(filepath.Separator)) {
		prefix += string(filepath.Separator)
	}
	if !strings.HasPrefix(target, prefix) {
		return "", fmt.Errorf("%s is %q, which resolves to %s, outside the agent directory %s; a "+
			"configuration may only name a rule set it ships with", what, rel, target, base)
	}
	return target, nil
}

// isRooted reports whether path states its own root rather than a location relative to something
// else.
//
// Deliberately wider than filepath.IsAbs, and wider on both platforms. IsAbs is host-shaped:
// "/etc/x.yarc" is not absolute on Windows and "C:\\x.yarc" is not absolute on Linux, yet each is
// plainly a rooted path written by a console on the other platform -- and each would otherwise be
// joined and silently reinterpreted as a relative name. A rooted value is refused rather than
// repaired wherever it is read, because this scanner does not fix a configuration it does not
// understand.
func isRooted(path string) bool {
	return filepath.IsAbs(path) ||
		filepath.VolumeName(path) != "" ||
		strings.HasPrefix(path, "/") ||
		strings.HasPrefix(path, `\`)
}

// resolveJSONOutput and resolveLowPriority run the two baked settings up the same ladder.
//
// They are enumerations in agent.json and booleans on the command line, so they have a mapping step
// the view set does not -- and nothing enforces that the two stay one-to-one. See resolveBakedBool.

func resolveJSONOutput(flagValue, flagSet bool, cfg agentcfg.Config) (bool, error) {
	return resolveBakedBool("output_format", flagValue, flagSet, cfg.Present, cfg.OutputFormat,
		agentcfg.OutputFormatJSON, agentcfg.OutputFormatText)
}

func resolveLowPriority(flagValue, flagSet bool, cfg agentcfg.Config) (bool, error) {
	return resolveBakedBool("process_priority", flagValue, flagSet, cfg.Present, cfg.ProcessPriority,
		agentcfg.ProcessPriorityLow, agentcfg.ProcessPriorityNormal)
}

// resolveBakedBool maps a Choice onto the bool its flag can express, and REFUSES a value it cannot.
//
// The refusal is the point. output_format and process_priority are enumerations precisely so a third
// value stays expressible, and the flags they feed -- -json and -low-priority -- are booleans that
// cannot hold one. A later schema adding "sarif" would Load cleanly and arrive here, and a resolver
// that picked a side would put the agent in a mode nobody chose while its config on disk described a
// different one. That silent disagreement is what a declared build exists to prevent, so it says so
// instead.
//
// flagValue when flagSet is false IS the built-in default: it is whatever the flag holds when nobody
// passed it. Taking it that way rather than as a separate parameter means the two cannot disagree.
//
// An explicit flag is honoured even when the config carries a value this build cannot map. A stale
// config beside the binary must not become an agent with no way past it, and the operator standing
// on the host has already said what they want.
func resolveBakedBool(field string, flagValue, flagSet, cfgPresent bool, choice agentcfg.Choice,
	trueValue, falseValue string) (bool, error) {
	if flagSet {
		return flagValue, nil
	}
	if !cfgPresent {
		return flagValue, nil
	}
	// Silence, which is the one state that lets the built-in default win. A config that named the
	// field does not reach here even when it named today's default: "text" is the analyst choosing
	// the format the scanner already defaults to, and a build that deliberately baked today's
	// default must not be re-pointed the day that default changes.
	if !choice.Specified {
		return flagValue, nil
	}
	switch choice.Value {
	case trueValue:
		return true, nil
	case falseValue:
		return false, nil
	}
	return false, fmt.Errorf("the agent configuration declares %s = %q, which this build cannot "+
		"apply: the setting is a flag here and maps only %q and %q",
		field, choice.Value, trueValue, falseValue)
}

// agentConfigName is the file a generated agent declares itself in, beside the binary.
const agentConfigName = "agent.json"

// loadAgentConfig reads the build's declaration and reports the path it read it from, which is also
// the path the config's own relative values resolve against.
//
// The two absences are not the same thing. NO configuration beside the binary is normal -- a
// scanner run by hand has none, and it falls back to built-in defaults, which is what Load reports
// by returning a Config that is not Present. A configuration the operator NAMED with -config and
// that is not there is a typo, and falling back for it would run a scan with a view set and a rule
// set nobody asked for while the operator believes they are running the one they pointed at.
//
// defaultDir is where the config sits when -config was not passed: exeDir() in production, a
// temporary directory in the tests, which is what lets the two absences be told apart without
// building a scan.
func loadAgentConfig(configFlag, defaultDir string) (agentcfg.Config, string, error) {
	path := configFlag
	if path == "" {
		path = filepath.Join(defaultDir, agentConfigName)
	}
	cfg, err := agentcfg.Load(path)
	if err != nil {
		return agentcfg.Config{}, path, err
	}
	if configFlag != "" && !cfg.Present {
		return agentcfg.Config{}, path, fmt.Errorf("-config names %s, which does not exist; reading no "+
			"configuration instead would scan with a view set and a rule set nobody asked for", path)
	}
	return cfg, path, nil
}

// agentDirFor is the directory a configuration's relative paths resolve against: the directory the
// configuration itself was read from.
//
// With no -config that is exeDir(), which is the generated-agent layout -- shellsight, agent.json and
// the rule set unpacked side by side. With -config naming a configuration staged elsewhere, its
// relative paths follow it, rather than resolving against a binary directory the file says nothing
// about and could not have known.
func agentDirFor(configPath string) string { return filepath.Dir(configPath) }

// flagWasSet reports whether name was passed on the command line, as opposed to holding its
// default value. FlagSet.Visit walks only the flags that were actually set, which is the only
// reliable signal: -views defaults to the built-in set, so its VALUE cannot distinguish an
// operator who typed the default from one who typed nothing, and -json=false is indistinguishable
// from an unpassed -json by value alone.
func flagWasSet(fs *flag.FlagSet, name string) bool {
	found := false
	fs.Visit(func(f *flag.Flag) {
		if f.Name == name {
			found = true
		}
	})
	return found
}
