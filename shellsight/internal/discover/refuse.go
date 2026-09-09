package discover

import (
	"fmt"
	"sort"
	"strings"
)

// Refusing mechanisms by name (FR-039).
//
// Two things an operator on a compromised host wants to say, and they are not the same:
//
//	--discovery-refuse=exec        do not run anything on this box
//	--discovery-refuse=nginx-dump  I do not trust this one binary
//
// The requirement is that exec-based mechanisms be INDIVIDUALLY refusable, so the name list is the
// primary form and `exec` is a group shorthand over it. Refusing discovery wholesale is a different
// switch (--discover=false), because "look, but not with that" and "do not look" lead to different
// coverage and different messages at the gate.

// execGroup is the group name that stands for every mechanism which runs a host binary.
const execGroup = "exec"

// ExecMechanisms lists the mechanisms that execute something on the host.
//
// On a compromised host that binary is attacker-reachable: it may have been replaced, and running it
// hands the intruder execution inside the responder's own process tree. That trade is why these are
// separable from the mechanisms that only read files.
func ExecMechanisms() []Mechanism {
	return []Mechanism{MechApacheDump, MechNginxDump}
}

// KnownMechanisms lists every mechanism discovery can report, in reporting order.
//
// This is discovery's capability set, and it is the reason a refusal can be validated rather than
// silently ignored: a typo in --discovery-refuse must be a warning, not a mechanism that quietly
// keeps running. Same rule US4 applies to an unknown --views name.
func KnownMechanisms() []Mechanism {
	return []Mechanism{
		MechExplicit,
		MechIISDefault, MechIISConfig,
		MechApacheConfig, MechApacheDump,
		MechNginxConfig, MechNginxDump,
		MechTomcatEnv, MechTomcatProcess, MechTomcatServerXML, MechTomcatConvention,
		MechAppserverProcess, MechAppserverConvention,
		MechConvention,
		MechDiscovery,
	}
}

// ParseRefusal turns a comma-separated list into a refusal set, returning any names it did not
// recognise so the caller can warn rather than pretend.
func ParseRefusal(spec string) (map[Mechanism]bool, []string) {
	known := map[string]Mechanism{}
	for _, m := range KnownMechanisms() {
		known[string(m)] = m
	}
	refuse := map[Mechanism]bool{}
	var unknown []string
	for _, raw := range strings.Split(spec, ",") {
		name := strings.ToLower(strings.TrimSpace(raw))
		if name == "" {
			continue
		}
		if name == execGroup {
			for _, m := range ExecMechanisms() {
				refuse[m] = true
			}
			continue
		}
		if m, ok := known[name]; ok {
			refuse[m] = true
			continue
		}
		unknown = append(unknown, raw)
	}
	if len(refuse) == 0 {
		return nil, unknown // nil, so Options.refused stays a cheap nil check
	}
	return refuse, unknown
}

// RefusalHelp is the flag help text. It names the group and the mechanisms, because an operator
// deciding whether to allow an exec on an incident host needs to know what would run.
func RefusalHelp() string {
	names := make([]string, 0, len(KnownMechanisms()))
	for _, m := range KnownMechanisms() {
		names = append(names, string(m))
	}
	sort.Strings(names)
	execNames := make([]string, 0, 2)
	for _, m := range ExecMechanisms() {
		execNames = append(execNames, string(m))
	}
	return fmt.Sprintf(
		"comma-separated discovery mechanisms to refuse; %q refuses the ones that run a host binary "+
			"(%s), which on a compromised host an intruder may have replaced. Known: %s",
		execGroup, strings.Join(execNames, ", "), strings.Join(names, ", "))
}
