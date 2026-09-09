package main

import (
	"fmt"
	"strings"

	"shellsight/internal/discover"
	"shellsight/internal/finding"
)

// resolveDiscovery locates the roots to scan, or resolves the ones the operator named.
//
// Indirected through a variable so a test can present a host where discovery finds nothing. That
// host cannot be arranged on a real machine -- the build box has C:\inetpub\wwwroot, WSL has no
// webroot at all -- and the untestable case is the one that shipped wrong.
var resolveDiscovery = discover.Discover

// webrootGate reports why no scan is possible, or "" when there is something to scan.
//
// Scanning nothing is not evidence of absence (FR-038). The probe already refused an
// explicitly-requested root that does not exist, and refused when every resolved root failed to
// scan, but nothing covered the case between them: no path supplied AND discovery finding nothing.
// Such a host reached the coverage block with Status: CovRan and TargetsScanned: 0, which the core
// reads as a completed scan of zero targets -- so a bare `shellsight scan` on a host whose layout
// discovery does not recognise reported clean and exited 0. That is the single most misleading
// answer this tool can give, because it is indistinguishable from a real all-clear, and it lands
// exactly on the unfamiliar host that discovery exists to serve.
//
// The failing arms keep separate messages on purpose, because they send a responder to different
// places: a stale command line, a host we do not recognise, a host that named directories we
// refused, and a scan nobody asked to look for anything are four different problems.
func webrootGate(requested int, res discover.Result) string {
	if len(res.Roots) > 0 {
		return "" // includes the partial case: some named roots resolved, and those get scanned
	}
	if requested > 0 {
		return fmt.Sprintf("none of the %d requested webroot(s) exist", requested)
	}
	if discoveryRefused(res) {
		// Distinct from "nothing could be discovered", which would be a lie: nothing was looked for.
		// Same failure as T075 by a different route -- an operator who disables discovery and names
		// no path has asked for a scan of nothing, and a scan of nothing is not an all-clear.
		return "discovery is disabled and no webroot was supplied, so there was nothing to scan; " +
			"name one with --path or re-enable discovery"
	}
	if n := len(res.Rejected); n > 0 {
		// Discovery DID find candidates and validation refused all of them. Saying "nothing could be
		// discovered" here would hide the more interesting fact: something on this host named a
		// directory we would not scan, and on a compromised host that is a lead, not noise.
		first := res.Rejected[0]
		return fmt.Sprintf("no usable webroot: all %d discovered candidate(s) were rejected "+
			"(%s: %s); name one with --path", n, first.Path, first.Reason) + mechanismSummary(res)
	}
	return "no webroot could be discovered on this host and none was supplied, so nothing was " +
		"scanned; name one with --path" + mechanismSummary(res)
}

// mechanismSummary carries each mechanism's own account into the failure when nothing survived.
//
// A failed probe emits no coverage block, so without this the outcome details -- "exists without an
// instance layout: /usr/local/tomcat", "checked 3 conventional location(s) …", "refused by the
// operator" -- were lost exactly when a responder needed them (spec 007 US2 scenarios 3 and 7;
// measured 2026-08-26 on a Tomcat image with its server.xml removed). Bounded, because every detail is
// attacker-influenced in length and the failure line must not become the report.
func mechanismSummary(res discover.Result) string {
	// Actionable accounts first, so the bound never cuts them: a mechanism that RAN and found nothing
	// (its detail names what it checked and what existed in an unrecognised shape) or was REFUSED is
	// what the responder acts on; "unavailable" mechanisms describe the wrong host or an absent server
	// and are listed by name only.
	var acted, quiet []string
	for _, o := range res.Outcomes {
		if o.Mechanism == discover.MechExplicit || o.Mechanism == discover.MechDiscovery {
			continue
		}
		s := string(o.Mechanism) + "=" + string(o.Status)
		if o.Status == discover.StatusUnavailable {
			quiet = append(quiet, s)
			continue
		}
		if o.Detail != "" {
			s += " (" + o.Detail + ")"
		}
		acted = append(acted, s)
	}
	parts := append(acted, quiet...)
	if len(parts) == 0 {
		return ""
	}
	return boundedMessage(" Mechanisms: "+strings.Join(parts, "; "), 2000)
}

// discoveryRefused reports whether discovery was turned off rather than merely unproductive.
func discoveryRefused(res discover.Result) bool {
	for _, o := range res.Outcomes {
		if o.Mechanism == discover.MechDiscovery && o.Status == discover.StatusRefused {
			return true
		}
	}
	return false
}

// discoveryReport converts the discovery result into the wire contract. Kept explicit rather than
// sharing the struct so a refactor inside internal/discover cannot silently change what a SIEM
// consumer receives.
func discoveryReport(res discover.Result) *finding.DiscoveryReport {
	rep := &finding.DiscoveryReport{
		Roots:      make([]finding.DiscoveredRoot, 0, len(res.Roots)),
		Mechanisms: make([]finding.DiscoveryMechanism, 0, len(res.Outcomes)),
	}
	for _, r := range res.Roots {
		also := make([]string, 0, len(r.AlsoFoundBy))
		for _, m := range r.AlsoFoundBy {
			also = append(also, string(m))
		}
		rep.Roots = append(rep.Roots, finding.DiscoveredRoot{
			Path:         r.Path,
			Mechanism:    string(r.Mechanism),
			Source:       r.Source,
			InFilesystem: r.InFilesystem,
			AlsoFoundBy:  also,
			Subsumes:     r.Subsumes,
		})
	}
	for _, o := range res.Outcomes {
		rep.Mechanisms = append(rep.Mechanisms, finding.DiscoveryMechanism{
			Mechanism: string(o.Mechanism), Status: string(o.Status), Roots: o.Roots, Detail: o.Detail,
		})
	}
	for _, r := range res.Rejected {
		rep.Rejected = append(rep.Rejected, finding.DiscoveryRejection{
			Path: r.Path, Mechanism: string(r.Mechanism), Source: r.Source, Reason: r.Reason,
		})
	}
	rep.RejectedTotal = res.RejectedTotal
	return rep
}
