package main

import (
	"strings"

	"shellsight/internal/finding"
)

// Detection bases for behavioral findings:
//   "behavioral"         — a genuine (if corroboration-capped) malicious signal (w3wp→shell child).
//   "behavioral-context" — informational only: surfaced for the analyst but never escalates and
//                          never corroborates (ViewState MAC failures + IIS-config changes are too
//                          noisy, and 1316 is NOT the signature of a successful key-signed ViewState
//                          attack — that runs in-memory with a valid MAC and is the .NET-mem view's job).
const (
	basisBehavioral        = "behavioral"
	basisBehavioralContext = "behavioral-context"
)

// behavioralFinding builds a Finding common to all behavioral detectors.
func behavioralFinding(host, basis, kbRef, identity, evidence string) finding.Finding {
	return finding.Finding{
		SchemaVersion: finding.SchemaVersion,
		Host:          host,
		View:          "behavioral",
		Artifact:      finding.Artifact{Kind: "log-event", Identity: identity},
		Detection:     finding.Detection{Basis: basis, KnowledgeRef: kbRef, Evidence: evidence},
		// score/tier are assigned centrally by fusion.Assess.
	}
}

// detectViewState flags ASP.NET ViewState MAC-validation failures (Event ID 1316 with a
// viewstate indication) — the on-host signature of a forged ViewState (ToolShell/GoldMelody).
func detectViewState(events []Event, host string) []finding.Finding {
	var out []finding.Finding
	for _, e := range events {
		if e.EventID != 1316 || !strings.HasPrefix(strings.ToLower(e.Provider), "asp.net") {
			continue
		}
		if !e.dataAny("viewstate") {
			continue
		}
		out = append(out, behavioralFinding(host, basisBehavioralContext, finding.KBBehaviorViewState,
			"asp.net:viewstate-mac-failure",
			"ASP.NET ViewState MAC validation FAILED (EventID 1316) — a keyless/botched forge or key rotation, NOT a successful key-signed attack (those pass MAC and leave no 1316). Context only."))
	}
	return out
}

// detectIISConfig flags IIS configuration changes that add a module or modify web.config
// (Microsoft-IIS-Configuration/Operational EventID 29 and 50) — the persistence trail of an
// IIS-component backdoor that disk/mem scans of a since-restarted host would miss.
func detectIISConfig(events []Event, host string) []finding.Finding {
	var out []finding.Finding
	for _, e := range events {
		if e.Channel != "Microsoft-IIS-Configuration/Operational" {
			continue
		}
		if e.EventID != 29 && e.EventID != 50 {
			continue
		}
		out = append(out, behavioralFinding(host, basisBehavioralContext, finding.KBBehaviorIISConfig,
			"iis:config-change",
			"IIS configuration changed (EventID "+itoa(e.EventID)+") — module/web.config persistence trail; high-FP (deploys/admin edits also fire). Context only."))
	}
	return out
}

// shellChildren is the set of shell/LOLBin/recon images that are suspicious as a w3wp child —
// a web worker has no legitimate reason to spawn any of these.
var shellChildren = map[string]bool{
	// shells / scripting hosts
	"cmd.exe": true, "powershell.exe": true, "pwsh.exe": true, "cscript.exe": true,
	"wscript.exe": true, "mshta.exe": true, "wsl.exe": true, "bash.exe": true,
	// proxy-exec / download LOLBins
	"rundll32.exe": true, "regsvr32.exe": true, "installutil.exe": true, "msbuild.exe": true,
	"bitsadmin.exe": true, "certutil.exe": true, "curl.exe": true, "ftp.exe": true,
	// recon
	"net.exe": true, "net1.exe": true, "whoami.exe": true, "wmic.exe": true, "reg.exe": true,
	"sc.exe": true, "tasklist.exe": true, "systeminfo.exe": true, "ipconfig.exe": true,
	"nltest.exe": true, "arp.exe": true, "dsquery.exe": true, "netstat.exe": true,
	"route.exe": true, "hostname.exe": true, "quser.exe": true,
	// persistence / lateral
	"schtasks.exe": true, "at.exe": true, "psexec.exe": true, "psexec64.exe": true,
}

// legitW3wpChildren is the SMALL set of processes an IIS worker spawns in normal operation:
// ASP.NET runtime compilation (csc/vbc + the cvtres resource step + the attached conhost),
// worker recycling (w3wp itself), and crash reporting (WER). Standard webshell process-tree
// hunts (Sigma/Elastic) exclude exactly these. ANY other child of w3wp is anomalous — a
// denylist of known shell names cannot catch process-migration targets (Meterpreter migrates
// into notepad.exe/etc.), dropped binaries, or renamed LOLBins; an allowlist can.
var legitW3wpChildren = map[string]bool{
	"csc.exe": true, "vbc.exe": true, "cvtres.exe": true, "conhost.exe": true,
	"w3wp.exe": true, "werfault.exe": true, "wermgr.exe": true,
}

// detectW3wpChild flags the IIS worker (w3wp.exe) spawning a child it has no business spawning —
// classic webshell command execution / post-exploitation. Two tiers, both behavioral (capped at
// suspicious, escalate only on independent corroboration):
//   - a known shell/LOLBin/recon image (shellChildren) → high-signal "executing a shell/LOLBin";
//   - any other non-allowlisted image (legitW3wpChildren) → "anomalous child" (migration target,
//     dropped binary, or — less often — a legit app that intentionally shells out).
//
// Covers Security 4688 (ParentProcessName/NewProcessName) and Sysmon 1 (ParentImage/Image).
func detectW3wpChild(events []Event, host string) []finding.Finding {
	var out []finding.Finding
	for _, e := range events {
		parent, child := "", ""
		switch {
		case e.Channel == "Security" && e.EventID == 4688:
			parent, child = e.Data["ParentProcessName"], e.Data["NewProcessName"]
		case e.EventID == 1 && strings.Contains(e.Channel, "Sysmon"):
			parent, child = e.Data["ParentImage"], e.Data["Image"]
		default:
			continue
		}
		if !strings.HasSuffix(strings.ToLower(parent), `\w3wp.exe`) {
			continue
		}
		c := baseLower(child)
		switch {
		case c == "":
			continue // no child image recorded — nothing to judge
		case shellChildren[c]:
			out = append(out, behavioralFinding(host, basisBehavioral, finding.KBBehaviorW3wpChild,
				"proc:w3wp->"+c,
				"w3wp.exe spawned "+c+" — web server executing a shell/LOLBin"))
		case !legitW3wpChildren[c]:
			out = append(out, behavioralFinding(host, basisBehavioral, finding.KBBehaviorW3wpAnomalousChild,
				"proc:w3wp->"+c,
				"w3wp.exe spawned "+c+" — unexpected child for an IIS worker (possible webshell command-exec, process-migration target, or dropped binary); benign only if this app intentionally shells out to "+c))
		}
	}
	return out
}

// baseLower returns the lower-cased file name of a Windows path.
func baseLower(p string) string {
	p = strings.ToLower(strings.TrimSpace(p))
	if i := strings.LastIndexAny(p, `\/`); i >= 0 {
		return p[i+1:]
	}
	return p
}

// itoa is a tiny local int→string to avoid importing strconv across this file.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b [12]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}
