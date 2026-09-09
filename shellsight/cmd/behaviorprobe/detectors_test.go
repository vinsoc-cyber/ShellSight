package main

import (
	"testing"

	"shellsight/internal/finding"
)

func TestDetectViewStateMacFailure(t *testing.T) {
	ev := []Event{
		{Channel: "Application", Provider: "ASP.NET 4.0.30319.0", EventID: 1316,
			Values: []string{"Event code: 4009", "Event message: Viewstate verification failed. Reason: The viewstate supplied failed integrity check."}},
		{Channel: "Application", Provider: "ASP.NET 4.0.30319.0", EventID: 1309, // a different ASP.NET event → ignore
			Values: []string{"Event message: An unhandled exception"}},
	}
	got := detectViewState(ev, "WEB01")
	if len(got) != 1 {
		t.Fatalf("want 1 ViewState finding, got %d", len(got))
	}
	f := got[0]
	if f.View != "behavioral" || f.Detection.Basis != "behavioral-context" || f.Detection.KnowledgeRef != finding.KBBehaviorViewState {
		t.Fatalf("wrong finding shape (ViewState must be informational context): %+v", f.Detection)
	}
	if f.Host != "WEB01" {
		t.Fatalf("host not stamped: %q", f.Host)
	}
}

func TestDetectViewStateIgnoresBenign1316WithoutViewstate(t *testing.T) {
	ev := []Event{{Channel: "Application", Provider: "ASP.NET 4.0.30319.0", EventID: 1316,
		Values: []string{"Event message: Forms authentication failed for the request."}}}
	if got := detectViewState(ev, "H"); len(got) != 0 {
		t.Fatalf("a 1316 without a viewstate indication must not fire, got %d", len(got))
	}
}

func TestDetectIISConfigChange(t *testing.T) {
	ev := []Event{
		{Channel: "Microsoft-IIS-Configuration/Operational", Provider: "Microsoft-IIS-Configuration", EventID: 29,
			Values: []string{"globalModules", "added module FooModule"}},
		{Channel: "Microsoft-IIS-Configuration/Operational", Provider: "Microsoft-IIS-Configuration", EventID: 50,
			Values: []string{"web.config changed"}},
		{Channel: "Microsoft-IIS-Configuration/Operational", Provider: "Microsoft-IIS-Configuration", EventID: 7, // unrelated
			Values: []string{"start"}},
	}
	got := detectIISConfig(ev, "WEB01")
	if len(got) != 2 {
		t.Fatalf("want 2 IIS-config findings (EID 29,50), got %d", len(got))
	}
	for _, f := range got {
		if f.Detection.KnowledgeRef != finding.KBBehaviorIISConfig {
			t.Fatalf("wrong kbref: %s", f.Detection.KnowledgeRef)
		}
	}
}

func TestDetectW3wpChildShell4688(t *testing.T) {
	ev := []Event{
		{Channel: "Security", Provider: "Microsoft-Windows-Security-Auditing", EventID: 4688,
			Data:   map[string]string{"ParentProcessName": `C:\Windows\System32\inetsrv\w3wp.exe`, "NewProcessName": `C:\Windows\System32\cmd.exe`},
			Values: []string{`C:\Windows\System32\inetsrv\w3wp.exe`, `C:\Windows\System32\cmd.exe`}},
		{Channel: "Security", Provider: "Microsoft-Windows-Security-Auditing", EventID: 4688, // benign: parent not w3wp
			Data:   map[string]string{"ParentProcessName": `C:\Windows\explorer.exe`, "NewProcessName": `C:\Windows\System32\cmd.exe`},
			Values: []string{`C:\Windows\explorer.exe`, `C:\Windows\System32\cmd.exe`}},
	}
	got := detectW3wpChild(ev, "WEB01")
	if len(got) != 1 {
		t.Fatalf("want 1 w3wp->shell finding, got %d", len(got))
	}
	if got[0].Detection.KnowledgeRef != finding.KBBehaviorW3wpChild {
		t.Fatalf("wrong kbref: %s", got[0].Detection.KnowledgeRef)
	}
}

func TestDetectW3wpChildShellSysmon(t *testing.T) {
	ev := []Event{{Channel: "Microsoft-Windows-Sysmon/Operational", Provider: "Microsoft-Windows-Sysmon", EventID: 1,
		Data:   map[string]string{"ParentImage": `C:\Windows\System32\inetsrv\w3wp.exe`, "Image": `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`},
		Values: []string{`C:\Windows\System32\inetsrv\w3wp.exe`, `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`}}}
	if got := detectW3wpChild(ev, "H"); len(got) != 1 {
		t.Fatalf("want 1 Sysmon w3wp->powershell finding, got %d", len(got))
	}
}

// A non-shell, non-allowlisted child (a dropped/unknown binary) is ANOMALOUS for an IIS worker
// and must surface — a denylist of shell names alone would miss dropped payloads.
func TestW3wpChildFlagsAnomalousNonShellChild(t *testing.T) {
	ev := []Event{{Channel: "Security", Provider: "Microsoft-Windows-Security-Auditing", EventID: 4688,
		Data:   map[string]string{"ParentProcessName": `C:\Windows\System32\inetsrv\w3wp.exe`, "NewProcessName": `C:\inetpub\app\helper.exe`},
		Values: []string{`C:\Windows\System32\inetsrv\w3wp.exe`, `C:\inetpub\app\helper.exe`}}}
	got := detectW3wpChild(ev, "H")
	if len(got) != 1 {
		t.Fatalf("w3wp spawning an unknown dropped binary must fire as anomalous, got %d", len(got))
	}
	if got[0].Detection.KnowledgeRef != finding.KBBehaviorW3wpAnomalousChild {
		t.Fatalf("want anomalous-child kbref, got %s", got[0].Detection.KnowledgeRef)
	}
}

// The real rotten-potato/Meterpreter case: the payload migrated into notepad.exe, so the only
// captured edge is w3wp->notepad.exe. notepad is not a "shell" — a denylist misses it; the
// allowlist catches it as anomalous. (EVTX-ATTACK-SAMPLES privesc_rotten_potato_from_webshell.)
func TestW3wpChildFlagsMigrationTargetNotepad(t *testing.T) {
	ev := []Event{{Channel: "Microsoft-Windows-Sysmon/Operational", Provider: "Microsoft-Windows-Sysmon", EventID: 1,
		Data:   map[string]string{"ParentImage": `C:\Windows\System32\inetsrv\w3wp.exe`, "Image": `C:\Windows\System32\notepad.exe`},
		Values: []string{`C:\Windows\System32\inetsrv\w3wp.exe`, `C:\Windows\System32\notepad.exe`}}}
	got := detectW3wpChild(ev, "WEB01")
	if len(got) != 1 || got[0].Detection.KnowledgeRef != finding.KBBehaviorW3wpAnomalousChild {
		t.Fatalf("want 1 anomalous-child finding for w3wp->notepad.exe, got %+v", got)
	}
	if got[0].Detection.Basis != "behavioral" {
		t.Fatalf("anomalous child must be a behavioral signal (corroboration-capped), got %q", got[0].Detection.Basis)
	}
}

// ASP.NET runtime compilation (csc/vbc/cvtres/conhost) is the IIS worker's NORMAL child set and
// must stay silent — this is the FP guard for the allowlist on every healthy ASP.NET host.
func TestW3wpChildIgnoresAspNetCompiler(t *testing.T) {
	for _, img := range []string{`C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe`,
		`C:\Windows\Microsoft.NET\Framework64\v4.0.30319\vbc.exe`,
		`C:\Windows\System32\conhost.exe`, `C:\Windows\System32\WerFault.exe`} {
		ev := []Event{{Channel: "Microsoft-Windows-Sysmon/Operational", Provider: "Microsoft-Windows-Sysmon", EventID: 1,
			Data:   map[string]string{"ParentImage": `C:\Windows\System32\inetsrv\w3wp.exe`, "Image": img},
			Values: []string{`C:\Windows\System32\inetsrv\w3wp.exe`, img}}}
		if got := detectW3wpChild(ev, "H"); len(got) != 0 {
			t.Fatalf("legit w3wp child %q must not fire, got %d", img, len(got))
		}
	}
}
