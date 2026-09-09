package main

import (
	"testing"

	"shellsight/internal/finding"
	"shellsight/internal/jvmtriage"
)

func target() procTarget {
	return procTarget{PID: 101, Server: "tomcat", Argv: []string{"/usr/bin/java", "-jar", "app.jar"}}
}

// Stage 1 alone must NEVER reach likely-malicious. External evidence says "look here"; it does not
// identify a webshell. Claiming malicious from an unlinked jar would false-positive on every estate
// whose deployment pipeline removes a jar after loading it.
func TestStrongExternalSignalCapsAtSuspicious(t *testing.T) {
	f := externalFindings(target(), []jvmtriage.Signal{{
		Code:     "deleted-mapping",
		Detail:   "unlinked code artifact still mapped by the JVM: /tmp/x.jar",
		Severity: jvmtriage.SevStrong,
	}})
	if len(f) != 1 {
		t.Fatalf("want 1 finding, got %d", len(f))
	}
	if f[0].Tier == finding.TierLikely {
		t.Error("Stage 1 evidence alone must not reach likely-malicious")
	}
	if f[0].Tier != finding.TierSuspicious {
		t.Errorf("want suspicious, got %v", f[0].Tier)
	}
}

func TestFindingNamesItsProcessAndCarriesAPivotKey(t *testing.T) {
	f := externalFindings(target(), []jvmtriage.Signal{{
		Code: "deleted-fd", Detail: "unlinked code artifact still open by the JVM: /tmp/a.jar",
		Severity: jvmtriage.SevStrong,
	}})
	if f[0].View != "java-mem" {
		t.Errorf("want view java-mem, got %q", f[0].View)
	}
	if f[0].Target.Process == nil || f[0].Target.Process.PID != 101 {
		t.Error("a finding must name the process it is about")
	}
	if f[0].Detection.KnowledgeRef != "kb:java-mem/deleted-fd" {
		t.Errorf("KnowledgeRef is the stable pivot key, got %q", f[0].Detection.KnowledgeRef)
	}
	if f[0].Detection.Evidence == "" {
		t.Error("evidence must be carried")
	}
	if f[0].Artifact.Identity == "" {
		t.Error("artifact identity must be set")
	}
}

// Info signals explain a result rather than being one. Emitting them as findings would bury the
// real signal under every APM host's -javaagent.
func TestInfoSignalsProduceNoFinding(t *testing.T) {
	sigs := []jvmtriage.Signal{{
		Code: "startup-javaagent", Detail: "agent loaded at startup: /opt/otel/agent.jar",
		Severity: jvmtriage.SevInfo,
	}}
	if f := externalFindings(target(), sigs); len(f) != 0 {
		t.Fatalf("info signals are context, not findings; got %d", len(f))
	}
	if infoContext(sigs) != "startup-javaagent" {
		t.Errorf("info signals must still reach the coverage record, got %q", infoContext(sigs))
	}
}

func TestNoSignalsProducesNoFindings(t *testing.T) {
	if f := externalFindings(target(), nil); len(f) != 0 {
		t.Errorf("a clean JVM produces no findings, got %+v", f)
	}
}

func TestWeakScoresBelowStrong(t *testing.T) {
	weak := externalFindings(target(), []jvmtriage.Signal{{Code: "a", Detail: "d", Severity: jvmtriage.SevWeak}})
	strong := externalFindings(target(), []jvmtriage.Signal{{Code: "b", Detail: "d", Severity: jvmtriage.SevStrong}})
	if weak[0].Score >= strong[0].Score {
		t.Errorf("weak (%d) must score below strong (%d)", weak[0].Score, strong[0].Score)
	}
}
