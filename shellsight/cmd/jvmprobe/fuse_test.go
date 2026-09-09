package main

import (
	"strings"
	"testing"

	"shellsight/internal/finding"
	"shellsight/internal/jvmprov"
	"shellsight/internal/jvmtriage"
)

func TestSpoofedPipelineClassReachesLikelyMalicious(t *testing.T) {
	f := fuse(target(), []classResult{{
		Claim: jvmprov.Claim{ClassName: "org.apache.Evil", Suspicion: 85,
			Contracts: []string{"javax.servlet.Filter"}},
		Verification: jvmprov.Verification{Status: jvmprov.Spoofed, LoaderContradiction: true},
	}}, nil)
	if len(f) != 1 {
		t.Fatalf("want 1 finding, got %d", len(f))
	}
	if f[0].Tier != finding.TierLikely {
		t.Errorf("a pipeline class forging its CodeSource is a webshell, got %v", f[0].Tier)
	}
	if f[0].Detection.KnowledgeRef != "kb:java-mem/loader-contradiction" {
		t.Errorf("the loader contradiction must own the pivot key, got %q", f[0].Detection.KnowledgeRef)
	}
}

func TestFilelessPipelineClassReachesLikelyMalicious(t *testing.T) {
	f := fuse(target(), []classResult{{
		Claim: jvmprov.Claim{ClassName: "org.apache.Evil",
			Contracts: []string{"org.apache.catalina.Valve"}},
		Verification: jvmprov.Verification{Status: jvmprov.DiskAbsentClaim},
	}}, nil)
	if len(f) != 1 || f[0].Tier != finding.TierLikely {
		t.Fatalf("a fileless Valve is the memshell shape, got %+v", f)
	}
}

// The ProxyValve / Agent-payload shape: fileless, NO pipeline contract, capability-rich. Losing
// this is what cost 20 of 92 cells when capture was score-gated, so it has a test.
func TestFilelessContractlessButCapableReachesLikelyMalicious(t *testing.T) {
	f := fuse(target(), []classResult{{
		Claim:        jvmprov.Claim{ClassName: "org.apache.http.q.ErrorProxyValve"},
		Verification: jvmprov.Verification{Status: jvmprov.DiskAbsentClaim},
		Capabilities: []string{"exec", "reflect"},
	}}, nil)
	if len(f) != 1 || f[0].Tier != finding.TierLikely {
		t.Fatalf("a fileless capability-rich payload must alert, got %+v", f)
	}
}

// A tunnel trips ONE capability and has no contract. It must be reported, but below the alert
// threshold rather than silently dropped — this is the measured Suo5 gap.
func TestFilelessSingleCapabilityIsSuspiciousNotSilent(t *testing.T) {
	f := fuse(target(), []classResult{{
		Claim:        jvmprov.Claim{ClassName: "org.apache.http.q.ErrorProxyValve"},
		Verification: jvmprov.Verification{Status: jvmprov.DiskAbsentClaim},
		Capabilities: []string{"reflect"},
	}}, nil)
	if len(f) != 1 {
		t.Fatalf("must still be reported, got %d", len(f))
	}
	if f[0].Tier != finding.TierSuspicious {
		t.Errorf("one weak capability is suspicious, not an alert, got %v", f[0].Tier)
	}
}

// The false positive that would end the project: a CORROBORATED class produces nothing, however
// many capabilities it has. Framework code is full of them.
func TestCorroboratedClassProducesNoFinding(t *testing.T) {
	f := fuse(target(), []classResult{{
		Claim: jvmprov.Claim{ClassName: "org.springframework.web.filter.CharacterEncodingFilter",
			Contracts: []string{"javax.servlet.Filter"}},
		Verification: jvmprov.Verification{Status: jvmprov.Corroborated},
		Capabilities: []string{"crypto", "loader", "reflect"},
	}}, nil)
	if len(f) != 0 {
		t.Fatalf("a class genuinely present in its own jar must produce no finding, got %+v", f)
	}
}

func TestFamilyAndCapabilityRideAlong(t *testing.T) {
	f := fuse(target(), []classResult{{
		Claim: jvmprov.Claim{ClassName: "org.apache.Evil",
			Contracts: []string{"javax.servlet.Filter"}},
		Verification: jvmprov.Verification{Status: jvmprov.DiskAbsentClaim},
		Family:       jvmprov.Family{Name: "behinder", Evidence: "default key literal", Confidence: 0.9},
		Capabilities: []string{"crypto", "exec"},
	}}, nil)
	if len(f) != 1 {
		t.Fatalf("want 1 finding, got %d", len(f))
	}
	if f[0].Classification.Family == nil || *f[0].Classification.Family != "behinder" {
		t.Error("family must reach the finding")
	}
	if len(f[0].Classification.Capability) != 2 {
		t.Errorf("capability belongs in Classification, got %v", f[0].Classification.Capability)
	}
	if f[0].Context["family_evidence"] == "" {
		t.Error("family evidence must be carried")
	}
}

// Attribution is ADDITIVE: it must not change the tier.
func TestAttributionDoesNotChangeTier(t *testing.T) {
	base := classResult{
		Claim:        jvmprov.Claim{ClassName: "a.A", Contracts: []string{"javax.servlet.Filter"}},
		Verification: jvmprov.Verification{Status: jvmprov.DiskAbsentClaim},
	}
	withFam := base
	withFam.Family = jvmprov.Family{Name: "godzilla", Confidence: 0.9}
	a := fuse(target(), []classResult{base}, nil)
	b := fuse(target(), []classResult{withFam}, nil)
	if a[0].Tier != b[0].Tier || a[0].Score != b[0].Score {
		t.Errorf("attribution must not move the tier or score: %v/%d vs %v/%d",
			a[0].Tier, a[0].Score, b[0].Tier, b[0].Score)
	}
}

// Ship gate: attach refusal must never be silent, and must carry the external evidence.
func TestAttachRefusalStillReportsExternalEvidence(t *testing.T) {
	f := fuse(target(), nil, []jvmtriage.Signal{{
		Code: "attach-refused", Detail: "-XX:+DisableAttachMechanism",
		Severity: jvmtriage.SevWeak,
	}})
	if len(f) == 0 {
		t.Fatal("a refused attach with external context must still produce a reportable finding")
	}
}

func TestMemContractsIsSortedAndNonEmpty(t *testing.T) {
	c := memContracts()
	if len(c) < 20 {
		t.Fatalf("contract set looks truncated: %d", len(c))
	}
	for i := 1; i < len(c); i++ {
		if c[i-1] >= c[i] {
			t.Fatalf("memContracts must be sorted and unique around %q", c[i])
		}
	}
}

// A tunnel is an alternative to command execution, not a lesser form of it. Suo5 relays TCP over
// HTTP and never executes anything, so requiring `exec` scored it a full tier below every command
// shell on the identical mechanism -- and left the report naming the injector rather than the class
// actually wired into the request path.
func TestTunnelIsActionGrade(t *testing.T) {
	if !actionCapable([]string{"tunnel"}) {
		t.Error("tunnel alone must be action-grade: a proxy shell executes nothing")
	}
	if !actionCapable([]string{"exec"}) {
		t.Error("exec must remain action-grade")
	}
	if !actionCapable([]string{"reflect", "tunnel"}) {
		t.Error("tunnel must count regardless of what else is present")
	}
}

// The gate exists to keep ordinary framework code out. Loader, reflection and crypto references are
// everywhere in a servlet container -- accepting them is what put Tomcat's own DefaultServlet at
// likely-malicious. `relay` is in this list deliberately: even if socket APIs are ever surfaced as
// an informational capability, they must never escalate on their own.
func TestNonActionCapabilitiesDoNotEscalate(t *testing.T) {
	for _, c := range []string{"loader", "reflect", "crypto", "script", "jndi", "relay"} {
		if actionCapable([]string{c}) {
			t.Errorf("%q must not be action-grade", c)
		}
	}
	if actionCapable([]string{"loader", "reflect", "crypto"}) {
		t.Error("a pile of non-action capabilities is still not action-grade")
	}
	if actionCapable(nil) {
		t.Error("no capabilities cannot be action-grade")
	}
}

// ---------------------------------------------------------------- out-of-contract code source
//
// The CISA AR25-261A shape: a class whose jar really exists and really contains it, so verification
// says Corroborated, but the jar is somewhere the container never declared. Before these arms the
// ladder's `default: continue` dropped it and the corpus cell produced no finding at any tier.

func TestOutOfContractWithCapabilityReachesLikelyMalicious(t *testing.T) {
	f := fuse(target(), []classResult{{
		Claim: jvmprov.Claim{ClassName: "com.shellsight.lab.unreg.ResidentExec",
			CodeSourceJar: "/tmp/ssunreg.jar", OutOfContract: true,
			DeclaredRepos: "4 declared repositor(ies)"},
		Verification: jvmprov.Verification{Status: jvmprov.Corroborated},
		Capabilities: []string{"exec"},
	}}, nil)
	if len(f) != 1 || f[0].Tier != finding.TierLikely {
		t.Fatalf("an action-capable class loaded from an undeclared location is the CISA shape, got %+v", f)
	}
	if f[0].Detection.KnowledgeRef != "kb:java-mem/codesource-out-of-contract" {
		t.Errorf("wrong pivot key: %q", f[0].Detection.KnowledgeRef)
	}
	// The report is only actionable if it names the file to go and look at.
	if !strings.Contains(f[0].Detection.Evidence, "/tmp/ssunreg.jar") {
		t.Errorf("evidence must name the offending code source, got %q", f[0].Detection.Evidence)
	}
}

func TestOutOfContractOnPipelineReachesLikelyMalicious(t *testing.T) {
	f := fuse(target(), []classResult{{
		Claim: jvmprov.Claim{ClassName: "com.evil.WanListener", CodeSourceJar: "/tmp/web-install.jar",
			OutOfContract: true, Contracts: []string{"javax.servlet.Filter"}},
		Verification: jvmprov.Verification{Status: jvmprov.Corroborated},
	}}, nil)
	if len(f) != 1 || f[0].Tier != finding.TierLikely || f[0].Score != 90 {
		t.Fatalf("wired + undeclared location is the AR25-261A listener, got %+v", f)
	}
}

// The load-bearing false-positive guard. A framework that extracts a WAR into java.io.tmpdir puts
// ordinary classes outside the declared set; they carry no action-grade capability and are wired to
// nothing, and they must NOT reach an operator's alert queue.
func TestOutOfContractAloneIsSuspiciousNotAnAlert(t *testing.T) {
	f := fuse(target(), []classResult{{
		Claim: jvmprov.Claim{ClassName: "com.framework.Extracted",
			CodeSourceJar: "/tmp/tomcat.9401/webapp.jar", OutOfContract: true},
		Verification: jvmprov.Verification{Status: jvmprov.Corroborated},
	}}, nil)
	if len(f) != 1 {
		t.Fatalf("want 1 finding, got %d", len(f))
	}
	if f[0].Tier != finding.TierSuspicious {
		t.Fatalf("out-of-contract with no capability and no contract must stay below the alert tier, got %v", f[0].Tier)
	}
}

// The other half of that guard: a corroborated class from a DECLARED location stays silent. If this
// ever fires, the check has stopped discriminating and is just reporting every jar-backed class.
func TestCorroboratedInContractStaysSilent(t *testing.T) {
	f := fuse(target(), []classResult{{
		Claim: jvmprov.Claim{ClassName: "org.apache.catalina.servlets.DefaultServlet",
			CodeSourceJar: "/usr/local/tomcat/lib/catalina.jar", OutOfContract: false,
			Contracts: []string{"javax.servlet.Servlet"}},
		Verification: jvmprov.Verification{Status: jvmprov.Corroborated},
		Capabilities: []string{"exec"},
	}}, nil)
	if len(f) != 0 {
		t.Fatalf("a corroborated class from a declared location must produce nothing, got %+v", f)
	}
}

// A JASPER-GENERATED JSP PAGE IS NOT A MEMSHELL. Measured 2026-09-03: a benign Jetty petclinic
// produced 5 findings at score 90 on its own compiled JSP pages, because Jasper writes them to a
// scratch directory under java.io.tmpdir that no Jetty deployment declares. The agent had ALREADY
// verified them as generated -- the ladder simply never read Claim.VerifiedGenerated, whose only
// other reader in the tree was, until this change, nobody.
//
// The equivalent Tomcat cell (jspheavy, JSPs by construction) measures 0, because catalina.base
// declares Jasper's work directory. This test pins the two containers to the same answer.
func TestGeneratedClassOutOfContractIsNotAnAlert(t *testing.T) {
	f := fuse(target(), []classResult{{
		Claim: jvmprov.Claim{ClassName: "org.apache.jsp.WEB_002dINF.jsp.welcome_jsp",
			CodeSourceJar:     "/tmp/jetty-0_0_0_0-8080-ROOT-_-any-1377/jsp/",
			OutOfContract:     true,
			VerifiedGenerated: true,
			Contracts:         []string{"javax.servlet.Servlet"},
			DeclaredRepos:     "3 declared repositor(ies)"},
		Verification: jvmprov.Verification{Status: jvmprov.Corroborated},
	}}, nil)
	if len(f) != 0 {
		t.Fatalf("a verified-generated class out of contract must not be reported, got %+v", f)
	}
}

// THE OTHER DIRECTION, and the one that keeps this from being a hole: generated-ness suppresses the
// LOCATION argument, never a capability. A Jasper-generated JSP that can execute commands is a JSP
// webshell; the disk view is its primary catcher but must not be its only one.
func TestGeneratedClassWithCapabilityStillAlerts(t *testing.T) {
	f := fuse(target(), []classResult{{
		Claim: jvmprov.Claim{ClassName: "org.apache.jsp.evil_jsp",
			CodeSourceJar: "/tmp/jetty-0_0_0_0-8080-ROOT-_-any-1377/jsp/",
			OutOfContract: true, VerifiedGenerated: true,
			Contracts: []string{"javax.servlet.Servlet"}},
		Verification: jvmprov.Verification{Status: jvmprov.Corroborated},
		Capabilities: []string{"exec"},
	}}, nil)
	if len(f) != 1 || f[0].Tier != finding.TierLikely || f[0].Score != 80 {
		t.Fatalf("an action-capable generated class must still alert, got %+v", f)
	}
}

// Generated-ness must not leak into the arms that do not reason about LOCATION. A fileless class
// whose loader contradicts the filesystem is a different argument entirely.
func TestGeneratedFlagDoesNotSuppressSpoofedOrigin(t *testing.T) {
	f := fuse(target(), []classResult{{
		Claim: jvmprov.Claim{ClassName: "org.apache.jsp.spoofer_jsp",
			CodeSourceJar: "/opt/app/lib/real.jar", VerifiedGenerated: true,
			Contracts: []string{"javax.servlet.Filter"}},
		Verification: jvmprov.Verification{Status: jvmprov.Spoofed},
	}}, nil)
	if len(f) != 1 || f[0].Tier != finding.TierLikely {
		t.Fatalf("a spoofed origin is not excused by generated-ness, got %+v", f)
	}
}
