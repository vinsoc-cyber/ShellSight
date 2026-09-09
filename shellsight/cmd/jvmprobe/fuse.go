package main

import (
	"fmt"
	"sort"

	"shellsight/internal/finding"
	"shellsight/internal/jvmprov"
	"shellsight/internal/jvmtriage"
)

// classResult is one class after BOTH vantage points have spoken: what the JVM claimed, and what
// the filesystem says independently.
type classResult struct {
	Claim        jvmprov.Claim
	Verification jvmprov.Verification
	Family       jvmprov.Family
	Capabilities []string
}

// pipelineContracts mirrors Contracts.PIPELINE in the agent jar and
// Discriminator.PIPELINE_CONTRACTS in the probe jar. Three artifacts with three classpaths cannot
// share one literal; ContractParityTests pins the two Java copies, and parity_test.go pins this one
// against the agent's source.
var pipelineContracts = map[string]bool{
	"javax.servlet.Filter": true, "javax.servlet.Servlet": true,
	"javax.servlet.http.HttpServlet": true, "javax.servlet.ServletRequestListener": true,
	"javax.servlet.http.HttpSessionListener": true, "javax.servlet.ServletContextListener": true,
	"jakarta.servlet.Filter": true, "jakarta.servlet.Servlet": true,
	"jakarta.servlet.http.HttpServlet": true, "jakarta.servlet.ServletRequestListener": true,
	"jakarta.servlet.http.HttpSessionListener": true, "jakarta.servlet.ServletContextListener": true,
	"org.apache.catalina.Valve": true, "org.apache.catalina.valves.ValveBase": true,
	"org.apache.catalina.Container": true, "org.apache.catalina.LifecycleListener": true,
	"org.apache.coyote.Adapter": true,
	"org.springframework.web.servlet.HandlerInterceptor":                true,
	"org.springframework.web.servlet.handler.HandlerInterceptorAdapter": true,
	// Spring's legacy handler interface, and what the generator's ControllerHandler shells actually
	// implement. Unlike the interceptor case this one was genuinely absent -- no transitive closure
	// could have found it, because nothing in this set is a supertype of it.
	"org.springframework.web.servlet.mvc.Controller": true,
	"org.springframework.web.filter.OncePerRequestFilter":               true,
	"com.opensymphony.xwork2.interceptor.Interceptor":                   true,
	"org.apache.struts2.interceptor.AbstractInterceptor":                true,
	"org.eclipse.jetty.server.Handler":                                 true,
	"org.eclipse.jetty.server.handler.AbstractHandler":                  true,
	"io.undertow.server.HttpHandler":                                   true,
	"javax.websocket.Endpoint": true, "jakarta.websocket.Endpoint": true,
	"javax.websocket.server.ServerEndpointConfig": true,
	"java.lang.instrument.ClassFileTransformer":   true,
}

func isPipelineContract(name string) bool { return pipelineContracts[name] }

// memContracts returns the contract set as a sorted slice, for staging to the agent so its scorer
// and this one cannot be configured differently.
func memContracts() []string {
	out := make([]string, 0, len(pipelineContracts))
	for c := range pipelineContracts {
		out = append(out, c)
	}
	sort.Strings(out)
	return out
}

// actionCapable reports whether the class can do something a webshell is FOR -- run a command, or
// tunnel traffic.
//
// Loader, reflection and crypto references are NOT action-grade: ordinary framework code is full of
// them. Treating them as corroboration is what put Tomcat's own DefaultServlet at likely-malicious
// in an earlier measurement.
//
// `tunnel` joins `exec` because the two are alternatives, not degrees: Suo5 is a TCP-over-HTTP
// proxy that never executes anything, and an exec-only test scored it a full tier below every
// command shell on the identical mechanism. `relay` is deliberately NOT here, and is not even a
// counted capability -- see the note in jvmprov.capabilityNeedles.
func actionCapable(caps []string) bool {
	for _, c := range caps {
		if c == "exec" || c == "tunnel" {
			return true
		}
	}
	return false
}

// fuse combines in-JVM claims with independent verification and external signals.
//
// The tier ladder, and why each rung sits where it does:
//
//	likely-malicious  a pipeline-wired class whose provenance is DISPROVEN from outside, or a
//	                  fileless pipeline-wired class. BOTH halves are required: disproven provenance
//	                  alone could be a broken deployment, and pipeline wiring alone is every
//	                  framework filter in existence.
//	suspicious        one half only, or external evidence.
//	(no finding)      corroborated provenance with nothing else against it.
//
// A bytecode difference on a CORROBORATED class is deliberately NOT malicious unless it also
// carries an execution capability. That is what an APM agent does all day, and it is the single
// largest false-positive risk in this view.
func fuse(t procTarget, classes []classResult, external []jvmtriage.Signal) []finding.Finding {
	var out []finding.Finding

	for _, cr := range classes {
		pipelineWired := false
		for _, c := range cr.Claim.Contracts {
			if isPipelineContract(c) {
				pipelineWired = true
				break
			}
		}

		var tier finding.Tier
		var score int
		var why, ref string

		switch {
		case cr.Verification.Status == jvmprov.Spoofed && pipelineWired:
			tier, score, ref = finding.TierLikely, 95, "kb:java-mem/codesource-spoofed"
			why = "a class wired into the request pipeline whose claimed on-disk origin is contradicted by the filesystem"
		case cr.Verification.Status == jvmprov.Spoofed && actionCapable(cr.Capabilities):
			tier, score, ref = finding.TierLikely, 90, "kb:java-mem/codesource-spoofed"
			why = "a class with execution capability whose claimed on-disk origin is contradicted by the filesystem"
		case cr.Verification.Status == jvmprov.Spoofed:
			tier, score, ref = finding.TierSuspicious, 60, "kb:java-mem/codesource-spoofed"
			why = "claimed on-disk origin contradicted by the filesystem, but the class is neither on the request path nor execution-capable"
		case cr.Verification.Status == jvmprov.DiskAbsentClaim && pipelineWired:
			tier, score, ref = finding.TierLikely, 95, "kb:java-mem/fileless-pipeline-class"
			why = "a fileless class wired into the request pipeline"
		case cr.Verification.Status == jvmprov.DiskAbsentClaim && actionCapable(cr.Capabilities):
			// One action-grade capability is enough on a class the filesystem does not back. This is
			// stated explicitly rather than left to the >=2 count below: Suo5 happens to also carry
			// a reflection reference, so the count would have escalated it by accident, and a
			// variant without that reference would have silently dropped back to suspicious.
			tier, score, ref = finding.TierLikely, 80, "kb:java-mem/fileless-capable-class"
			why = "a fileless class that can execute commands or tunnel traffic, with no benign provenance"
		case cr.Verification.Status == jvmprov.DiskAbsentClaim && len(cr.Capabilities) >= 2:
			// The ProxyValve / Agent-payload shape: fileless, no contract, but capability-rich.
			tier, score, ref = finding.TierLikely, 80, "kb:java-mem/fileless-capable-class"
			why = "a fileless class with multiple capability indicators and no benign provenance"
		case cr.Verification.Status == jvmprov.DiskAbsentClaim && len(cr.Capabilities) == 1:
			tier, score, ref = finding.TierSuspicious, 55, "kb:java-mem/fileless-class"
			why = "a fileless class with a single capability indicator; warrants analyst review"
		case cr.Verification.Status == jvmprov.DiskAbsentClaim:
			tier, score, ref = finding.TierSuspicious, 50, "kb:java-mem/fileless-class"
			why = "a fileless class with no benign provenance and no strong malicious signal"
		case cr.Verification.Status == jvmprov.Unverifiable && pipelineWired:
			tier, score, ref = finding.TierSuspicious, 50, "kb:java-mem/unverifiable-origin"
			why = "a pipeline class whose origin could not be verified from outside the JVM"

		// OUT-OF-CONTRACT CODE SOURCE. These sit below the Spoofed and DiskAbsent arms on purpose:
		// the class's claim about itself is TRUE -- the file exists and contains it -- so the only
		// thing wrong is WHERE it came from. Verification cannot see that, because a location the
		// container never declared is still a real location.
		//
		// Laddered exactly like Spoofed (60 alone, 90 with capability), for the same reason and with
		// one difference that matters: the predicted false positive is a framework that extracts a
		// WAR into java.io.tmpdir, which is benign and carries no action-grade capability. Capping
		// the no-capability case at `suspicious` is what keeps that out of an operator's alert queue.
		// A RUNTIME GENERATOR'S OUTPUT LOCATION IS NOT A DECLARED REPOSITORY, BY CONSTRUCTION, so
		// for a class the agent structurally verified as generator output, "out of contract" is a
		// restatement of how the generator works and says nothing about malice. The agent already
		// applies exactly this reasoning to the fileless routes (Suspicion.java:57 and :63,
		// `&& !in.verifiedGenerated`) -- but a generated class can reach candidacy by a THIRD route,
		// pipeline contract, and this ladder used to escalate it without ever asking.
		//
		// Measured 2026-09-03 (docs/measurements/2026-09-03-jetty-jasper-fp/): a benign Jetty
		// petclinic produced 5 findings at score 90 on its own Jasper-compiled JSP pages. Those
		// classes were ALREADY verified-generated -- the agent computes the fact, claim.go parses it
		// into Claim.VerifiedGenerated, and NOTHING IN THE TREE READ IT. The signal crossed the
		// boundary and died there, which is why a correct fingerprint produced a false positive.
		//
		// actionCapable below is deliberately NOT gated on this. A Jasper-generated JSP that can
		// execute commands or tunnel traffic is a JSP webshell; the disk view is its primary catcher
		// but must not be its only one. That is affordable because it was measured rather than
		// assumed: the five benign pages carry no capabilities at all, so keeping this arm live
		// costs nothing in false positives. A generated, out-of-contract, capability-free class now
		// produces no finding -- which is what the tool already does on Tomcat, where catalina.base
		// declares Jasper's work directory and the jspheavy cell measures 0.
		case cr.Claim.OutOfContract && pipelineWired && !cr.Claim.VerifiedGenerated:
			tier, score, ref = finding.TierLikely, 90, "kb:java-mem/codesource-out-of-contract"
			why = "a class wired into the request pipeline whose code came from outside every repository the container declares"
		case cr.Claim.OutOfContract && actionCapable(cr.Capabilities):
			tier, score, ref = finding.TierLikely, 80, "kb:java-mem/codesource-out-of-contract"
			why = "a class that can execute commands or tunnel traffic, loaded from outside every repository the container declares"
		case cr.Claim.OutOfContract && !cr.Claim.VerifiedGenerated:
			tier, score, ref = finding.TierSuspicious, 55, "kb:java-mem/codesource-out-of-contract"
			why = "code loaded from outside every repository the container declares, but the class is neither on the request path nor action-capable"

		default:
			continue // corroborated from a declared location, or nothing worth reporting
		}

		// Name the offending path and what it was judged against. Without this the report says a
		// class came from "outside every declared repository" and leaves the responder to guess
		// which file to go and look at -- and this signal is only actionable if they can.
		if cr.Claim.OutOfContract {
			why += fmt.Sprintf(" — code source %s, measured against %s",
				cr.Claim.CodeSourceJar, cr.Claim.DeclaredRepos)
		}

		if cr.Verification.LoaderContradiction {
			score += 5
			ref = "kb:java-mem/loader-contradiction"
			why += "; the JVM's own ClassLoader supplied bytes the filesystem does not back"
		}

		f := finding.Finding{
			SchemaVersion: finding.SchemaVersion,
			ID:            fmt.Sprintf("jvm-%d-%s", t.PID, cr.Claim.ClassName),
			View:          "java-mem",
			Target: finding.Target{
				Kind:    "process",
				Process: &finding.Process{PID: t.PID, Name: "java"},
			},
			Artifact: finding.Artifact{
				Kind:     "java-memory-class",
				Identity: cr.Claim.ClassName,
				Location: fmt.Sprintf("in-memory (pid %d)", t.PID),
			},
			Detection: finding.Detection{
				Basis:        "structural-heuristic",
				KnowledgeRef: ref,
				Evidence:     why + " — " + cr.Verification.Detail,
			},
			Score: score,
			Tier:  tier,
			Context: map[string]string{
				"suspicion": fmt.Sprint(cr.Claim.Suspicion),
				"vantage":   "internal+external",
				"verified":  cr.Verification.Status.String(),
			},
		}
		if cr.Family.Name != "" {
			// Classification.Family is a *string: it marshals to JSON null when absent, which is
			// what keeps the schema stable for consumers.
			fam := cr.Family.Name
			f.Classification.Family = &fam
			f.Classification.Confidence = cr.Family.Confidence
			src := "memory-constant-pool"
			f.Classification.Source = &src
			f.Context["family_evidence"] = cr.Family.Evidence
		}
		// Capability is additive: it tells the responder what the thing can DO, which is the
		// question an incident turns on. It never changes the tier by itself.
		f.Classification.Capability = cr.Capabilities
		out = append(out, f)
	}

	// External signals are reported whether or not the attach succeeded. When it failed they are
	// the ONLY evidence, and they must reach the operator rather than being collapsed into a bare
	// "unknown".
	out = append(out, externalFindings(t, external)...)
	return out
}
