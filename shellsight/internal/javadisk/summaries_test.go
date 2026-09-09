package javadisk

import (
	"context"
	"strings"
	"testing"
)

func requireSummaryFinding(t *testing.T, fixture string) *Finding {
	t.Helper()
	result := analyzeClasses("app.jar", fixtureArtifact(t, fixture), DefaultOptions())
	finding := findingByRule(result.Findings, "javadisk:class-request-exec")
	if finding == nil || finding.Score != 75 {
		t.Fatalf("fixture=%s result=%+v", fixture, result)
	}
	return finding
}

func TestSummaryMapsArgumentToReturn(t *testing.T) {
	finding := requireSummaryFinding(t, "request_helper_return")
	if !strings.Contains(finding.Evidence, "Identity.pass") {
		t.Fatalf("finding=%+v", finding)
	}
}

func TestSummaryFindsRequestThroughHelper(t *testing.T) {
	result := analyzeClasses("app.jar", fixtureArtifact(t, "request_exec_helper"), DefaultOptions())
	finding := findingByRule(result.Findings, "javadisk:class-request-exec")
	if finding == nil || finding.Score != 75 || !strings.Contains(finding.Evidence, "Helper") {
		t.Fatalf("result=%+v", result)
	}
}

func TestSummaryMapsHelperCreatedRequestSourceToReturn(t *testing.T) {
	finding := requireSummaryFinding(t, "request_helper_source")
	if !strings.Contains(finding.Evidence, "Source.read") {
		t.Fatalf("finding=%+v", finding)
	}
}

func TestSummaryFindsHelperExecSink(t *testing.T) {
	finding := requireSummaryFinding(t, "helper_exec_sink")
	if !strings.Contains(finding.Evidence, "Sink.exec") {
		t.Fatalf("finding=%+v", finding)
	}
}

func TestSummaryConvergesAcrossThreeMethodChain(t *testing.T) {
	finding := requireSummaryFinding(t, "summary_three_method_chain")
	if !strings.Contains(finding.Evidence, "Middle.pass") && !strings.Contains(finding.Evidence, "Sink.exec") {
		t.Fatalf("finding=%+v", finding)
	}
}

func TestSummaryRecursionConvergesDeterministically(t *testing.T) {
	first := analyzeClasses("app.jar", fixtureArtifact(t, "summary_recursion"), DefaultOptions())
	second := analyzeClasses("app.jar", fixtureArtifact(t, "summary_recursion"), DefaultOptions())
	finding := findingByRule(first.Findings, "javadisk:class-request-exec")
	if finding == nil || finding.Score != 75 || len(first.Diagnostics) != len(second.Diagnostics) ||
		len(first.Findings) != len(second.Findings) {
		t.Fatalf("first=%+v second=%+v", first, second)
	}
}

func TestSummaryResolvesInterfaceDispatchAcrossLocalImplementations(t *testing.T) {
	finding := requireSummaryFinding(t, "summary_interface_dispatch")
	if !strings.Contains(finding.Evidence, "Runner.run") {
		t.Fatalf("finding=%+v", finding)
	}
}

func TestSummaryResolvesLambdaSAMToSameArtifactImplementation(t *testing.T) {
	finding := requireSummaryFinding(t, "summary_lambda_local")
	if !strings.Contains(finding.Evidence, "Runnable.run") {
		t.Fatalf("finding=%+v", finding)
	}
}

func TestSummaryRejectsExternalAndAmbiguousLambdaNearNeighbors(t *testing.T) {
	for _, fixture := range []string{"summary_lambda_external", "summary_lambda_ambiguous"} {
		t.Run(fixture, func(t *testing.T) {
			result := analyzeClasses("app.jar", fixtureArtifact(t, fixture), DefaultOptions())
			if findingByRule(result.Findings, "javadisk:class-request-exec") != nil {
				t.Fatalf("fixture=%s result=%+v", fixture, result)
			}
			if fixture == "summary_lambda_ambiguous" && !hasDiagnosticCode(result.Diagnostics, diagClassDuplicate) {
				t.Fatalf("missing duplicate diagnostic: %+v", result)
			}
		})
	}
}

func TestSummaryExternalReturnTaintStaysConservativeAndUnproven(t *testing.T) {
	result := analyzeClasses("app.jar", fixtureArtifact(t, "summary_external_return"), DefaultOptions())
	if findingByRule(result.Findings, "javadisk:class-request-exec") != nil {
		t.Fatalf("external call created proven flow: %+v", result)
	}
}

func TestSummaryDuplicateBinaryNamesKeepDirectAnalysisButBlockLocalResolution(t *testing.T) {
	result := analyzeClasses("app.jar", fixtureArtifact(t, "summary_duplicate_binary_name"), DefaultOptions())
	finding := findingByRule(result.Findings, "javadisk:class-request-exec")
	if finding == nil || finding.Score != 85 || !strings.Contains(finding.Evidence, "Duplicate") ||
		!hasDiagnosticCode(result.Diagnostics, diagClassDuplicate) {
		t.Fatalf("result=%+v", result)
	}
}

func TestSummaryCallTargetCapRemainsConservative(t *testing.T) {
	opts := DefaultOptions()
	opts.Limits.MaxCallTargets = 1
	result := analyzeClasses("app.jar", fixtureArtifact(t, "summary_target_cap"), opts)
	if findingByRule(result.Findings, "javadisk:class-request-exec") != nil ||
		!hasDiagnosticCode(result.Diagnostics, diagAnalysisBudget) {
		t.Fatalf("result=%+v", result)
	}
}

func TestSummaryRoundCapStopsBeforeUnprovenChainConverges(t *testing.T) {
	opts := DefaultOptions()
	opts.Limits.MaxSummaryRounds = 1
	result := analyzeClasses("app.jar", fixtureArtifact(t, "summary_round_cap"), opts)
	if findingByRule(result.Findings, "javadisk:class-request-exec") != nil ||
		!hasDiagnosticCode(result.Diagnostics, diagAnalysisBudget) {
		t.Fatalf("result=%+v", result)
	}
}

func TestAnalyzeClassesPrioritizesServerFacingCode(t *testing.T) {
	opts := DefaultOptions()
	opts.Limits.MaxArtifactInstructions = 40
	classes := fixtureArtifact(t, "large_benign_before_request_exec")
	result := analyzeClasses("app.war", classes, opts)
	if findingByRule(result.Findings, "javadisk:class-request-exec") == nil {
		t.Fatalf("server-facing class was starved: %+v", result)
	}
}

func TestSummaryReviewUnknownExternalReturnDoesNotPublishProvenTaint(t *testing.T) {
	result := analyzeClasses("app.jar", fixtureArtifact(t, "summary_review_external_unproven_return"), DefaultOptions())
	if finding := findingByRule(result.Findings, "javadisk:class-request-exec"); finding != nil {
		t.Fatalf("unknown external return became proven summary evidence: %+v", result)
	}
}

func TestSummaryReviewInvokeSpecialUsesExactTarget(t *testing.T) {
	result := analyzeClasses("app.jar", fixtureArtifact(t, "summary_review_invokespecial_exact"), DefaultOptions())
	if finding := findingByRule(result.Findings, "javadisk:class-request-exec"); finding != nil {
		t.Fatalf("invokespecial consumed a virtual override summary: %+v", result)
	}
}

func TestSummaryReviewDirectFlowMixedWithUntaintedSummaryStaysDirect(t *testing.T) {
	result := analyzeClasses("app.jar", fixtureArtifact(t, "summary_review_direct_mixed_untainted_summary"), DefaultOptions())
	finding := findingByRule(result.Findings, "javadisk:class-request-exec")
	if finding == nil || finding.Score != 85 {
		t.Fatalf("direct same-method flow was downgraded: %+v", result)
	}
}

func TestSummaryReviewTargetCapStopsCandidateCountingAtOverflow(t *testing.T) {
	opts := DefaultOptions()
	opts.Limits.MaxCallTargets = 1
	result := analyzeClasses("app.jar", fixtureArtifact(t, "summary_target_cap"), opts)
	for _, diagnostic := range result.Diagnostics {
		if diagnostic.Code == diagAnalysisBudget && strings.Contains(diagnostic.Detail, "more than 1 local call targets") {
			return
		}
	}
	t.Fatalf("missing bounded target-overflow diagnostic: %+v", result.Diagnostics)
}

func TestSummaryReviewLambdaManyCapturedArgumentsPreservesFlow(t *testing.T) {
	opts := DefaultOptions()
	opts.Limits.MaxCallTargets = 1
	result := analyzeClasses("app.jar", fixtureArtifact(t, "summary_review_lambda_many_captures"), opts)
	finding := findingByRule(result.Findings, "javadisk:class-request-exec")
	if finding == nil || finding.Score != 75 {
		t.Fatalf("JVM-legal lambda captures were truncated by target cap: %+v", result)
	}
}

func TestSummaryReviewTargetCapReleasesCandidateStorage(t *testing.T) {
	set := newDispatchCandidates()
	alias := methodKey{Owner: "fixture/Base", Name: "run", Descriptor: "()V"}
	set.add(alias, methodKey{Owner: "fixture/First", Name: "run", Descriptor: "()V"}, emptyMethodSummary(), 1)
	set.add(alias, methodKey{Owner: "fixture/Second", Name: "run", Descriptor: "()V"}, emptyMethodSummary(), 1)
	set.add(alias, methodKey{Owner: "fixture/Third", Name: "run", Descriptor: "()V"}, emptyMethodSummary(), 1)
	if !set.capped[alias] {
		t.Fatal("dispatch alias was not capped at the first overflow")
	}
	if _, retained := set.targets[alias]; retained {
		t.Fatal("over-cap dispatch alias retained candidate storage")
	}
}

func TestSummaryReviewNilClassDiagnosticsArePathSorted(t *testing.T) {
	prepared := prepareArtifact(context.Background(), "app.jar", map[string]*classModel{
		"z/Bad.class": nil,
		"a/Bad.class": nil,
	}, DefaultOptions())
	if len(prepared.Diagnostics) != 2 || prepared.Diagnostics[0].Artifact != "a/Bad.class" || prepared.Diagnostics[1].Artifact != "z/Bad.class" {
		t.Fatalf("diagnostics are not deterministic: %+v", prepared.Diagnostics)
	}
}

func TestSummarySecondReviewSyntheticMarkerCannotCollideWithRealMethod(t *testing.T) {
	result := analyzeClasses("app.jar", fixtureArtifact(t, "summary_second_review_marker_collision"), DefaultOptions())
	if finding := findingByRule(result.Findings, "javadisk:class-request-exec"); finding != nil {
		t.Fatalf("synthetic virtual key replaced a hostile exact method summary: %+v", result)
	}
}

func TestSummarySecondReviewReturnedArrayElementRemainsSummaryOnly(t *testing.T) {
	result := analyzeClasses("app.jar", fixtureArtifact(t, "summary_second_review_returned_array"), DefaultOptions())
	finding := findingByRule(result.Findings, "javadisk:class-request-exec")
	if finding == nil || finding.Score != 75 {
		t.Fatalf("summary-returned array element lost summary provenance: %+v", result)
	}
}

func TestSummarySecondReviewArrayElementCarriesArgumentFlow(t *testing.T) {
	result := analyzeClasses("app.jar", fixtureArtifact(t, "summary_second_review_array_argument"), DefaultOptions())
	finding := findingByRule(result.Findings, "javadisk:class-request-exec")
	if finding == nil || finding.Score != 75 {
		t.Fatalf("array element load did not publish argument-to-return flow: %+v", result)
	}
}
