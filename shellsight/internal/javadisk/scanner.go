package javadisk

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
)

type classParser func([]byte, Limits) (*classModel, error)

type semanticCandidate struct {
	Path   string
	Class  *classModel
	Method *methodModel
	Result sinkResult
}

func AnalyzeArtifact(path string, data []byte, opts Options) Result {
	return AnalyzeArtifactContext(context.Background(), path, data, opts)
}

func AnalyzeArtifactContext(ctx context.Context, path string, data []byte, opts Options) Result {
	return analyzeArtifactContextWithParser(ctx, path, data, opts, parseClass)
}

func analyzeArtifactContextWithParser(
	ctx context.Context,
	path string,
	data []byte,
	opts Options,
	parser classParser,
) Result {
	if ctx == nil {
		ctx = context.Background()
	}
	opts = normalizeOptions(opts)
	if ctx.Err() != nil {
		return diagnosticResult(path, diagCancelled, "analysis cancelled")
	}

	extension := strings.ToLower(filepath.Ext(path))
	if isArchiveExtension(extension) {
		return analyzeArchiveBytes(ctx, path, data, opts, parser)
	}
	isSource := isJavaSourceExtension(extension) || isJSPSourceExtension(extension)
	if (isSource || extension == ".class") && int64(len(data)) > opts.Limits.MaxArtifactBytes {
		return diagnosticResult(path, diagAnalysisBudget, "artifact exceeds byte limit")
	}
	if isSource {
		findings := Analyze(path, data)
		setArtifactPaths(findings, path)
		return Result{Findings: findings}
	}
	if extension != ".class" {
		return Result{}
	}

	class, diagnostic := parseClassIsolatedWith(path, data, opts.Limits, parser)
	if diagnostic != nil {
		return Result{Diagnostics: []Diagnostic{*diagnostic}}
	}
	if ctx.Err() != nil {
		return diagnosticResult(path, diagCancelled, "analysis cancelled")
	}
	result := analyzeClassWithFlowsContext(ctx, path, class, opts)
	setArtifactPaths(result.Findings, path)
	return result
}

func analyzeClassWithFlowsContext(ctx context.Context, path string, class *classModel, opts Options) Result {
	return analyzeClassesContext(ctx, path, map[string]*classModel{path: class}, opts)
}

func analyzeClasses(logicalRoot string, classes map[string]*classModel, opts Options) Result {
	return analyzeClassesContext(context.Background(), logicalRoot, classes, opts)
}

func analyzeClassesContext(ctx context.Context, logicalRoot string, classes map[string]*classModel, opts Options) Result {
	if ctx == nil {
		ctx = context.Background()
	}
	opts = normalizeOptions(opts)
	if ctx.Err() != nil {
		return diagnosticResult(logicalRoot, diagCancelled, "analysis cancelled")
	}
	prepared := prepareArtifact(ctx, logicalRoot, classes, opts)
	diagnostics := append([]Diagnostic(nil), prepared.Diagnostics...)
	evidenceByClass := make(map[string]map[string]string)
	semanticValid := make(map[string]bool)
	for _, class := range prepared.Classes {
		evidenceByClass[class.Path] = make(map[string]string, len(structuralRules))
		semanticValid[class.Path] = !class.VerifierInvalid
	}
	var candidates []semanticCandidate
	cancelled := hasDiagnosticCode(diagnostics, diagCancelled)
	visitMethods := func(summaries summarySet, structural, reportErrors bool) {
		for _, method := range prepared.Methods {
			if ctx.Err() != nil {
				if !cancelled {
					diagnostics = append(diagnostics, newDiagnostic(logicalRoot, diagCancelled, "analysis cancelled"))
					cancelled = true
				}
				break
			}
			if structural {
				features, extractionCancelled := extractMethodFeaturesContext(ctx, method.Class, method.CFG)
				if extractionCancelled {
					if !cancelled {
						diagnostics = append(diagnostics, newDiagnostic(logicalRoot, diagCancelled, "analysis cancelled"))
						cancelled = true
					}
					break
				}
				recordStructuralEvidence(evidenceByClass[method.Path], method.Class, method.Method, features, serverContextEvidence(method.Class))
			}
			activeSummaries := summaries
			if prepared.DuplicateNames[method.Class.Name] {
				activeSummaries = summarySet{}
			}
			analysis := analyzeMethodContext(ctx, method.Class, method.Method, method.CFG, opts, activeSummaries)
			if analysis.VerifierInvalid {
				semanticValid[method.Path] = false
			}
			switch {
			case analysis.Cancelled:
				if !cancelled {
					diagnostics = append(diagnostics, newDiagnostic(logicalRoot, diagCancelled, "analysis cancelled"))
					cancelled = true
				}
			case analysis.BudgetExhausted != "":
				if reportErrors {
					diagnostics = append(diagnostics, methodDiagnostic(method.Path, diagAnalysisBudget, method.Class,
						method.Method, "abstract interpretation budget exhausted", errors.New(analysis.BudgetExhausted)))
				}
			case analysis.Unsupported != "":
				if reportErrors {
					diagnostics = append(diagnostics, methodDiagnostic(method.Path, diagBytecodeUnsupported, method.Class,
						method.Method, "abstract interpretation stopped", errors.New(analysis.Unsupported)))
				}
			default:
				for _, sink := range analysis.SinkResults {
					candidates = append(candidates, semanticCandidate{Path: method.Path, Class: method.Class, Method: method.Method, Result: sink})
				}
			}
			if cancelled {
				break
			}
		}
	}
	visitMethods(summarySet{}, true, true)
	if !cancelled {
		summaries, summaryDiagnostics := buildPreparedSummaries(ctx, prepared, opts)
		diagnostics = append(diagnostics, summaryDiagnostics...)
		cancelled = hasDiagnosticCode(summaryDiagnostics, diagCancelled)
		if !cancelled {
			visitMethods(summaries, false, false)
		}
	}

	var findings []Finding
	findingLimitHit := false
	for _, class := range prepared.Classes {
		for _, rule := range structuralRules {
			evidence := evidenceByClass[class.Path][rule.Rule]
			if evidence == "" {
				continue
			}
			if len(findings) >= opts.Limits.MaxFindings {
				findingLimitHit = true
				continue
			}
			findings = append(findings, Finding{
				Score: structuralScore, Family: rule.Family, Rule: rule.Rule,
				Evidence:     boundedEvidenceComponent("artifact="+class.Path+" "+evidence, maxDiagnosticTextBytes),
				ArtifactPath: class.Path,
			})
		}
	}
	selected := make(map[sinkKind]semanticCandidate)
	for _, candidate := range candidates {
		if !semanticValid[candidate.Path] && candidate.Result.Score == 85 {
			continue
		}
		existing, ok := selected[candidate.Result.Kind]
		if !ok || semanticCandidateLess(candidate, existing) {
			selected[candidate.Result.Kind] = candidate
		}
	}
	for _, kind := range orderedSemanticSinkKinds() {
		candidate, ok := selected[kind]
		if !ok {
			continue
		}
		if len(findings) >= opts.Limits.MaxFindings {
			findingLimitHit = true
			continue
		}
		rule, family := semanticSinkRule(candidate.Result.Kind)
		findings = append(findings, Finding{
			Score: candidate.Result.Score, Family: family, Rule: rule,
			Evidence: boundedEvidenceWithEndpoints(candidate.Path, candidate.Class.Name, candidate.Method.Name,
				candidate.Result.Source, candidate.Result.Sink, candidate.Result.Evidence,
				candidate.Method.Code.Lines, opts.Limits),
			ArtifactPath: candidate.Path,
		})
	}
	if findingLimitHit {
		diagnostics = append(diagnostics, newDiagnostic(logicalRoot, diagAnalysisBudget, "finding limit reached"))
	}
	setArtifactPaths(findings, logicalRoot)
	return Result{Findings: findings, Diagnostics: aggregateDiagnostics(diagnostics)}
}

func semanticCandidateLess(left, right semanticCandidate) bool {
	if left.Result.Score != right.Result.Score {
		return left.Result.Score > right.Result.Score
	}
	if provenanceLess(left.Result.Evidence, right.Result.Evidence) {
		return true
	}
	if provenanceLess(right.Result.Evidence, left.Result.Evidence) {
		return false
	}
	leftClass, rightClass := "", ""
	if left.Class != nil {
		leftClass = left.Class.Name
	}
	if right.Class != nil {
		rightClass = right.Class.Name
	}
	if leftClass != rightClass {
		return leftClass < rightClass
	}
	leftMethod, rightMethod := "", ""
	if left.Method != nil {
		leftMethod = left.Method.Name + left.Method.Descriptor
	}
	if right.Method != nil {
		rightMethod = right.Method.Name + right.Method.Descriptor
	}
	return leftMethod < rightMethod
}

func orderedSemanticSinkKinds() []sinkKind {
	return []sinkKind{
		sinkExec,
		sinkDynamicLoad,
		sinkScriptEval,
		sinkExecutableWrite,
		sinkReflection,
		sinkDeserializationJNDI,
		sinkHookRegistration,
	}
}

func semanticSinkRule(kind sinkKind) (string, string) {
	switch kind {
	case sinkExec:
		return "javadisk:class-request-exec", "GenericJSP"
	case sinkDynamicLoad:
		return "javadisk:class-dynamic-classload", "DynamicClassload"
	case sinkScriptEval:
		return "javadisk:class-script-eval", "ScriptEngine"
	case sinkExecutableWrite:
		return "javadisk:class-executable-write", "FileDrop"
	case sinkReflection:
		return "javadisk:class-reflection-exec", "Reflection"
	case sinkDeserializationJNDI:
		return "javadisk:class-deserialization-jndi", "DeserializationJNDI"
	case sinkHookRegistration:
		return "javadisk:class-hook-registration", "MemshellDropper"
	default:
		return "javadisk:class-unknown-semantic", "JavaBytecode"
	}
}

func boundedEvidence(
	logicalPath, className, methodName string,
	steps []provenanceStep,
	lines []lineNumber,
	limits Limits,
) string {
	source, sink := provenanceStep{}, provenanceStep{}
	if len(steps) != 0 {
		source = steps[0]
		sink = steps[len(steps)-1]
	}
	return boundedEvidenceWithEndpoints(logicalPath, className, methodName, source, sink, steps, lines, limits)
}

func boundedEvidenceWithEndpoints(
	logicalPath, className, methodName string,
	source, sink provenanceStep,
	steps []provenanceStep,
	lines []lineNumber,
	limits Limits,
) string {
	if limits.MaxProvenanceSteps <= 0 {
		limits.MaxProvenanceSteps = DefaultOptions().Limits.MaxProvenanceSteps
	}
	maxSteps := limits.MaxProvenanceSteps
	if len(steps) < maxSteps {
		maxSteps = len(steps)
	}
	var builder strings.Builder
	if logicalPath != "" {
		builder.WriteString("artifact=")
		builder.WriteString(boundedEvidenceComponent(logicalPath, 64))
		builder.WriteByte(' ')
	}
	builder.WriteString("class=")
	builder.WriteString(boundedEvidenceComponent(className, 46))
	builder.WriteString(" method=")
	builder.WriteString(boundedEvidenceComponent(methodName, 40))
	if source.API != "" {
		builder.WriteString(" source=")
		builder.WriteString(boundedEvidenceComponent(source.API, 60))
		builder.WriteByte('@')
		builder.WriteString(fmt.Sprint(source.Offset))
		if line, ok := nearestLine(lines, source.Offset); ok {
			builder.WriteString(":line=")
			builder.WriteString(fmt.Sprint(line))
		}
	}
	if sink.API != "" {
		builder.WriteString(" sink=")
		builder.WriteString(boundedEvidenceComponent(sink.API, 40))
		builder.WriteByte('@')
		builder.WriteString(fmt.Sprint(sink.Offset))
		if line, ok := nearestLine(lines, sink.Offset); ok {
			builder.WriteString(":line=")
			builder.WriteString(fmt.Sprint(line))
		}
	}
	if maxSteps != 0 {
		builder.WriteString(" flow=")
		for index := 0; index < maxSteps; index++ {
			if index != 0 {
				builder.WriteString("->")
			}
			step := steps[index]
			builder.WriteString(boundedEvidenceComponent(step.API, 40))
			builder.WriteByte('@')
			builder.WriteString(fmt.Sprint(step.Offset))
		}
	}
	return boundedEvidenceComponent(builder.String(), 1024)
}

func methodFlowEvidence(class *classModel, method *methodModel, analysis methodAnalysis) string {
	lines := []lineNumber(nil)
	if method != nil && method.Code != nil {
		lines = method.Code.Lines
	}
	return boundedEvidenceWithEndpoints(
		"", class.Name, method.Name, analysis.Source, analysis.Sink, analysis.Evidence, lines, DefaultOptions().Limits,
	)
}

func nearestLine(lines []lineNumber, offset uint32) (uint16, bool) {
	if len(lines) == 0 {
		return 0, false
	}
	found := false
	var result uint16
	for _, line := range lines {
		if line.Offset > offset {
			break
		}
		result = line.Line
		found = true
	}
	return result, found
}

func boundedEvidenceComponent(value string, limit int) string {
	var result strings.Builder
	result.Grow(limit)
	for _, r := range value {
		if r == '\r' || r == '\n' || r == '\t' || r < 0x20 || r == 0x7f {
			r = ' '
		}
		size := len(string(r))
		if result.Len()+size > limit {
			break
		}
		result.WriteRune(r)
	}
	return result.String()
}

func hasDiagnosticCode(diagnostics []Diagnostic, code string) bool {
	for _, diagnostic := range diagnostics {
		if diagnostic.Code == code {
			return true
		}
	}
	return false
}

func parseClassIsolated(path string, data []byte, limits Limits) (class *classModel, diagnostic *Diagnostic) {
	return parseClassIsolatedWith(path, data, limits, parseClass)
}

func parseClassIsolatedWith(
	path string,
	data []byte,
	limits Limits,
	parser classParser,
) (class *classModel, diagnostic *Diagnostic) {
	limits = normalizeOptions(Options{Limits: limits}).Limits
	if int64(len(data)) > limits.MaxArtifactBytes {
		value := newDiagnostic(path, diagAnalysisBudget, "artifact exceeds byte limit")
		return nil, &value
	}
	defer func() {
		if recovered := recover(); recovered != nil {
			value := newDiagnostic(path, diagParserPanic, fmt.Sprintf("Java class parser panic: %v", recovered))
			class = nil
			diagnostic = &value
		}
	}()
	parsed, err := parser(data, limits)
	if err != nil {
		code := diagClassMalformed
		var versionError *unsupportedClassVersionError
		if errors.As(err, &versionError) {
			code = diagClassUnsupported
		}
		value := newDiagnostic(path, code, err.Error())
		return nil, &value
	}
	return parsed, nil
}

func isJavaSourceExtension(extension string) bool {
	return extension == ".java"
}

func isJSPSourceExtension(extension string) bool {
	switch extension {
	case ".jsp", ".jspx", ".jspf", ".jsw", ".jsv", ".jhtml":
		return true
	default:
		return false
	}
}

func setArtifactPaths(findings []Finding, path string) {
	for i := range findings {
		if findings[i].ArtifactPath == "" {
			findings[i].ArtifactPath = path
		}
	}
}

func diagnosticResult(path, code, detail string) Result {
	return Result{Diagnostics: []Diagnostic{newDiagnostic(path, code, detail)}}
}
