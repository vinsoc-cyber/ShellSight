package javadisk

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"sort"
	"strings"
	"unicode/utf8"
)

const structuralScore = 60

const structuralCancellationCheckInterval = 256

type structuralRule struct {
	Rule   string
	Family string
}

type methodVisitResult struct {
	Finding    *Finding
	Diagnostic *Diagnostic
	Cancelled  bool
}

type classMethodVisitor func(
	context.Context,
	*classModel,
	*methodModel,
	*controlFlowGraph,
	Options,
) methodVisitResult

type classModelAnalysis struct {
	Result
	VerifierInvalid bool
}

var structuralRules = []structuralRule{
	{Rule: "javadisk:class-dynamic-load-structure", Family: "DynamicClassload"},
	{Rule: "javadisk:class-hook-registration-structure", Family: "MemshellDropper"},
	{Rule: "javadisk:class-request-exec-structure", Family: "GenericJSP"},
	{Rule: "javadisk:class-script-eval-structure", Family: "ScriptEngine"},
}

func analyzeClassModel(path string, class *classModel, opts Options) Result {
	return analyzeClassModelContext(context.Background(), path, class, opts)
}

func analyzeClassModelContext(ctx context.Context, path string, class *classModel, opts Options) Result {
	return analyzeClassModelContextWithVisitor(ctx, path, class, opts, nil)
}

func analyzeClassModelContextWithVisitor(
	ctx context.Context,
	path string,
	class *classModel,
	opts Options,
	visitor classMethodVisitor,
) Result {
	return analyzeClassModelContextWithVisitorStatus(ctx, path, class, opts, visitor).Result
}

func analyzeClassModelContextWithVisitorStatus(
	ctx context.Context,
	path string,
	class *classModel,
	opts Options,
	visitor classMethodVisitor,
) classModelAnalysis {
	if ctx == nil {
		ctx = context.Background()
	}
	opts = normalizeOptions(opts)
	if class == nil {
		return classModelAnalysis{
			Result: Result{Diagnostics: []Diagnostic{
				newDiagnostic(path, diagClassMalformed, "Java class parser returned a nil class model"),
			}},
			VerifierInvalid: true,
		}
	}

	methods := sortedMethods(class.Methods)
	serverContext := serverContextEvidence(class)
	evidenceByRule := make(map[string]string, len(structuralRules))
	var diagnostics []Diagnostic
	var semanticFindings []Finding
	charged := 0
	cancellationRecorded := false
	verifierInvalid := false
	recordCancellation := func() {
		if cancellationRecorded {
			return
		}
		diagnostics = append(diagnostics, newDiagnostic(path, diagCancelled, "analysis cancelled"))
		cancellationRecorded = true
	}
	cancelled := func() bool {
		if ctx.Err() == nil {
			return false
		}
		recordCancellation()
		return true
	}

	for _, method := range methods {
		if cancelled() {
			break
		}
		if method.Code == nil {
			continue
		}
		remaining := opts.Limits.MaxArtifactInstructions - charged
		activeLimit := opts.Limits.MaxInstructions
		artifactLimited := remaining <= activeLimit
		if remaining < activeLimit {
			activeLimit = remaining
		}
		instructions, decoded, err := decodeInstructionsCounted(method.Code.Bytes, activeLimit)
		if cancelled() {
			break
		}
		charged += decoded
		if err != nil {
			var limitError *instructionLimitError
			if errors.As(err, &limitError) {
				if artifactLimited {
					diagnostics = append(diagnostics, newDiagnostic(
						path,
						diagAnalysisBudget,
						fmt.Sprintf(
							"class %s method %s%s exhausted the artifact instruction limit %d at bytecode offset %d",
							class.Name, method.Name, method.Descriptor,
							opts.Limits.MaxArtifactInstructions, limitError.Offset,
						),
					))
					break
				}
				diagnostics = append(diagnostics, methodDiagnostic(
					path, diagBytecodeUnsupported, class, method, "bytecode decode failed", err,
				))
				continue
			}
			verifierInvalid = true
			diagnostics = append(diagnostics, methodDiagnostic(
				path, diagBytecodeUnsupported, class, method, "bytecode decode failed", err,
			))
			continue
		}
		cfg, err := buildCFG(method.Code, instructions)
		if cancelled() {
			break
		}
		if err != nil {
			verifierInvalid = true
			diagnostics = append(diagnostics, methodDiagnostic(
				path, diagBytecodeUnsupported, class, method, "CFG validation failed", err,
			))
		} else {
			features, extractionCancelled := extractMethodFeaturesContext(ctx, class, cfg)
			if extractionCancelled {
				recordCancellation()
				break
			}
			if visitor != nil {
				visited := visitor(ctx, class, method, cfg, opts)
				if visited.Cancelled || ctx.Err() != nil {
					recordCancellation()
					break
				}
				if visited.Diagnostic != nil {
					diagnostics = append(diagnostics, *visited.Diagnostic)
				}
				if visited.Finding != nil {
					semanticFindings = append(semanticFindings, *visited.Finding)
				}
			}
			recordStructuralEvidence(evidenceByRule, class, method, features, serverContext)
			if cancelled() {
				break
			}
		}

		if charged == opts.Limits.MaxArtifactInstructions {
			diagnostics = append(diagnostics, newDiagnostic(
				path,
				diagAnalysisBudget,
				fmt.Sprintf("class %s exhausted the artifact instruction limit %d", class.Name, charged),
			))
			break
		}
	}

	findings := make([]Finding, 0, len(structuralRules))
	for _, rule := range structuralRules {
		evidence := evidenceByRule[rule.Rule]
		if evidence == "" {
			continue
		}
		findings = append(findings, Finding{
			Score:    structuralScore,
			Family:   rule.Family,
			Rule:     rule.Rule,
			Evidence: evidence,
		})
	}
	findings = append(findings, semanticFindings...)
	return classModelAnalysis{
		Result:          Result{Findings: findings, Diagnostics: diagnostics},
		VerifierInvalid: verifierInvalid,
	}
}

func sortedMethods(methods []methodModel) []*methodModel {
	result := make([]*methodModel, len(methods))
	for i := range methods {
		result[i] = &methods[i]
	}
	sort.SliceStable(result, func(i, j int) bool {
		if result[i].Name != result[j].Name {
			return result[i].Name < result[j].Name
		}
		return result[i].Descriptor < result[j].Descriptor
	})
	return result
}

func methodDiagnostic(
	path, code string,
	class *classModel,
	method *methodModel,
	operation string,
	err error,
) Diagnostic {
	return newDiagnostic(
		path,
		code,
		fmt.Sprintf(
			"class %s method %s%s: %s: %v",
			class.Name, method.Name, method.Descriptor, operation, err,
		),
	)
}

func extractMethodFeaturesContext(
	ctx context.Context,
	class *classModel,
	cfg *controlFlowGraph,
) (methodFeatures, bool) {
	var result methodFeatures
	if cfg == nil || len(cfg.Blocks) == 0 {
		return result, false
	}
	if ctx == nil {
		ctx = context.Background()
	}

	visited := make(map[uint32]struct{}, len(cfg.Blocks))
	queue := []uint32{cfg.Entry}
	evidence := make(map[string]struct{})
	for len(queue) != 0 {
		if ctx.Err() != nil {
			return methodFeatures{}, true
		}
		start := queue[0]
		queue = queue[1:]
		if _, ok := visited[start]; ok {
			continue
		}
		block, ok := cfg.Blocks[start]
		if !ok {
			continue
		}
		visited[start] = struct{}{}

		for index, instruction := range block.Instructions {
			if index > 0 && index%structuralCancellationCheckInterval == 0 && ctx.Err() != nil {
				return methodFeatures{}, true
			}
			reference, ok := resolvedInvokeReference(class, instruction)
			if !ok {
				continue
			}
			features := semanticFeatures(reference)
			if isInheritedClassDefinition(class, reference) {
				features.DynamicLoad = true
			}
			if !hasSemanticFeature(features) {
				continue
			}
			result.RequestSource = result.RequestSource || features.RequestSource
			result.Exec = result.Exec || features.Exec
			result.DynamicLoad = result.DynamicLoad || features.DynamicLoad
			result.Decode = result.Decode || features.Decode
			result.ScriptEval = result.ScriptEval || features.ScriptEval
			result.HookRegistration = result.HookRegistration || features.HookRegistration
			evidence[resolvedAPI(reference)] = struct{}{}
		}
		queue = append(queue, block.Successors...)
	}

	result.Evidence = make([]string, 0, len(evidence))
	for value := range evidence {
		result.Evidence = append(result.Evidence, value)
	}
	sort.Strings(result.Evidence)
	return result, false
}

func resolvedInvokeReference(class *classModel, instruction instruction) (memberReference, bool) {
	if class == nil || len(instruction.Operands) < 2 {
		return memberReference{}, false
	}
	if instruction.Opcode < 0xb6 || instruction.Opcode > 0xb9 {
		return memberReference{}, false
	}

	index := binary.BigEndian.Uint16(instruction.Operands[:2])
	entry, err := class.poolEntry(index)
	if err != nil {
		return memberReference{}, false
	}
	switch instruction.Opcode {
	case 0xb6:
		if entry.tag != cpMethodref {
			return memberReference{}, false
		}
	case 0xb7, 0xb8:
		if entry.tag != cpMethodref && (class.Major < 52 || entry.tag != cpInterfaceMethodref) {
			return memberReference{}, false
		}
	case 0xb9:
		if entry.tag != cpInterfaceMethodref {
			return memberReference{}, false
		}
	}
	reference, err := class.memberRef(index)
	if err != nil {
		return memberReference{}, false
	}
	return reference, true
}

func hasSemanticFeature(features methodFeatures) bool {
	return features.RequestSource || features.Exec || features.DynamicLoad || features.Decode ||
		features.ScriptEval || features.HookRegistration
}

func resolvedAPI(reference memberReference) string {
	return strings.ReplaceAll(reference.Owner, "/", ".") + "." + reference.Name + reference.Descriptor
}

func recordStructuralEvidence(
	evidenceByRule map[string]string,
	class *classModel,
	method *methodModel,
	features methodFeatures,
	serverContext []string,
) {
	record := func(rule string, support ...string) {
		if evidenceByRule[rule] != "" {
			return
		}
		for _, value := range support {
			if value == "" {
				return
			}
		}
		evidenceByRule[rule] = structuralMethodEvidence(class, method, support)
	}
	if features.RequestSource && features.Exec {
		record(
			"javadisk:class-request-exec-structure",
			firstCatalogSupport(features.Evidence, requestSourceAPIs),
			firstCatalogSupport(features.Evidence, runtimeExecAPIs),
		)
	}
	if features.Decode && features.DynamicLoad {
		record(
			"javadisk:class-dynamic-load-structure",
			firstCatalogSupport(features.Evidence, base64DecodeAPIs),
			firstDynamicLoadSupport(class, features.Evidence),
		)
	}
	if features.ScriptEval && (features.RequestSource || len(serverContext) != 0) {
		context := firstCatalogSupport(features.Evidence, requestSourceAPIs)
		if context == "" && len(serverContext) != 0 {
			context = structuralContextDisplay(serverContext[0])
		}
		record("javadisk:class-script-eval-structure", context,
			firstCatalogSupport(features.Evidence, scriptEvaluationAPIs))
	}
	if features.HookRegistration {
		record(
			"javadisk:class-hook-registration-structure",
			firstCatalogSupport(features.Evidence, hookRegistrationAPIs),
		)
	}
}

func structuralMethodEvidence(
	class *classModel,
	method *methodModel,
	support []string,
) string {
	methodIdentity := boundedStructuralText(class.Name, 20) + "." +
		boundedStructuralText(method.Name+method.Descriptor, 35)
	parts := []string{
		"class=" + boundedStructuralText(class.Name, 40),
		"method=" + methodIdentity,
		"support=" + strings.Join(support, " -> "),
	}
	return boundedDiagnosticText(strings.Join(parts, " "))
}

func firstCatalogSupport(evidence []string, values apiCatalog) string {
	var matches []string
	for signature := range values {
		canonical := resolvedAPI(memberReference{
			Owner: signature.Owner, Name: signature.Name, Descriptor: signature.Descriptor,
		})
		index := sort.SearchStrings(evidence, canonical)
		if index < len(evidence) && evidence[index] == canonical {
			matches = append(matches, structuralAPIDisplay(signature.Owner, signature.Name))
		}
	}
	if len(matches) == 0 {
		return ""
	}
	sort.Strings(matches)
	return matches[0]
}

func firstDynamicLoadSupport(class *classModel, evidence []string) string {
	if support := firstCatalogSupport(evidence, classDefinitionAPIs); support != "" {
		return support
	}
	if class == nil {
		return ""
	}
	var matches []string
	addDescriptors := func(descriptors map[string]struct{}) {
		for descriptor := range descriptors {
			reference := memberReference{Owner: class.Name, Name: "defineClass", Descriptor: descriptor}
			canonical := resolvedAPI(reference)
			index := sort.SearchStrings(evidence, canonical)
			if index < len(evidence) && evidence[index] == canonical && isInheritedClassDefinition(class, reference) {
				matches = append(matches, structuralAPIDisplay(reference.Owner, reference.Name))
			}
		}
	}
	addDescriptors(classLoaderDefinitionDescriptors)
	addDescriptors(secureClassLoaderDefinitionDescriptors)
	if len(matches) == 0 {
		return ""
	}
	sort.Strings(matches)
	return matches[0]
}

func structuralAPIDisplay(owner, name string) string {
	if index := strings.LastIndexByte(owner, '/'); index >= 0 {
		owner = owner[index+1:]
	}
	return boundedStructuralText(owner, 24) + "." + boundedStructuralText(name, 22)
}

func structuralContextDisplay(value string) string {
	kind, name, ok := strings.Cut(value, ":")
	if !ok {
		return boundedStructuralText(value, 48)
	}
	name = strings.TrimSuffix(name, ";")
	name = strings.TrimPrefix(name, "L")
	if index := strings.LastIndexByte(name, '/'); index >= 0 {
		name = name[index+1:]
	}
	return boundedStructuralText(kind, 12) + ":" + boundedStructuralText(name, 32)
}

func boundedStructuralText(value string, limit int) string {
	value = boundedDiagnosticText(value)
	if len(value) <= limit {
		return value
	}
	for limit > 0 && !utf8.ValidString(value[:limit]) {
		limit--
	}
	return value[:limit]
}

func serverContextEvidence(class *classModel) []string {
	if class == nil {
		return nil
	}
	values := make(map[string]struct{})
	addAnnotations := func(annotations []annotationModel) {
		for _, annotation := range annotations {
			if _, ok := serverAnnotationDescriptors[annotation.Descriptor]; ok {
				values["annotation:"+annotation.Descriptor] = struct{}{}
			}
		}
	}
	addAnnotations(class.Annotations)
	for i := range class.Methods {
		addAnnotations(class.Methods[i].Annotations)
	}
	for _, name := range append([]string{class.Super}, class.Interfaces...) {
		if _, ok := serverHierarchyTypes[name]; ok {
			values["hierarchy:"+name] = struct{}{}
		}
	}
	result := make([]string, 0, len(values))
	for value := range values {
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}
