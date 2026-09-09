package javadisk

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"sort"
)

type methodKey struct {
	Owner, Name, Descriptor string
}

type summaryNamespace uint8

const (
	summaryExact summaryNamespace = iota
	summaryVirtual
	summaryLambdaClass
	summaryLambdaInterface
)

type summaryKey struct {
	Method    methodKey
	Namespace summaryNamespace
}

type argumentSet [4]uint64

func (set *argumentSet) add(slot int) {
	if slot >= 0 && slot < len(set)*64 {
		set[slot/64] |= uint64(1) << uint(slot%64)
	}
}

func (set argumentSet) has(slot int) bool {
	return slot >= 0 && slot < len(set)*64 && set[slot/64]&(uint64(1)<<uint(slot%64)) != 0
}

func (set argumentSet) empty() bool {
	return set == argumentSet{}
}

func (set argumentSet) union(other argumentSet) argumentSet {
	for index := range set {
		set[index] |= other[index]
	}
	return set
}

type methodSummary struct {
	ReturnFromArgs argumentSet
	SinkFromArgs   map[sinkKind]argumentSet
	ReturnTaint    taint
	SinkTaint      map[sinkKind]taint
	ReturnKinds    valueKind
	Constant       string
}

type summarySet map[summaryKey]methodSummary

func exactSummaryKey(key methodKey) summaryKey {
	return summaryKey{Method: key, Namespace: summaryExact}
}

func emptyMethodSummary() methodSummary {
	return methodSummary{
		SinkFromArgs: make(map[sinkKind]argumentSet),
		SinkTaint:    make(map[sinkKind]taint),
	}
}

func mergeMethodSummaries(left, right methodSummary) methodSummary {
	result := emptyMethodSummary()
	result.ReturnFromArgs = left.ReturnFromArgs.union(right.ReturnFromArgs)
	result.ReturnTaint = left.ReturnTaint | right.ReturnTaint
	result.ReturnKinds = left.ReturnKinds | right.ReturnKinds
	if left.Constant == right.Constant {
		result.Constant = left.Constant
	}
	for _, kind := range orderedSemanticSinkKinds() {
		result.SinkFromArgs[kind] = left.SinkFromArgs[kind].union(right.SinkFromArgs[kind])
		result.SinkTaint[kind] = left.SinkTaint[kind] | right.SinkTaint[kind]
	}
	return result
}

type preparedMethod struct {
	Path   string
	Class  *classModel
	Method *methodModel
	CFG    *controlFlowGraph
}

type preparedClass struct {
	Path            string
	Class           *classModel
	Methods         []*preparedMethod
	VerifierInvalid bool
}

type preparedArtifact struct {
	Classes        []*preparedClass
	Methods        []*preparedMethod
	ByName         map[string]*classModel
	DuplicateNames map[string]bool
	Diagnostics    []Diagnostic
}

func buildSummaries(classes map[string]*classModel, opts Options) (summarySet, []Diagnostic) {
	opts = normalizeOptions(opts)
	prepared := prepareArtifact(context.Background(), "", classes, opts)
	summaries, diagnostics := buildPreparedSummaries(context.Background(), prepared, opts)
	diagnostics = append(append([]Diagnostic(nil), prepared.Diagnostics...), diagnostics...)
	return summaries, aggregateDiagnostics(diagnostics)
}

func prepareArtifact(ctx context.Context, logicalRoot string, classes map[string]*classModel, opts Options) *preparedArtifact {
	if ctx == nil {
		ctx = context.Background()
	}
	result := &preparedArtifact{
		ByName:         make(map[string]*classModel),
		DuplicateNames: make(map[string]bool),
	}
	inputPaths := make([]string, 0, len(classes))
	for path := range classes {
		inputPaths = append(inputPaths, path)
	}
	sort.Strings(inputPaths)
	pathsByName := make(map[string][]string)
	for _, path := range inputPaths {
		class := classes[path]
		if class == nil {
			result.Diagnostics = append(result.Diagnostics, newDiagnostic(path, diagClassMalformed, "nil Java class model"))
			continue
		}
		pathsByName[class.Name] = append(pathsByName[class.Name], path)
	}
	names := make([]string, 0, len(pathsByName))
	for name := range pathsByName {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		paths := pathsByName[name]
		sort.Strings(paths)
		if len(paths) > 1 {
			result.DuplicateNames[name] = true
			result.Diagnostics = append(result.Diagnostics, newDiagnostic(logicalRoot, diagClassDuplicate,
				fmt.Sprintf("duplicate binary class name %s appears in %d logical paths", name, len(paths))))
			continue
		}
		result.ByName[name] = classes[paths[0]]
	}

	classOrder := make([]*preparedClass, 0, len(classes))
	for _, path := range inputPaths {
		class := classes[path]
		if class != nil {
			classOrder = append(classOrder, &preparedClass{Path: path, Class: class})
		}
	}
	sort.Slice(classOrder, func(i, j int) bool {
		leftPriority, rightPriority := classSchedulingPriority(classOrder[i].Class), classSchedulingPriority(classOrder[j].Class)
		if leftPriority != rightPriority {
			return leftPriority < rightPriority
		}
		if classOrder[i].Path != classOrder[j].Path {
			return classOrder[i].Path < classOrder[j].Path
		}
		return classOrder[i].Class.Name < classOrder[j].Class.Name
	})

	charged := 0
	exhausted := false
	for _, preparedClass := range classOrder {
		if ctx.Err() != nil {
			result.Diagnostics = append(result.Diagnostics, newDiagnostic(logicalRoot, diagCancelled, "analysis cancelled"))
			break
		}
		for _, method := range sortedMethods(preparedClass.Class.Methods) {
			if ctx.Err() != nil {
				result.Diagnostics = append(result.Diagnostics, newDiagnostic(logicalRoot, diagCancelled, "analysis cancelled"))
				exhausted = true
				break
			}
			if method.Code == nil {
				continue
			}
			remaining := opts.Limits.MaxArtifactInstructions - charged
			if remaining <= 0 {
				result.Diagnostics = append(result.Diagnostics, newDiagnostic(logicalRoot, diagAnalysisBudget,
					fmt.Sprintf("artifact instruction limit %d exhausted", opts.Limits.MaxArtifactInstructions)))
				exhausted = true
				break
			}
			activeLimit := opts.Limits.MaxInstructions
			artifactLimited := remaining <= activeLimit
			if remaining < activeLimit {
				activeLimit = remaining
			}
			instructions, decoded, err := decodeInstructionsCounted(method.Code.Bytes, activeLimit)
			charged += decoded
			if err != nil {
				var limitError *instructionLimitError
				if errors.As(err, &limitError) && artifactLimited {
					result.Diagnostics = append(result.Diagnostics, methodDiagnostic(logicalRoot, diagAnalysisBudget,
						preparedClass.Class, method, "artifact instruction budget exhausted", err))
					exhausted = true
					break
				}
				preparedClass.VerifierInvalid = true
				result.Diagnostics = append(result.Diagnostics, methodDiagnostic(logicalRoot, diagBytecodeUnsupported,
					preparedClass.Class, method, "bytecode decode failed", err))
				continue
			}
			cfg, err := buildCFG(method.Code, instructions)
			if err != nil {
				preparedClass.VerifierInvalid = true
				result.Diagnostics = append(result.Diagnostics, methodDiagnostic(logicalRoot, diagBytecodeUnsupported,
					preparedClass.Class, method, "CFG validation failed", err))
				continue
			}
			prepared := &preparedMethod{Path: preparedClass.Path, Class: preparedClass.Class, Method: method, CFG: cfg}
			preparedClass.Methods = append(preparedClass.Methods, prepared)
			result.Methods = append(result.Methods, prepared)
			if charged == opts.Limits.MaxArtifactInstructions {
				result.Diagnostics = append(result.Diagnostics, newDiagnostic(logicalRoot, diagAnalysisBudget,
					fmt.Sprintf("artifact instruction limit %d exhausted", charged)))
				exhausted = true
				break
			}
		}
		result.Classes = append(result.Classes, preparedClass)
		if exhausted {
			break
		}
	}
	return result
}

func classSchedulingPriority(class *classModel) int {
	if class == nil {
		return 3
	}
	hasSource, hasSink := false, false
	for index := 1; index < len(class.Pool); index++ {
		tag := class.Pool[index].tag
		if tag != cpMethodref && tag != cpInterfaceMethodref {
			continue
		}
		ref, err := class.memberRef(uint16(index))
		if err != nil {
			continue
		}
		hasSource = hasSource || requestSourceAPIs.matches(ref) || sessionAttributeSourceAPIs.matches(ref) ||
			applicationAttributeSourceAPIs.matches(ref) || pageContextRequestAPIs.matches(ref)
		features := semanticFeatures(ref)
		hasSink = hasSink || features.Exec || features.DynamicLoad || features.ScriptEval || features.HookRegistration ||
			executableWriteAPIs.matches(ref) || reflectionExecutionAPIs.matches(ref) ||
			deserializationAPIs.matches(ref) || jndiLookupAPIs.matches(ref)
	}
	if hasSource && hasSink {
		return 0
	}
	if hasSource || hasSink {
		return 1
	}
	if len(serverContextEvidence(class)) != 0 {
		return 2
	}
	return 3
}

func buildPreparedSummaries(ctx context.Context, prepared *preparedArtifact, opts Options) (summarySet, []Diagnostic) {
	base := make(summarySet)
	var diagnostics []Diagnostic
	methods := append([]*preparedMethod(nil), prepared.Methods...)
	sort.Slice(methods, func(i, j int) bool {
		left := methodKey{Owner: methods[i].Class.Name, Name: methods[i].Method.Name, Descriptor: methods[i].Method.Descriptor}
		right := methodKey{Owner: methods[j].Class.Name, Name: methods[j].Method.Name, Descriptor: methods[j].Method.Descriptor}
		if left != right {
			return methodKeyLess(left, right)
		}
		return methods[i].Path < methods[j].Path
	})
	for round := 0; round < opts.Limits.MaxSummaryRounds; round++ {
		if ctx.Err() != nil {
			diagnostics = append(diagnostics, newDiagnostic("", diagCancelled, "analysis cancelled"))
			return dispatchSummarySet(base, prepared, opts, &diagnostics), diagnostics
		}
		available := dispatchSummarySet(base, prepared, opts, &diagnostics)
		next := make(summarySet)
		for _, method := range methods {
			if ctx.Err() != nil {
				diagnostics = append(diagnostics, newDiagnostic("", diagCancelled, "analysis cancelled"))
				return dispatchSummarySet(next, prepared, opts, &diagnostics), diagnostics
			}
			if prepared.DuplicateNames[method.Class.Name] {
				continue
			}
			analysis := analyzeMethodSummaryContext(ctx, method.Class, method.Method, method.CFG, opts, available)
			if analysis.Cancelled {
				diagnostics = append(diagnostics, newDiagnostic(method.Path, diagCancelled, "analysis cancelled"))
				return dispatchSummarySet(next, prepared, opts, &diagnostics), diagnostics
			}
			if analysis.BudgetExhausted != "" {
				diagnostics = append(diagnostics, methodDiagnostic(method.Path, diagAnalysisBudget, method.Class,
					method.Method, "summary analysis budget exhausted", errors.New(analysis.BudgetExhausted)))
				continue
			}
			if analysis.Unsupported != "" {
				continue
			}
			next[exactSummaryKey(methodKey{Owner: method.Class.Name, Name: method.Method.Name, Descriptor: method.Method.Descriptor})] = analysis.Summary
		}
		if reflect.DeepEqual(base, next) {
			return dispatchSummarySet(next, prepared, opts, &diagnostics), diagnostics
		}
		base = next
	}
	diagnostics = append(diagnostics, newDiagnostic("", diagAnalysisBudget,
		fmt.Sprintf("method summary fixed point exceeded %d rounds", opts.Limits.MaxSummaryRounds)))
	return dispatchSummarySet(base, prepared, opts, &diagnostics), diagnostics
}

func dispatchSummarySet(base summarySet, prepared *preparedArtifact, opts Options, diagnostics *[]Diagnostic) summarySet {
	result := make(summarySet, len(base))
	for key, summary := range base {
		result[key] = summary
	}
	candidates := newDispatchCandidates()
	for _, method := range prepared.Methods {
		concreteKey := methodKey{Owner: method.Class.Name, Name: method.Method.Name, Descriptor: method.Method.Descriptor}
		if summary, ok := base[exactSummaryKey(concreteKey)]; ok && !prepared.DuplicateNames[method.Class.Name] && method.Method.Access&0x0008 != 0 {
			namespace := summaryLambdaClass
			if method.Class.Access&0x0200 != 0 {
				namespace = summaryLambdaInterface
			}
			result[summaryKey{Method: concreteKey, Namespace: namespace}] = summary
		}
		if prepared.DuplicateNames[method.Class.Name] || method.Method.Access&(0x0008|0x0002) != 0 ||
			method.Method.Name == "<init>" || method.Method.Name == "<clinit>" {
			continue
		}
		summary, ok := base[exactSummaryKey(concreteKey)]
		if !ok {
			continue
		}
		for _, owner := range localAncestors(method.Class, prepared.ByName) {
			alias := methodKey{Owner: owner, Name: method.Method.Name, Descriptor: method.Method.Descriptor}
			candidates.add(alias, concreteKey, summary, opts.Limits.MaxCallTargets)
		}
	}
	aliases := make([]methodKey, 0, len(candidates.targets)+len(candidates.capped))
	for alias := range candidates.targets {
		aliases = append(aliases, alias)
	}
	for alias := range candidates.capped {
		aliases = append(aliases, alias)
	}
	sortMethodKeys(aliases)
	for _, alias := range aliases {
		if candidates.capped[alias] {
			*diagnostics = append(*diagnostics, newDiagnostic(alias.Owner, diagAnalysisBudget,
				fmt.Sprintf("more than %d local call targets for %s%s", opts.Limits.MaxCallTargets, alias.Name, alias.Descriptor)))
			continue
		}
		targets := candidates.targets[alias]
		keys := make([]methodKey, 0, len(targets))
		for key := range targets {
			keys = append(keys, key)
		}
		sortMethodKeys(keys)
		merged := emptyMethodSummary()
		first := true
		for _, key := range keys {
			if first {
				merged = targets[key]
				first = false
			} else {
				merged = mergeMethodSummaries(merged, targets[key])
			}
		}
		result[summaryKey{Method: alias, Namespace: summaryVirtual}] = merged
	}
	return result
}

type dispatchCandidates struct {
	targets map[methodKey]map[methodKey]methodSummary
	capped  map[methodKey]bool
}

func newDispatchCandidates() *dispatchCandidates {
	return &dispatchCandidates{
		targets: make(map[methodKey]map[methodKey]methodSummary),
		capped:  make(map[methodKey]bool),
	}
}

func (set *dispatchCandidates) add(alias, concrete methodKey, summary methodSummary, limit int) {
	if set.capped[alias] {
		return
	}
	targets := set.targets[alias]
	if targets == nil {
		targets = make(map[methodKey]methodSummary)
		set.targets[alias] = targets
	}
	if _, exists := targets[concrete]; exists {
		return
	}
	if len(targets) >= limit {
		delete(set.targets, alias)
		set.capped[alias] = true
		return
	}
	targets[concrete] = summary
}

func localAncestors(class *classModel, index map[string]*classModel) []string {
	seen := make(map[string]bool)
	var visit func(string)
	visit = func(name string) {
		if seen[name] || index[name] == nil {
			return
		}
		seen[name] = true
		candidate := index[name]
		visit(candidate.Super)
		for _, iface := range candidate.Interfaces {
			visit(iface)
		}
	}
	visit(class.Name)
	result := make([]string, 0, len(seen))
	for name := range seen {
		result = append(result, name)
	}
	sort.Strings(result)
	return result
}

func sortMethodKeys(keys []methodKey) {
	sort.Slice(keys, func(i, j int) bool { return methodKeyLess(keys[i], keys[j]) })
}

func methodKeyLess(left, right methodKey) bool {
	if left.Owner != right.Owner {
		return left.Owner < right.Owner
	}
	if left.Name != right.Name {
		return left.Name < right.Name
	}
	return left.Descriptor < right.Descriptor
}

func aggregateDiagnostics(diagnostics []Diagnostic) []Diagnostic {
	result := make([]Diagnostic, 0, len(diagnostics))
	byCode := make(map[string]int)
	for _, diagnostic := range diagnostics {
		if index, ok := byCode[diagnostic.Code]; ok {
			result[index].Count += diagnostic.Count
			continue
		}
		byCode[diagnostic.Code] = len(result)
		result = append(result, diagnostic)
	}
	return result
}
