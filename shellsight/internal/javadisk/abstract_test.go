package javadisk

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"
)

func analyzeCode(t *testing.T, code *codeModel, descriptor string, opts Options) methodAnalysis {
	t.Helper()
	ins, err := decodeInstructions(code.Bytes, 10_000)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := buildCFG(code, ins)
	if err != nil {
		t.Fatal(err)
	}
	method := &methodModel{Access: 0x0009, Name: "run", Descriptor: descriptor, Code: code}
	return analyzeMethod(&classModel{Name: "fixture/Abstract", Major: 49}, method, cfg, opts, summarySet{})
}

func analyzeSpecMethod(t *testing.T, spec classSpec, methodName string, opts Options) methodAnalysis {
	t.Helper()
	if spec.Major == 0 {
		spec.Major = 49
	}
	data, _ := classBytes(t, spec)
	cf, err := parseClass(data, opts.Limits)
	if err != nil {
		t.Fatal(err)
	}
	for i := range cf.Methods {
		method := &cf.Methods[i]
		if method.Name != methodName {
			continue
		}
		ins, err := decodeInstructions(method.Code.Bytes, 10_000)
		if err != nil {
			t.Fatal(err)
		}
		cfg, err := buildCFG(method.Code, ins)
		if err != nil {
			t.Fatal(err)
		}
		return analyzeMethod(cf, method, cfg, opts, summarySet{})
	}
	t.Fatalf("method %q not found", methodName)
	return methodAnalysis{}
}

func TestAbstractCategoryTwoStackOperations(t *testing.T) {
	valid := analyzeCode(t, &codeModel{
		MaxStack: 4, Bytes: []byte{0x09, 0x5c, 0x58, 0x58, 0xb1},
	}, "()V", DefaultOptions())
	if valid.Unsupported != "" || valid.BudgetExhausted != "" {
		t.Fatalf("valid analysis=%+v", valid)
	}

	for _, code := range [][]byte{
		{0x03, 0x58, 0xb1},
		{0x09, 0x59, 0xb1},
		{0x09, 0x03, 0x5c, 0xb1},
	} {
		got := analyzeCode(t, &codeModel{MaxStack: 4, Bytes: code}, "()V", DefaultOptions())
		if got.Unsupported == "" {
			t.Fatalf("accepted impossible category-two shape %x: %+v", code, got)
		}
	}
}

func TestAbstractAcceptsEveryValidDupStackForm(t *testing.T) {
	tests := []struct {
		name string
		code []byte
	}{
		{"dup", []byte{0x03, 0x59, 0x57, 0x57, 0xb1}},
		{"dup_x1", []byte{0x03, 0x04, 0x5a, 0x57, 0x57, 0x57, 0xb1}},
		{"dup_x2 category2", []byte{0x09, 0x03, 0x5b, 0x57, 0x58, 0x57, 0xb1}},
		{"dup_x2 category1", []byte{0x03, 0x04, 0x05, 0x5b, 0x57, 0x57, 0x57, 0x57, 0xb1}},
		{"dup2 category2", []byte{0x09, 0x5c, 0x58, 0x58, 0xb1}},
		{"dup2 category1", []byte{0x03, 0x04, 0x5c, 0x57, 0x57, 0x57, 0x57, 0xb1}},
		{"dup2_x1 category2", []byte{0x03, 0x09, 0x5d, 0x58, 0x57, 0x58, 0xb1}},
		{"dup2_x1 category1", []byte{0x03, 0x04, 0x05, 0x5d, 0x57, 0x57, 0x57, 0x57, 0x57, 0xb1}},
		{"dup2_x2 two category2", []byte{0x09, 0x0a, 0x5e, 0x58, 0x58, 0x58, 0xb1}},
		{"dup2_x2 top category2", []byte{0x03, 0x04, 0x09, 0x5e, 0x58, 0x57, 0x57, 0x58, 0xb1}},
		{"dup2_x2 lower category2", []byte{0x09, 0x03, 0x04, 0x5e, 0x57, 0x57, 0x58, 0x57, 0x57, 0xb1}},
		{"dup2_x2 category1", []byte{0x03, 0x04, 0x05, 0x06, 0x5e, 0x57, 0x57, 0x57, 0x57, 0x57, 0x57, 0xb1}},
		{"swap", []byte{0x03, 0x04, 0x5f, 0x57, 0x57, 0xb1}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			analysis := analyzeCode(t, &codeModel{MaxStack: 8, Bytes: tt.code}, "()V", DefaultOptions())
			if analysis.Unsupported != "" || analysis.BudgetExhausted != "" {
				t.Fatalf("valid form rejected: %+v", analysis)
			}
		})
	}
}

func TestAbstractRejectsInvalidDupStackForms(t *testing.T) {
	for _, code := range [][]byte{
		{0x09, 0x5a, 0xb1},
		{0x03, 0x09, 0x5b, 0xb1},
		{0x09, 0x03, 0x5d, 0xb1},
		{0x09, 0x03, 0x5e, 0xb1},
		{0x09, 0x03, 0x5f, 0xb1},
	} {
		analysis := analyzeCode(t, &codeModel{MaxStack: 8, Bytes: code}, "()V", DefaultOptions())
		if analysis.Unsupported == "" {
			t.Fatalf("invalid form accepted: code=%x analysis=%+v", code, analysis)
		}
	}
}

func TestAbstractRejectsStackUnderflowAndIncompatibleMergeHeight(t *testing.T) {
	underflow := analyzeCode(t, &codeModel{MaxStack: 1, Bytes: []byte{0x57, 0xb1}}, "()V", DefaultOptions())
	if underflow.Unsupported == "" {
		t.Fatalf("underflow=%+v", underflow)
	}

	merge := analyzeCode(t, &codeModel{
		MaxStack: 2,
		Bytes:    []byte{0x03, 0x99, 0x00, 0x07, 0x04, 0xa7, 0x00, 0x03, 0xb1},
	}, "()V", DefaultOptions())
	if merge.Unsupported == "" || !strings.Contains(merge.Unsupported, "stack") {
		t.Fatalf("merge=%+v", merge)
	}
}

func TestAbstractExceptionEntryUsesPredecessorLocalsAndOneThrowable(t *testing.T) {
	code := &codeModel{
		MaxStack: 1, MaxLocals: 2,
		Bytes:    []byte{0x03, 0x3b, 0x01, 0xbf, 0x4c, 0xb1},
		Handlers: []exceptionHandler{{Start: 0, End: 4, Handler: 4, CatchType: "java/lang/Exception"}},
	}
	got := analyzeCode(t, code, "()V", DefaultOptions())
	if got.Unsupported != "" {
		t.Fatalf("analysis=%+v", got)
	}
	entry, ok := got.Frames[4]
	if !ok || len(entry.Stack) != 1 || entry.Stack[0].Width != 1 || len(entry.Locals) != 2 || entry.Locals[0].Width != 1 {
		t.Fatalf("handler entry=%+v", entry)
	}
}

func TestAbstractTargetMayHaveNormalAndExceptionalIncomingEdges(t *testing.T) {
	code := &codeModel{
		MaxStack: 1,
		Bytes:    []byte{0x01, 0xa7, 0x00, 0x03, 0x57, 0xb1},
		Handlers: []exceptionHandler{{Start: 0, End: 4, Handler: 4}},
	}
	got := analyzeCode(t, code, "()V", DefaultOptions())
	if got.Unsupported != "" || len(got.Frames[4].Stack) != 1 {
		t.Fatalf("analysis=%+v", got)
	}
}

func TestAbstractDeadUnsupportedBytecodeIsIgnoredButReachableJSRFallsBack(t *testing.T) {
	dead := analyzeCode(t, &codeModel{
		MaxStack: 1, Bytes: []byte{0xa7, 0x00, 0x04, 0xc2, 0xb1},
	}, "()V", DefaultOptions())
	if dead.Unsupported != "" {
		t.Fatalf("dead analysis=%+v", dead)
	}

	reachable := analyzeCode(t, &codeModel{
		MaxStack: 1, MaxLocals: 1, Bytes: []byte{0xa8, 0x00, 0x04, 0xb1, 0xa9, 0x00},
	}, "()V", DefaultOptions())
	if reachable.Unsupported == "" || !strings.Contains(reachable.Unsupported, "jsr") {
		t.Fatalf("reachable analysis=%+v", reachable)
	}
}

func TestAbstractMaxStateMergesBudgetIsDiagnostic(t *testing.T) {
	opts := DefaultOptions()
	opts.Limits.MaxStateMerges = 1
	got := analyzeCode(t, &codeModel{
		MaxStack: 1, Bytes: []byte{0x03, 0x99, 0x00, 0x04, 0xb1, 0xb1},
	}, "()V", opts)
	if got.BudgetExhausted == "" {
		t.Fatalf("analysis=%+v", got)
	}
}

func TestAbstractGetStaticSeedsConstantValue(t *testing.T) {
	field := memberReference{Owner: "fixture/Constant", Name: "COMMAND", Descriptor: "Ljava/lang/String;"}
	got := analyzeSpecMethod(t, classSpec{
		Name: "fixture/Constant",
		Fields: []classFieldSpec{{
			Access: 0x0019, Name: field.Name, Descriptor: field.Descriptor,
			Constant: &constantValue{Kind: constantString, String: "echo safe"},
		}},
		Methods: []classMethodSpec{{
			Access: 0x0009, Name: "run", MaxStack: 1,
			Code: []classInstructionSpec{
				{Opcode: 0xb2, Field: &field},
				{Opcode: 0xa7, Operands: []byte{0x00, 0x03}},
				{Opcode: 0x57}, {Opcode: 0xb1},
			},
		}},
	}, "run", DefaultOptions())
	if got.Unsupported != "" || got.Frames[6].Stack[0].Constant != "echo safe" {
		t.Fatalf("analysis=%+v", got)
	}
}

func TestAbstractFieldTaintFlowsRequirePriorWrites(t *testing.T) {
	for _, static := range []bool{false, true} {
		name := "instance"
		opPut, opGet := byte(0xb5), byte(0xb4)
		access := uint16(0x0001)
		if static {
			name, opPut, opGet, access = "static", 0xb3, 0xb2, 0x0009
		}
		t.Run(name, func(t *testing.T) {
			field := memberReference{Owner: "fixture/FieldFlow", Name: "command", Descriptor: "Ljava/lang/String;"}
			build := func(seed bool) []classInstructionSpec {
				code := []classInstructionSpec{}
				if seed {
					code = append(code,
						classInstructionSpec{Opcode: 0x2b},
						classInstructionSpec{Opcode: 0x12, Constant: &constantValue{Kind: constantString, String: "cmd"}},
						classInstructionSpec{Opcode: 0xb9, Member: &fixtureRequestParameter},
						classInstructionSpec{Opcode: 0x4e},
					)
					if !static {
						code = append(code, classInstructionSpec{Opcode: 0x2a})
					}
					code = append(code, classInstructionSpec{Opcode: 0x2d}, classInstructionSpec{Opcode: opPut, Field: &field})
				}
				code = append(code, classInstructionSpec{Opcode: 0xb8, Member: &fixtureRuntimeGet})
				if !static {
					code = append(code, classInstructionSpec{Opcode: 0x2a})
				}
				return append(code,
					classInstructionSpec{Opcode: opGet, Field: &field},
					classInstructionSpec{Opcode: 0xb6, Member: &fixtureRuntimeExec},
					classInstructionSpec{Opcode: 0x57}, classInstructionSpec{Opcode: 0xb1},
				)
			}
			for _, seed := range []bool{false, true} {
				data, _ := classBytes(t, classSpec{
					Name: "fixture/FieldFlow", Super: "javax/servlet/http/HttpServlet",
					Fields: []classFieldSpec{{Access: access, Name: field.Name, Descriptor: field.Descriptor}},
					Methods: []classMethodSpec{{
						Name: "service", Descriptor: "(Ljavax/servlet/http/HttpServletRequest;Ljavax/servlet/http/HttpServletResponse;)V",
						MaxStack: 3, MaxLocals: 4, Code: build(seed),
					}},
				})
				result := AnalyzeArtifact(name+".class", data, DefaultOptions())
				got := findingByRule(result.Findings, "javadisk:class-request-exec") != nil
				if got != seed {
					t.Fatalf("seed=%v result=%+v", seed, result)
				}
			}
		})
	}
}

func TestAbstractProcessBuilderRequiresSameTaintedReceiver(t *testing.T) {
	request := fixtureRequestParameter
	constructor := memberReference{
		Owner: "java/lang/ProcessBuilder", Name: "<init>", Descriptor: "([Ljava/lang/String;)V",
	}
	start := memberReference{
		Owner: "java/lang/ProcessBuilder", Name: "start", Descriptor: "()Ljava/lang/Process;",
	}
	build := func(sameReceiver bool) classSpec {
		startLocal := byte(0x2d)
		if !sameReceiver {
			startLocal = 0x19
		}
		code := []classInstructionSpec{
			{Opcode: 0xbb, ClassName: "java/lang/ProcessBuilder"}, {Opcode: 0x59},
			{Opcode: 0x04}, {Opcode: 0xbd, ClassName: "java/lang/String"}, {Opcode: 0x59}, {Opcode: 0x03},
			{Opcode: 0x2b}, {Opcode: 0x12, Constant: &constantValue{Kind: constantString, String: "cmd"}},
			{Opcode: 0xb9, Member: &request}, {Opcode: 0x53}, {Opcode: 0xb7, Member: &constructor}, {Opcode: 0x4e},
		}
		if !sameReceiver {
			code = append(code,
				classInstructionSpec{Opcode: 0xbb, ClassName: "java/lang/ProcessBuilder"},
				classInstructionSpec{Opcode: 0x3a, Operands: []byte{0x04}},
			)
			startLocal = 0x19
			code = append(code, classInstructionSpec{Opcode: startLocal, Operands: []byte{0x04}})
		} else {
			code = append(code, classInstructionSpec{Opcode: startLocal})
		}
		code = append(code, classInstructionSpec{Opcode: 0xb6, Member: &start}, classInstructionSpec{Opcode: 0x57}, classInstructionSpec{Opcode: 0xb1})
		return classSpec{Name: "fixture/Builder", Super: "javax/servlet/http/HttpServlet", Methods: []classMethodSpec{{
			Name: "service", Descriptor: "(Ljavax/servlet/http/HttpServletRequest;)V", MaxStack: 8, MaxLocals: 5, Code: code,
		}}}
	}

	for _, tt := range []struct {
		name string
		same bool
		want bool
	}{{"same", true, true}, {"different", false, false}} {
		t.Run(tt.name, func(t *testing.T) {
			data, _ := classBytes(t, build(tt.same))
			result := AnalyzeArtifact(tt.name+".class", data, DefaultOptions())
			got := findingByRule(result.Findings, "javadisk:class-request-exec") != nil
			if got != tt.want {
				t.Fatalf("finding=%v result=%+v", got, result)
			}
		})
	}
}

func TestAbstractSourcesAndSinksRequireExactOwnersAndDescriptors(t *testing.T) {
	for _, tt := range []struct {
		name    string
		source  memberReference
		sink    memberReference
		finding bool
	}{
		{"exact", fixtureRequestParameter, fixtureRuntimeExec, true},
		{"source owner", memberReference{Owner: "evil/HttpServletRequest", Name: "getParameter", Descriptor: fixtureRequestParameter.Descriptor, Interface: true}, fixtureRuntimeExec, false},
		{"source descriptor", memberReference{Owner: fixtureRequestParameter.Owner, Name: "getParameter", Descriptor: "()Ljava/lang/String;", Interface: true}, fixtureRuntimeExec, false},
		{"sink owner", fixtureRequestParameter, memberReference{Owner: "evil/Runtime", Name: "exec", Descriptor: fixtureRuntimeExec.Descriptor}, false},
		{"sink descriptor", fixtureRequestParameter, memberReference{Owner: fixtureRuntimeExec.Owner, Name: "exec", Descriptor: "()Ljava/lang/Process;"}, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			parsedSource, err := parseMethodDescriptor(tt.source.Descriptor)
			if err != nil {
				t.Fatal(err)
			}
			code := []classInstructionSpec{{Opcode: 0x2a}}
			if len(parsedSource.Parameters) != 0 {
				code = append(code, classInstructionSpec{Opcode: 0x12, Constant: &constantValue{Kind: constantString, String: "cmd"}})
			}
			code = append(code,
				classInstructionSpec{Opcode: 0xb9, Member: &tt.source},
				classInstructionSpec{Opcode: 0x4b}, classInstructionSpec{Opcode: 0xb8, Member: &fixtureRuntimeGet},
				classInstructionSpec{Opcode: 0x2a}, classInstructionSpec{Opcode: 0xb6, Member: &tt.sink},
				classInstructionSpec{Opcode: 0x57}, classInstructionSpec{Opcode: 0xb1},
			)
			data, _ := classBytes(t, classSpec{Name: "fixture/Exact", Methods: []classMethodSpec{{
				Access: 0x0009, Name: "run", Descriptor: "(L" + tt.source.Owner + ";)V",
				MaxStack: 3, MaxLocals: 1, Code: code,
			}}})
			result := AnalyzeArtifact(tt.name+".class", data, DefaultOptions())
			got := findingByRule(result.Findings, "javadisk:class-request-exec") != nil
			if got != tt.finding {
				t.Fatalf("finding=%v result=%+v", got, result)
			}
		})
	}
}

func TestAbstractEntryRequestParameterIsTypedFromDescriptorAndHierarchy(t *testing.T) {
	got := analyzeSpecMethod(t, classSpec{
		Name: "fixture/Servlet", Super: "javax/servlet/http/HttpServlet",
		Methods: []classMethodSpec{{
			Name: "doGet", Descriptor: "(Ljavax/servlet/http/HttpServletRequest;Ljavax/servlet/http/HttpServletResponse;)V",
			MaxLocals: 3, Code: []classInstructionSpec{{Opcode: 0xb1}},
		}},
	}, "doGet", DefaultOptions())
	entry := got.Frames[0]
	if len(entry.Locals) < 2 || entry.Locals[1].Taint == 0 || len(entry.Locals[1].Provenance) == 0 {
		t.Fatalf("entry=%+v analysis=%+v", entry, got)
	}
}

func TestAbstractServletEntriesRequireExactHierarchySignatureAndAccess(t *testing.T) {
	requestResponse := "(Ljavax/servlet/http/HttpServletRequest;Ljavax/servlet/http/HttpServletResponse;)V"
	jakartaRequestResponse := "(Ljakarta/servlet/http/HttpServletRequest;Ljakarta/servlet/http/HttpServletResponse;)V"
	positives := []struct {
		name       string
		class      classModel
		methodName string
		descriptor string
	}{
		{"javax servlet", classModel{Interfaces: []string{"javax/servlet/Servlet"}}, "service", "(Ljavax/servlet/ServletRequest;Ljavax/servlet/ServletResponse;)V"},
		{"jakarta servlet", classModel{Interfaces: []string{"jakarta/servlet/Servlet"}}, "service", "(Ljakarta/servlet/ServletRequest;Ljakarta/servlet/ServletResponse;)V"},
		{"javax http", classModel{Super: "javax/servlet/http/HttpServlet"}, "doPost", requestResponse},
		{"jakarta http", classModel{Super: "jakarta/servlet/http/HttpServlet"}, "doTrace", jakartaRequestResponse},
		{"javax http generic service", classModel{Super: "javax/servlet/http/HttpServlet"}, "service", "(Ljavax/servlet/ServletRequest;Ljavax/servlet/ServletResponse;)V"},
		{"jakarta http generic service", classModel{Super: "jakarta/servlet/http/HttpServlet"}, "service", "(Ljakarta/servlet/ServletRequest;Ljakarta/servlet/ServletResponse;)V"},
		{"javax filter", classModel{Interfaces: []string{"javax/servlet/Filter"}}, "doFilter", "(Ljavax/servlet/ServletRequest;Ljavax/servlet/ServletResponse;Ljavax/servlet/FilterChain;)V"},
		{"jakarta filter", classModel{Interfaces: []string{"jakarta/servlet/Filter"}}, "doFilter", "(Ljakarta/servlet/ServletRequest;Ljakarta/servlet/ServletResponse;Ljakarta/servlet/FilterChain;)V"},
		{"generated jsp", classModel{Super: "org/apache/jasper/runtime/HttpJspBase"}, "_jspService", requestResponse},
		{"javax generic servlet", classModel{Super: "javax/servlet/GenericServlet"}, "service", "(Ljavax/servlet/ServletRequest;Ljavax/servlet/ServletResponse;)V"},
		{"jakarta generic servlet", classModel{Super: "jakarta/servlet/GenericServlet"}, "service", "(Ljakarta/servlet/ServletRequest;Ljakarta/servlet/ServletResponse;)V"},
	}
	for _, tt := range positives {
		t.Run(tt.name, func(t *testing.T) {
			method := &methodModel{Access: 0x0001, Name: tt.methodName, Descriptor: tt.descriptor}
			if !isServletEntry(&tt.class, method) {
				t.Fatalf("exact servlet entry was rejected: class=%+v method=%+v", tt.class, method)
			}
		})
	}

	base := classModel{Super: "javax/servlet/http/HttpServlet"}
	for _, tt := range []methodModel{
		{Access: 0x0009, Name: "doGet", Descriptor: requestResponse},
		{Access: 0x0002, Name: "doGet", Descriptor: requestResponse},
		{Access: 0x0001, Name: "doGet", Descriptor: "(Ljavax/servlet/http/HttpServletRequest;)V"},
		{Access: 0x0001, Name: "doPatch", Descriptor: requestResponse},
		{Access: 0x0001, Name: "_jspService", Descriptor: requestResponse},
	} {
		if isServletEntry(&base, &tt) {
			t.Fatalf("accepted servlet near neighbor: %+v", tt)
		}
	}
	wrongHierarchy := classModel{Super: "example/HttpServlet"}
	if isServletEntry(&wrongHierarchy, &methodModel{Access: 1, Name: "service", Descriptor: requestResponse}) {
		t.Fatal("accepted name-only servlet entry")
	}
	for _, method := range []methodModel{
		{Access: 0x0009, Name: "service", Descriptor: "(Ljavax/servlet/ServletRequest;Ljavax/servlet/ServletResponse;)V"},
		{Access: 0x0001, Name: "service", Descriptor: "(Ljavax/servlet/ServletRequest;)V"},
		{Access: 0x0001, Name: "serviceLike", Descriptor: "(Ljavax/servlet/ServletRequest;Ljavax/servlet/ServletResponse;)V"},
	} {
		if isServletEntry(&classModel{Super: "javax/servlet/GenericServlet"}, &method) {
			t.Fatalf("accepted GenericServlet near neighbor: %+v", method)
		}
	}
}

func TestAbstractPageContextGetRequestReturnsTypedRequestAlias(t *testing.T) {
	getRequest := memberReference{
		Owner: "javax/servlet/jsp/PageContext", Name: "getRequest", Descriptor: "()Ljavax/servlet/ServletRequest;",
	}
	data, _ := classBytes(t, classSpec{Name: "fixture/PageAlias", Methods: []classMethodSpec{{
		Access: 0x0009, Name: "run", MaxStack: 1, Code: []classInstructionSpec{
			{Opcode: 0x01}, {Opcode: 0xb6, Member: &getRequest}, {Opcode: 0x57}, {Opcode: 0xb1},
		},
	}}})
	cf, err := parseClass(data, DefaultOptions().Limits)
	if err != nil {
		t.Fatal(err)
	}
	instructions, err := decodeInstructions(cf.Methods[0].Code.Bytes, 100)
	if err != nil {
		t.Fatal(err)
	}
	state := frame{Stack: []abstractValue{{Verifier: verifierReference, Reference: "javax/servlet/jsp/PageContext", Width: 1}}, Fields: map[fieldKey]abstractValue{}}
	analysis := methodAnalysis{}
	budget := &abstractBudget{limit: DefaultOptions().Limits.MaxStateMerges}
	if err := transferInvoke(cf, instructions[1], &state, &analysis, cf.Methods[0].Code, DefaultOptions(), budget); err != nil {
		t.Fatal(err)
	}
	if len(state.Stack) != 1 || state.Stack[0].Reference != "javax/servlet/ServletRequest" ||
		!isExecutionTainted(state.Stack[0].Taint) || len(state.Stack[0].Provenance) == 0 {
		t.Fatalf("PageContext alias=%+v", state.Stack)
	}
}

func TestAbstractDeterministicFramesAndBoundedProvenance(t *testing.T) {
	opts := DefaultOptions()
	opts.Limits.MaxProvenanceSteps = 2
	first := analyzeSpecMethod(t, fixtureClasses["branch_join"](), "service", opts)
	for i := 0; i < 20; i++ {
		got := analyzeSpecMethod(t, fixtureClasses["branch_join"](), "service", opts)
		if !reflect.DeepEqual(got, first) {
			t.Fatalf("iteration %d got=%+v want=%+v", i, got, first)
		}
	}
	for _, step := range first.Evidence {
		if step.API == "" {
			t.Fatalf("empty evidence step: %+v", first.Evidence)
		}
	}
	if len(first.Evidence) > opts.Limits.MaxProvenanceSteps {
		t.Fatalf("evidence=%+v", first.Evidence)
	}
}

func TestAbstractStateBudgetChargesLargeLocalFrameChainsBeforeRetention(t *testing.T) {
	code := make([]byte, 0, 3*200+1)
	for i := 0; i < 200; i++ {
		code = append(code, 0xa7, 0x00, 0x03)
	}
	code = append(code, 0xb1)
	opts := DefaultOptions()
	opts.Limits.MaxStateMerges = 3_000
	model := &codeModel{MaxLocals: 128, Bytes: code}

	first := analyzeCode(t, model, "()V", opts)
	if first.BudgetExhausted == "" {
		t.Fatalf("analysis retained %d frames without exhausting cumulative state budget", len(first.Frames))
	}
	if len(first.Frames) >= 40 {
		t.Fatalf("retained frames=%d, want deterministic early stop", len(first.Frames))
	}
	second := analyzeCode(t, model, "()V", opts)
	if !reflect.DeepEqual(first, second) {
		t.Fatalf("nondeterministic exhaustion: first=%+v second=%+v", first, second)
	}
}

func TestAbstractBudgetChargesTransientValueClones(t *testing.T) {
	for _, tt := range []struct {
		name string
		code []byte
	}{
		{
			name: "load store clones",
			code: func() []byte {
				code := make([]byte, 0, 121)
				for i := 0; i < 60; i++ {
					code = append(code, 0x2a, 0x4b)
				}
				return append(code, 0xb1)
			}(),
		},
		{
			name: "dup clones",
			code: func() []byte {
				code := []byte{0x2a}
				for i := 0; i < 50; i++ {
					code = append(code, 0x59, 0x57)
				}
				return append(code, 0x57, 0xb1)
			}(),
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			opts := DefaultOptions()
			opts.Limits.MaxProvenanceSteps = 1
			opts.Limits.MaxStateMerges = 300
			analysis := analyzeCode(t, &codeModel{MaxStack: 2, MaxLocals: 1, Bytes: tt.code}, "(Ljava/lang/String;)V", opts)
			if analysis.BudgetExhausted == "" || analysis.WorkUnits > opts.Limits.MaxStateMerges {
				t.Fatalf("transient clones escaped budget: %+v", analysis)
			}
		})
	}
}

func TestAbstractBudgetChargesInvokeArgumentSliceBeforeAllocation(t *testing.T) {
	descriptor := "(" + strings.Repeat("Ljava/lang/String;", 64) + ")V"
	target := memberReference{Owner: "fixture/Target", Name: "consume", Descriptor: descriptor}
	data, _ := classBytes(t, classSpec{Name: "fixture/ManyArgs", Methods: []classMethodSpec{{
		Access: 0x0009, Name: "run", MaxStack: 64, Code: []classInstructionSpec{{Opcode: 0xb8, Member: &target}, {Opcode: 0xb1}},
	}}})
	cf, err := parseClass(data, DefaultOptions().Limits)
	if err != nil {
		t.Fatal(err)
	}
	instructions, err := decodeInstructions(cf.Methods[0].Code.Bytes, 100)
	if err != nil {
		t.Fatal(err)
	}
	state := frame{Fields: map[fieldKey]abstractValue{}}
	for i := 0; i < 64; i++ {
		state.Stack = append(state.Stack, abstractValue{
			Verifier: verifierReference, Reference: "java/lang/String", Width: 1,
			Provenance: []provenanceStep{{Offset: uint32(i), API: "source"}},
		})
	}
	budget := &abstractBudget{limit: 32}
	analysis := methodAnalysis{}
	err = transferInvoke(cf, instructions[0], &state, &analysis, cf.Methods[0].Code, DefaultOptions(), budget)
	if _, ok := err.(*abstractBudgetError); !ok || budget.used > budget.limit {
		t.Fatalf("invoke argument allocation was not precharged: used=%d err=%v", budget.used, err)
	}
}

func TestAbstractFieldMergeOrderIsSortedBeforeBudgetSensitiveWork(t *testing.T) {
	keys := []fieldKey{
		{ObjectID: 3, Owner: "z/Owner", Name: "c", Descriptor: "Ljava/lang/Object;"},
		{ObjectID: 1, Owner: "a/Owner", Name: "b", Descriptor: "Ljava/lang/String;"},
		{ObjectID: 1, Owner: "a/Owner", Name: "a", Descriptor: "Ljava/lang/String;"},
	}
	fields := map[fieldKey]abstractValue{}
	for _, key := range keys {
		fields[key] = abstractValue{Verifier: verifierReference, Reference: "java/lang/Object", Width: 1}
	}
	ordered := orderedFieldKeys(fields)
	if !sort.SliceIsSorted(ordered, func(i, j int) bool { return fieldKeyLess(ordered[i], ordered[j]) }) {
		t.Fatalf("field keys are not sorted: %+v", ordered)
	}
}

func TestAbstractNearBudgetFieldMergeIsDeterministic(t *testing.T) {
	keys := []fieldKey{
		{ObjectID: 1, Owner: "fixture/Budget", Name: "a", Descriptor: "Ljava/lang/Object;"},
		{ObjectID: 2, Owner: "fixture/Budget", Name: "b", Descriptor: "Ljava/lang/Object;"},
		{ObjectID: 3, Owner: "fixture/Budget", Name: "c", Descriptor: "Ljava/lang/Object;"},
	}
	leftValues := map[fieldKey]abstractValue{
		keys[0]: {Verifier: verifierReference, Reference: "java/lang/Object", ObjectID: 10, Width: 1},
		keys[1]: {Verifier: verifierReference, Reference: "java/lang/Object", ObjectID: 20, Width: 1},
		keys[2]: {Verifier: verifierReference, Reference: "java/lang/Object", ObjectIDs: []uint32{30, 31}, Width: 1},
	}
	rightValues := map[fieldKey]abstractValue{
		keys[0]: {Verifier: verifierReference, Reference: "java/lang/Object", ObjectID: 10, Width: 1},
		keys[1]: {Verifier: verifierReference, Reference: "java/lang/Object", ObjectID: 21, Width: 1},
		keys[2]: {Verifier: verifierReference, Reference: "java/lang/Object", ObjectID: 32, Width: 1},
	}
	limits := DefaultOptions().Limits
	limits.MaxProvenanceSteps = 1
	var wantUsed int
	var wantError string
	for iteration := 0; iteration < 100; iteration++ {
		left := frame{Fields: make(map[fieldKey]abstractValue, len(keys))}
		right := frame{Fields: make(map[fieldKey]abstractValue, len(keys))}
		for offset := range keys {
			index := (offset + iteration) % len(keys)
			left.Fields[keys[index]] = leftValues[keys[index]]
			right.Fields[keys[index]] = rightValues[keys[index]]
		}
		budget := &abstractBudget{limit: 23}
		_, _, err := mergeFrames(left, right, limits, budget)
		if err == nil {
			t.Fatal("near-budget merge unexpectedly completed")
		}
		if iteration == 0 {
			wantUsed, wantError = budget.used, err.Error()
			continue
		}
		if budget.used != wantUsed || err.Error() != wantError {
			t.Fatalf("iteration %d used=%d err=%q want used=%d err=%q", iteration, budget.used, err, wantUsed, wantError)
		}
	}
}

func TestAbstractWorkQueueIsBudgetedDeterministicAndCancellable(t *testing.T) {
	run := func(ctx context.Context, limit int) ([]stateWorkItem, int, error, int) {
		budget := &abstractBudget{limit: limit}
		queue := stateWorkQueue{}
		for index := 4095; index >= 0; index-- {
			item := stateWorkItem{Block: uint32((index * 4051) % 4096), Index: index % 31}
			if err := queue.push(ctx, item, budget); err != nil {
				return nil, budget.used, err, queue.len()
			}
		}
		items := make([]stateWorkItem, 0, queue.len())
		for queue.len() != 0 {
			item, err := queue.pop(ctx, budget)
			if err != nil {
				return items, budget.used, err, queue.len()
			}
			items = append(items, item)
		}
		return items, budget.used, nil, 0
	}
	first, firstUnits, err, remaining := run(context.Background(), 1_000_000)
	if err != nil || remaining != 0 || len(first) != 4096 {
		t.Fatalf("first queue run items=%d units=%d remaining=%d err=%v", len(first), firstUnits, remaining, err)
	}
	for index := 1; index < len(first); index++ {
		if stateWorkLess(first[index], first[index-1]) {
			t.Fatalf("queue order is not deterministic at %d: %+v then %+v", index, first[index-1], first[index])
		}
	}
	second, secondUnits, secondErr, secondRemaining := run(context.Background(), 1_000_000)
	if secondErr != nil || secondRemaining != 0 || firstUnits != secondUnits || !reflect.DeepEqual(first, second) {
		t.Fatalf("repeat differs: units=%d/%d remaining=%d err=%v", firstUnits, secondUnits, secondRemaining, secondErr)
	}
	_, lowUnits, lowErr, lowRemaining := run(context.Background(), 128)
	if lowErr == nil || lowUnits > 128 || lowRemaining > lowUnits {
		t.Fatalf("low budget units=%d remaining=%d err=%v", lowUnits, lowRemaining, lowErr)
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	_, _, cancelErr, cancelRemaining := run(cancelled, 1_000_000)
	if !errors.Is(cancelErr, context.Canceled) || cancelRemaining != 0 {
		t.Fatalf("cancel err=%v remaining=%d", cancelErr, cancelRemaining)
	}
}

func TestAbstractHandlerIntervalIndexAvoidsFullTableScans(t *testing.T) {
	handlers := make([]exceptionHandler, 4096)
	for index := range handlers {
		start := uint32(index * 4)
		handlers[index] = exceptionHandler{Start: start, End: start + 3, Handler: 20_000, CatchType: "java/lang/Throwable"}
	}
	run := func(ctx context.Context) (int, int, error) {
		budget := &abstractBudget{limit: 1_000_000}
		index, err := newHandlerIntervalIndex(ctx, handlers, budget)
		if err != nil {
			return 0, budget.used, err
		}
		total := 0
		for offset := uint32(0); offset < uint32(len(handlers))*4; offset += 4 {
			applicable, queryErr := index.applicable(ctx, offset, budget)
			if queryErr != nil {
				return total, budget.used, queryErr
			}
			total += len(applicable)
		}
		return total, budget.used, nil
	}
	firstTotal, firstUnits, err := run(context.Background())
	secondTotal, secondUnits, secondErr := run(context.Background())
	if err != nil || secondErr != nil || firstTotal != len(handlers) || secondTotal != firstTotal || secondUnits != firstUnits {
		t.Fatalf("handler index total=%d/%d units=%d/%d err=%v/%v", firstTotal, secondTotal, firstUnits, secondUnits, err, secondErr)
	}
	if firstUnits >= len(handlers)*len(handlers) {
		t.Fatalf("handler index used quadratic work: %d", firstUnits)
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, cancelErr := run(cancelled); !errors.Is(cancelErr, context.Canceled) {
		t.Fatalf("cancel err=%v", cancelErr)
	}
	midBuild := &analysisCancellingContext{cancelAt: 2}
	budget := &abstractBudget{limit: 1_000_000}
	if _, buildErr := newHandlerIntervalIndex(midBuild, handlers, budget); !errors.Is(buildErr, context.Canceled) {
		t.Fatalf("mid-build cancellation was not observed: err=%v calls=%d", buildErr, midBuild.calls)
	}
}

func TestAbstractFrameEqualityChargesBeforeComparison(t *testing.T) {
	value := abstractValue{Verifier: verifierReference, Reference: "java/lang/String", Width: 1, Provenance: make([]provenanceStep, 16)}
	left := frame{Locals: make([]abstractValue, 256), Fields: map[fieldKey]abstractValue{}}
	for index := range left.Locals {
		left.Locals[index] = value
	}
	right := cloneFrame(left)
	budget := &abstractBudget{limit: 64}
	if _, err := framesEqualBudget(left, right, budget); err == nil || budget.used > budget.limit {
		t.Fatalf("large frame equality bypassed budget: used=%d err=%v", budget.used, err)
	}
}

func TestAbstractFrameEqualityPollsCancellationDuringLargeComparison(t *testing.T) {
	left := frame{Locals: make([]abstractValue, 4096), Fields: map[fieldKey]abstractValue{}}
	for index := range left.Locals {
		left.Locals[index] = abstractValue{Verifier: verifierInt, Width: 1, Constant: "1"}
	}
	right := cloneFrame(left)
	ctx := &analysisCancellingContext{cancelAt: 3}
	budget := &abstractBudget{limit: 100_000, ctx: ctx}
	if _, err := framesEqualBudget(left, right, budget); !errors.Is(err, context.Canceled) {
		t.Fatalf("large frame equality ignored cancellation: err=%v calls=%d used=%d", err, ctx.calls, budget.used)
	}
}

func TestAbstractVerifierPreflightIsBudgetedBeforeStateRetention(t *testing.T) {
	const count = 4096
	blocks := make(map[uint32]*basicBlock, count)
	order := make([]uint32, count)
	stackMaps := make([]stackMapFrame, count)
	for index := 0; index < count; index++ {
		offset := uint32(index)
		order[index] = offset
		blocks[offset] = &basicBlock{Start: offset, Instructions: []instruction{{Offset: offset, Opcode: 0xb1}}}
		stackMaps[index] = stackMapFrame{Offset: offset}
	}
	cfg := &controlFlowGraph{Entry: 0, Blocks: blocks, Order: order}

	stackMapMethod := &methodModel{
		Access: 0x0009, Name: "run", Descriptor: "()V",
		Code: &codeModel{MaxLocals: 1, StackMapFrames: stackMaps},
	}
	opts := DefaultOptions()
	opts.Limits.MaxStateMerges = 1
	stackMapAnalysis := analyzeMethod(&classModel{Name: "fixture/Preflight", Major: 52}, stackMapMethod, cfg, opts, summarySet{})
	if stackMapAnalysis.BudgetExhausted == "" || !strings.Contains(stackMapAnalysis.BudgetExhausted, "StackMap") || stackMapAnalysis.WorkUnits > 1 {
		t.Fatalf("StackMap preflight escaped budget: %+v", stackMapAnalysis)
	}

	handlers := make([]exceptionHandler, count)
	for index := range handlers {
		handlers[index] = exceptionHandler{Start: 0, End: 1, Handler: 0, CatchType: "java/lang/Throwable"}
	}
	handlerMethod := &methodModel{
		Access: 0x0009, Name: "run", Descriptor: "()V",
		Code: &codeModel{MaxLocals: 1, Handlers: handlers},
	}
	handlerAnalysis := analyzeMethod(&classModel{Name: "fixture/Preflight", Major: 49}, handlerMethod,
		&controlFlowGraph{Entry: 0, Blocks: map[uint32]*basicBlock{0: blocks[0]}, Order: []uint32{0}}, opts, summarySet{})
	if handlerAnalysis.BudgetExhausted == "" || !strings.Contains(handlerAnalysis.BudgetExhausted, "handler catch type validation") || handlerAnalysis.WorkUnits > 1 {
		t.Fatalf("handler preflight escaped budget: %+v", handlerAnalysis)
	}
}

func TestAbstractStackMapPreflightPollsCancellationBeforeLateError(t *testing.T) {
	const count = 4096
	blocks := make(map[uint32]*basicBlock, count)
	order := make([]uint32, count)
	stackMaps := make([]stackMapFrame, 0, count+1)
	for index := 0; index < count; index++ {
		offset := uint32(index)
		order[index] = offset
		blocks[offset] = &basicBlock{Start: offset, Instructions: []instruction{{Offset: offset, Opcode: 0xb1}}}
		stackMaps = append(stackMaps, stackMapFrame{Offset: offset})
	}
	stackMaps = append(stackMaps, stackMapFrame{Offset: uint32(count - 1)})
	method := &methodModel{
		Access: 0x0009, Name: "run", Descriptor: "()V",
		Code: &codeModel{MaxLocals: 1, StackMapFrames: stackMaps},
	}
	ctx := &analysisCancellingContext{cancelAt: 2}
	analysis := analyzeMethodContext(ctx, &classModel{Name: "fixture/CancelPreflight", Major: 52}, method,
		&controlFlowGraph{Entry: 0, Blocks: blocks, Order: order}, DefaultOptions())
	if !analysis.Cancelled || analysis.Unsupported != "" || analysis.RequestExec {
		t.Fatalf("late StackMap error won over cancellation: analysis=%+v calls=%d", analysis, ctx.calls)
	}
}

func TestAnalyzeMethodHostileWideWorklistTerminatesDeterministically(t *testing.T) {
	const arms = 2048
	const exit = uint32(10_000)
	targets := make([]uint32, arms)
	cfg := &controlFlowGraph{Entry: 0, Blocks: make(map[uint32]*basicBlock, arms+2), Order: make([]uint32, 0, arms+2)}
	for index := 0; index < arms; index++ {
		start := uint32(100 + index)
		targets[arms-index-1] = start
		cfg.Blocks[start] = &basicBlock{
			Start: start,
			Instructions: []instruction{
				{Offset: start, Opcode: 0x10, Operands: []byte{byte(index)}},
				{Offset: start + 1, Opcode: 0x3c},
				{Offset: start + 2, Opcode: 0xa7, Targets: []uint32{exit}},
			},
			Successors: []uint32{exit},
		}
	}
	cfg.Blocks[0] = &basicBlock{
		Start: 0,
		Instructions: []instruction{
			{Offset: 0, Opcode: 0x1a},
			{Offset: 1, Opcode: 0xab, Targets: targets},
		},
		Successors: targets,
	}
	cfg.Blocks[exit] = &basicBlock{Start: exit, Instructions: []instruction{{Offset: exit, Opcode: 0xb1}}}
	cfg.Order = append(cfg.Order, 0)
	for start := uint32(100); start < 100+arms; start++ {
		cfg.Order = append(cfg.Order, start)
	}
	cfg.Order = append(cfg.Order, exit)
	method := &methodModel{
		Access: 0x0009, Name: "hostile", Descriptor: "(I)V",
		Code: &codeModel{MaxStack: 1, MaxLocals: 2},
	}
	cf := &classModel{Name: "fixture/HostileWorklist", Major: 49}
	opts := DefaultOptions()
	opts.Limits.MaxStateMerges = 120_000
	first := analyzeMethod(cf, method, cfg, opts, summarySet{})
	second := analyzeMethod(cf, method, cfg, opts, summarySet{})
	if first.WorkUnits > opts.Limits.MaxStateMerges || !reflect.DeepEqual(first, second) {
		t.Fatalf("hostile worklist is unbounded/nondeterministic: first=%+v second=%+v", first, second)
	}
	if first.BudgetExhausted == "" {
		t.Fatalf("hostile worklist did not terminate at a configured bound: %+v", first)
	}
	ctx := &analysisCancellingContext{cancelAt: 64}
	cancelled := analyzeMethodContext(ctx, cf, method, cfg, opts)
	if !cancelled.Cancelled || cancelled.RequestExec || cancelled.WorkUnits > opts.Limits.MaxStateMerges {
		t.Fatalf("hostile worklist cancellation failed: analysis=%+v calls=%d", cancelled, ctx.calls)
	}
}

func TestAbstractFieldStateIsBoundedBeforeAddingUniqueKeys(t *testing.T) {
	fields := make([]classFieldSpec, 0, 100)
	code := make([]classInstructionSpec, 0, 201)
	for i := 0; i < 100; i++ {
		name := "F" + string(rune('A'+i%26)) + string(rune('a'+i/26))
		fields = append(fields, classFieldSpec{Access: 0x0009, Name: name, Descriptor: "I"})
		ref := memberReference{Owner: "fixture/ManyFields", Name: name, Descriptor: "I"}
		code = append(code, classInstructionSpec{Opcode: 0x03}, classInstructionSpec{Opcode: 0xb3, Field: &ref})
	}
	code = append(code, classInstructionSpec{Opcode: 0xb1})
	opts := DefaultOptions()
	opts.Limits.MaxFrameSlots = 16
	opts.Limits.MaxStateMerges = 100_000
	analysis := analyzeSpecMethod(t, classSpec{
		Name: "fixture/ManyFields", Fields: fields,
		Methods: []classMethodSpec{{Access: 0x0009, Name: "run", MaxStack: 1, MaxLocals: 1, Code: code}},
	}, "run", opts)
	if analysis.BudgetExhausted == "" {
		t.Fatalf("analysis accepted 100 retained field keys: %+v", analysis)
	}
	for start, state := range analysis.Frames {
		if len(state.Fields)+len(state.Locals)+stackSlots(state.Stack) > opts.Limits.MaxFrameSlots {
			t.Fatalf("frame %d retained unbounded state: locals=%d stack=%d fields=%d", start, len(state.Locals), stackSlots(state.Stack), len(state.Fields))
		}
	}
}

type analysisCancellingContext struct {
	calls    int
	cancelAt int
}

func (*analysisCancellingContext) Deadline() (time.Time, bool) { return time.Time{}, false }
func (*analysisCancellingContext) Done() <-chan struct{}       { return nil }
func (*analysisCancellingContext) Value(any) any               { return nil }
func (c *analysisCancellingContext) Err() error {
	c.calls++
	if c.calls >= c.cancelAt {
		return context.Canceled
	}
	return nil
}

func TestAnalyzeMethodContextCancelsWithinLongBlockAndDiscardsFlow(t *testing.T) {
	code := append(make([]byte, 700), 0xb1)
	model := &codeModel{Bytes: code}
	ins, err := decodeInstructions(code, 10_000)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := buildCFG(model, ins)
	if err != nil {
		t.Fatal(err)
	}
	ctx := &analysisCancellingContext{cancelAt: 4}
	analysis := analyzeMethodContext(ctx, &classModel{Name: "fixture/Cancel"}, &methodModel{
		Access: 0x0009, Name: "run", Descriptor: "()V", Code: model,
	}, cfg, DefaultOptions())
	if !analysis.Cancelled || analysis.RequestExec || analysis.Unsupported != "" || analysis.BudgetExhausted != "" {
		t.Fatalf("analysis=%+v calls=%d", analysis, ctx.calls)
	}
	if ctx.calls > 8 {
		t.Fatalf("cancellation polling was not bounded: calls=%d", ctx.calls)
	}
}

func TestInstructionMayThrowCatalogIsAuditable(t *testing.T) {
	throwing := []byte{
		0x2e, 0x4f, 0x6c, 0x6d, 0x70, 0x71,
		0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8, 0xb9, 0xba,
		0xbb, 0xbc, 0xbd, 0xbe, 0xbf, 0xc0, 0xc2, 0xc3, 0xc5,
	}
	for _, opcode := range throwing {
		if !instructionMayThrow(nil, instruction{Opcode: opcode}) {
			t.Errorf("opcode 0x%02x classified nonthrowing", opcode)
		}
	}
	for _, opcode := range []byte{0x00, 0x03, 0x3b, 0x60, 0x84, 0x99, 0xa7, 0xac, 0xb1} {
		if instructionMayThrow(nil, instruction{Opcode: opcode}) {
			t.Errorf("opcode 0x%02x classified throwing", opcode)
		}
	}
	if !instructionMayThrow(nil, instruction{Opcode: 0xc1}) {
		t.Error("instanceof was classified nonthrowing")
	}
	for _, tt := range []struct {
		tag  uint8
		want bool
	}{{cpInteger, false}, {cpFloat, false}, {cpString, true}, {cpClass, true}, {cpMethodType, true}, {cpMethodHandle, true}, {cpDynamic, true}} {
		cf := &classModel{Pool: []cpEntry{{}, {tag: tt.tag}}}
		if got := instructionMayThrow(cf, instruction{Opcode: 0x12, Operands: []byte{1}}); got != tt.want {
			t.Errorf("ldc tag %d throwing=%v want %v", tt.tag, got, tt.want)
		}
	}
}

func TestAbstractInstanceofPropagatesLinkageExceptionState(t *testing.T) {
	analysis := analyzeSpecMethod(t, classSpec{Name: "fixture/InstanceofHandler", Methods: []classMethodSpec{{
		Access: 0x0009, Name: "run", MaxStack: 1,
		Code: []classInstructionSpec{
			{Opcode: 0x01}, {Opcode: 0xc1, ClassName: "java/lang/String"},
			{Opcode: 0x57}, {Opcode: 0xb1}, {Opcode: 0x57}, {Opcode: 0xb1},
		},
		Handlers: []exceptionHandler{{Start: 1, End: 4, Handler: 6, CatchType: "java/lang/LinkageError"}},
	}}}, "run", DefaultOptions())
	if analysis.Unsupported != "" || analysis.BudgetExhausted != "" {
		t.Fatalf("analysis=%+v", analysis)
	}
	if handler, ok := analysis.Frames[6]; !ok || len(handler.Stack) != 1 || handler.Stack[0].Verifier != verifierReference {
		t.Fatalf("missing instanceof exception state: %+v", analysis.Frames)
	}
}

func TestAbstractExceptionStateUsesPreInstructionLocals(t *testing.T) {
	yield := memberReference{Owner: "java/lang/Thread", Name: "yield", Descriptor: "()V"}
	tests := []struct {
		name      string
		code      []classInstructionSpec
		handler   exceptionHandler
		wantLocal bool
	}{
		{
			name: "write before later throw is retained",
			code: []classInstructionSpec{
				{Opcode: 0x03}, {Opcode: 0x3b}, {Opcode: 0xb8, Member: &yield}, {Opcode: 0xb1},
				{Opcode: 0x57}, {Opcode: 0xb1},
			},
			handler: exceptionHandler{Start: 2, End: 5, Handler: 6}, wantLocal: true,
		},
		{
			name: "write after earlier throw is absent",
			code: []classInstructionSpec{
				{Opcode: 0xb8, Member: &yield}, {Opcode: 0x03}, {Opcode: 0x3b}, {Opcode: 0xb1},
				{Opcode: 0x57}, {Opcode: 0xb1},
			},
			handler: exceptionHandler{Start: 0, End: 3, Handler: 6}, wantLocal: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			analysis := analyzeSpecMethod(t, classSpec{Name: "fixture/ThrowState", Methods: []classMethodSpec{{
				Access: 0x0009, Name: "run", MaxStack: 1, MaxLocals: 1, Code: tt.code,
				Handlers: []exceptionHandler{tt.handler},
			}}}, "run", DefaultOptions())
			if analysis.Unsupported != "" || analysis.BudgetExhausted != "" {
				t.Fatalf("analysis=%+v", analysis)
			}
			entry, ok := analysis.Frames[tt.handler.Handler]
			if !ok || len(entry.Stack) != 1 || entry.Stack[0].Verifier != verifierReference {
				t.Fatalf("handler entry=%+v analysis=%+v", entry, analysis)
			}
			gotLocal := len(entry.Locals) != 0 && entry.Locals[0].Verifier == verifierInt
			if gotLocal != tt.wantLocal {
				t.Fatalf("handler local int=%v want %v entry=%+v", gotLocal, tt.wantLocal, entry)
			}
		})
	}
}

func TestAbstractNonthrowingProtectedInstructionsDoNotCreateHandlerState(t *testing.T) {
	analysis := analyzeCode(t, &codeModel{
		MaxStack: 1, MaxLocals: 1,
		Bytes:    []byte{0x03, 0x3b, 0xa7, 0x00, 0x04, 0x57, 0xb1},
		Handlers: []exceptionHandler{{Start: 0, End: 2, Handler: 5}},
	}, "()V", DefaultOptions())
	if analysis.Unsupported != "" || analysis.BudgetExhausted != "" {
		t.Fatalf("analysis=%+v", analysis)
	}
	if _, ok := analysis.Frames[5]; ok {
		t.Fatalf("nonthrowing protected instructions created handler frame: %+v", analysis.Frames[5])
	}
}

func TestAbstractVerifierRejectsInvalidRuntimeReceiverBeforePromotion(t *testing.T) {
	source := fixtureRequestParameter
	exec := fixtureRuntimeExec
	data, _ := classBytes(t, classSpec{Name: "fixture/BadReceiver", Major: 49, Methods: []classMethodSpec{{
		Access: 0x0009, Name: "run", MaxStack: 3, Code: []classInstructionSpec{
			{Opcode: 0x03},
			{Opcode: 0xbb, ClassName: "fixture/ExternalRequest"}, {Opcode: 0x12, Constant: &constantValue{Kind: constantString, String: "cmd"}},
			{Opcode: 0xb9, Member: &source},
			{Opcode: 0xb6, Member: &exec}, {Opcode: 0x57}, {Opcode: 0xb1},
		},
	}}})
	result := AnalyzeArtifact("BadReceiver.class", data, DefaultOptions())
	if findingByRule(result.Findings, "javadisk:class-request-exec") != nil ||
		!hasDiagnosticCode(result.Diagnostics, diagBytecodeUnsupported) {
		t.Fatalf("result=%+v", result)
	}
}

func TestAbstractVerifierRejectsWidthCompatibleWrongTypes(t *testing.T) {
	tests := []struct {
		name       string
		descriptor string
		code       []byte
		maxStack   uint16
	}{
		{"int returned as reference", "()Ljava/lang/String;", []byte{0x03, 0xb0}, 1},
		{"null returned as int", "()I", []byte{0x01, 0xac}, 1},
		{"int used by ifnull", "()V", []byte{0x03, 0xc6, 0x00, 0x03, 0xb1}, 1},
		{"null used by ifeq", "()V", []byte{0x01, 0x99, 0x00, 0x03, 0xb1}, 1},
		{"mixed if_acmp operands", "()V", []byte{0x03, 0x01, 0xa5, 0x00, 0x03, 0xb1}, 2},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			analysis := analyzeCode(t, &codeModel{MaxStack: tt.maxStack, Bytes: tt.code}, tt.descriptor, DefaultOptions())
			if analysis.Unsupported == "" {
				t.Fatalf("accepted verifier-invalid bytecode: %+v", analysis)
			}
		})
	}
}

func TestAbstractVerifierRejectsInvalidFieldAndArrayShapes(t *testing.T) {
	field := memberReference{Owner: "fixture/Typed", Name: "command", Descriptor: "Ljava/lang/String;"}
	tests := []struct {
		name string
		code []classInstructionSpec
	}{
		{"getfield int receiver", []classInstructionSpec{{Opcode: 0x03}, {Opcode: 0xb4, Field: &field}, {Opcode: 0x57}, {Opcode: 0xb1}}},
		{"putfield int value", []classInstructionSpec{{Opcode: 0x01}, {Opcode: 0x03}, {Opcode: 0xb5, Field: &field}, {Opcode: 0xb1}}},
		{"aaload int index mismatch", []classInstructionSpec{{Opcode: 0x04}, {Opcode: 0xbc, Operands: []byte{10}}, {Opcode: 0x03}, {Opcode: 0x32}, {Opcode: 0x57}, {Opcode: 0xb1}}},
		{"iastore reference value", []classInstructionSpec{{Opcode: 0x04}, {Opcode: 0xbc, Operands: []byte{10}}, {Opcode: 0x03}, {Opcode: 0x01}, {Opcode: 0x4f}, {Opcode: 0xb1}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			analysis := analyzeSpecMethod(t, classSpec{Name: "fixture/Typed", Fields: []classFieldSpec{{Name: field.Name, Descriptor: field.Descriptor}}, Methods: []classMethodSpec{{
				Access: 0x0009, Name: "run", MaxStack: 4, Code: tt.code,
			}}}, "run", DefaultOptions())
			if analysis.Unsupported == "" {
				t.Fatalf("accepted verifier-invalid bytecode: %+v", analysis)
			}
		})
	}
}

func TestAbstractVerifierRejectsInvokeArgumentCategory(t *testing.T) {
	data, _ := classBytes(t, classSpec{Name: "fixture/BadArgument", Methods: []classMethodSpec{{
		Access: 0x0009, Name: "run", MaxStack: 2, Code: []classInstructionSpec{
			{Opcode: 0xb8, Member: &fixtureRuntimeGet}, {Opcode: 0x03},
			{Opcode: 0xb6, Member: &fixtureRuntimeExec}, {Opcode: 0x57}, {Opcode: 0xb1},
		},
	}}})
	result := AnalyzeArtifact("BadArgument.class", data, DefaultOptions())
	if findingByRule(result.Findings, "javadisk:class-request-exec") != nil ||
		!hasDiagnosticCode(result.Diagnostics, diagBytecodeUnsupported) {
		t.Fatalf("result=%+v", result)
	}
}

func TestAbstractRejectsKnownImpossibleRequestReceivers(t *testing.T) {
	for _, tt := range []struct {
		name     string
		receiver classInstructionSpec
	}{
		{"string receiver", classInstructionSpec{Opcode: 0x12, Constant: &constantValue{Kind: constantString, String: "not-a-request"}}},
		{"array receiver", classInstructionSpec{Opcode: 0x04}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			code := []classInstructionSpec{tt.receiver}
			if tt.name == "array receiver" {
				code = append(code, classInstructionSpec{Opcode: 0xbd, ClassName: "java/lang/String"})
			}
			code = append(code,
				classInstructionSpec{Opcode: 0x12, Constant: &constantValue{Kind: constantString, String: "cmd"}},
				classInstructionSpec{Opcode: 0xb9, Member: &fixtureRequestParameter},
				classInstructionSpec{Opcode: 0x4b},
				classInstructionSpec{Opcode: 0xb8, Member: &fixtureRuntimeGet},
				classInstructionSpec{Opcode: 0x2a},
				classInstructionSpec{Opcode: 0xb6, Member: &fixtureRuntimeExec},
				classInstructionSpec{Opcode: 0x57}, classInstructionSpec{Opcode: 0xb1},
			)
			data, _ := classBytes(t, classSpec{Name: "fixture/ImpossibleReceiver", Methods: []classMethodSpec{{
				Access: 0x0009, Name: "run", MaxStack: 3, MaxLocals: 1, Code: code,
			}}})
			result := AnalyzeArtifact(tt.name+".class", data, DefaultOptions())
			if findingByRule(result.Findings, "javadisk:class-request-exec") != nil ||
				!hasDiagnosticCode(result.Diagnostics, diagBytecodeUnsupported) {
				t.Fatalf("result=%+v", result)
			}
		})
	}
}

func TestAbstractNullRequestReceiverHasOnlyExceptionalFlow(t *testing.T) {
	data, _ := classBytes(t, classSpec{Name: "fixture/NullRequest", Major: 49, Methods: []classMethodSpec{{
		Access: 0x0009, Name: "run", MaxStack: 2, MaxLocals: 1,
		Code: []classInstructionSpec{
			{Opcode: 0x01},
			{Opcode: 0x12, Constant: &constantValue{Kind: constantString, String: "cmd"}},
			{Opcode: 0xb9, Member: &fixtureRequestParameter},
			{Opcode: 0x4b}, {Opcode: 0xb8, Member: &fixtureRuntimeGet}, {Opcode: 0x2a},
			{Opcode: 0xb6, Member: &fixtureRuntimeExec}, {Opcode: 0x57}, {Opcode: 0xb1},
			{Opcode: 0x57}, {Opcode: 0xb1},
		},
		Handlers: []exceptionHandler{{Start: 3, End: 8, Handler: 18, CatchType: "java/lang/Throwable"}},
	}}})
	cf, err := parseClass(data, DefaultOptions().Limits)
	if err != nil {
		t.Fatal(err)
	}
	instructions, err := decodeInstructions(cf.Methods[0].Code.Bytes, 100)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := buildCFG(cf.Methods[0].Code, instructions)
	if err != nil {
		t.Fatal(err)
	}
	analysis := analyzeMethod(cf, &cf.Methods[0], cfg, DefaultOptions(), summarySet{})
	if analysis.Unsupported != "" || analysis.BudgetExhausted != "" || analysis.RequestExec {
		t.Fatalf("analysis=%+v", analysis)
	}
	if _, ok := analysis.Frames[8]; ok {
		t.Fatalf("null receiver produced a normal invoke result: %+v", analysis.Frames)
	}
	if handler, ok := analysis.Frames[18]; !ok || len(handler.Stack) != 1 {
		t.Fatalf("missing exceptional-only handler state: %+v", analysis.Frames)
	}
}

func TestAbstractRejectsIllegalInvokeSpecialNamesAndOpcodes(t *testing.T) {
	constructor := memberReference{Owner: "java/lang/ProcessBuilder", Name: "<init>", Descriptor: "([Ljava/lang/String;)V"}
	clinit := memberReference{Owner: "fixture/IllegalInvoke", Name: "<clinit>", Descriptor: "()V"}
	for _, tt := range []struct {
		name string
		code []classInstructionSpec
	}{
		{
			name: "constructor via invokevirtual",
			code: []classInstructionSpec{
				{Opcode: 0xbb, ClassName: "java/lang/ProcessBuilder"}, {Opcode: 0x59},
				{Opcode: 0x04}, {Opcode: 0xbd, ClassName: "java/lang/String"},
				{Opcode: 0xb6, Member: &constructor}, {Opcode: 0x4b}, {Opcode: 0x2a},
				{Opcode: 0xb6, Member: &memberReference{Owner: "java/lang/ProcessBuilder", Name: "start", Descriptor: "()Ljava/lang/Process;"}},
				{Opcode: 0x57}, {Opcode: 0xb1},
			},
		},
		{name: "clinit via invokestatic", code: []classInstructionSpec{{Opcode: 0xb8, Member: &clinit}, {Opcode: 0xb1}}},
		{name: "init via invokestatic", code: []classInstructionSpec{{Opcode: 0x04}, {Opcode: 0xbd, ClassName: "java/lang/String"}, {Opcode: 0xb8, Member: &constructor}, {Opcode: 0xb1}}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if tt.name == "clinit via invokestatic" {
				data, _ := classBytes(t, classSpec{Name: "fixture/IllegalInvoke", Major: 49, Methods: []classMethodSpec{{
					Access: 0x0009, Name: "run", MaxStack: 4, MaxLocals: 1, Code: tt.code,
				}}})
				result := AnalyzeArtifact("IllegalInvoke.class", data, DefaultOptions())
				if findingByRule(result.Findings, "javadisk:class-request-exec") != nil ||
					!hasDiagnosticCode(result.Diagnostics, diagClassMalformed) {
					t.Fatalf("illegal class initializer reference accepted: %+v", result)
				}
				return
			}
			analysis := analyzeSpecMethod(t, classSpec{Name: "fixture/IllegalInvoke", Methods: []classMethodSpec{{
				Access: 0x0009, Name: "run", MaxStack: 4, MaxLocals: 1, Code: tt.code,
			}}}, "run", DefaultOptions())
			if analysis.Unsupported == "" || analysis.RequestExec {
				t.Fatalf("illegal invoke accepted: %+v", analysis)
			}
		})
	}
}

func TestAbstractRejectsInvokeSpecialRuntimeExecSink(t *testing.T) {
	data, _ := classBytes(t, classSpec{
		Name: "fixture/SpecialRuntime", Super: "javax/servlet/http/HttpServlet",
		Methods: []classMethodSpec{{
			Name: "service", Descriptor: "(Ljavax/servlet/http/HttpServletRequest;Ljavax/servlet/http/HttpServletResponse;)V",
			MaxStack: 3, MaxLocals: 4, Code: []classInstructionSpec{
				{Opcode: 0x2b}, {Opcode: 0x12, Constant: &constantValue{Kind: constantString, String: "cmd"}},
				{Opcode: 0xb9, Member: &fixtureRequestParameter}, {Opcode: 0x4e},
				{Opcode: 0xb8, Member: &fixtureRuntimeGet}, {Opcode: 0x2d},
				{Opcode: 0xb7, Member: &fixtureRuntimeExec}, {Opcode: 0x57}, {Opcode: 0xb1},
			},
		}},
	})
	result := AnalyzeArtifact("SpecialRuntime.class", data, DefaultOptions())
	if findingByRule(result.Findings, "javadisk:class-request-exec") != nil ||
		!hasDiagnosticCode(result.Diagnostics, diagBytecodeUnsupported) {
		t.Fatalf("illegal invokespecial result=%+v", result)
	}
}

func TestAbstractRejectsUninitializedRuntimeSinkReceiver(t *testing.T) {
	data, _ := classBytes(t, classSpec{
		Name: "fixture/UninitializedRuntime", Super: "javax/servlet/http/HttpServlet",
		Methods: []classMethodSpec{{
			Name: "service", Descriptor: "(Ljavax/servlet/http/HttpServletRequest;Ljavax/servlet/http/HttpServletResponse;)V",
			MaxStack: 3, MaxLocals: 4, Code: []classInstructionSpec{
				{Opcode: 0x2b}, {Opcode: 0x12, Constant: &constantValue{Kind: constantString, String: "cmd"}},
				{Opcode: 0xb9, Member: &fixtureRequestParameter}, {Opcode: 0x4e},
				{Opcode: 0xbb, ClassName: "java/lang/Runtime"}, {Opcode: 0x2d},
				{Opcode: 0xb6, Member: &fixtureRuntimeExec}, {Opcode: 0x57}, {Opcode: 0xb1},
			},
		}},
	})
	result := AnalyzeArtifact("UninitializedRuntime.class", data, DefaultOptions())
	if findingByRule(result.Findings, "javadisk:class-request-exec") != nil ||
		!hasDiagnosticCode(result.Diagnostics, diagBytecodeUnsupported) {
		t.Fatalf("uninitialized Runtime result=%+v", result)
	}
}

func TestAbstractTracksUninitializedAliasesAndRejectsProhibitedUses(t *testing.T) {
	processBuilderInit := memberReference{Owner: "java/lang/ProcessBuilder", Name: "<init>", Descriptor: "([Ljava/lang/String;)V"}
	objectInit := memberReference{Owner: "java/lang/Object", Name: "<init>", Descriptor: "()V"}
	consume := memberReference{Owner: "fixture/UninitializedUses", Name: "consume", Descriptor: "(Ljava/lang/Object;)V"}
	field := memberReference{Owner: "fixture/UninitializedUses", Name: "value", Descriptor: "Ljava/lang/Object;"}
	tests := []struct {
		name       string
		descriptor string
		maxStack   uint16
		maxLocals  uint16
		code       []classInstructionSpec
	}{
		{
			name: "double initialization", descriptor: "()V", maxStack: 3,
			code: []classInstructionSpec{
				{Opcode: 0xbb, ClassName: "java/lang/ProcessBuilder"}, {Opcode: 0x59},
				{Opcode: 0x03}, {Opcode: 0xbd, ClassName: "java/lang/String"},
				{Opcode: 0xb7, Member: &processBuilderInit}, {Opcode: 0x59}, {Opcode: 0x03},
				{Opcode: 0xbd, ClassName: "java/lang/String"}, {Opcode: 0xb7, Member: &processBuilderInit},
				{Opcode: 0x57}, {Opcode: 0xb1},
			},
		},
		{
			name: "wrong constructor owner", descriptor: "()V", maxStack: 2,
			code: []classInstructionSpec{
				{Opcode: 0xbb, ClassName: "java/lang/ProcessBuilder"}, {Opcode: 0x59},
				{Opcode: 0xb7, Member: &objectInit}, {Opcode: 0x57}, {Opcode: 0xb1},
			},
		},
		{
			name: "method argument before init", descriptor: "()V", maxStack: 1,
			code: []classInstructionSpec{
				{Opcode: 0xbb, ClassName: "java/lang/ProcessBuilder"},
				{Opcode: 0xb8, Member: &consume}, {Opcode: 0xb1},
			},
		},
		{
			name: "return before init", descriptor: "()Ljava/lang/Object;", maxStack: 1,
			code: []classInstructionSpec{{Opcode: 0xbb, ClassName: "java/lang/ProcessBuilder"}, {Opcode: 0xb0}},
		},
		{
			name: "field store before init", descriptor: "()V", maxStack: 1,
			code: []classInstructionSpec{
				{Opcode: 0xbb, ClassName: "java/lang/ProcessBuilder"},
				{Opcode: 0xb3, Field: &field}, {Opcode: 0xb1},
			},
		},
		{
			name: "array store before init", descriptor: "()V", maxStack: 3,
			code: []classInstructionSpec{
				{Opcode: 0x04}, {Opcode: 0xbd, ClassName: "java/lang/Object"}, {Opcode: 0x03},
				{Opcode: 0xbb, ClassName: "java/lang/ProcessBuilder"}, {Opcode: 0x53}, {Opcode: 0xb1},
			},
		},
		{
			name: "checkcast before init", descriptor: "()V", maxStack: 1,
			code: []classInstructionSpec{
				{Opcode: 0xbb, ClassName: "java/lang/ProcessBuilder"},
				{Opcode: 0xc0, ClassName: "java/lang/Object"}, {Opcode: 0x57}, {Opcode: 0xb1},
			},
		},
		{
			name: "monitor before init", descriptor: "()V", maxStack: 1,
			code: []classInstructionSpec{
				{Opcode: 0xbb, ClassName: "java/lang/ProcessBuilder"}, {Opcode: 0xc2}, {Opcode: 0xb1},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			analysis := analyzeSpecMethod(t, classSpec{
				Name:   "fixture/UninitializedUses",
				Fields: []classFieldSpec{{Access: 0x0009, Name: "value", Descriptor: "Ljava/lang/Object;"}},
				Methods: []classMethodSpec{
					{Access: 0x0009, Name: "consume", Descriptor: "(Ljava/lang/Object;)V", MaxLocals: 1, Code: []classInstructionSpec{{Opcode: 0xb1}}},
					{Access: 0x0009, Name: "run", Descriptor: tt.descriptor, MaxStack: tt.maxStack, MaxLocals: tt.maxLocals, Code: tt.code},
				},
			}, "run", DefaultOptions())
			if analysis.Unsupported == "" || analysis.RequestExec {
				t.Fatalf("accepted prohibited uninitialized use: %+v", analysis)
			}
		})
	}
}

func TestAbstractInitializesEveryAllocationAliasExactlyOnce(t *testing.T) {
	constructor := memberReference{Owner: "java/lang/ProcessBuilder", Name: "<init>", Descriptor: "([Ljava/lang/String;)V"}
	analysis := analyzeSpecMethod(t, classSpec{Name: "fixture/InitializedAlias", Methods: []classMethodSpec{{
		Access: 0x0009, Name: "run", Descriptor: "()V", MaxStack: 3, MaxLocals: 1,
		Code: []classInstructionSpec{
			{Opcode: 0xbb, ClassName: "java/lang/ProcessBuilder"}, {Opcode: 0x59}, {Opcode: 0x4b},
			{Opcode: 0x03}, {Opcode: 0xbd, ClassName: "java/lang/String"}, {Opcode: 0xb7, Member: &constructor},
			{Opcode: 0x2a}, {Opcode: 0x57}, {Opcode: 0xb1},
		},
	}}}, "run", DefaultOptions())
	if analysis.Unsupported != "" || analysis.BudgetExhausted != "" {
		t.Fatalf("legal alias initialization failed: %+v", analysis)
	}
}

func TestAbstractConstructorMustInitializeThisBeforeReturn(t *testing.T) {
	analysis := analyzeSpecMethod(t, classSpec{Name: "fixture/BadConstructor", Methods: []classMethodSpec{{
		Access: 0x0001, Name: "<init>", Descriptor: "()V", MaxLocals: 1,
		Code: []classInstructionSpec{{Opcode: 0xb1}},
	}}}, "<init>", DefaultOptions())
	if analysis.Unsupported == "" {
		t.Fatalf("constructor returned with uninitializedThis: %+v", analysis)
	}

	objectInit := memberReference{Owner: "java/lang/Object", Name: "<init>", Descriptor: "()V"}
	valid := analyzeSpecMethod(t, classSpec{Name: "fixture/GoodConstructor", Super: "java/lang/Object", Methods: []classMethodSpec{{
		Access: 0x0001, Name: "<init>", Descriptor: "()V", MaxStack: 1, MaxLocals: 1,
		Code: []classInstructionSpec{{Opcode: 0x2a}, {Opcode: 0xb7, Member: &objectInit}, {Opcode: 0xb1}},
	}}}, "<init>", DefaultOptions())
	if valid.Unsupported != "" || valid.BudgetExhausted != "" {
		t.Fatalf("legal constructor initialization failed: %+v", valid)
	}
}

func TestAbstractConstructorCompletionDoesNotDependOnLocalZero(t *testing.T) {
	tests := []struct {
		name      string
		maxStack  uint16
		maxLocals uint16
		code      []classInstructionSpec
	}{
		{
			name: "overwritten local zero", maxStack: 1, maxLocals: 1,
			code: []classInstructionSpec{{Opcode: 0x01}, {Opcode: 0x4b}, {Opcode: 0xb1}},
		},
		{
			name: "moved then overwritten local zero", maxStack: 1, maxLocals: 2,
			code: []classInstructionSpec{{Opcode: 0x2a}, {Opcode: 0x4c}, {Opcode: 0x01}, {Opcode: 0x4b}, {Opcode: 0xb1}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			analysis := analyzeSpecMethod(t, classSpec{Name: "fixture/ConstructorFlag", Methods: []classMethodSpec{{
				Access: 0x0001, Name: "<init>", Descriptor: "()V", MaxStack: tt.maxStack,
				MaxLocals: tt.maxLocals, Code: tt.code,
			}}}, "<init>", DefaultOptions())
			if analysis.Unsupported == "" {
				t.Fatalf("constructor returned without initializing this: %+v", analysis)
			}
		})
	}
}

func TestAbstractFailedThisInitializationPoisonsHandlerAliases(t *testing.T) {
	objectInit := memberReference{Owner: "java/lang/Object", Name: "<init>", Descriptor: "()V"}
	analysis := analyzeSpecMethod(t, classSpec{Name: "fixture/ProtectedConstructor", Super: "java/lang/Object", Methods: []classMethodSpec{{
		Access: 0x0001, Name: "<init>", Descriptor: "()V", MaxStack: 1, MaxLocals: 2,
		Code: []classInstructionSpec{
			{Opcode: 0x2a}, {Opcode: 0xb7, Member: &objectInit}, {Opcode: 0xb1},
			{Opcode: 0x4c}, {Opcode: 0x2a}, {Opcode: 0xb7, Member: &objectInit}, {Opcode: 0xb1},
		},
		Handlers: []exceptionHandler{{Start: 1, End: 4, Handler: 5, CatchType: "java/lang/Throwable"}},
	}}}, "<init>", DefaultOptions())
	if analysis.Unsupported == "" {
		t.Fatalf("handler reused uninitializedThis after failed initialization: %+v", analysis)
	}
}

func TestAbstractUnresolvedInvocationReturnsAreUnproven(t *testing.T) {
	fakeRuntime := memberReference{Owner: "missing/Factory", Name: "runtime", Descriptor: "()Ljava/lang/Runtime;"}
	fakeRequest := memberReference{Owner: "missing/Factory", Name: "request", Descriptor: "()Ljavax/servlet/http/HttpServletRequest;"}
	fakeTransform := memberReference{Owner: "missing/Factory", Name: "transform", Descriptor: "(Ljava/lang/String;)Ljava/lang/String;"}
	fakeBuilder := memberReference{Owner: "missing/Factory", Name: "builder", Descriptor: "([Ljava/lang/String;)Ljava/lang/ProcessBuilder;"}
	startBuilder := memberReference{Owner: "java/lang/ProcessBuilder", Name: "start", Descriptor: "()Ljava/lang/Process;"}
	tests := []struct {
		name     string
		code     []classInstructionSpec
		handlers []exceptionHandler
	}{
		{
			name: "runtime direct",
			code: []classInstructionSpec{
				{Opcode: 0x2b}, {Opcode: 0x12, Constant: &constantValue{Kind: constantString, String: "cmd"}},
				{Opcode: 0xb9, Member: &fixtureRequestParameter}, {Opcode: 0x4e},
				{Opcode: 0xb8, Member: &fakeRuntime}, {Opcode: 0x2d},
				{Opcode: 0xb6, Member: &fixtureRuntimeExec}, {Opcode: 0x57}, {Opcode: 0xb1},
			},
		},
		{
			name: "runtime store load cast",
			code: []classInstructionSpec{
				{Opcode: 0x2b}, {Opcode: 0x12, Constant: &constantValue{Kind: constantString, String: "cmd"}},
				{Opcode: 0xb9, Member: &fixtureRequestParameter}, {Opcode: 0x4e},
				{Opcode: 0xb8, Member: &fakeRuntime}, {Opcode: 0x3a, Operands: []byte{4}},
				{Opcode: 0x19, Operands: []byte{4}}, {Opcode: 0xc0, ClassName: "java/lang/Runtime"}, {Opcode: 0x2d},
				{Opcode: 0xb6, Member: &fixtureRuntimeExec}, {Opcode: 0x57}, {Opcode: 0xb1},
			},
		},
		{
			name: "request source",
			code: []classInstructionSpec{
				{Opcode: 0xb8, Member: &fakeRequest},
				{Opcode: 0x12, Constant: &constantValue{Kind: constantString, String: "cmd"}},
				{Opcode: 0xb9, Member: &fixtureRequestParameter}, {Opcode: 0x4e},
				{Opcode: 0xb8, Member: &fixtureRuntimeGet}, {Opcode: 0x2d},
				{Opcode: 0xb6, Member: &fixtureRuntimeExec}, {Opcode: 0x57}, {Opcode: 0xb1},
			},
		},
		{
			name: "unresolved taint transform",
			code: []classInstructionSpec{
				{Opcode: 0x2b}, {Opcode: 0x12, Constant: &constantValue{Kind: constantString, String: "cmd"}},
				{Opcode: 0xb9, Member: &fixtureRequestParameter}, {Opcode: 0xb8, Member: &fakeTransform}, {Opcode: 0x3a, Operands: []byte{4}},
				{Opcode: 0xb8, Member: &fixtureRuntimeGet}, {Opcode: 0x19, Operands: []byte{4}},
				{Opcode: 0xb6, Member: &fixtureRuntimeExec}, {Opcode: 0x57}, {Opcode: 0xb1},
			},
		},
		{
			name: "process builder return",
			code: []classInstructionSpec{
				{Opcode: 0x04}, {Opcode: 0xbd, ClassName: "java/lang/String"}, {Opcode: 0x3a, Operands: []byte{4}},
				{Opcode: 0x19, Operands: []byte{4}}, {Opcode: 0x03}, {Opcode: 0x2b},
				{Opcode: 0x12, Constant: &constantValue{Kind: constantString, String: "cmd"}},
				{Opcode: 0xb9, Member: &fixtureRequestParameter}, {Opcode: 0x53},
				{Opcode: 0x19, Operands: []byte{4}}, {Opcode: 0xb8, Member: &fakeBuilder},
				{Opcode: 0xb6, Member: &startBuilder}, {Opcode: 0x57}, {Opcode: 0xb1},
			},
		},
		{
			name: "exception handler",
			code: []classInstructionSpec{
				{Opcode: 0x2b}, {Opcode: 0x12, Constant: &constantValue{Kind: constantString, String: "cmd"}},
				{Opcode: 0xb9, Member: &fixtureRequestParameter}, {Opcode: 0x4e},
				{Opcode: 0xb8, Member: &fakeRuntime}, {Opcode: 0x57}, {Opcode: 0xb1},
				{Opcode: 0x57}, {Opcode: 0xb8, Member: &fixtureRuntimeGet}, {Opcode: 0x2d},
				{Opcode: 0xb6, Member: &fixtureRuntimeExec}, {Opcode: 0x57}, {Opcode: 0xb1},
			},
			handlers: []exceptionHandler{{Start: 9, End: 12, Handler: 14, CatchType: "java/lang/Throwable"}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, _ := classBytes(t, classSpec{
				Name: "fixture/UnresolvedReturns", Super: "javax/servlet/http/HttpServlet", Major: 49,
				Methods: []classMethodSpec{{
					Name: "service", Descriptor: "(Ljavax/servlet/http/HttpServletRequest;Ljavax/servlet/http/HttpServletResponse;)V",
					MaxStack: 4, MaxLocals: 6, Code: tt.code, Handlers: tt.handlers,
				}},
			})
			result := AnalyzeArtifact(tt.name+".class", data, DefaultOptions())
			if findingByRule(result.Findings, "javadisk:class-request-exec") != nil {
				t.Fatalf("unresolved invocation produced trusted flow: %+v", result)
			}
		})
	}
}

func TestAbstractUnresolvedRuntimeReturnRemainsUnprovenAcrossJoin(t *testing.T) {
	fakeRuntime := memberReference{Owner: "missing/Factory", Name: "runtime", Descriptor: "()Ljava/lang/Runtime;"}
	data, _ := classBytes(t, classSpec{
		Name: "fixture/UnresolvedJoin", Super: "javax/servlet/http/HttpServlet", Major: 49,
		Methods: []classMethodSpec{{
			Name: "service", Descriptor: "(Ljavax/servlet/http/HttpServletRequest;Ljavax/servlet/http/HttpServletResponse;I)V",
			MaxStack: 3, MaxLocals: 6,
			Code: []classInstructionSpec{
				{Opcode: 0x2b}, {Opcode: 0x12, Constant: &constantValue{Kind: constantString, String: "cmd"}},
				{Opcode: 0xb9, Member: &fixtureRequestParameter}, {Opcode: 0x3a, Operands: []byte{4}},
				{Opcode: 0x1d}, {Opcode: 0x99, Operands: []byte{0x00, 0x09}},
				{Opcode: 0xb8, Member: &fakeRuntime}, {Opcode: 0xa7, Operands: []byte{0x00, 0x06}},
				{Opcode: 0xb8, Member: &fakeRuntime}, {Opcode: 0x3a, Operands: []byte{5}},
				{Opcode: 0x19, Operands: []byte{5}}, {Opcode: 0x19, Operands: []byte{4}},
				{Opcode: 0xb6, Member: &fixtureRuntimeExec}, {Opcode: 0x57}, {Opcode: 0xb1},
			},
		}},
	})
	result := AnalyzeArtifact("UnresolvedJoin.class", data, DefaultOptions())
	if findingByRule(result.Findings, "javadisk:class-request-exec") != nil || len(result.Diagnostics) != 0 {
		t.Fatalf("joined unresolved Runtime return became trusted: %+v", result)
	}
}

func TestAbstractImpossibleRuntimeDereferencesCannotReachExec(t *testing.T) {
	runtimeField := memberReference{Owner: "fixture/ImpossibleRuntime", Name: "runtime", Descriptor: "Ljava/lang/Runtime;"}
	for _, tt := range []struct {
		name     string
		receiver []classInstructionSpec
	}{
		{
			name: "null checkcast",
			receiver: []classInstructionSpec{
				{Opcode: 0x01}, {Opcode: 0xc0, ClassName: "java/lang/Runtime"},
			},
		},
		{
			name: "exact incompatible checkcast",
			receiver: []classInstructionSpec{
				{Opcode: 0x12, Constant: &constantValue{Kind: constantString, String: "not-runtime"}},
				{Opcode: 0xc0, ClassName: "java/lang/Runtime"},
			},
		},
		{
			name: "null getfield",
			receiver: []classInstructionSpec{
				{Opcode: 0x01}, {Opcode: 0xb4, Field: &runtimeField},
			},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			code := []classInstructionSpec{
				{Opcode: 0x2b}, {Opcode: 0x12, Constant: &constantValue{Kind: constantString, String: "cmd"}},
				{Opcode: 0xb9, Member: &fixtureRequestParameter}, {Opcode: 0x4e},
			}
			code = append(code, tt.receiver...)
			code = append(code,
				classInstructionSpec{Opcode: 0x2d}, classInstructionSpec{Opcode: 0xb6, Member: &fixtureRuntimeExec},
				classInstructionSpec{Opcode: 0x57}, classInstructionSpec{Opcode: 0xb1},
			)
			data, _ := classBytes(t, classSpec{
				Name: "fixture/ImpossibleRuntime", Super: "javax/servlet/http/HttpServlet",
				Fields: []classFieldSpec{{Name: "runtime", Descriptor: "Ljava/lang/Runtime;"}},
				Methods: []classMethodSpec{{
					Name: "service", Descriptor: "(Ljavax/servlet/http/HttpServletRequest;Ljavax/servlet/http/HttpServletResponse;)V",
					MaxStack: 3, MaxLocals: 4, Code: code,
				}},
			})
			result := AnalyzeArtifact(tt.name+".class", data, DefaultOptions())
			if findingByRule(result.Findings, "javadisk:class-request-exec") != nil ||
				hasDiagnosticCode(result.Diagnostics, diagBytecodeUnsupported) {
				t.Fatalf("impossible Runtime dereference result=%+v", result)
			}
		})
	}
}

func TestAbstractNullCheckcastCannotCreateRequestSource(t *testing.T) {
	data, _ := classBytes(t, classSpec{Name: "fixture/NullCastRequest", Methods: []classMethodSpec{{
		Access: 0x0009, Name: "run", Descriptor: "()V", MaxStack: 2, MaxLocals: 1,
		Code: []classInstructionSpec{
			{Opcode: 0x01}, {Opcode: 0xc0, ClassName: "javax/servlet/http/HttpServletRequest"},
			{Opcode: 0x12, Constant: &constantValue{Kind: constantString, String: "cmd"}},
			{Opcode: 0xb9, Member: &fixtureRequestParameter}, {Opcode: 0x4b},
			{Opcode: 0xb8, Member: &fixtureRuntimeGet}, {Opcode: 0x2a},
			{Opcode: 0xb6, Member: &fixtureRuntimeExec}, {Opcode: 0x57}, {Opcode: 0xb1},
		},
	}}})
	result := AnalyzeArtifact("NullCastRequest.class", data, DefaultOptions())
	if findingByRule(result.Findings, "javadisk:class-request-exec") != nil ||
		hasDiagnosticCode(result.Diagnostics, diagBytecodeUnsupported) {
		t.Fatalf("null checkcast request result=%+v", result)
	}
}

func TestAbstractKnownNullDereferencesHaveNoNormalSuccessor(t *testing.T) {
	field := memberReference{Owner: "fixture/NullDereference", Name: "value", Descriptor: "Ljava/lang/Object;"}
	for _, tt := range []struct {
		name     string
		maxStack uint16
		code     []classInstructionSpec
	}{
		{"array load", 2, []classInstructionSpec{{Opcode: 0x01}, {Opcode: 0x03}, {Opcode: 0x32}}},
		{"array store", 3, []classInstructionSpec{{Opcode: 0x01}, {Opcode: 0x03}, {Opcode: 0x01}, {Opcode: 0x53}}},
		{"array length", 1, []classInstructionSpec{{Opcode: 0x01}, {Opcode: 0xbe}}},
		{"getfield", 1, []classInstructionSpec{{Opcode: 0x01}, {Opcode: 0xb4, Field: &field}}},
		{"putfield", 2, []classInstructionSpec{{Opcode: 0x01}, {Opcode: 0x01}, {Opcode: 0xb5, Field: &field}}},
		{"monitorenter", 1, []classInstructionSpec{{Opcode: 0x01}, {Opcode: 0xc2}}},
		{"monitorexit", 1, []classInstructionSpec{{Opcode: 0x01}, {Opcode: 0xc3}}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			code := append([]classInstructionSpec(nil), tt.code...)
			code = append(code,
				classInstructionSpec{Opcode: 0xa8, Operands: []byte{0x00, 0x04}},
				classInstructionSpec{Opcode: 0xb1}, classInstructionSpec{Opcode: 0x4b},
				classInstructionSpec{Opcode: 0xa9, Operands: []byte{0}},
			)
			data, _ := classBytes(t, classSpec{
				Name: "fixture/NullDereference", Major: 49, Fields: []classFieldSpec{{Name: "value", Descriptor: "Ljava/lang/Object;"}},
				Methods: []classMethodSpec{{Access: 0x0009, Name: "run", MaxStack: tt.maxStack, MaxLocals: 1, Code: code}},
			})
			result := AnalyzeArtifact(tt.name+".class", data, DefaultOptions())
			if hasDiagnosticCode(result.Diagnostics, diagBytecodeUnsupported) {
				t.Fatalf("known-null normal successor remained reachable: %+v", result)
			}
		})
	}
}

func TestAbstractFailedDereferencesPropagatePreInstructionHandlerState(t *testing.T) {
	field := memberReference{Owner: "fixture/FailedDereferenceHandlers", Name: "value", Descriptor: "Ljava/lang/Object;"}
	toString := memberReference{Owner: "java/lang/Object", Name: "toString", Descriptor: "()Ljava/lang/String;"}
	for _, tt := range []struct {
		name    string
		code    []classInstructionSpec
		handler exceptionHandler
	}{
		{
			name: "failed checkcast",
			code: []classInstructionSpec{
				{Opcode: 0x03}, {Opcode: 0x3b},
				{Opcode: 0x12, Constant: &constantValue{Kind: constantString, String: "exact-string"}},
				{Opcode: 0xc0, ClassName: "java/lang/Runtime"}, {Opcode: 0x57}, {Opcode: 0xb1},
				{Opcode: 0x57}, {Opcode: 0xb1},
			},
			handler: exceptionHandler{Start: 4, End: 7, Handler: 9, CatchType: "java/lang/ClassCastException"},
		},
		{
			name: "null getfield",
			code: []classInstructionSpec{
				{Opcode: 0x03}, {Opcode: 0x3b}, {Opcode: 0x01}, {Opcode: 0xb4, Field: &field},
				{Opcode: 0x57}, {Opcode: 0xb1}, {Opcode: 0x57}, {Opcode: 0xb1},
			},
			handler: exceptionHandler{Start: 3, End: 6, Handler: 8, CatchType: "java/lang/NullPointerException"},
		},
		{
			name: "new allocation",
			code: []classInstructionSpec{
				{Opcode: 0x03}, {Opcode: 0x3b}, {Opcode: 0xbb, ClassName: "java/lang/Object"},
				{Opcode: 0x57}, {Opcode: 0xb1}, {Opcode: 0x57}, {Opcode: 0xb1},
			},
			handler: exceptionHandler{Start: 2, End: 5, Handler: 7, CatchType: "java/lang/Throwable"},
		},
		{
			name: "null invoke",
			code: []classInstructionSpec{
				{Opcode: 0x03}, {Opcode: 0x3b}, {Opcode: 0x01}, {Opcode: 0xb6, Member: &toString},
				{Opcode: 0x57}, {Opcode: 0xb1}, {Opcode: 0x57}, {Opcode: 0xb1},
			},
			handler: exceptionHandler{Start: 3, End: 6, Handler: 8, CatchType: "java/lang/NullPointerException"},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			analysis := analyzeSpecMethod(t, classSpec{
				Name:   "fixture/FailedDereferenceHandlers",
				Fields: []classFieldSpec{{Name: "value", Descriptor: "Ljava/lang/Object;"}},
				Methods: []classMethodSpec{{
					Access: 0x0009, Name: "run", MaxStack: 1, MaxLocals: 1, Code: tt.code,
					Handlers: []exceptionHandler{tt.handler},
				}},
			}, "run", DefaultOptions())
			if analysis.Unsupported != "" || analysis.BudgetExhausted != "" {
				t.Fatalf("analysis=%+v", analysis)
			}
			handler, ok := analysis.Frames[tt.handler.Handler]
			if !ok || len(handler.Stack) != 1 || handler.Stack[0].Reference != tt.handler.CatchType ||
				len(handler.Locals) == 0 || handler.Locals[0].Verifier != verifierInt {
				t.Fatalf("handler did not receive exact pre-instruction state: %+v", handler)
			}
		})
	}
}

func TestAbstractConstantDivideByZeroStopsNormalExec(t *testing.T) {
	data, _ := classBytes(t, classSpec{
		Name: "fixture/DivideAbrupt", Super: "javax/servlet/http/HttpServlet",
		Methods: []classMethodSpec{{
			Name: "service", Descriptor: "(Ljavax/servlet/http/HttpServletRequest;Ljavax/servlet/http/HttpServletResponse;)V",
			MaxStack: 3, MaxLocals: 4, Code: []classInstructionSpec{
				{Opcode: 0x2b}, {Opcode: 0x12, Constant: &constantValue{Kind: constantString, String: "cmd"}},
				{Opcode: 0xb9, Member: &fixtureRequestParameter}, {Opcode: 0x4e},
				{Opcode: 0x04}, {Opcode: 0x03}, {Opcode: 0x6c}, {Opcode: 0x57},
				{Opcode: 0xb8, Member: &fixtureRuntimeGet}, {Opcode: 0x2d},
				{Opcode: 0xb6, Member: &fixtureRuntimeExec}, {Opcode: 0x57}, {Opcode: 0xb1},
			},
		}},
	})
	result := AnalyzeArtifact("DivideAbrupt.class", data, DefaultOptions())
	if findingByRule(result.Findings, "javadisk:class-request-exec") != nil ||
		hasDiagnosticCode(result.Diagnostics, diagBytecodeUnsupported) {
		t.Fatalf("divide-by-zero retained normal sink flow: %+v", result)
	}
}

func TestAbstractTypedArithmeticHandlersFilterImpossibleCatches(t *testing.T) {
	for _, tt := range []struct {
		catchType string
		wantExec  bool
	}{
		{"java/lang/ClassCastException", false},
		{"java/lang/ArithmeticException", true},
		{"java/lang/RuntimeException", true},
		{"java/lang/Exception", true},
		{"java/lang/Throwable", true},
	} {
		t.Run(tt.catchType, func(t *testing.T) {
			data, _ := classBytes(t, classSpec{
				Name: "fixture/TypedDivide", Super: "javax/servlet/http/HttpServlet", Major: 49,
				Methods: []classMethodSpec{{
					Name: "service", Descriptor: "(Ljavax/servlet/http/HttpServletRequest;Ljavax/servlet/http/HttpServletResponse;)V",
					MaxStack: 3, MaxLocals: 4,
					Code: []classInstructionSpec{
						{Opcode: 0x2b}, {Opcode: 0x12, Constant: &constantValue{Kind: constantString, String: "cmd"}},
						{Opcode: 0xb9, Member: &fixtureRequestParameter}, {Opcode: 0x4e},
						{Opcode: 0x04}, {Opcode: 0x03}, {Opcode: 0x6c}, {Opcode: 0x57}, {Opcode: 0xb1},
						{Opcode: 0x57}, {Opcode: 0xb8, Member: &fixtureRuntimeGet}, {Opcode: 0x2d},
						{Opcode: 0xb6, Member: &fixtureRuntimeExec}, {Opcode: 0x57}, {Opcode: 0xb1},
					},
					Handlers: []exceptionHandler{{Start: 9, End: 12, Handler: 14, CatchType: tt.catchType}},
				}},
			})
			result := AnalyzeArtifact(tt.catchType+".class", data, DefaultOptions())
			got := findingByRule(result.Findings, "javadisk:class-request-exec") != nil
			if got != tt.wantExec || hasDiagnosticCode(result.Diagnostics, diagBytecodeUnsupported) {
				t.Fatalf("catch=%s finding=%v result=%+v", tt.catchType, got, result)
			}
			if tt.wantExec {
				analysis := analyzeSpecMethod(t, classSpec{
					Name: "fixture/TypedDivide", Super: "javax/servlet/http/HttpServlet",
					Methods: []classMethodSpec{{
						Name: "service", Descriptor: "(Ljavax/servlet/http/HttpServletRequest;Ljavax/servlet/http/HttpServletResponse;)V",
						MaxStack: 3, MaxLocals: 4,
						Code: []classInstructionSpec{
							{Opcode: 0x2b}, {Opcode: 0x12, Constant: &constantValue{Kind: constantString, String: "cmd"}},
							{Opcode: 0xb9, Member: &fixtureRequestParameter}, {Opcode: 0x4e},
							{Opcode: 0x04}, {Opcode: 0x03}, {Opcode: 0x6c}, {Opcode: 0x57}, {Opcode: 0xb1},
							{Opcode: 0x57}, {Opcode: 0xb8, Member: &fixtureRuntimeGet}, {Opcode: 0x2d},
							{Opcode: 0xb6, Member: &fixtureRuntimeExec}, {Opcode: 0x57}, {Opcode: 0xb1},
						},
						Handlers: []exceptionHandler{{Start: 9, End: 12, Handler: 14, CatchType: tt.catchType}},
					}},
				}, "service", DefaultOptions())
				if handler := analysis.Frames[14]; len(handler.Stack) != 1 || handler.Stack[0].Reference != tt.catchType {
					t.Fatalf("handler stack is not typed as catch %s: %+v", tt.catchType, handler)
				}
			}
		})
	}
}

func TestAbstractExceptionHandlersUseClassFileFirstMatchOrder(t *testing.T) {
	toString := memberReference{Owner: "java/lang/Object", Name: "toString", Descriptor: "()Ljava/lang/String;"}
	tests := []struct {
		name     string
		handlers []exceptionHandler
		wantExec bool
	}{
		{
			name: "earlier catch all wins",
			handlers: []exceptionHandler{
				{Start: 9, End: 13, Handler: 23, CatchType: "java/lang/Throwable"},
				{Start: 9, End: 13, Handler: 15, CatchType: "java/lang/NullPointerException"},
			},
		},
		{
			name: "earlier exact catch wins",
			handlers: []exceptionHandler{
				{Start: 9, End: 13, Handler: 15, CatchType: "java/lang/NullPointerException"},
				{Start: 9, End: 13, Handler: 23, CatchType: "java/lang/Throwable"},
			},
			wantExec: true,
		},
		{
			name: "earlier catch all entry wins",
			handlers: []exceptionHandler{
				{Start: 9, End: 13, Handler: 23},
				{Start: 9, End: 13, Handler: 15, CatchType: "java/lang/NullPointerException"},
			},
		},
		{
			name: "earlier duplicate exact entry wins",
			handlers: []exceptionHandler{
				{Start: 9, End: 13, Handler: 23, CatchType: "java/lang/NullPointerException"},
				{Start: 9, End: 13, Handler: 15, CatchType: "java/lang/NullPointerException"},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, _ := classBytes(t, classSpec{
				Name: "fixture/HandlerOrder", Super: "javax/servlet/http/HttpServlet", Major: 49,
				Methods: []classMethodSpec{{
					Name: "service", Descriptor: "(Ljavax/servlet/http/HttpServletRequest;Ljavax/servlet/http/HttpServletResponse;)V",
					MaxStack: 3, MaxLocals: 4,
					Code: []classInstructionSpec{
						{Opcode: 0x2b}, {Opcode: 0x12, Constant: &constantValue{Kind: constantString, String: "cmd"}},
						{Opcode: 0xb9, Member: &fixtureRequestParameter}, {Opcode: 0x4e},
						{Opcode: 0x01}, {Opcode: 0xb6, Member: &toString}, {Opcode: 0x57}, {Opcode: 0xb1},
						{Opcode: 0x57}, {Opcode: 0xb8, Member: &fixtureRuntimeGet}, {Opcode: 0x2d},
						{Opcode: 0xb6, Member: &fixtureRuntimeExec}, {Opcode: 0x57}, {Opcode: 0xb1},
						{Opcode: 0x57}, {Opcode: 0xb1},
					},
					Handlers: tt.handlers,
				}},
			})
			result := AnalyzeArtifact(tt.name+".class", data, DefaultOptions())
			got := findingByRule(result.Findings, "javadisk:class-request-exec") != nil
			if got != tt.wantExec || hasDiagnosticCode(result.Diagnostics, diagBytecodeUnsupported) {
				t.Fatalf("finding=%v want=%v result=%+v", got, tt.wantExec, result)
			}
		})
	}
}

func TestAbstractKnownNullInvokeFiltersImpossibleHandlers(t *testing.T) {
	toString := memberReference{Owner: "java/lang/Object", Name: "toString", Descriptor: "()Ljava/lang/String;"}
	for _, tt := range []struct {
		catchType string
		wantExec  bool
	}{
		{"java/lang/ClassCastException", false},
		{"java/lang/NullPointerException", true},
		{"java/lang/RuntimeException", true},
		{"java/lang/Throwable", true},
	} {
		t.Run(tt.catchType, func(t *testing.T) {
			data, _ := classBytes(t, classSpec{
				Name: "fixture/NullInvokeCatch", Super: "javax/servlet/http/HttpServlet", Major: 49,
				Methods: []classMethodSpec{{
					Name: "service", Descriptor: "(Ljavax/servlet/http/HttpServletRequest;Ljavax/servlet/http/HttpServletResponse;)V",
					MaxStack: 3, MaxLocals: 4,
					Code: []classInstructionSpec{
						{Opcode: 0x2b}, {Opcode: 0x12, Constant: &constantValue{Kind: constantString, String: "cmd"}},
						{Opcode: 0xb9, Member: &fixtureRequestParameter}, {Opcode: 0x4e},
						{Opcode: 0x01}, {Opcode: 0xb6, Member: &toString}, {Opcode: 0x57}, {Opcode: 0xb1},
						{Opcode: 0x57}, {Opcode: 0xb8, Member: &fixtureRuntimeGet}, {Opcode: 0x2d},
						{Opcode: 0xb6, Member: &fixtureRuntimeExec}, {Opcode: 0x57}, {Opcode: 0xb1},
					},
					Handlers: []exceptionHandler{{Start: 9, End: 13, Handler: 15, CatchType: tt.catchType}},
				}},
			})
			result := AnalyzeArtifact(tt.catchType+".class", data, DefaultOptions())
			got := findingByRule(result.Findings, "javadisk:class-request-exec") != nil
			if got != tt.wantExec || len(result.Diagnostics) != 0 {
				t.Fatalf("finding=%v want=%v result=%+v", got, tt.wantExec, result)
			}
		})
	}
}

func TestAbstractKnownArrayFailuresHaveOnlyMatchingExceptionalFlow(t *testing.T) {
	for _, tt := range []struct {
		name          string
		operation     []classInstructionSpec
		start, end    uint32
		handler       uint32
		matchingCatch string
	}{
		{
			name: "negative size", operation: []classInstructionSpec{
				{Opcode: 0x02}, {Opcode: 0xbd, ClassName: "java/lang/String"}, {Opcode: 0x57},
			},
			start: 9, end: 13, handler: 15, matchingCatch: "java/lang/NegativeArraySizeException",
		},
		{
			name: "zero length bounds", operation: []classInstructionSpec{
				{Opcode: 0x03}, {Opcode: 0xbd, ClassName: "java/lang/String"}, {Opcode: 0x03}, {Opcode: 0x32}, {Opcode: 0x57},
			},
			start: 9, end: 15, handler: 17, matchingCatch: "java/lang/ArrayIndexOutOfBoundsException",
		},
	} {
		for _, catchType := range []string{"java/lang/ClassCastException", tt.matchingCatch} {
			t.Run(tt.name+"/"+catchType, func(t *testing.T) {
				code := []classInstructionSpec{
					{Opcode: 0x2b}, {Opcode: 0x12, Constant: &constantValue{Kind: constantString, String: "cmd"}},
					{Opcode: 0xb9, Member: &fixtureRequestParameter}, {Opcode: 0x4e},
				}
				code = append(code, tt.operation...)
				code = append(code,
					classInstructionSpec{Opcode: 0xb1}, classInstructionSpec{Opcode: 0x57},
					classInstructionSpec{Opcode: 0xb8, Member: &fixtureRuntimeGet}, classInstructionSpec{Opcode: 0x2d},
					classInstructionSpec{Opcode: 0xb6, Member: &fixtureRuntimeExec}, classInstructionSpec{Opcode: 0x57},
					classInstructionSpec{Opcode: 0xb1},
				)
				data, _ := classBytes(t, classSpec{
					Name: "fixture/ArrayAbrupt", Super: "javax/servlet/http/HttpServlet", Major: 49,
					Methods: []classMethodSpec{{
						Name: "service", Descriptor: "(Ljavax/servlet/http/HttpServletRequest;Ljavax/servlet/http/HttpServletResponse;)V",
						MaxStack: 3, MaxLocals: 4, Code: code,
						Handlers: []exceptionHandler{{Start: tt.start, End: tt.end, Handler: tt.handler, CatchType: catchType}},
					}},
				})
				result := AnalyzeArtifact(tt.name+catchType+".class", data, DefaultOptions())
				got := findingByRule(result.Findings, "javadisk:class-request-exec") != nil
				want := catchType == tt.matchingCatch
				if got != want || hasDiagnosticCode(result.Diagnostics, diagBytecodeUnsupported) {
					t.Fatalf("finding=%v want=%v result=%+v", got, want, result)
				}
			})
		}
	}
}

func TestAbstractMultiANewArrayNegativeDimensionHasNoNormalExecFlow(t *testing.T) {
	for _, tt := range []struct {
		name      string
		dimension byte
		wantExec  bool
	}{
		{name: "negative dimension", dimension: 0x02, wantExec: false},
		{name: "zero dimension", dimension: 0x03, wantExec: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			data, _ := classBytes(t, classSpec{
				Name: "fixture/MultiArrayAbrupt", Super: "javax/servlet/http/HttpServlet", Major: 49,
				Methods: []classMethodSpec{{
					Name: "service", Descriptor: "(Ljavax/servlet/http/HttpServletRequest;Ljavax/servlet/http/HttpServletResponse;)V",
					MaxStack: 2, MaxLocals: 4,
					Code: []classInstructionSpec{
						{Opcode: 0x04}, {Opcode: tt.dimension},
						{Opcode: 0xc5, ClassName: "[[Ljava/lang/String;", Operands: []byte{0x02}},
						{Opcode: 0x57},
						{Opcode: 0x2b}, {Opcode: 0x12, Constant: &constantValue{Kind: constantString, String: "cmd"}},
						{Opcode: 0xb9, Member: &fixtureRequestParameter}, {Opcode: 0x4e},
						{Opcode: 0xb8, Member: &fixtureRuntimeGet}, {Opcode: 0x2d},
						{Opcode: 0xb6, Member: &fixtureRuntimeExec}, {Opcode: 0x57}, {Opcode: 0xb1},
					},
				}},
			})
			result := AnalyzeArtifact(tt.name+".class", data, DefaultOptions())
			gotExec := findingByRule(result.Findings, "javadisk:class-request-exec") != nil
			if gotExec != tt.wantExec || hasDiagnosticCode(result.Diagnostics, diagBytecodeUnsupported) {
				t.Fatalf("finding=%v want=%v result=%+v", gotExec, tt.wantExec, result)
			}
		})
	}
}

func TestAbstractInvalidReferenceReturnDiscardsEarlierExec(t *testing.T) {
	objectInit := memberReference{Owner: "java/lang/Object", Name: "<init>", Descriptor: "()V"}
	data, _ := classBytes(t, classSpec{Name: "fixture/BadReturn", Methods: []classMethodSpec{{
		Access: 0x0009, Name: "run", Descriptor: "(Ljavax/servlet/http/HttpServletRequest;)Ljava/lang/String;",
		MaxStack: 3, MaxLocals: 2, Code: []classInstructionSpec{
			{Opcode: 0x2a}, {Opcode: 0x12, Constant: &constantValue{Kind: constantString, String: "cmd"}},
			{Opcode: 0xb9, Member: &fixtureRequestParameter}, {Opcode: 0x4c},
			{Opcode: 0xb8, Member: &fixtureRuntimeGet}, {Opcode: 0x2b},
			{Opcode: 0xb6, Member: &fixtureRuntimeExec}, {Opcode: 0x57},
			{Opcode: 0xbb, ClassName: "java/lang/Object"}, {Opcode: 0x59},
			{Opcode: 0xb7, Member: &objectInit}, {Opcode: 0xb0},
		},
	}}})
	result := AnalyzeArtifact("BadReturn.class", data, DefaultOptions())
	if findingByRule(result.Findings, "javadisk:class-request-exec") != nil ||
		!hasDiagnosticCode(result.Diagnostics, diagBytecodeUnsupported) {
		t.Fatalf("invalid areturn retained earlier semantic execution: %+v", result)
	}
}

func TestAbstractReferenceAssignmentsAndAthrowUseDeclaredTypes(t *testing.T) {
	runtimeStatic := memberReference{Owner: "fixture/AssignmentTypes", Name: "runtimeStatic", Descriptor: "Ljava/lang/Runtime;"}
	runtimeInstance := memberReference{Owner: "fixture/AssignmentTypes", Name: "runtimeInstance", Descriptor: "Ljava/lang/Runtime;"}
	for _, tt := range []struct {
		name       string
		descriptor string
		code       []classInstructionSpec
	}{
		{
			name: "putstatic incompatible reference", descriptor: "()V",
			code: []classInstructionSpec{
				{Opcode: 0x12, Constant: &constantValue{Kind: constantString, String: "not-runtime"}},
				{Opcode: 0xb3, Field: &runtimeStatic}, {Opcode: 0xb1},
			},
		},
		{
			name: "putfield incompatible reference", descriptor: "(Lfixture/AssignmentTypes;)V",
			code: []classInstructionSpec{
				{Opcode: 0x2a}, {Opcode: 0x12, Constant: &constantValue{Kind: constantString, String: "not-runtime"}},
				{Opcode: 0xb5, Field: &runtimeInstance}, {Opcode: 0xb1},
			},
		},
		{
			name: "athrow incompatible reference", descriptor: "()V",
			code: []classInstructionSpec{
				{Opcode: 0x12, Constant: &constantValue{Kind: constantString, String: "not-throwable"}}, {Opcode: 0xbf},
			},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			analysis := analyzeSpecMethod(t, classSpec{
				Name: "fixture/AssignmentTypes",
				Fields: []classFieldSpec{
					{Access: 0x0009, Name: "runtimeStatic", Descriptor: "Ljava/lang/Runtime;"},
					{Access: 0x0001, Name: "runtimeInstance", Descriptor: "Ljava/lang/Runtime;"},
				},
				Methods: []classMethodSpec{{
					Access: 0x0009, Name: "run", Descriptor: tt.descriptor, MaxStack: 2, MaxLocals: 1, Code: tt.code,
				}},
			}, "run", DefaultOptions())
			if analysis.Unsupported == "" {
				t.Fatalf("accepted incompatible reference assignment: %+v", analysis)
			}
		})
	}

	validSubclass := analyzeSpecMethod(t, classSpec{
		Name: "fixture/FileChild", Super: "java/io/File",
		Methods: []classMethodSpec{{
			Access: 0x0009, Name: "asFile", Descriptor: "(Lfixture/FileChild;)Ljava/io/File;",
			MaxStack: 1, MaxLocals: 1, Code: []classInstructionSpec{{Opcode: 0x2a}, {Opcode: 0xb0}},
		}},
	}, "asFile", DefaultOptions())
	if validSubclass.Unsupported != "" || validSubclass.BudgetExhausted != "" {
		t.Fatalf("valid File subclass assignment failed: %+v", validSubclass)
	}
}

func TestAbstractCurrentFieldStaticAndFinalFormsAreVerified(t *testing.T) {
	staticField := memberReference{Owner: "fixture/FieldForms", Name: "shared", Descriptor: "Ljava/lang/Object;"}
	instanceField := memberReference{Owner: "fixture/FieldForms", Name: "owned", Descriptor: "Ljava/lang/Object;"}
	finalStatic := memberReference{Owner: "fixture/FieldForms", Name: "finalShared", Descriptor: "Ljava/lang/Object;"}
	finalInstance := memberReference{Owner: "fixture/FieldForms", Name: "finalOwned", Descriptor: "Ljava/lang/Object;"}
	for _, tt := range []struct {
		name string
		code []classInstructionSpec
	}{
		{"getfield static", []classInstructionSpec{{Opcode: 0x01}, {Opcode: 0xb4, Field: &staticField}, {Opcode: 0x57}, {Opcode: 0xb1}}},
		{"getstatic instance", []classInstructionSpec{{Opcode: 0xb2, Field: &instanceField}, {Opcode: 0x57}, {Opcode: 0xb1}}},
		{"putstatic final outside clinit", []classInstructionSpec{{Opcode: 0x01}, {Opcode: 0xb3, Field: &finalStatic}, {Opcode: 0xb1}}},
		{"putfield final outside init", []classInstructionSpec{{Opcode: 0x01}, {Opcode: 0x01}, {Opcode: 0xb5, Field: &finalInstance}, {Opcode: 0xb1}}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			analysis := analyzeSpecMethod(t, classSpec{
				Name: "fixture/FieldForms",
				Fields: []classFieldSpec{
					{Access: 0x0009, Name: "shared", Descriptor: "Ljava/lang/Object;"},
					{Access: 0x0001, Name: "owned", Descriptor: "Ljava/lang/Object;"},
					{Access: 0x0019, Name: "finalShared", Descriptor: "Ljava/lang/Object;"},
					{Access: 0x0011, Name: "finalOwned", Descriptor: "Ljava/lang/Object;"},
				},
				Methods: []classMethodSpec{{Access: 0x0009, Name: "run", MaxStack: 2, Code: tt.code}},
			}, "run", DefaultOptions())
			if analysis.Unsupported == "" {
				t.Fatalf("accepted invalid current field form: %+v", analysis)
			}
		})
	}
}

func TestAbstractExternalFieldFlowIsNotHighConfidence(t *testing.T) {
	field := memberReference{Owner: "external/Holder", Name: "command", Descriptor: "Ljava/lang/String;"}
	data, _ := classBytes(t, classSpec{Name: "fixture/ExternalField", Major: 49, Methods: []classMethodSpec{{
		Access: 0x0009, Name: "run", Descriptor: "(Ljavax/servlet/http/HttpServletRequest;)V",
		MaxStack: 2, MaxLocals: 2, Code: []classInstructionSpec{
			{Opcode: 0x2a}, {Opcode: 0x12, Constant: &constantValue{Kind: constantString, String: "cmd"}},
			{Opcode: 0xb9, Member: &fixtureRequestParameter}, {Opcode: 0xb3, Field: &field},
			{Opcode: 0xb8, Member: &fixtureRuntimeGet}, {Opcode: 0xb2, Field: &field},
			{Opcode: 0xb6, Member: &fixtureRuntimeExec}, {Opcode: 0x57}, {Opcode: 0xb1},
		},
	}}})
	result := AnalyzeArtifact("ExternalField.class", data, DefaultOptions())
	if findingByRule(result.Findings, "javadisk:class-request-exec") != nil || len(result.Diagnostics) != 0 {
		t.Fatalf("external field metadata was treated as proven: %+v", result)
	}
}

func TestAbstractRejectsNonThrowableAndUnprovenCatchTypes(t *testing.T) {
	for _, catchType := range []string{"java/lang/String", "fixture/UnknownCatch"} {
		t.Run(catchType, func(t *testing.T) {
			analysis := analyzeSpecMethod(t, classSpec{Name: "fixture/BadCatch", Methods: []classMethodSpec{{
				Access: 0x0009, Name: "run", MaxStack: 2,
				Code: []classInstructionSpec{
					{Opcode: 0x04}, {Opcode: 0x03}, {Opcode: 0x6c}, {Opcode: 0x57}, {Opcode: 0xb1},
					{Opcode: 0x57}, {Opcode: 0xb1},
				},
				Handlers: []exceptionHandler{{Start: 0, End: 3, Handler: 5, CatchType: catchType}},
			}}}, "run", DefaultOptions())
			if analysis.Unsupported == "" {
				t.Fatalf("accepted invalid/unproven catch type %s: %+v", catchType, analysis)
			}
		})
	}
}

func TestAbstractLegalMonitorPairPreservesRequestExecFlow(t *testing.T) {
	data, _ := classBytes(t, classSpec{
		Name: "fixture/SynchronizedExec", Super: "javax/servlet/http/HttpServlet",
		Methods: []classMethodSpec{{
			Name: "service", Descriptor: "(Ljavax/servlet/http/HttpServletRequest;Ljavax/servlet/http/HttpServletResponse;)V",
			MaxStack: 3, MaxLocals: 4, Code: []classInstructionSpec{
				{Opcode: 0x2a}, {Opcode: 0x59}, {Opcode: 0xc2},
				{Opcode: 0x2b}, {Opcode: 0x12, Constant: &constantValue{Kind: constantString, String: "cmd"}},
				{Opcode: 0xb9, Member: &fixtureRequestParameter}, {Opcode: 0x4e},
				{Opcode: 0xb8, Member: &fixtureRuntimeGet}, {Opcode: 0x2d},
				{Opcode: 0xb6, Member: &fixtureRuntimeExec}, {Opcode: 0x57},
				{Opcode: 0xc3}, {Opcode: 0xb1},
			},
		}},
	})
	result := AnalyzeArtifact("SynchronizedExec.class", data, DefaultOptions())
	finding := findingByRule(result.Findings, "javadisk:class-request-exec")
	if finding == nil || finding.Score != 85 || hasDiagnosticCode(result.Diagnostics, diagBytecodeUnsupported) {
		t.Fatalf("legal monitor flow result=%+v", result)
	}
}

func TestAbstractRejectsKnownIncompatibleReferenceArgumentBeforeBuilderStart(t *testing.T) {
	constructor := memberReference{Owner: "java/lang/ProcessBuilder", Name: "<init>", Descriptor: "(Ljava/util/List;)V"}
	start := memberReference{Owner: "java/lang/ProcessBuilder", Name: "start", Descriptor: "()Ljava/lang/Process;"}
	data, _ := classBytes(t, classSpec{
		Name: "fixture/BadBuilderArgument", Super: "javax/servlet/http/HttpServlet",
		Methods: []classMethodSpec{{
			Name: "service", Descriptor: "(Ljavax/servlet/http/HttpServletRequest;Ljavax/servlet/http/HttpServletResponse;)V",
			MaxStack: 4, MaxLocals: 3, Code: []classInstructionSpec{
				{Opcode: 0xbb, ClassName: "java/lang/ProcessBuilder"}, {Opcode: 0x59},
				{Opcode: 0x2b}, {Opcode: 0x12, Constant: &constantValue{Kind: constantString, String: "cmd"}},
				{Opcode: 0xb9, Member: &fixtureRequestParameter},
				{Opcode: 0xb7, Member: &constructor}, {Opcode: 0xb6, Member: &start},
				{Opcode: 0x57}, {Opcode: 0xb1},
			},
		}},
	})
	result := AnalyzeArtifact("BadBuilderArgument.class", data, DefaultOptions())
	if findingByRule(result.Findings, "javadisk:class-request-exec") != nil ||
		!hasDiagnosticCode(result.Diagnostics, diagBytecodeUnsupported) {
		t.Fatalf("result=%+v", result)
	}
}

func TestDecoderRejectsMalformedInvokeInterfaceReservedByte(t *testing.T) {
	data, _ := classBytes(t, classSpec{Name: "fixture/InvokeReserved", Methods: []classMethodSpec{{
		Access: 0x0009, Name: "run", MaxStack: 2, Code: []classInstructionSpec{
			{Opcode: 0x01}, {Opcode: 0x12, Constant: &constantValue{Kind: constantString, String: "cmd"}},
			{Opcode: 0xb9, Member: &fixtureRequestParameter}, {Opcode: 0x57}, {Opcode: 0xb1},
		},
	}}})
	cf, err := parseClass(data, DefaultOptions().Limits)
	if err != nil {
		t.Fatal(err)
	}
	code := cf.Methods[0].Code
	for offset := range code.Bytes {
		if code.Bytes[offset] == 0xb9 {
			code.Bytes[offset+4] = 1
			break
		}
	}
	instructions, err := decodeInstructions(code.Bytes, 100)
	if err == nil || instructions != nil {
		t.Fatalf("malformed invokeinterface was decoded: instructions=%+v err=%v", instructions, err)
	}
}

func TestAbstractIdentityJoinPreservesBuilderAndNull(t *testing.T) {
	limits := DefaultOptions().Limits
	budget := &abstractBudget{limit: limits.MaxStateMerges}
	builder := abstractValue{Verifier: verifierReference, Reference: "java/lang/ProcessBuilder", ObjectID: 17, Width: 1}
	null := abstractValue{Verifier: verifierNull, Width: 1}
	joined, err := mergeValues(builder, null, limits, budget)
	if err != nil {
		t.Fatal(err)
	}
	if joined.ObjectID != 17 || joined.Reference != "java/lang/ProcessBuilder" {
		t.Fatalf("joined=%+v", joined)
	}
}

func TestAbstractIdentityJoinCapFailsBeforeAllocation(t *testing.T) {
	limits := DefaultOptions().Limits
	limits.MaxFrameSlots = 2
	budget := &abstractBudget{limit: limits.MaxStateMerges}
	left := abstractValue{Verifier: verifierReference, Reference: "java/lang/Object", ObjectIDs: []uint32{1, 2}, Width: 1}
	right := abstractValue{Verifier: verifierReference, Reference: "java/lang/Object", ObjectID: 3, Width: 1}
	if _, err := mergeValues(left, right, limits, budget); err == nil {
		t.Fatal("identity join exceeded cap without a budget error")
	}
}

func TestAbstractProcessBuilderStartReadsEveryJoinedReceiverIdentity(t *testing.T) {
	start := memberReference{Owner: "java/lang/ProcessBuilder", Name: "start", Descriptor: "()Ljava/lang/Process;"}
	data, _ := classBytes(t, classSpec{Name: "fixture/JoinedBuilder", Methods: []classMethodSpec{{
		Access: 0x0009, Name: "run", MaxStack: 1, Code: []classInstructionSpec{
			{Opcode: 0x01}, {Opcode: 0xb6, Member: &start}, {Opcode: 0x57}, {Opcode: 0xb1},
		},
	}}})
	cf, err := parseClass(data, DefaultOptions().Limits)
	if err != nil {
		t.Fatal(err)
	}
	instructions, err := decodeInstructions(cf.Methods[0].Code.Bytes, 100)
	if err != nil {
		t.Fatal(err)
	}
	limits := DefaultOptions().Limits
	budget := &abstractBudget{limit: limits.MaxStateMerges}
	builder := abstractValue{Verifier: verifierReference, Reference: "java/lang/ProcessBuilder", ObjectID: 33, Width: 1}
	withNull, err := mergeValues(builder, abstractValue{Verifier: verifierNull, Width: 1}, limits, budget)
	if err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct {
		name     string
		receiver abstractValue
		fields   map[fieldKey]abstractValue
	}{
		{
			name: "two builders",
			receiver: abstractValue{
				Verifier: verifierReference, Reference: "java/lang/ProcessBuilder", ObjectIDs: []uint32{11, 22}, Width: 1,
			},
			fields: map[fieldKey]abstractValue{
				processBuilderCommandKey(11): {Verifier: verifierReference, Reference: "java/lang/String", Width: 1},
				processBuilderCommandKey(22): {
					Taint: taintRequestParameter, Verifier: verifierReference, Reference: "java/lang/String", Width: 1,
				},
			},
		},
		{
			name: "builder and null", receiver: withNull,
			fields: map[fieldKey]abstractValue{
				processBuilderCommandKey(33): {
					Taint: taintRequestParameter, Verifier: verifierReference, Reference: "java/lang/String", Width: 1,
				},
			},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			state := frame{Stack: []abstractValue{tt.receiver}, Fields: tt.fields}
			analysis := methodAnalysis{}
			if err := transferInvoke(cf, instructions[1], &state, &analysis, cf.Methods[0].Code, DefaultOptions(), budget); err != nil {
				t.Fatal(err)
			}
			if !analysis.RequestExec {
				t.Fatalf("joined ProcessBuilder receiver lost tainted command: %+v", analysis)
			}
		})
	}
}

func TestAbstractLaterUnsupportedStateDiscardsEarlierExecutionWitness(t *testing.T) {
	request := fixtureRequestParameter
	data, _ := classBytes(t, classSpec{Name: "fixture/DiscardPartial", Methods: []classMethodSpec{{
		Access: 0x0009, Name: "run", MaxStack: 2, MaxLocals: 1, Code: []classInstructionSpec{
			{Opcode: 0xbb, ClassName: "fixture/ExternalRequest"}, {Opcode: 0x12, Constant: &constantValue{Kind: constantString, String: "cmd"}},
			{Opcode: 0xb9, Member: &request}, {Opcode: 0x4b},
			{Opcode: 0xb8, Member: &fixtureRuntimeGet}, {Opcode: 0x2a},
			{Opcode: 0xb6, Member: &fixtureRuntimeExec}, {Opcode: 0x57},
			{Opcode: 0xa8, Operands: []byte{0x00, 0x03}}, {Opcode: 0xb1},
		},
	}}})
	cf, err := parseClass(data, DefaultOptions().Limits)
	if err != nil {
		t.Fatal(err)
	}
	instructions, err := decodeInstructions(cf.Methods[0].Code.Bytes, 100)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := buildCFG(cf.Methods[0].Code, instructions)
	if err != nil {
		t.Fatal(err)
	}
	analysis := analyzeMethod(cf, &cf.Methods[0], cfg, DefaultOptions(), summarySet{})
	if analysis.Unsupported == "" || analysis.RequestExec || analysis.Source.API != "" || analysis.Sink.API != "" {
		t.Fatalf("partial high-confidence state survived unsupported transfer: %+v", analysis)
	}
}

func dynamicConstantModel(descriptor string, opcode byte) (*classModel, *methodModel, *controlFlowGraph, error) {
	pool := make([]cpEntry, 5)
	pool[1] = cpEntry{tag: cpUtf8, text: "value"}
	pool[2] = cpEntry{tag: cpUtf8, text: descriptor}
	pool[3] = cpEntry{tag: cpNameAndType, a: 1, b: 2}
	pool[4] = cpEntry{tag: cpDynamic, b: 3}
	pop := byte(0x57)
	maxStack := uint16(1)
	if opcode == 0x14 {
		pop = 0x58
		maxStack = 2
	}
	code := &codeModel{MaxStack: maxStack, Bytes: []byte{opcode, 0x00, 0x04, pop, 0xb1}}
	ins, err := decodeInstructions(code.Bytes, 100)
	if err != nil {
		return nil, nil, nil, err
	}
	cfg, err := buildCFG(code, ins)
	if err != nil {
		return nil, nil, nil, err
	}
	return &classModel{Name: "fixture/Condy", Major: 55, Pool: pool},
		&methodModel{Access: 0x0009, Name: "run", Descriptor: "()V", Code: code}, cfg, nil
}

func TestAbstractConstantDynamicUsesDescriptorWidth(t *testing.T) {
	for _, tt := range []struct {
		name       string
		descriptor string
		opcode     byte
		valid      bool
	}{
		{"long ldc2", "J", 0x14, true},
		{"long ldc_w", "J", 0x13, false},
		{"string ldc_w", "Ljava/lang/String;", 0x13, true},
		{"string ldc2", "Ljava/lang/String;", 0x14, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			cf, method, cfg, err := dynamicConstantModel(tt.descriptor, tt.opcode)
			if err != nil {
				t.Fatal(err)
			}
			analysis := analyzeMethod(cf, method, cfg, DefaultOptions(), summarySet{})
			got := analysis.Unsupported == "" && analysis.BudgetExhausted == ""
			if got != tt.valid {
				t.Fatalf("valid=%v analysis=%+v", got, analysis)
			}
		})
	}
}

func bootstrapFlowModel(t *testing.T, invokedynamic, cyclic bool) (*classModel, *methodModel, *controlFlowGraph) {
	t.Helper()
	pool := []cpEntry{{}}
	add := func(entry cpEntry) uint16 {
		pool = append(pool, entry)
		return uint16(len(pool) - 1)
	}
	utf8 := func(value string) uint16 { return add(cpEntry{tag: cpUtf8, text: value}) }
	class := func(name string) uint16 { return add(cpEntry{tag: cpClass, a: utf8(name)}) }
	member := func(tag uint8, owner, name, descriptor string) uint16 {
		ownerIndex := class(owner)
		nameType := add(cpEntry{tag: cpNameAndType, a: utf8(name), b: utf8(descriptor)})
		return add(cpEntry{tag: tag, a: ownerIndex, b: nameType})
	}
	request := member(cpInterfaceMethodref, fixtureRequestParameter.Owner, fixtureRequestParameter.Name, fixtureRequestParameter.Descriptor)
	runtimeGet := member(cpMethodref, fixtureRuntimeGet.Owner, fixtureRuntimeGet.Name, fixtureRuntimeGet.Descriptor)
	runtimeExec := member(cpMethodref, fixtureRuntimeExec.Owner, fixtureRuntimeExec.Name, fixtureRuntimeExec.Descriptor)
	command := add(cpEntry{tag: cpString, a: utf8("cmd")})
	name := "constant"
	descriptor := "Ljava/lang/String;"
	tag := uint8(cpDynamic)
	if invokedynamic {
		name, descriptor, tag = "identity", "(Ljava/lang/String;)Ljava/lang/String;", cpInvokeDynamic
	}
	nameType := add(cpEntry{tag: cpNameAndType, a: utf8(name), b: utf8(descriptor)})
	dynamic := add(cpEntry{tag: tag, a: 0, b: nameType})
	arguments := []uint16(nil)
	if cyclic {
		arguments = []uint16{dynamic}
	}
	cf := &classModel{
		Name: "fixture/BootstrapFlow", Major: 55, Pool: pool,
		Bootstraps: []bootstrapMethod{{ArgumentIndexes: arguments}},
	}
	cf.BootstrapFailures = computeBootstrapFailures(cf)
	code := []byte{0x2a, 0x12, byte(command), 0xb9, byte(request >> 8), byte(request), 0x02, 0x00, 0x4c}
	if invokedynamic {
		code = append(code, 0x2b, 0xba, byte(dynamic>>8), byte(dynamic), 0x00, 0x00, 0x4c)
	} else {
		code = append(code, 0x13, byte(dynamic>>8), byte(dynamic), 0x57)
	}
	code = append(code,
		0xb8, byte(runtimeGet>>8), byte(runtimeGet), 0x2b,
		0xb6, byte(runtimeExec>>8), byte(runtimeExec), 0x57, 0xb1,
	)
	model := &codeModel{MaxStack: 3, MaxLocals: 2, Bytes: code}
	method := &methodModel{
		Access: 0x0009, Name: "run", Descriptor: "(Ljavax/servlet/http/HttpServletRequest;)V", Code: model,
	}
	instructions, err := decodeInstructions(code, 100)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := buildCFG(model, instructions)
	if err != nil {
		t.Fatal(err)
	}
	return cf, method, cfg
}

func TestAbstractBootstrapResolutionCannotCreateHighConfidenceBridge(t *testing.T) {
	for _, tt := range []struct {
		name          string
		invokedynamic bool
		cyclic        bool
	}{
		{"unknown condy", false, false},
		{"self cyclic condy", false, true},
		{"unknown invokedynamic transform", true, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			cf, method, cfg := bootstrapFlowModel(t, tt.invokedynamic, tt.cyclic)
			analysis := analyzeMethod(cf, method, cfg, DefaultOptions(), summarySet{})
			if analysis.Unsupported != "" || analysis.BudgetExhausted != "" || analysis.RequestExec {
				t.Fatalf("bootstrap path gained confidence: %+v", analysis)
			}
		})
	}
}

func TestAbstractJoinedArrayIdentitiesReadEveryPossibleAllocation(t *testing.T) {
	limits := DefaultOptions().Limits
	budget := &abstractBudget{limit: limits.MaxStateMerges}
	left := abstractValue{Verifier: verifierReference, Reference: "[Ljava/lang/String;", ObjectID: 11, Width: 1}
	right := abstractValue{Verifier: verifierReference, Reference: "[Ljava/lang/String;", ObjectID: 22, Width: 1}
	joined, err := mergeValues(left, right, limits, budget)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(joined.ObjectIDs, []uint32{11, 22}) {
		t.Fatalf("joined identities=%v", joined.ObjectIDs)
	}
	f := frame{
		Stack: []abstractValue{joined, {Verifier: verifierInt, Width: 1}},
		Fields: map[fieldKey]abstractValue{
			arrayElementKey(11): {Verifier: verifierReference, Reference: "java/lang/String", Kinds: kindString, Constant: "left", Width: 1},
			arrayElementKey(22): {Verifier: verifierReference, Reference: "java/lang/String", Kinds: kindString, Taint: taintRequestParameter, Width: 1},
		},
	}
	if err := transferArrayLoad(0x32, &f, func(value abstractValue) error {
		f.Stack = append(f.Stack, value)
		return nil
	}, limits, budget); err != nil {
		t.Fatal(err)
	}
	if len(f.Stack) != 1 || f.Stack[0].Taint != taintRequestParameter {
		t.Fatalf("stack=%+v", f.Stack)
	}
}

func TestAbstractJVMArrayAssignmentCompatibility(t *testing.T) {
	cf := &classModel{Name: "fixture/Arrays", Super: "java/lang/Object"}
	for _, tt := range []struct {
		source, target string
		want           bool
	}{
		{"[Ljava/lang/String;", "[Ljava/lang/Object;", true},
		{"[[Ljava/lang/String;", "[[Ljava/lang/Object;", true},
		{"[[Ljava/lang/String;", "[Ljava/lang/Object;", true},
		{"[I", "[Ljava/lang/Object;", false},
		{"[[I", "[[Ljava/lang/Object;", false},
		{"[[I", "[Ljava/lang/Object;", true},
		{"[I", "java/lang/Cloneable", true},
		{"[I", "java/io/Serializable", true},
	} {
		if got := referenceAssignableTo(cf, tt.source, tt.target); got != tt.want {
			t.Errorf("%s assignable to %s = %v, want %v", tt.source, tt.target, got, tt.want)
		}
	}
}

func TestAbstractCovariantStringArrayFieldPreservesExecFlow(t *testing.T) {
	field := memberReference{Owner: "fixture/CovariantArray", Name: "commands", Descriptor: "[Ljava/lang/Object;"}
	execArray := memberReference{Owner: "java/lang/Runtime", Name: "exec", Descriptor: "([Ljava/lang/String;)Ljava/lang/Process;"}
	data, _ := classBytes(t, classSpec{
		Name: "fixture/CovariantArray", Super: "javax/servlet/http/HttpServlet", Major: 49,
		Fields: []classFieldSpec{{Access: 0x0009, Name: "commands", Descriptor: "[Ljava/lang/Object;"}},
		Methods: []classMethodSpec{{
			Name: "service", Descriptor: "(Ljavax/servlet/http/HttpServletRequest;Ljavax/servlet/http/HttpServletResponse;)V",
			MaxStack: 5, MaxLocals: 4,
			Code: []classInstructionSpec{
				{Opcode: 0x04}, {Opcode: 0xbd, ClassName: "java/lang/String"}, {Opcode: 0x59}, {Opcode: 0x03},
				{Opcode: 0x2b}, {Opcode: 0x12, Constant: &constantValue{Kind: constantString, String: "cmd"}},
				{Opcode: 0xb9, Member: &fixtureRequestParameter}, {Opcode: 0x53}, {Opcode: 0x4e},
				{Opcode: 0x2d}, {Opcode: 0xb3, Field: &field},
				{Opcode: 0xb8, Member: &fixtureRuntimeGet}, {Opcode: 0xb2, Field: &field},
				{Opcode: 0xb6, Member: &execArray}, {Opcode: 0x57}, {Opcode: 0xb1},
			},
		}},
	})
	result := AnalyzeArtifact("CovariantArray.class", data, DefaultOptions())
	if findingByRule(result.Findings, "javadisk:class-request-exec") == nil || len(result.Diagnostics) != 0 {
		t.Fatalf("result=%+v", result)
	}
}

func incompatibleArrayStoreSpec(handler bool) classSpec {
	code := []classInstructionSpec{
		{Opcode: 0x2b}, {Opcode: 0x12, Constant: &constantValue{Kind: constantString, String: "cmd"}},
		{Opcode: 0xb9, Member: &fixtureRequestParameter}, {Opcode: 0x4e},
		{Opcode: 0x04}, {Opcode: 0xbd, ClassName: "java/lang/String"}, {Opcode: 0x3a, Operands: []byte{4}},
		{Opcode: 0x19, Operands: []byte{4}}, {Opcode: 0x03}, {Opcode: 0xb8, Member: &fixtureRuntimeGet}, {Opcode: 0x53},
	}
	var handlers []exceptionHandler
	if handler {
		code = append(code, classInstructionSpec{Opcode: 0xb1}, classInstructionSpec{Opcode: 0x57})
		handlers = []exceptionHandler{{Start: 15, End: 22, Handler: 23, CatchType: "java/lang/ArrayStoreException"}}
	} else {
		code = append(code,
			classInstructionSpec{Opcode: 0xb8, Member: &fixtureRuntimeGet}, classInstructionSpec{Opcode: 0x2d},
			classInstructionSpec{Opcode: 0xb6, Member: &fixtureRuntimeExec}, classInstructionSpec{Opcode: 0x57},
		)
	}
	code = append(code,
		classInstructionSpec{Opcode: 0xb8, Member: &fixtureRuntimeGet}, classInstructionSpec{Opcode: 0x2d},
		classInstructionSpec{Opcode: 0xb6, Member: &fixtureRuntimeExec}, classInstructionSpec{Opcode: 0x57},
		classInstructionSpec{Opcode: 0xb1},
	)
	return classSpec{
		Name: "fixture/IncompatibleArrayStore", Super: "javax/servlet/http/HttpServlet", Major: 49,
		Methods: []classMethodSpec{{
			Name: "service", Descriptor: "(Ljavax/servlet/http/HttpServletRequest;Ljavax/servlet/http/HttpServletResponse;)V",
			MaxStack: 4, MaxLocals: 5, Code: code, Handlers: handlers,
		}},
	}
}

func TestAbstractKnownIncompatibleArrayStoreHasNoNormalFlow(t *testing.T) {
	for _, tt := range []struct {
		name, catch string
		handler     bool
		wantExec    bool
	}{
		{"normal successor", "", false, false},
		{"matching handler", "java/lang/ArrayStoreException", true, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			data, _ := classBytes(t, incompatibleArrayStoreSpec(tt.handler))
			result := AnalyzeArtifact(tt.name+".class", data, DefaultOptions())
			got := findingByRule(result.Findings, "javadisk:class-request-exec") != nil
			if got != tt.wantExec || len(result.Diagnostics) != 0 {
				t.Fatalf("finding=%v want=%v result=%+v", got, tt.wantExec, result)
			}
		})
	}
}

func exactArrayIndexFlowSpec(loadIndex byte) classSpec {
	return classSpec{
		Name: "fixture/ExactArrayIndex", Super: "javax/servlet/http/HttpServlet", Major: 49,
		Methods: []classMethodSpec{{
			Name: "service", Descriptor: "(Ljavax/servlet/http/HttpServletRequest;Ljavax/servlet/http/HttpServletResponse;)V",
			MaxStack: 4, MaxLocals: 4,
			Code: []classInstructionSpec{
				{Opcode: 0x05}, {Opcode: 0xbd, ClassName: "java/lang/String"}, {Opcode: 0x4e},
				{Opcode: 0x2d}, {Opcode: 0x04}, {Opcode: 0x2b},
				{Opcode: 0x12, Constant: &constantValue{Kind: constantString, String: "cmd"}},
				{Opcode: 0xb9, Member: &fixtureRequestParameter}, {Opcode: 0x53},
				{Opcode: 0xb8, Member: &fixtureRuntimeGet}, {Opcode: 0x2d}, {Opcode: loadIndex},
				{Opcode: 0x32}, {Opcode: 0xb6, Member: &fixtureRuntimeExec}, {Opcode: 0x57}, {Opcode: 0xb1},
			},
		}},
	}
}

func TestAbstractExactArrayIndexesDoNotConflateCommands(t *testing.T) {
	for _, tt := range []struct {
		name      string
		loadIndex byte
		wantExec  bool
	}{
		{"safe index zero", 0x03, false},
		{"tainted index one", 0x04, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			data, _ := classBytes(t, exactArrayIndexFlowSpec(tt.loadIndex))
			result := AnalyzeArtifact(tt.name+".class", data, DefaultOptions())
			got := findingByRule(result.Findings, "javadisk:class-request-exec") != nil
			if got != tt.wantExec || len(result.Diagnostics) != 0 {
				t.Fatalf("finding=%v want=%v result=%+v", got, tt.wantExec, result)
			}
		})
	}
}

func TestAbstractExactArrayStoreStronglyUpdatesOneIdentity(t *testing.T) {
	for _, tt := range []struct {
		name      string
		alias     bool
		taintLast bool
		wantExec  bool
	}{
		{"taint overwritten directly", false, false, false},
		{"taint overwritten through alias", true, false, false},
		{"taint written last", true, true, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			firstValue := []classInstructionSpec{{Opcode: 0x2b}, {Opcode: 0x12, Constant: &constantValue{Kind: constantString, String: "cmd"}}, {Opcode: 0xb9, Member: &fixtureRequestParameter}}
			secondValue := []classInstructionSpec{{Opcode: 0x12, Constant: &constantValue{Kind: constantString, String: "safe"}}}
			if tt.taintLast {
				firstValue, secondValue = secondValue, firstValue
			}
			storeLocal := byte(4)
			if tt.alias {
				storeLocal = 5
			}
			code := []classInstructionSpec{
				{Opcode: 0x04}, {Opcode: 0xbd, ClassName: "java/lang/String"}, {Opcode: 0x3a, Operands: []byte{4}},
				{Opcode: 0x19, Operands: []byte{4}}, {Opcode: 0x3a, Operands: []byte{5}},
				{Opcode: 0x19, Operands: []byte{4}}, {Opcode: 0x03},
			}
			code = append(code, firstValue...)
			code = append(code, classInstructionSpec{Opcode: 0x53}, classInstructionSpec{Opcode: 0x19, Operands: []byte{storeLocal}}, classInstructionSpec{Opcode: 0x03})
			code = append(code, secondValue...)
			code = append(code,
				classInstructionSpec{Opcode: 0x53}, classInstructionSpec{Opcode: 0xb8, Member: &fixtureRuntimeGet},
				classInstructionSpec{Opcode: 0x19, Operands: []byte{4}}, classInstructionSpec{Opcode: 0x03}, classInstructionSpec{Opcode: 0x32},
				classInstructionSpec{Opcode: 0xb6, Member: &fixtureRuntimeExec}, classInstructionSpec{Opcode: 0x57}, classInstructionSpec{Opcode: 0xb1},
			)
			data, _ := classBytes(t, classSpec{
				Name: "fixture/ArrayStrongUpdate", Super: "javax/servlet/http/HttpServlet", Major: 49,
				Methods: []classMethodSpec{{
					Name: "service", Descriptor: "(Ljavax/servlet/http/HttpServletRequest;Ljavax/servlet/http/HttpServletResponse;)V",
					MaxStack: 4, MaxLocals: 6, Code: code,
				}},
			})
			result := AnalyzeArtifact(tt.name+".class", data, DefaultOptions())
			got := findingByRule(result.Findings, "javadisk:class-request-exec") != nil
			if got != tt.wantExec || len(result.Diagnostics) != 0 {
				t.Fatalf("finding=%v want=%v result=%+v", got, tt.wantExec, result)
			}
		})
	}
}

func TestAbstractUnknownArrayIndexWriteRemainsConservative(t *testing.T) {
	data, _ := classBytes(t, classSpec{
		Name: "fixture/UnknownArrayIndex", Super: "javax/servlet/http/HttpServlet", Major: 49,
		Methods: []classMethodSpec{{
			Name: "service", Descriptor: "(Ljavax/servlet/http/HttpServletRequest;Ljavax/servlet/http/HttpServletResponse;I)V",
			MaxStack: 4, MaxLocals: 5,
			Code: []classInstructionSpec{
				{Opcode: 0x05}, {Opcode: 0xbd, ClassName: "java/lang/String"}, {Opcode: 0x3a, Operands: []byte{4}},
				{Opcode: 0x19, Operands: []byte{4}}, {Opcode: 0x1d}, {Opcode: 0x2b},
				{Opcode: 0x12, Constant: &constantValue{Kind: constantString, String: "cmd"}},
				{Opcode: 0xb9, Member: &fixtureRequestParameter}, {Opcode: 0x53},
				{Opcode: 0xb8, Member: &fixtureRuntimeGet}, {Opcode: 0x19, Operands: []byte{4}}, {Opcode: 0x03},
				{Opcode: 0x32}, {Opcode: 0xb6, Member: &fixtureRuntimeExec}, {Opcode: 0x57}, {Opcode: 0xb1},
			},
		}},
	})
	result := AnalyzeArtifact("UnknownArrayIndex.class", data, DefaultOptions())
	if findingByRule(result.Findings, "javadisk:class-request-exec") == nil || len(result.Diagnostics) != 0 {
		t.Fatalf("result=%+v", result)
	}
}

func crossedArraySelectionSpec(selectTaintedPath bool) classSpec {
	branchASelection := byte(4)
	if selectTaintedPath {
		branchASelection = 3
	}
	return classSpec{
		Name: "fixture/CrossedArrays", Super: "javax/servlet/http/HttpServlet", Major: 49,
		Methods: []classMethodSpec{{
			Name: "service", Descriptor: "(Ljavax/servlet/http/HttpServletRequest;Ljavax/servlet/http/HttpServletResponse;I)V",
			MaxStack: 4, MaxLocals: 7,
			Code: []classInstructionSpec{
				{Opcode: 0x04}, {Opcode: 0xbd, ClassName: "java/lang/String"}, {Opcode: 0x3a, Operands: []byte{4}},
				{Opcode: 0x04}, {Opcode: 0xbd, ClassName: "java/lang/String"}, {Opcode: 0x3a, Operands: []byte{5}},
				{Opcode: 0x1d}, {Opcode: 0x99, Operands: []byte{0x00, 0x16}},
				{Opcode: 0x19, Operands: []byte{4}}, {Opcode: 0x03}, {Opcode: 0x2b},
				{Opcode: 0x12, Constant: &constantValue{Kind: constantString, String: "cmd"}},
				{Opcode: 0xb9, Member: &fixtureRequestParameter}, {Opcode: 0x53},
				{Opcode: 0x19, Operands: []byte{branchASelection + 1}}, {Opcode: 0x3a, Operands: []byte{6}},
				{Opcode: 0xa7, Operands: []byte{0x00, 0x13}},
				{Opcode: 0x19, Operands: []byte{5}}, {Opcode: 0x03}, {Opcode: 0x2b},
				{Opcode: 0x12, Constant: &constantValue{Kind: constantString, String: "cmd"}},
				{Opcode: 0xb9, Member: &fixtureRequestParameter}, {Opcode: 0x53},
				{Opcode: 0x19, Operands: []byte{4}}, {Opcode: 0x3a, Operands: []byte{6}},
				{Opcode: 0xb8, Member: &fixtureRuntimeGet}, {Opcode: 0x19, Operands: []byte{6}},
				{Opcode: 0x03}, {Opcode: 0x32}, {Opcode: 0xb6, Member: &fixtureRuntimeExec},
				{Opcode: 0x57}, {Opcode: 0xb1},
			},
		}},
	}
}

func TestAbstractArraySelectionKeepsHeapPathCorrelation(t *testing.T) {
	for _, tt := range []struct {
		name              string
		selectTaintedPath bool
		wantFinding       bool
	}{
		{"crossed safe selections", false, false},
		{"one tainted selected path", true, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			data, _ := classBytes(t, crossedArraySelectionSpec(tt.selectTaintedPath))
			result := AnalyzeArtifact(tt.name+".class", data, DefaultOptions())
			got := findingByRule(result.Findings, "javadisk:class-request-exec") != nil
			if got != tt.wantFinding || len(result.Diagnostics) != 0 {
				t.Fatalf("finding=%v result=%+v", got, result)
			}
		})
	}
}

func TestAbstractProcessBuilderObservesCommandArrayMutationAfterConstruction(t *testing.T) {
	constructor := memberReference{Owner: "java/lang/ProcessBuilder", Name: "<init>", Descriptor: "([Ljava/lang/String;)V"}
	start := memberReference{Owner: "java/lang/ProcessBuilder", Name: "start", Descriptor: "()Ljava/lang/Process;"}
	data, _ := classBytes(t, classSpec{
		Name: "fixture/BuilderArrayMutation", Super: "javax/servlet/http/HttpServlet", Major: 49,
		Methods: []classMethodSpec{{
			Name: "service", Descriptor: "(Ljavax/servlet/http/HttpServletRequest;Ljavax/servlet/http/HttpServletResponse;I)V",
			MaxStack: 5, MaxLocals: 7, Code: []classInstructionSpec{
				{Opcode: 0x04}, {Opcode: 0xbd, ClassName: "java/lang/String"}, {Opcode: 0x3a, Operands: []byte{4}},
				{Opcode: 0xbb, ClassName: "java/lang/ProcessBuilder"}, {Opcode: 0x59}, {Opcode: 0x19, Operands: []byte{4}},
				{Opcode: 0xb7, Member: &constructor}, {Opcode: 0x3a, Operands: []byte{5}},
				{Opcode: 0x1d}, {Opcode: 0x99, Operands: []byte{0x00, 0x0a}},
				{Opcode: 0x19, Operands: []byte{4}}, {Opcode: 0x3a, Operands: []byte{6}},
				{Opcode: 0xa7, Operands: []byte{0x00, 0x06}},
				{Opcode: 0x01}, {Opcode: 0x3a, Operands: []byte{6}},
				{Opcode: 0x19, Operands: []byte{6}}, {Opcode: 0x03}, {Opcode: 0x2b},
				{Opcode: 0x12, Constant: &constantValue{Kind: constantString, String: "cmd"}},
				{Opcode: 0xb9, Member: &fixtureRequestParameter}, {Opcode: 0x53},
				{Opcode: 0x19, Operands: []byte{5}}, {Opcode: 0xb6, Member: &start},
				{Opcode: 0x57}, {Opcode: 0xb1},
			},
		}},
	})
	result := AnalyzeArtifact("BuilderArrayMutation.class", data, DefaultOptions())
	finding := findingByRule(result.Findings, "javadisk:class-request-exec")
	if finding == nil || !strings.Contains(finding.Evidence, "getParameter") ||
		!strings.Contains(finding.Evidence, "ProcessBuilder.start") || len(result.Diagnostics) != 0 {
		t.Fatalf("result=%+v", result)
	}
}

func FuzzAnalyzeMethodNeverPanics(f *testing.F) {
	for _, seed := range [][]byte{
		{0x00}, {0x01}, {0x02}, {0x04}, {0x08}, {0x10}, {0x1f}, {0x20}, {0x30}, {0x3f},
		{0xb1}, {0x00, 0x03, 0x57, 0xc2, 0xbf},
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		cf, method := fixedFuzzSemanticMethod(data)
		instructions, err := decodeInstructions(method.Code.Bytes, 10_000)
		if err != nil {
			t.Fatal(err)
		}
		cfg, err := buildCFG(method.Code, instructions)
		if err != nil {
			t.Fatal(err)
		}
		opts := DefaultOptions()
		analysis := analyzeMethod(cf, method, cfg, opts, summarySet{})
		repeat := analyzeMethod(cf, method, cfg, opts, summarySet{})
		if !reflect.DeepEqual(analysis, repeat) {
			t.Fatalf("nondeterministic fixed analysis: first=%+v second=%+v", analysis, repeat)
		}
		assertAnalysisInvariants(t, analysis, cfg, opts)
		if analysis.Unsupported != "" || analysis.BudgetExhausted != "" || analysis.Cancelled ||
			!analysis.RequestExec || analysis.Source.API == "" ||
			(analysis.Sink.API != "Runtime.exec" && analysis.Sink.API != "ProcessBuilder.start") {
			t.Fatalf("fixed semantic model did not complete substantive flow: %+v", analysis)
		}

		budgetOpts := opts
		budgetOpts.Limits.MaxStateMerges = 1
		budgeted := analyzeMethod(cf, method, cfg, budgetOpts, summarySet{})
		assertAnalysisInvariants(t, budgeted, cfg, budgetOpts)
		if budgeted.BudgetExhausted == "" || budgeted.RequestExec {
			t.Fatalf("budgeted analysis retained confidence: %+v", budgeted)
		}

		cancelledContext, cancel := context.WithCancel(context.Background())
		cancel()
		cancelled := analyzeMethodContext(cancelledContext, cf, method, cfg, opts, summarySet{})
		assertAnalysisInvariants(t, cancelled, cfg, opts)
		if !cancelled.Cancelled || cancelled.RequestExec {
			t.Fatalf("cancelled analysis retained confidence: %+v", cancelled)
		}

		if len(data) > 512 {
			data = data[:512]
		}
		randomInstructions, decodeErr := decodeInstructions(data, 10_000)
		if decodeErr != nil {
			return
		}
		randomCode := &codeModel{MaxStack: 8, MaxLocals: 8, Bytes: data}
		randomCFG, cfgErr := buildCFG(randomCode, randomInstructions)
		if cfgErr != nil {
			return
		}
		randomMethod := &methodModel{Access: 0x0009, Name: "random", Descriptor: "()V", Code: randomCode}
		random := analyzeMethod(cf, randomMethod, randomCFG, opts, summarySet{})
		assertAnalysisInvariants(t, random, randomCFG, opts)
		if random.Unsupported != "" || random.BudgetExhausted != "" || random.Cancelled {
			if random.RequestExec || random.Source.API != "" || random.Sink.API != "" {
				t.Fatalf("failed random analysis retained confidence: %+v", random)
			}
		}
	})
}

func TestFixedFuzzSemanticMutationsAffectReachableAnalysis(t *testing.T) {
	signatures := map[string]struct{}{}
	sources := map[string]struct{}{}
	sinks := map[string]struct{}{}
	for _, seed := range [][]byte{{0x00}, {0x01}, {0x02}, {0x04}, {0x08}, {0x10}, {0x1f}, {0x20}, {0x30}, {0x3f}} {
		cf, method := fixedFuzzSemanticMethod(seed)
		instructions, err := decodeInstructions(method.Code.Bytes, 10_000)
		if err != nil {
			t.Fatal(err)
		}
		cfg, err := buildCFG(method.Code, instructions)
		if err != nil {
			t.Fatal(err)
		}
		analysis := analyzeMethod(cf, method, cfg, DefaultOptions(), summarySet{})
		if analysis.Unsupported != "" || analysis.BudgetExhausted != "" || !analysis.RequestExec {
			t.Fatalf("seed %x did not exercise a valid semantic flow: %+v", seed, analysis)
		}
		sources[analysis.Source.API] = struct{}{}
		sinks[analysis.Sink.API] = struct{}{}
		reachable := strings.Builder{}
		for _, start := range cfg.Order {
			if _, ok := analysis.Frames[start]; !ok {
				continue
			}
			for _, instruction := range cfg.Blocks[start].Instructions {
				fmt.Fprintf(&reachable, "%02x:%x;", instruction.Opcode, instruction.Operands)
			}
		}
		handler := method.Code.Handlers[0]
		signatures[fmt.Sprintf("%s|%s|%d:%d|%s", analysis.Source.API, analysis.Sink.API, handler.Start, handler.End, reachable.String())] = struct{}{}
	}
	if len(sources) < 2 || len(sinks) < 2 || len(signatures) < 5 {
		t.Fatalf("mutations did not affect reachable semantics: sources=%v sinks=%v signatures=%d", sources, sinks, len(signatures))
	}
}

func TestFixedFuzzSemanticIdentityBranchesUseRuntimeInput(t *testing.T) {
	_, safeSelection := fixedFuzzSemanticMethod([]byte{0x10})
	_, alternateSelection := fixedFuzzSemanticMethod([]byte{0x30})
	if safeSelection.Descriptor != "(Ljavax/servlet/http/HttpServletRequest;I)V" ||
		alternateSelection.Descriptor != safeSelection.Descriptor {
		t.Fatalf("identity fuzz methods lack runtime branch input: %q %q", safeSelection.Descriptor, alternateSelection.Descriptor)
	}
	if len(safeSelection.Code.Bytes) == 0 || safeSelection.Code.Bytes[0] != 0x1b {
		t.Fatalf("identity branch does not load runtime input before semantic flow: %x", safeSelection.Code.Bytes)
	}
	if reflect.DeepEqual(safeSelection.Code.Bytes, alternateSelection.Code.Bytes) {
		t.Fatal("selection mutation bit does not alter reachable identity selection")
	}
}

type fuzzSemanticIndexes struct {
	parameterSource, headerSource uint16
	runtimeGet, runtimeExec       uint16
	processBuilderClass           uint16
	processBuilderConstructor     uint16
	processBuilderStart           uint16
	stringClass, field, command   uint16
}

type fuzzBranchFixup struct {
	offset int
	label  string
}

type fuzzBytecodeBuilder struct {
	code     []byte
	labels   map[string]int
	branches []fuzzBranchFixup
}

func (b *fuzzBytecodeBuilder) emit(values ...byte) {
	b.code = append(b.code, values...)
}

func (b *fuzzBytecodeBuilder) mark(label string) {
	if b.labels == nil {
		b.labels = make(map[string]int)
	}
	b.labels[label] = len(b.code)
}

func (b *fuzzBytecodeBuilder) branch(opcode byte, label string) {
	offset := len(b.code)
	b.emit(opcode, 0, 0)
	b.branches = append(b.branches, fuzzBranchFixup{offset: offset, label: label})
}

func (b *fuzzBytecodeBuilder) finish() []byte {
	for _, fixup := range b.branches {
		target, ok := b.labels[fixup.label]
		if !ok {
			panic("missing fuzz bytecode label " + fixup.label)
		}
		delta := target - fixup.offset
		if delta < math.MinInt16 || delta > math.MaxInt16 {
			panic("fuzz bytecode branch exceeds s16")
		}
		binary.BigEndian.PutUint16(b.code[fixup.offset+1:fixup.offset+3], uint16(int16(delta)))
	}
	return b.code
}

func fixedFuzzSemanticMethod(data []byte) (*classModel, *methodModel) {
	pool := []cpEntry{{}}
	add := func(entry cpEntry) uint16 {
		pool = append(pool, entry)
		return uint16(len(pool) - 1)
	}
	utf8 := func(value string) uint16 { return add(cpEntry{tag: cpUtf8, text: value}) }
	class := func(name string) uint16 { return add(cpEntry{tag: cpClass, a: utf8(name)}) }
	member := func(tag uint8, owner, name, descriptor string) uint16 {
		ownerIndex := class(owner)
		nameType := add(cpEntry{tag: cpNameAndType, a: utf8(name), b: utf8(descriptor)})
		return add(cpEntry{tag: tag, a: ownerIndex, b: nameType})
	}
	indexes := fuzzSemanticIndexes{}
	indexes.parameterSource = member(cpInterfaceMethodref, "javax/servlet/http/HttpServletRequest", "getParameter", "(Ljava/lang/String;)Ljava/lang/String;")
	indexes.headerSource = member(cpInterfaceMethodref, "javax/servlet/http/HttpServletRequest", "getHeader", "(Ljava/lang/String;)Ljava/lang/String;")
	indexes.runtimeGet = member(cpMethodref, "java/lang/Runtime", "getRuntime", "()Ljava/lang/Runtime;")
	indexes.runtimeExec = member(cpMethodref, "java/lang/Runtime", "exec", "(Ljava/lang/String;)Ljava/lang/Process;")
	indexes.processBuilderClass = class("java/lang/ProcessBuilder")
	indexes.processBuilderConstructor = member(cpMethodref, "java/lang/ProcessBuilder", "<init>", "([Ljava/lang/String;)V")
	indexes.processBuilderStart = member(cpMethodref, "java/lang/ProcessBuilder", "start", "()Ljava/lang/Process;")
	indexes.stringClass = class("java/lang/String")
	indexes.field = member(cpFieldref, "fixture/Fuzz", "command", "Ljava/lang/String;")
	indexes.command = add(cpEntry{tag: cpString, a: utf8("cmd")})
	mode := byte(0)
	for index, value := range data {
		if index == 16 {
			break
		}
		mode ^= value + byte(index*17)
	}

	builder := &fuzzBytecodeBuilder{}
	methodDescriptor := "(Ljavax/servlet/http/HttpServletRequest;)V"
	if mode&0x10 != 0 {
		methodDescriptor = "(Ljavax/servlet/http/HttpServletRequest;I)V"
		builder.emit(0x1b)
	}
	builder.emit(0x2a, 0x12, byte(indexes.command))
	sourceStart := uint32(len(builder.code))
	builder.emit(0xb9)
	builder.emit(u2Bytes(indexes.parameterSource)...)
	if mode&0x01 != 0 {
		binary.BigEndian.PutUint16(builder.code[len(builder.code)-2:], indexes.headerSource)
	}
	builder.emit(0x02, 0x00)
	sourceEnd := uint32(len(builder.code))
	builder.emit(0x4c)

	if mode&0x10 != 0 {
		builder.emit(0x04, 0xbd)
		builder.emit(u2Bytes(indexes.stringClass)...)
		builder.emit(0x4d)
		builder.emit(0x04, 0xbd)
		builder.emit(u2Bytes(indexes.stringClass)...)
		builder.emit(0x4e)
		builder.emit(0x2c, 0x03, 0x2b, 0x53)
		builder.branch(0x99, "identity-path-b")
		builder.emit(0x2c, 0x3a, 0x04)
		builder.branch(0xa7, "identity-join")
		builder.mark("identity-path-b")
		selection := byte(0x2d)
		if mode&0x20 != 0 {
			selection = 0x2c
		}
		builder.emit(selection, 0x3a, 0x04)
		builder.mark("identity-join")
		builder.emit(0x19, 0x04, 0x03, 0x32, 0x4c)
	}

	if mode&0x02 != 0 {
		builder.emit(0x2b, 0xb3)
		builder.emit(u2Bytes(indexes.field)...)
	}

	if mode&0x04 != 0 {
		builder.emit(0x04, 0xbd)
		builder.emit(u2Bytes(indexes.stringClass)...)
		builder.emit(0x59, 0x03)
		if mode&0x02 != 0 {
			builder.emit(0xb2)
			builder.emit(u2Bytes(indexes.field)...)
		} else {
			builder.emit(0x2b)
		}
		builder.emit(0x53, 0x3a, 0x05)
		builder.emit(0xbb)
		builder.emit(u2Bytes(indexes.processBuilderClass)...)
		builder.emit(0x59, 0x19, 0x05, 0xb7)
		builder.emit(u2Bytes(indexes.processBuilderConstructor)...)
		builder.emit(0x3a, 0x06, 0x19, 0x06)
		sinkStart := uint32(len(builder.code))
		builder.emit(0xb6)
		builder.emit(u2Bytes(indexes.processBuilderStart)...)
		sinkEnd := uint32(len(builder.code))
		builder.emit(0x57, 0xb1)
		handler := uint32(len(builder.code))
		builder.emit(0x57, 0xb1)
		start, end := sourceStart, sourceEnd
		if mode&0x08 != 0 {
			start, end = sinkStart, sinkEnd
		}
		model := &codeModel{MaxStack: 8, MaxLocals: 7, Bytes: builder.finish(), Handlers: []exceptionHandler{{Start: start, End: end, Handler: handler, CatchType: "java/lang/Throwable"}}}
		cf := &classModel{Name: "fixture/Fuzz", Major: 49, Pool: pool, Fields: []fieldModel{{Access: 0x0009, Name: "command", Descriptor: "Ljava/lang/String;"}}}
		return cf, &methodModel{Access: 0x0009, Name: "fuzz", Descriptor: methodDescriptor, Code: model}
	}

	builder.emit(0xb8)
	builder.emit(u2Bytes(indexes.runtimeGet)...)
	if mode&0x02 != 0 {
		builder.emit(0xb2)
		builder.emit(u2Bytes(indexes.field)...)
	} else {
		builder.emit(0x2b)
	}
	sinkStart := uint32(len(builder.code))
	builder.emit(0xb6)
	builder.emit(u2Bytes(indexes.runtimeExec)...)
	sinkEnd := uint32(len(builder.code))
	builder.emit(0x57, 0xb1)
	handler := uint32(len(builder.code))
	builder.emit(0x57, 0xb1)
	start, end := sourceStart, sourceEnd
	if mode&0x08 != 0 {
		start, end = sinkStart, sinkEnd
	}
	model := &codeModel{
		MaxStack: 8, MaxLocals: 7, Bytes: builder.finish(),
		Handlers: []exceptionHandler{{Start: start, End: end, Handler: handler, CatchType: "java/lang/Throwable"}},
	}
	cf := &classModel{
		Name: "fixture/Fuzz", Major: 49, Pool: pool,
		Fields: []fieldModel{{Access: 0x0009, Name: "command", Descriptor: "Ljava/lang/String;"}},
	}
	return cf, &methodModel{Access: 0x0009, Name: "fuzz", Descriptor: methodDescriptor, Code: model}
}

func assertAnalysisInvariants(t *testing.T, analysis methodAnalysis, cfg *controlFlowGraph, opts Options) {
	t.Helper()
	if analysis.WorkUnits < 0 || analysis.WorkUnits > opts.Limits.MaxStateMerges {
		t.Fatalf("work units=%d limit=%d", analysis.WorkUnits, opts.Limits.MaxStateMerges)
	}
	if len(analysis.Frames) > len(cfg.Blocks) {
		t.Fatalf("frames=%d blocks=%d", len(analysis.Frames), len(cfg.Blocks))
	}
	for start, state := range analysis.Frames {
		if cfg.Blocks[start] == nil {
			t.Fatalf("frame for non-block %d", start)
		}
		if len(state.Locals)+stackSlots(state.Stack)+len(state.Fields) > opts.Limits.MaxFrameSlots {
			t.Fatalf("frame %d exceeds configured slots: %+v", start, state)
		}
		values := append(append([]abstractValue(nil), state.Locals...), state.Stack...)
		for _, value := range state.Fields {
			values = append(values, value)
		}
		for _, value := range values {
			if len(value.ObjectIDs) > 32 || !sort.SliceIsSorted(value.ObjectIDs, func(i, j int) bool {
				return value.ObjectIDs[i] < value.ObjectIDs[j]
			}) {
				t.Fatalf("invalid allocation identities: %v", value.ObjectIDs)
			}
			for i := 1; i < len(value.ObjectIDs); i++ {
				if value.ObjectIDs[i-1] == value.ObjectIDs[i] {
					t.Fatalf("duplicate allocation identity: %v", value.ObjectIDs)
				}
			}
		}
	}
}
