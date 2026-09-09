package javadisk

import (
	"context"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"
)

type structuralInstructionSpec struct {
	opcode    byte
	operands  []byte
	reference *memberReference
}

type structuralMethodSpec struct {
	name       string
	descriptor string
	code       []structuralInstructionSpec
}

type structuralClassSpec struct {
	name        string
	super       string
	interfaces  []string
	annotations []string
	rawUTF8     []string
	methods     []structuralMethodSpec
}

func structuralCall(opcode byte, reference memberReference) structuralInstructionSpec {
	return structuralInstructionSpec{opcode: opcode, reference: &reference}
}

func structuralOpcode(opcode byte) structuralInstructionSpec {
	return structuralInstructionSpec{opcode: opcode}
}

func structuralOpcodeOperands(opcode byte, operands ...byte) structuralInstructionSpec {
	return structuralInstructionSpec{opcode: opcode, operands: operands}
}

func structuralClassBytes(t *testing.T, spec structuralClassSpec) []byte {
	t.Helper()
	if spec.name == "" {
		spec.name = "fixture/Structural"
	}
	if spec.super == "" {
		spec.super = "java/lang/Object"
	}

	pool := newConstantPoolBuilder()
	thisClass := pool.u2Entry(cpClass, pool.utf8(spec.name))
	superClass := pool.u2Entry(cpClass, pool.utf8(spec.super))
	interfaces := make([]uint16, 0, len(spec.interfaces))
	for _, name := range spec.interfaces {
		interfaces = append(interfaces, pool.u2Entry(cpClass, pool.utf8(name)))
	}
	for _, value := range spec.rawUTF8 {
		pool.utf8(value)
	}

	codeName := pool.utf8("Code")
	methods := make([][]byte, 0, len(spec.methods))
	for _, method := range spec.methods {
		name := pool.utf8(method.name)
		descriptor := method.descriptor
		if descriptor == "" {
			descriptor = "()V"
		}
		descriptorIndex := pool.utf8(descriptor)
		var bytecode []byte
		for _, instruction := range method.code {
			if instruction.reference == nil {
				bytecode = append(bytecode, instruction.opcode)
				bytecode = append(bytecode, instruction.operands...)
				continue
			}
			descriptor, err := parseMethodDescriptor(instruction.reference.Descriptor)
			if err != nil {
				t.Fatalf("invalid structural call descriptor %q: %v", instruction.reference.Descriptor, err)
			}
			if instruction.opcode != 0xb8 {
				bytecode = append(bytecode, 0x01)
			}
			for _, parameter := range descriptor.Parameters {
				switch parameter.Descriptor[0] {
				case 'J':
					bytecode = append(bytecode, 0x09)
				case 'D':
					bytecode = append(bytecode, 0x0e)
				case 'F':
					bytecode = append(bytecode, 0x0b)
				case 'L', '[':
					bytecode = append(bytecode, 0x01)
				default:
					bytecode = append(bytecode, 0x03)
				}
			}
			bytecode = append(bytecode, instruction.opcode)
			owner := pool.u2Entry(cpClass, pool.utf8(instruction.reference.Owner))
			nameAndType := pool.pairEntry(
				cpNameAndType,
				pool.utf8(instruction.reference.Name),
				pool.utf8(instruction.reference.Descriptor),
			)
			tag := byte(cpMethodref)
			if instruction.reference.Interface {
				tag = cpInterfaceMethodref
			}
			index := pool.pairEntry(tag, owner, nameAndType)
			bytecode = append(bytecode, u2Bytes(index)...)
			if instruction.opcode == 0xb9 {
				bytecode = append(bytecode, structuralInvokeInterfaceCount(t, instruction.reference.Descriptor), 0)
			}
			if !descriptor.Return.Void {
				if descriptor.Return.Width == 2 {
					bytecode = append(bytecode, 0x58)
				} else {
					bytecode = append(bytecode, 0x57)
				}
			}
		}
		code := append(u2Bytes(8), u2Bytes(8)...)
		code = append(code, u4Bytes(uint32(len(bytecode)))...)
		code = append(code, bytecode...)
		code = append(code, 0, 0, 0, 0)
		methods = append(methods, memberFixture(
			0x0001, name, descriptorIndex, attributeFixture(codeName, code),
		))
	}

	var attributes [][]byte
	if len(spec.annotations) != 0 {
		attributeName := pool.utf8("RuntimeVisibleAnnotations")
		payload := u2Bytes(uint16(len(spec.annotations)))
		for _, descriptor := range spec.annotations {
			payload = append(payload, u2Bytes(pool.utf8(descriptor))...)
			payload = append(payload, 0, 0)
		}
		attributes = append(attributes, attributeFixture(attributeName, payload))
	}

	data := finishClass(0, 49, pool, thisClass, superClass, interfaces)
	data = data[:len(data)-6]
	data = append(data, 0, 0)
	data = append(data, u2Bytes(uint16(len(methods)))...)
	for _, method := range methods {
		data = append(data, method...)
	}
	data = append(data, u2Bytes(uint16(len(attributes)))...)
	for _, attribute := range attributes {
		data = append(data, attribute...)
	}
	return data
}

func structuralInvokeInterfaceCount(t *testing.T, descriptor string) byte {
	t.Helper()
	if len(descriptor) < 3 || descriptor[0] != '(' {
		t.Fatalf("invalid method descriptor %q", descriptor)
	}
	slots := 1
	for index := 1; ; {
		if index >= len(descriptor) {
			t.Fatalf("unterminated method descriptor %q", descriptor)
		}
		if descriptor[index] == ')' {
			if slots > 255 {
				t.Fatalf("invokeinterface count %d exceeds u1 for %q", slots, descriptor)
			}
			return byte(slots)
		}
		switch descriptor[index] {
		case 'J', 'D':
			slots += 2
			index++
		case 'B', 'C', 'F', 'I', 'S', 'Z':
			slots++
			index++
		case 'L':
			end := strings.IndexByte(descriptor[index:], ';')
			if end < 1 {
				t.Fatalf("invalid object parameter in descriptor %q", descriptor)
			}
			slots++
			index += end + 1
		case '[':
			slots++
			for index < len(descriptor) && descriptor[index] == '[' {
				index++
			}
			if index >= len(descriptor) {
				t.Fatalf("invalid array parameter in descriptor %q", descriptor)
			}
			if descriptor[index] == 'L' {
				end := strings.IndexByte(descriptor[index:], ';')
				if end < 1 {
					t.Fatalf("invalid array object parameter in descriptor %q", descriptor)
				}
				index += end + 1
			} else {
				index++
			}
		default:
			t.Fatalf("invalid parameter descriptor %q in %q", descriptor[index], descriptor)
		}
	}
}

func findingByRule(findings []Finding, rule string) *Finding {
	for i := range findings {
		if findings[i].Rule == rule {
			return &findings[i]
		}
	}
	return nil
}

var (
	javaxRequestParameter = memberReference{
		Owner: "javax/servlet/http/HttpServletRequest", Name: "getParameter",
		Descriptor: "(Ljava/lang/String;)Ljava/lang/String;", Interface: true,
	}
	jakartaRequestHeader = memberReference{
		Owner: "jakarta/servlet/http/HttpServletRequest", Name: "getHeader",
		Descriptor: "(Ljava/lang/String;)Ljava/lang/String;", Interface: true,
	}
	runtimeExecString = memberReference{
		Owner: "java/lang/Runtime", Name: "exec",
		Descriptor: "(Ljava/lang/String;)Ljava/lang/Process;",
	}
	base64DecodeString = memberReference{
		Owner: "java/util/Base64$Decoder", Name: "decode",
		Descriptor: "(Ljava/lang/String;)[B",
	}
	classLoaderDefine = memberReference{
		Owner: "java/lang/ClassLoader", Name: "defineClass",
		Descriptor: "([BII)Ljava/lang/Class;",
	}
	scriptEngineEval = memberReference{
		Owner: "javax/script/ScriptEngine", Name: "eval",
		Descriptor: "(Ljava/lang/String;)Ljava/lang/Object;", Interface: true,
	}
	servletAddFilter = memberReference{
		Owner: "jakarta/servlet/ServletContext", Name: "addFilter",
		Descriptor: "(Ljava/lang/String;Ljakarta/servlet/Filter;)Ljakarta/servlet/FilterRegistration$Dynamic;",
		Interface:  true,
	}
)

func TestStructuralFindingsAreResolvedMethodLocalAndDeterministic(t *testing.T) {
	data := structuralClassBytes(t, structuralClassSpec{
		name: "fixture/Shell",
		methods: []structuralMethodSpec{
			{name: "requestExec", code: []structuralInstructionSpec{
				structuralCall(0xb9, javaxRequestParameter), structuralCall(0xb6, runtimeExecString), structuralOpcode(0xb1),
			}},
			{name: "dynamicLoad", code: []structuralInstructionSpec{
				structuralCall(0xb6, base64DecodeString), structuralCall(0xb6, classLoaderDefine), structuralOpcode(0xb1),
			}},
			{name: "scriptEval", code: []structuralInstructionSpec{
				structuralCall(0xb9, jakartaRequestHeader), structuralCall(0xb9, scriptEngineEval), structuralOpcode(0xb1),
			}},
			{name: "register", code: []structuralInstructionSpec{
				structuralCall(0xb9, servletAddFilter), structuralOpcode(0xb1),
			}},
		},
	})
	path := `C:\physical\webapps\ROOT\WEB-INF\classes\fixture\Shell.class`
	first := AnalyzeArtifact(path, data, DefaultOptions())
	if len(first.Diagnostics) != 0 || len(first.Findings) != 4 {
		t.Fatalf("result=%+v", first)
	}
	wantRules := []string{
		"javadisk:class-dynamic-load-structure",
		"javadisk:class-hook-registration-structure",
		"javadisk:class-request-exec-structure",
		"javadisk:class-script-eval-structure",
	}
	for i, rule := range wantRules {
		finding := first.Findings[i]
		if finding.Rule != rule || finding.Score != 60 || finding.ArtifactPath != path {
			t.Fatalf("finding[%d]=%+v want rule=%q score=60 path=%q", i, finding, rule, path)
		}
		if !strings.Contains(finding.Evidence, "fixture/Shell.") ||
			len(finding.Evidence) > maxDiagnosticTextBytes || strings.ContainsAny(finding.Evidence, "\r\n\t") {
			t.Fatalf("unbounded or incomplete evidence: %q", finding.Evidence)
		}
	}
	if evidence := findingByRule(first.Findings, "javadisk:class-request-exec-structure").Evidence; !strings.Contains(evidence, "HttpServletRequest.getParameter") || !strings.Contains(evidence, "Runtime.exec") {
		t.Fatalf("request/exec evidence=%q", evidence)
	}
	if evidence := findingByRule(first.Findings, "javadisk:class-dynamic-load-structure").Evidence; !strings.Contains(evidence, "Base64$Decoder.decode") || !strings.Contains(evidence, "ClassLoader.defineClass") {
		t.Fatalf("dynamic-load evidence=%q", evidence)
	}
	for i := 0; i < 20; i++ {
		if got := AnalyzeArtifact(path, data, DefaultOptions()); !reflect.DeepEqual(got, first) {
			t.Fatalf("repeat %d differs:\nfirst=%+v\ngot=%+v", i, first, got)
		}
	}
}

func TestStructuralRejectsUnresolvedCrossMethodAndUnreachableNearNeighbors(t *testing.T) {
	harmless := memberReference{Owner: "java/lang/Object", Name: "toString", Descriptor: "()Ljava/lang/String;"}
	tests := []struct {
		name string
		spec structuralClassSpec
	}{
		{
			name: "references split between methods",
			spec: structuralClassSpec{methods: []structuralMethodSpec{
				{name: "source", code: []structuralInstructionSpec{structuralCall(0xb9, javaxRequestParameter), structuralOpcode(0xb1)}},
				{name: "sink", code: []structuralInstructionSpec{structuralCall(0xb6, runtimeExecString), structuralOpcode(0xb1)}},
			}},
		},
		{
			name: "sink after terminal transfer",
			spec: structuralClassSpec{methods: []structuralMethodSpec{{name: "dead", code: []structuralInstructionSpec{
				structuralCall(0xb9, javaxRequestParameter), structuralOpcode(0xb1),
				structuralCall(0xb6, runtimeExecString), structuralOpcode(0xb1),
			}}}},
		},
		{
			name: "all dangerous calls unreachable",
			spec: structuralClassSpec{methods: []structuralMethodSpec{{name: "dead", code: []structuralInstructionSpec{
				structuralOpcode(0xb1), structuralCall(0xb9, javaxRequestParameter),
				structuralCall(0xb6, runtimeExecString), structuralOpcode(0xb1),
			}}}},
		},
		{
			name: "raw UTF8 strings only",
			spec: structuralClassSpec{
				rawUTF8: []string{"java/lang/Runtime", "exec", "(Ljava/lang/String;)Ljava/lang/Process;", "getParameter"},
				methods: []structuralMethodSpec{{name: "text", code: []structuralInstructionSpec{structuralOpcode(0xb1)}}},
			},
		},
		{
			name: "owner suffix",
			spec: structuralClassSpec{methods: []structuralMethodSpec{{name: "near", code: []structuralInstructionSpec{
				structuralCall(0xb9, javaxRequestParameter),
				structuralCall(0xb6, memberReference{Owner: "evil/java/lang/Runtime", Name: "exec", Descriptor: runtimeExecString.Descriptor}),
				structuralOpcode(0xb1),
			}}}},
		},
		{
			name: "near neighbor name",
			spec: structuralClassSpec{methods: []structuralMethodSpec{{name: "near", code: []structuralInstructionSpec{
				structuralCall(0xb9, javaxRequestParameter),
				structuralCall(0xb6, memberReference{Owner: runtimeExecString.Owner, Name: "execute", Descriptor: runtimeExecString.Descriptor}),
				structuralOpcode(0xb1),
			}}}},
		},
		{
			name: "wrong descriptor",
			spec: structuralClassSpec{methods: []structuralMethodSpec{{name: "near", code: []structuralInstructionSpec{
				structuralCall(0xb9, javaxRequestParameter),
				structuralCall(0xb6, memberReference{Owner: runtimeExecString.Owner, Name: runtimeExecString.Name, Descriptor: "()Ljava/lang/Process;"}),
				structuralOpcode(0xb1),
			}}}},
		},
		{
			name: "annotation alone",
			spec: structuralClassSpec{
				annotations: []string{"Ljakarta/servlet/annotation/WebServlet;"},
				methods:     []structuralMethodSpec{{name: "service", code: []structuralInstructionSpec{structuralOpcode(0xb1)}}},
			},
		},
		{
			name: "annotation and harmless call",
			spec: structuralClassSpec{
				annotations: []string{"Ljavax/servlet/annotation/WebFilter;"},
				methods: []structuralMethodSpec{{name: "filter", code: []structuralInstructionSpec{
					structuralCall(0xb6, harmless), structuralOpcode(0xb1),
				}}},
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := AnalyzeArtifact(test.name+".class", structuralClassBytes(t, test.spec), DefaultOptions())
			if len(result.Findings) != 0 || len(result.Diagnostics) != 0 {
				t.Fatalf("result=%+v", result)
			}
		})
	}
}

func TestStructuralExactCatalogFamilies(t *testing.T) {
	tests := []struct {
		name       string
		context    memberReference
		calls      []memberReference
		annotation string
		rule       string
	}{
		{
			name:    "jakarta request and Runtime array exec",
			context: jakartaRequestHeader,
			calls: []memberReference{{
				Owner: "java/lang/Runtime", Name: "exec", Descriptor: "([Ljava/lang/String;[Ljava/lang/String;Ljava/io/File;)Ljava/lang/Process;",
			}},
			rule: "javadisk:class-request-exec-structure",
		},
		{
			name: "JDK Base64 and lookup defineClass",
			calls: []memberReference{
				{Owner: "java/util/Base64$Decoder", Name: "decode", Descriptor: "([B)[B"},
				{Owner: "java/lang/invoke/MethodHandles$Lookup", Name: "defineClass", Descriptor: "([B)Ljava/lang/Class;"},
			},
			rule: "javadisk:class-dynamic-load-structure",
		},
		{
			name:       "server annotation and ScriptEngine compile",
			annotation: "Lorg/springframework/web/bind/annotation/RestController;",
			calls: []memberReference{{
				Owner: "javax/script/Compilable", Name: "compile", Descriptor: "(Ljava/io/Reader;)Ljavax/script/CompiledScript;", Interface: true,
			}},
			rule: "javadisk:class-script-eval-structure",
		},
		{
			name:    "request and Groovy evaluation",
			context: javaxRequestParameter,
			calls: []memberReference{{
				Owner: "groovy/lang/GroovyShell", Name: "evaluate", Descriptor: "(Ljava/lang/String;)Ljava/lang/Object;",
			}},
			rule: "javadisk:class-script-eval-structure",
		},
		{
			name:    "request and OGNL evaluation",
			context: javaxRequestParameter,
			calls: []memberReference{{
				Owner: "ognl/Ognl", Name: "getValue", Descriptor: "(Ljava/lang/String;Ljava/util/Map;Ljava/lang/Object;)Ljava/lang/Object;",
			}},
			rule: "javadisk:class-script-eval-structure",
		},
		{
			name:    "request and modern OGNL context evaluation",
			context: javaxRequestParameter,
			calls: []memberReference{{
				Owner: "ognl/Ognl", Name: "getValue", Descriptor: "(Ljava/lang/String;Lognl/OgnlContext;Ljava/lang/Object;)Ljava/lang/Object;",
			}},
			rule: "javadisk:class-script-eval-structure",
		},
		{
			name:    "request and MVEL evaluation",
			context: javaxRequestParameter,
			calls: []memberReference{{
				Owner: "org/mvel2/MVEL", Name: "eval", Descriptor: "(Ljava/lang/String;Ljava/lang/Object;)Ljava/lang/Object;",
			}},
			rule: "javadisk:class-script-eval-structure",
		},
		{
			name: "WebSocket registration",
			calls: []memberReference{{
				Owner: "jakarta/websocket/server/ServerContainer", Name: "addEndpoint", Descriptor: "(Ljava/lang/Class;)V", Interface: true,
			}},
			rule: "javadisk:class-hook-registration-structure",
		},
		{
			name: "javax JSP registration",
			calls: []memberReference{{
				Owner: "javax/servlet/ServletContext", Name: "addJspFile",
				Descriptor: "(Ljava/lang/String;Ljava/lang/String;)Ljavax/servlet/ServletRegistration$Dynamic;", Interface: true,
			}},
			rule: "javadisk:class-hook-registration-structure",
		},
		{
			name: "jakarta JSP registration",
			calls: []memberReference{{
				Owner: "jakarta/servlet/ServletContext", Name: "addJspFile",
				Descriptor: "(Ljava/lang/String;Ljava/lang/String;)Ljakarta/servlet/ServletRegistration$Dynamic;", Interface: true,
			}},
			rule: "javadisk:class-hook-registration-structure",
		},
		{
			name: "Tomcat filter registration",
			calls: []memberReference{{
				Owner: "org/apache/catalina/core/StandardContext", Name: "addFilterDef",
				Descriptor: "(Lorg/apache/tomcat/util/descriptor/web/FilterDef;)V",
			}},
			rule: "javadisk:class-hook-registration-structure",
		},
		{
			name: "Spring mapping registration",
			calls: []memberReference{{
				Owner: "org/springframework/web/servlet/mvc/method/annotation/RequestMappingHandlerMapping", Name: "registerMapping",
				Descriptor: "(Lorg/springframework/web/servlet/mvc/method/RequestMappingInfo;Ljava/lang/Object;Ljava/lang/reflect/Method;)V",
			}},
			rule: "javadisk:class-hook-registration-structure",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var code []structuralInstructionSpec
			if test.context.Owner != "" {
				opcode := byte(0xb6)
				if test.context.Interface {
					opcode = 0xb9
				}
				code = append(code, structuralCall(opcode, test.context))
			}
			for _, call := range test.calls {
				opcode := byte(0xb6)
				if call.Interface {
					opcode = 0xb9
				}
				code = append(code, structuralCall(opcode, call))
			}
			code = append(code, structuralOpcode(0xb1))
			spec := structuralClassSpec{methods: []structuralMethodSpec{{name: "run", code: code}}}
			if test.annotation != "" {
				spec.annotations = []string{test.annotation}
			}
			result := AnalyzeArtifact(test.name+".class", structuralClassBytes(t, spec), DefaultOptions())
			finding := findingByRule(result.Findings, test.rule)
			if finding == nil || finding.Score != 60 || len(result.Diagnostics) != 0 {
				t.Fatalf("result=%+v", result)
			}
		})
	}
}

func TestStructuralInheritedClassLoaderDefinitionIsExact(t *testing.T) {
	tests := []struct {
		name    string
		class   string
		super   string
		owner   string
		method  string
		desc    string
		finding bool
	}{
		{
			name: "direct ClassLoader subclass", class: "fixture/Loader", super: "java/lang/ClassLoader",
			owner: "fixture/Loader", method: "defineClass", desc: "([BII)Ljava/lang/Class;", finding: true,
		},
		{
			name: "direct SecureClassLoader subclass", class: "fixture/SecureLoader", super: "java/security/SecureClassLoader",
			owner: "fixture/SecureLoader", method: "defineClass",
			desc: "(Ljava/lang/String;[BIILjava/security/CodeSource;)Ljava/lang/Class;", finding: true,
		},
		{
			name: "lookalike superclass", class: "fixture/Loader", super: "evil/ClassLoader",
			owner: "fixture/Loader", method: "defineClass", desc: "([BII)Ljava/lang/Class;",
		},
		{
			name: "arbitrary owner", class: "fixture/Loader", super: "java/lang/ClassLoader",
			owner: "fixture/Other", method: "defineClass", desc: "([BII)Ljava/lang/Class;",
		},
		{
			name: "near neighbor name", class: "fixture/Loader", super: "java/lang/ClassLoader",
			owner: "fixture/Loader", method: "defineClasses", desc: "([BII)Ljava/lang/Class;",
		},
		{
			name: "wrong descriptor", class: "fixture/Loader", super: "java/lang/ClassLoader",
			owner: "fixture/Loader", method: "defineClass", desc: "([B)Ljava/lang/Class;",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			load := memberReference{Owner: test.owner, Name: test.method, Descriptor: test.desc}
			data := structuralClassBytes(t, structuralClassSpec{
				name: test.class, super: test.super,
				methods: []structuralMethodSpec{{name: "load", code: []structuralInstructionSpec{
					structuralCall(0xb6, base64DecodeString), structuralCall(0xb6, load), structuralOpcode(0xb1),
				}}},
			})
			result := AnalyzeArtifact(test.name+".class", data, DefaultOptions())
			got := findingByRule(result.Findings, "javadisk:class-dynamic-load-structure") != nil
			if got != test.finding || len(result.Diagnostics) != 0 {
				t.Fatalf("finding=%v result=%+v", got, result)
			}
		})
	}
}

func TestStructuralEvidencePrioritizesRuleSupportAndBoundsIdentity(t *testing.T) {
	className := "fixture/" + strings.Repeat("LongClass", 24)
	methodName := "method" + strings.Repeat("LongMethod", 24)
	data := structuralClassBytes(t, structuralClassSpec{
		name: className,
		methods: []structuralMethodSpec{{name: methodName, code: []structuralInstructionSpec{
			structuralCall(0xb9, javaxRequestParameter),
			structuralCall(0xb6, base64DecodeString),
			structuralCall(0xb6, classLoaderDefine),
			structuralCall(0xb9, scriptEngineEval),
			structuralCall(0xb9, servletAddFilter),
			structuralCall(0xb6, runtimeExecString),
			structuralOpcode(0xb1),
		}}},
	})
	result := AnalyzeArtifact("Long.class", data, DefaultOptions())
	finding := findingByRule(result.Findings, "javadisk:class-request-exec-structure")
	if finding == nil {
		t.Fatalf("result=%+v", result)
	}
	evidence := finding.Evidence
	if len(evidence) > maxDiagnosticTextBytes || strings.ContainsAny(evidence, "\r\n\t") ||
		!strings.Contains(evidence, "class=fixture/") || !strings.Contains(evidence, ".methodLongMethod") ||
		!strings.Contains(evidence, "HttpServletRequest.getParameter") || !strings.Contains(evidence, "Runtime.exec") {
		t.Fatalf("evidence=%q", evidence)
	}
	for _, unrelated := range []string{"Base64", "defineClass", "ScriptEngine", "addFilter"} {
		if strings.Contains(evidence, unrelated) {
			t.Fatalf("request/exec evidence contains unrelated API %q: %q", unrelated, evidence)
		}
	}
}

func TestStructuralEvidenceRetainsOnlyEarliestMatchingMethod(t *testing.T) {
	method := func(name string) structuralMethodSpec {
		return structuralMethodSpec{name: name, code: []structuralInstructionSpec{
			structuralCall(0xb9, javaxRequestParameter), structuralCall(0xb6, runtimeExecString), structuralOpcode(0xb1),
		}}
	}
	single := AnalyzeArtifact("Many.class", structuralClassBytes(t, structuralClassSpec{
		methods: []structuralMethodSpec{method("a000")},
	}), DefaultOptions())
	methods := make([]structuralMethodSpec, 128)
	for i := range methods {
		methods[i] = method(fmt.Sprintf("a%03d", i))
	}
	many := AnalyzeArtifact("Many.class", structuralClassBytes(t, structuralClassSpec{methods: methods}), DefaultOptions())
	want := findingByRule(single.Findings, "javadisk:class-request-exec-structure")
	got := findingByRule(many.Findings, "javadisk:class-request-exec-structure")
	if want == nil || got == nil || got.Evidence != want.Evidence || strings.Contains(got.Evidence, "a127") {
		t.Fatalf("single=%+v many=%+v", single, many)
	}
}

func TestStructuralFixtureInvokeInterfaceCountUsesArgumentSlots(t *testing.T) {
	reference := memberReference{
		Owner: "fixture/SlotInterface", Name: "call",
		Descriptor: "(JD[DLjava/lang/Object;I)Ljava/lang/Object;", Interface: true,
	}
	data := structuralClassBytes(t, structuralClassSpec{methods: []structuralMethodSpec{{name: "slots", code: []structuralInstructionSpec{
		structuralCall(0xb9, reference), structuralOpcode(0xb1),
	}}}})
	class, err := parseClass(data, DefaultOptions().Limits)
	if err != nil {
		t.Fatal(err)
	}
	instructions, err := decodeInstructions(class.Methods[0].Code.Bytes, 10)
	if err != nil {
		t.Fatal(err)
	}
	for _, instruction := range instructions {
		if instruction.Opcode == 0xb9 {
			if got := instruction.Operands[2]; got != 8 {
				t.Fatalf("invokeinterface count=%d want 8", got)
			}
			return
		}
	}
	t.Fatal("invokeinterface instruction not found")
}

func TestStructuralRejectsInvokeWithWrongConstantPoolTag(t *testing.T) {
	wrongTagExec := runtimeExecString
	wrongTagExec.Interface = true
	data := structuralClassBytes(t, structuralClassSpec{methods: []structuralMethodSpec{{name: "wrongTag", code: []structuralInstructionSpec{
		structuralCall(0xb6, wrongTagExec),
		structuralCall(0xb9, javaxRequestParameter),
		structuralOpcode(0xb1),
	}}}})
	result := AnalyzeArtifact("WrongTag.class", data, DefaultOptions())
	if len(result.Findings) != 0 || len(result.Diagnostics) != 1 || result.Diagnostics[0].Code != diagBytecodeUnsupported {
		t.Fatalf("result=%+v", result)
	}
}

func TestStructuralServerHierarchyCanCorroborateScriptEval(t *testing.T) {
	data := structuralClassBytes(t, structuralClassSpec{
		super: "jakarta/servlet/http/HttpServlet",
		methods: []structuralMethodSpec{{name: "service", code: []structuralInstructionSpec{
			structuralCall(0xb9, scriptEngineEval), structuralOpcode(0xb1),
		}}},
	})
	result := AnalyzeArtifact("Servlet.class", data, DefaultOptions())
	if finding := findingByRule(result.Findings, "javadisk:class-script-eval-structure"); finding == nil || finding.Score != 60 || len(result.Diagnostics) != 0 {
		t.Fatalf("result=%+v", result)
	}
}

type structuralCancellingContext struct {
	cancelAt int
	errCalls int
}

func (*structuralCancellingContext) Deadline() (time.Time, bool) { return time.Time{}, false }
func (*structuralCancellingContext) Done() <-chan struct{}       { return nil }
func (*structuralCancellingContext) Value(any) any               { return nil }

func (c *structuralCancellingContext) Err() error {
	c.errCalls++
	if c.errCalls >= c.cancelAt {
		return context.Canceled
	}
	return nil
}

func TestStructuralContextCancellationRetainsCompletedFindings(t *testing.T) {
	data := structuralClassBytes(t, structuralClassSpec{methods: []structuralMethodSpec{
		{name: "aRequestExec", code: []structuralInstructionSpec{
			structuralCall(0xb9, javaxRequestParameter), structuralCall(0xb6, runtimeExecString), structuralOpcode(0xb1),
		}},
		{name: "zRegister", code: []structuralInstructionSpec{
			structuralCall(0xb9, servletAddFilter), structuralOpcode(0xb1),
		}},
	}})
	class, err := parseClass(data, DefaultOptions().Limits)
	if err != nil {
		t.Fatal(err)
	}
	parser := func([]byte, Limits) (*classModel, error) { return class, nil }

	cancelAt := 0
	for candidate := 2; candidate < 80; candidate++ {
		ctx := &structuralCancellingContext{cancelAt: candidate}
		result := analyzeArtifactContextWithParser(ctx, "Cancelled.class", data, DefaultOptions(), parser)
		if len(result.Diagnostics) == 1 && result.Diagnostics[0].Code == diagCancelled &&
			findingByRule(result.Findings, "javadisk:class-request-exec-structure") != nil &&
			findingByRule(result.Findings, "javadisk:class-hook-registration-structure") == nil {
			cancelAt = candidate
			break
		}
	}
	if cancelAt == 0 {
		t.Fatal("no cancellation point retained the completed earlier method")
	}
	for repeat := 0; repeat < 10; repeat++ {
		ctx := &structuralCancellingContext{cancelAt: cancelAt}
		result := analyzeArtifactContextWithParser(ctx, "Cancelled.class", data, DefaultOptions(), parser)
		if len(result.Diagnostics) != 1 || result.Diagnostics[0].Code != diagCancelled ||
			findingByRule(result.Findings, "javadisk:class-request-exec-structure") == nil ||
			findingByRule(result.Findings, "javadisk:class-hook-registration-structure") != nil {
			t.Fatalf("repeat=%d cancelAt=%d calls=%d result=%+v", repeat, cancelAt, ctx.errCalls, result)
		}
	}
}

func TestStructuralContextCancellationAfterDecodeStopsMethod(t *testing.T) {
	data := structuralClassBytes(t, structuralClassSpec{methods: []structuralMethodSpec{{
		name: "requestExec", code: []structuralInstructionSpec{
			structuralCall(0xb9, javaxRequestParameter), structuralCall(0xb6, runtimeExecString), structuralOpcode(0xb1),
		},
	}}})
	class, err := parseClass(data, DefaultOptions().Limits)
	if err != nil {
		t.Fatal(err)
	}
	ctx := &structuralCancellingContext{cancelAt: 4}
	result := analyzeArtifactContextWithParser(
		ctx, "DecodeCancelled.class", data, DefaultOptions(),
		func([]byte, Limits) (*classModel, error) { return class, nil },
	)
	if len(result.Findings) != 0 || len(result.Diagnostics) != 1 ||
		result.Diagnostics[0].Code != diagCancelled {
		t.Fatalf("calls=%d result=%+v", ctx.errCalls, result)
	}
}

func TestStructuralContextCancellationAfterFinalMethodRetainsFinding(t *testing.T) {
	data := structuralClassBytes(t, structuralClassSpec{methods: []structuralMethodSpec{{
		name: "requestExec", code: []structuralInstructionSpec{
			structuralCall(0xb9, javaxRequestParameter), structuralCall(0xb6, runtimeExecString), structuralOpcode(0xb1),
		},
	}}})
	class, err := parseClass(data, DefaultOptions().Limits)
	if err != nil {
		t.Fatal(err)
	}
	parser := func([]byte, Limits) (*classModel, error) { return class, nil }
	for cancelAt := 2; cancelAt < 80; cancelAt++ {
		ctx := &structuralCancellingContext{cancelAt: cancelAt}
		result := analyzeArtifactContextWithParser(ctx, "FinalCancelled.class", data, DefaultOptions(), parser)
		if findingByRule(result.Findings, "javadisk:class-request-exec-structure") != nil &&
			len(result.Diagnostics) == 1 && result.Diagnostics[0].Code == diagCancelled {
			return
		}
	}
	t.Fatal("no final-method cancellation point retained its completed finding")
}

func TestStructuralContextCancellationDuringReachableTraversalDropsPartialMethod(t *testing.T) {
	data := structuralClassBytes(t, structuralClassSpec{methods: []structuralMethodSpec{{
		name: "requestExec", code: []structuralInstructionSpec{
			structuralCall(0xb9, javaxRequestParameter),
			structuralOpcodeOperands(0xa7, 0, 3),
			structuralCall(0xb6, runtimeExecString),
			structuralOpcode(0xb1),
		},
	}}})
	class, err := parseClass(data, DefaultOptions().Limits)
	if err != nil {
		t.Fatal(err)
	}
	ctx := &structuralCancellingContext{cancelAt: 7}
	result := analyzeArtifactContextWithParser(
		ctx, "TraversalCancelled.class", data, DefaultOptions(),
		func([]byte, Limits) (*classModel, error) { return class, nil },
	)
	if len(result.Findings) != 0 || len(result.Diagnostics) != 1 ||
		result.Diagnostics[0].Code != diagCancelled {
		t.Fatalf("calls=%d result=%+v", ctx.errCalls, result)
	}
}

func TestStructuralBudgetsAndCFGFailuresAreStableDiagnostics(t *testing.T) {
	positive := structuralClassSpec{methods: []structuralMethodSpec{{name: "run", code: []structuralInstructionSpec{
		structuralCall(0xb9, javaxRequestParameter), structuralCall(0xb6, runtimeExecString), structuralOpcode(0xb1),
	}}}}
	t.Run("method instruction limit", func(t *testing.T) {
		opts := DefaultOptions()
		opts.Limits.MaxInstructions = 2
		result := AnalyzeArtifact("MethodLimit.class", structuralClassBytes(t, positive), opts)
		assertBoundedDiagnostic(t, result, diagBytecodeUnsupported)
	})
	t.Run("aggregate budget blocks uncharged method", func(t *testing.T) {
		spec := positive
		spec.methods = append([]structuralMethodSpec{{name: "a", code: []structuralInstructionSpec{structuralOpcode(0xb1)}}}, spec.methods...)
		opts := DefaultOptions()
		opts.Limits.MaxArtifactInstructions = 2
		result := AnalyzeArtifact("ArtifactLimit.class", structuralClassBytes(t, spec), opts)
		assertBoundedDiagnostic(t, result, diagAnalysisBudget)
	})
	t.Run("invalid opcode after aggregate cap is not decoded", func(t *testing.T) {
		spec := structuralClassSpec{methods: []structuralMethodSpec{{name: "capped", code: []structuralInstructionSpec{
			structuralOpcode(0x00), structuralOpcode(0xcb),
		}}}}
		opts := DefaultOptions()
		opts.Limits.MaxArtifactInstructions = 1
		result := AnalyzeArtifact("CappedInvalid.class", structuralClassBytes(t, spec), opts)
		assertBoundedDiagnostic(t, result, diagAnalysisBudget)
	})
	t.Run("invalid opcode inside aggregate cap remains unsupported", func(t *testing.T) {
		spec := structuralClassSpec{methods: []structuralMethodSpec{{name: "invalid", code: []structuralInstructionSpec{
			structuralOpcode(0xcb), structuralOpcode(0xb1),
		}}}}
		opts := DefaultOptions()
		opts.Limits.MaxArtifactInstructions = 2
		result := AnalyzeArtifact("InvalidWithinBudget.class", structuralClassBytes(t, spec), opts)
		assertBoundedDiagnostic(t, result, diagBytecodeUnsupported)
	})
	t.Run("malformed decoded prefix is charged to aggregate budget", func(t *testing.T) {
		spec := positive
		spec.methods = append([]structuralMethodSpec{{name: "aMalformed", code: []structuralInstructionSpec{
			structuralOpcode(0x00), structuralOpcode(0xcb),
		}}}, spec.methods...)
		opts := DefaultOptions()
		opts.Limits.MaxArtifactInstructions = 3
		result := AnalyzeArtifact("MalformedPrefix.class", structuralClassBytes(t, spec), opts)
		if len(result.Findings) != 0 || len(result.Diagnostics) != 2 ||
			result.Diagnostics[0].Code != diagBytecodeUnsupported ||
			result.Diagnostics[1].Code != diagAnalysisBudget {
			t.Fatalf("result=%+v", result)
		}
	})
	t.Run("exact aggregate exhaustion retains charged findings and stops", func(t *testing.T) {
		spec := positive
		spec.methods = append(spec.methods, structuralMethodSpec{name: "zRegister", code: []structuralInstructionSpec{
			structuralCall(0xb9, servletAddFilter), structuralOpcode(0xb1),
		}})
		opts := DefaultOptions()
		opts.Limits.MaxArtifactInstructions = 9
		result := AnalyzeArtifact("ExactLimit.class", structuralClassBytes(t, spec), opts)
		if len(result.Diagnostics) != 1 || result.Diagnostics[0].Code != diagAnalysisBudget ||
			findingByRule(result.Findings, "javadisk:class-request-exec-structure") == nil ||
			findingByRule(result.Findings, "javadisk:class-hook-registration-structure") != nil {
			t.Fatalf("result=%+v", result)
		}
	})
	t.Run("invalid CFG", func(t *testing.T) {
		spec := structuralClassSpec{methods: []structuralMethodSpec{{name: "fallsOffEnd", code: []structuralInstructionSpec{
			structuralOpcode(0x00),
		}}}}
		data := structuralClassBytes(t, spec)
		first := AnalyzeArtifact("BadCFG.class", data, DefaultOptions())
		assertBoundedDiagnostic(t, first, diagBytecodeUnsupported)
		for i := 0; i < 10; i++ {
			if got := AnalyzeArtifact("BadCFG.class", data, DefaultOptions()); !reflect.DeepEqual(got, first) {
				t.Fatalf("repeat %d differs: first=%+v got=%+v", i, first, got)
			}
		}
	})
}

func TestStructuralMethodVisitorUsesEachAuthoritativeCFGOnce(t *testing.T) {
	data := structuralClassBytes(t, structuralClassSpec{methods: []structuralMethodSpec{
		{name: "a", code: []structuralInstructionSpec{structuralOpcode(0xb1)}},
		{name: "b", code: []structuralInstructionSpec{structuralOpcode(0xb1)}},
	}})
	class, diagnostic := parseClassIsolated("Visitor.class", data, DefaultOptions().Limits)
	if diagnostic != nil {
		t.Fatalf("diagnostic=%+v", diagnostic)
	}
	visits := map[string]int{}
	result := analyzeClassModelContextWithVisitor(context.Background(), "Visitor.class", class, DefaultOptions(),
		func(_ context.Context, _ *classModel, method *methodModel, cfg *controlFlowGraph, _ Options) methodVisitResult {
			visits[method.Name]++
			if cfg == nil || cfg.Blocks[cfg.Entry] == nil {
				t.Fatalf("method %s received invalid CFG", method.Name)
			}
			return methodVisitResult{}
		})
	if len(result.Diagnostics) != 0 || !reflect.DeepEqual(visits, map[string]int{"a": 1, "b": 1}) {
		t.Fatalf("visits=%v result=%+v", visits, result)
	}
}
