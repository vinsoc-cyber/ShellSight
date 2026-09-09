package javadisk

import (
	"encoding/binary"
	"reflect"
	"strings"
	"testing"
)

func TestJSPCloneTokensStructuralNormalization(t *testing.T) {
	left := []byte("<%-- ignored --%>\r\n<%! String helper(String value) { return value; } %>\r\n<% String command = request.getParameter(\"cmd\"); Runtime.getRuntime().exec(command); %>")
	right := []byte("\n<%! String helper(String input) { return input; } %>\n<% String payload=request.getParameter(\"cmd\"); Runtime.getRuntime().exec(payload); %>")
	leftLiteral, leftStructural, err := JSPCloneTokens("shell.jsp", left)
	if err != nil {
		t.Fatal(err)
	}
	rightLiteral, rightStructural, err := JSPCloneTokens("shell.jsp", right)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(leftStructural, rightStructural) {
		t.Fatalf("structural tokens differ:\nleft=%q\nright=%q", leftStructural, rightStructural)
	}
	if reflect.DeepEqual(leftLiteral, rightLiteral) {
		t.Fatalf("literal tokens unexpectedly match: %q", leftLiteral)
	}
}

func TestJSPCloneTokensPreserveSecurityRelevantSyntax(t *testing.T) {
	base := []byte("<%@ page import=\"java.lang.Runtime\" %><jsp:include page=\"x.jsp\"/><custom:run mode=\"safe\"/><% Runtime.getRuntime().exec(\"id\"); %>")
	baseLiteral, _, err := JSPCloneTokens("shell.jsp", base)
	if err != nil {
		t.Fatal(err)
	}
	variants := []struct {
		name string
		data []byte
	}{
		{"directive", []byte("<%@ page import=\"java.lang.ProcessBuilder\" %><jsp:include page=\"x.jsp\"/><custom:run mode=\"safe\"/><% Runtime.getRuntime().exec(\"id\"); %>")},
		{"action", []byte("<%@ page import=\"java.lang.Runtime\" %><jsp:forward page=\"x.jsp\"/><custom:run mode=\"safe\"/><% Runtime.getRuntime().exec(\"id\"); %>")},
		{"tag", []byte("<%@ page import=\"java.lang.Runtime\" %><jsp:include page=\"x.jsp\"/><custom:other mode=\"safe\"/><% Runtime.getRuntime().exec(\"id\"); %>")},
		{"literal", []byte("<%@ page import=\"java.lang.Runtime\" %><jsp:include page=\"x.jsp\"/><custom:run mode=\"safe\"/><% Runtime.getRuntime().exec(\"whoami\"); %>")},
		{"operator", []byte("<%@ page import=\"java.lang.Runtime\" %><jsp:include page=\"x.jsp\"/><custom:run mode=\"safe\"/><% Runtime.getRuntime().exec(\"id\") != null; %>")},
		{"sink", []byte("<%@ page import=\"java.lang.Runtime\" %><jsp:include page=\"x.jsp\"/><custom:run mode=\"safe\"/><% new ProcessBuilder(\"id\").start(); %>")},
	}
	for _, tc := range variants {
		t.Run(tc.name, func(t *testing.T) {
			literal, _, err := JSPCloneTokens("shell.jsp", tc.data)
			if err != nil {
				t.Fatal(err)
			}
			if reflect.DeepEqual(baseLiteral, literal) {
				t.Fatalf("literal stream did not change: %q", literal)
			}
		})
	}
}

func TestJSPCloneTokensHandleJSPVariantsAndMalformedInput(t *testing.T) {
	cases := []struct {
		path string
		data []byte
	}{
		{"shell.jspx", []byte("<?xml version=\"1.0\"?><jsp:root xmlns:jsp=\"http://java.sun.com/JSP/Page\"><jsp:scriptlet><![CDATA[ String command = \\u0052untime.getRuntime().exec(\"id\"); ]]></jsp:scriptlet></jsp:root>")},
		{"shell.jspf", append([]byte{0xef, 0xbb, 0xbf}, []byte("<% String command = request.getParameter(\"cmd\"); %>")...)},
		{"shell.jsp", append([]byte{0xff, 0xfe}, utf16LE("<% String command = request.getParameter(\"cmd\"); %> mixed <b>html</b>")...)},
	}
	for _, tc := range cases {
		t.Run(tc.path, func(t *testing.T) {
			literal, structural, err := JSPCloneTokens(tc.path, tc.data)
			if err != nil {
				t.Fatal(err)
			}
			if len(literal) == 0 || len(structural) == 0 {
				t.Fatalf("empty clone streams: literal=%q structural=%q", literal, structural)
			}
		})
	}
}

func TestJSPCloneTokensRejectMalformedInput(t *testing.T) {
	tests := []struct {
		name string
		path string
		data []byte
	}{
		{"unterminated-scriptlet", "broken.jsp", []byte("<% String command = request.getParameter(\"cmd\");")},
		{"unterminated-jsp-comment", "broken.jsp", []byte("<%-- never closed")},
		{"truncated-utf16", "broken.jsp", []byte{0xff, 0xfe, '<'}},
		{"invalid-utf8", "broken.jsp", []byte{0xff, 0xfe, 0x00, 0xd8}},
		{"malformed-jspx", "broken.jspx", []byte(`<jsp:root xmlns:jsp="http://java.sun.com/JSP/Page"><jsp:scriptlet>int x = 1;</jsp:root>`)},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			literal, structural, err := JSPCloneTokens(tc.path, tc.data)
			if err == nil {
				t.Fatalf("malformed input accepted: literal=%q structural=%q", literal, structural)
			}
			if literal != nil || structural != nil {
				t.Fatalf("malformed input returned partial tokens: literal=%q structural=%q", literal, structural)
			}
		})
	}
}

func TestJSPCloneTokensCanonicalizeServiceLocalsAcrossBlocks(t *testing.T) {
	left := []byte(`<% String command = request.getParameter("cmd"); %><%= command %><% Runtime.getRuntime().exec(command); %>`)
	right := []byte(`<% String payload = request.getParameter("cmd"); %><%= payload %><% Runtime.getRuntime().exec(payload); %>`)
	_, leftStructural, err := JSPCloneTokens("shell.jsp", left)
	if err != nil {
		t.Fatal(err)
	}
	_, rightStructural, err := JSPCloneTokens("shell.jsp", right)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(leftStructural, rightStructural) {
		t.Fatalf("cross-block local rename changed structural stream:\nleft=%q\nright=%q", leftStructural, rightStructural)
	}
}

func TestJSPCloneTokensPreserveDeclarationMembersButNormalizeMethodLocals(t *testing.T) {
	left := []byte(`<%! String commandField = "id"; String execute(String command) { String copy = command; return copy + commandField; } %>`)
	localRename := []byte(`<%! String commandField = "id"; String execute(String payload) { String result = payload; return result + commandField; } %>`)
	fieldRename := []byte(`<%! String payloadField = "id"; String execute(String command) { String copy = command; return copy + payloadField; } %>`)
	methodRename := []byte(`<%! String commandField = "id"; String run(String command) { String copy = command; return copy + commandField; } %>`)

	_, base, err := JSPCloneTokens("shell.jsp", left)
	if err != nil {
		t.Fatal(err)
	}
	_, renamedLocals, err := JSPCloneTokens("shell.jsp", localRename)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(base, renamedLocals) {
		t.Fatalf("declaration method local rename changed structural stream:\nbase=%q\nrenamed=%q", base, renamedLocals)
	}
	for name, data := range map[string][]byte{"field": fieldRename, "method": methodRename} {
		t.Run(name, func(t *testing.T) {
			_, changed, err := JSPCloneTokens("shell.jsp", data)
			if err != nil {
				t.Fatal(err)
			}
			if reflect.DeepEqual(base, changed) {
				t.Fatalf("declaration %s name was canonicalized: %q", name, changed)
			}
		})
	}
}

func TestJSPCloneTokensPreserveJSPXExpandedNames(t *testing.T) {
	custom := []byte(`<r:root xmlns:r="urn:root" xmlns:c="urn:custom"><c:include c:mode="safe"/></r:root>`)
	renamedPrefix := []byte(`<x:root xmlns:x="urn:root" xmlns:y="urn:custom"><y:include y:mode="safe"/></x:root>`)
	jspAction := []byte(`<r:root xmlns:r="urn:root" xmlns:jsp="http://java.sun.com/JSP/Page"><jsp:include jsp:mode="safe"/></r:root>`)
	customLiteral, customStructural, err := JSPCloneTokens("shell.jspx", custom)
	if err != nil {
		t.Fatal(err)
	}
	prefixLiteral, prefixStructural, err := JSPCloneTokens("shell.jspx", renamedPrefix)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(customLiteral, prefixLiteral) || !reflect.DeepEqual(customStructural, prefixStructural) {
		t.Fatalf("namespace-prefix-only change affected streams:\ncustom=%q\nrenamed=%q", customLiteral, prefixLiteral)
	}
	actionLiteral, actionStructural, err := JSPCloneTokens("shell.jspx", jspAction)
	if err != nil {
		t.Fatal(err)
	}
	if reflect.DeepEqual(customLiteral, actionLiteral) || reflect.DeepEqual(customStructural, actionStructural) {
		t.Fatalf("custom tag collapsed into JSP action:\ncustom=%q\naction=%q", customLiteral, actionLiteral)
	}
}

func TestJSPCloneTokensIgnoreClassicCommentsAndMarkupWhitespace(t *testing.T) {
	left := []byte(`<div  class = "shell"> alpha   beta <!-- ignored --><%-- ignored --%></div><% String command = "id"; %>`)
	right := []byte("<div class=\"shell\">\nalpha beta\n</div><% String payload=\"id\"; %>")
	leftLiteral, leftStructural, err := JSPCloneTokens("shell.jsp", left)
	if err != nil {
		t.Fatal(err)
	}
	rightLiteral, rightStructural, err := JSPCloneTokens("shell.jsp", right)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(leftStructural, rightStructural) {
		t.Fatalf("comments or insignificant whitespace changed structural stream:\nleft=%q\nright=%q", leftStructural, rightStructural)
	}
	if reflect.DeepEqual(leftLiteral, rightLiteral) {
		t.Fatalf("literal stream lost local spelling distinction: %q", leftLiteral)
	}
	changed := []byte(`<div class="shell">alpha gamma</div><% String payload="id"; %>`)
	changedLiteral, changedStructural, err := JSPCloneTokens("shell.jsp", changed)
	if err != nil {
		t.Fatal(err)
	}
	if reflect.DeepEqual(rightLiteral, changedLiteral) || reflect.DeepEqual(rightStructural, changedStructural) {
		t.Fatalf("security-relevant markup content was discarded: literal=%q structural=%q", changedLiteral, changedStructural)
	}
}

func TestJSPCloneTokensPreserveWhitespaceSensitiveMarkup(t *testing.T) {
	tests := []struct {
		name  string
		path  string
		left  string
		right string
	}{
		{"pre", "page.jsp", `<pre>alpha  beta</pre>`, `<pre>alpha beta</pre>`},
		{"textarea", "page.jsp", "<textarea>line 1\n  line 2</textarea>", "<textarea>line 1\n line 2</textarea>"},
		{"script", "page.jsp", `<script>const marker = "alpha  beta";</script>`, `<script>const marker = "alpha beta";</script>`},
		{"style", "page.jsp", `<style>.marker::after { content: "alpha  beta"; }</style>`, `<style>.marker::after { content: "alpha beta"; }</style>`},
		{"jspx-pre", "page.jspx", `<root><pre>alpha  beta</pre></root>`, `<root><pre>alpha beta</pre></root>`},
		{"jspx-script", "page.jspx", `<root><script>const marker = "alpha  beta";</script></root>`, `<root><script>const marker = "alpha beta";</script></root>`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			leftLiteral, leftStructural, err := JSPCloneTokens(tc.path, []byte(tc.left))
			if err != nil {
				t.Fatal(err)
			}
			rightLiteral, rightStructural, err := JSPCloneTokens(tc.path, []byte(tc.right))
			if err != nil {
				t.Fatal(err)
			}
			if reflect.DeepEqual(leftLiteral, rightLiteral) || reflect.DeepEqual(leftStructural, rightStructural) {
				t.Fatalf("significant %s content collapsed:\nleft=%q\nright=%q", tc.name, leftLiteral, rightLiteral)
			}
		})
	}
}

func TestJSPCloneTokensPreserveQuotedMarkupDelimiter(t *testing.T) {
	literal, structural, err := JSPCloneTokens("page.jsp", []byte(`<div data-marker="alpha>beta">body</div>`))
	if err != nil {
		t.Fatal(err)
	}
	const want = `attr:literal:"alpha>beta"`
	if !cloneTokensContain(literal, want) || !cloneTokensContain(structural, want) {
		t.Fatalf("quoted markup delimiter split attribute: literal=%q structural=%q", literal, structural)
	}
}

func TestJSPCloneTokensRequireJSPNamespaceForJSPXCode(t *testing.T) {
	standard := []byte(`<root xmlns:page="http://java.sun.com/JSP/Page"><page:scriptlet>Runtime.getRuntime().exec("id");</page:scriptlet></root>`)
	custom := []byte(`<root xmlns:custom="urn:example"><custom:scriptlet>Runtime.getRuntime().exec("id");</custom:scriptlet></root>`)
	standardLiteral, _, err := JSPCloneTokens("page.jspx", standard)
	if err != nil {
		t.Fatal(err)
	}
	customLiteral, _, err := JSPCloneTokens("page.jspx", custom)
	if err != nil {
		t.Fatal(err)
	}
	if !cloneTokensContain(standardLiteral, "jsp:scriptlet") ||
		!cloneTokensContain(standardLiteral, "java:id:Runtime") {
		t.Fatalf("JSP namespace alias was not treated as server code: %q", standardLiteral)
	}
	if cloneTokensContain(customLiteral, "jsp:scriptlet") ||
		cloneTokensContain(customLiteral, "java:id:Runtime") {
		t.Fatalf("custom namespace was treated as JSP server code: %q", customLiteral)
	}
}

func TestJSPCloneTokensKeepEscapedClassicTerminatorInServerCode(t *testing.T) {
	escaped := []byte(`<% String marker = "%\>"; Runtime.getRuntime().exec("id"); %>`)
	raw := []byte(`<% String marker = "%>"; Runtime.getRuntime().exec("id"); %>`)
	escapedLiteral, _, err := JSPCloneTokens("page.jsp", escaped)
	if err != nil {
		t.Fatal(err)
	}
	rawLiteral, _, err := JSPCloneTokens("page.jsp", raw)
	if err != nil {
		t.Fatal(err)
	}
	if !cloneTokensContain(escapedLiteral, "java:id:Runtime") {
		t.Fatalf("escaped %%\\> ended server code: %q", escapedLiteral)
	}
	if cloneTokensContain(rawLiteral, "java:id:Runtime") {
		t.Fatalf("raw %%> did not end server code: %q", rawLiteral)
	}
}

func TestClassCloneTokensNormalizeNonSemanticDifferences(t *testing.T) {
	left, _ := classBytes(t, classSpec{Name: "fixture/Proxy$$EnhancerByCGLIB$$a1b2c3", Methods: []classMethodSpec{{Name: "run", Code: []classInstructionSpec{{Opcode: 0x12, Constant: &constantValue{Kind: constantString, String: "id"}}, {Opcode: 0x57}, {Opcode: 0xb1}}}}})
	right, _ := classBytes(t, classSpec{Name: "fixture/Proxy$$EnhancerByCGLIB$$d4e5f6", Methods: []classMethodSpec{{Name: "run", Code: []classInstructionSpec{{Opcode: 0x12, Constant: &constantValue{Kind: constantString, String: "id"}}, {Opcode: 0x57}, {Opcode: 0xb1}}}}})
	leftTokens, err := ClassCloneTokens(left)
	if err != nil {
		t.Fatal(err)
	}
	rightTokens, err := ClassCloneTokens(right)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(leftTokens, rightTokens) {
		t.Fatalf("generated suffix changed clone stream:\nleft=%q\nright=%q", leftTokens, rightTokens)
	}
}

func TestClassCloneTokensIgnoreDebugAttributesAndConstantPoolIndexes(t *testing.T) {
	plain := cloneTokenFixtureClass(t, false, true)
	debug := cloneTokenFixtureClass(t, true, true)
	plainTokens, err := ClassCloneTokens(plain)
	if err != nil {
		t.Fatal(err)
	}
	debugTokens, err := ClassCloneTokens(debug)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(plainTokens, debugTokens) {
		t.Fatalf("debug metadata or shifted pool indexes changed clone stream:\nplain=%q\ndebug=%q", plainTokens, debugTokens)
	}
}

func TestClassCloneTokensPreserveSemanticStructure(t *testing.T) {
	base, _ := classBytes(t, classSpec{Interfaces: []string{"java/io/Serializable"}, MethodOwner: "java/lang/Runtime", MethodName: "exec", MethodDesc: "(Ljava/lang/String;)Ljava/lang/Process;", Methods: []classMethodSpec{{Name: "run", Code: []classInstructionSpec{{Opcode: 0x01}, {Opcode: 0xb6, Member: &memberReference{Owner: "java/lang/Runtime", Name: "exec", Descriptor: "(Ljava/lang/String;)Ljava/lang/Process;"}}, {Opcode: 0x57}, {Opcode: 0xb1}}}}})
	baseTokens, err := ClassCloneTokens(base)
	if err != nil {
		t.Fatal(err)
	}
	variants := []struct {
		name string
		spec classSpec
	}{
		{"opcode-order", classSpec{Methods: []classMethodSpec{{Name: "run", Code: []classInstructionSpec{{Opcode: 0x03}, {Opcode: 0x57}, {Opcode: 0xb1}}}}}},
		{"superclass", classSpec{Super: "javax/servlet/http/HttpServlet", Methods: []classMethodSpec{{Name: "run", Code: []classInstructionSpec{{Opcode: 0xb1}}}}}},
		{"interface", classSpec{Interfaces: []string{"java/lang/Runnable"}, Methods: []classMethodSpec{{Name: "run", Code: []classInstructionSpec{{Opcode: 0xb1}}}}}},
		{"resolved-call", classSpec{MethodOwner: "java/lang/ProcessBuilder", MethodName: "start", MethodDesc: "()Ljava/lang/Process;", Methods: []classMethodSpec{{Name: "run", Code: []classInstructionSpec{{Opcode: 0xb6, Member: &memberReference{Owner: "java/lang/ProcessBuilder", Name: "start", Descriptor: "()Ljava/lang/Process;"}}, {Opcode: 0x57}, {Opcode: 0xb1}}}}}},
		{"constant", classSpec{Methods: []classMethodSpec{{Name: "run", Code: []classInstructionSpec{{Opcode: 0x12, Constant: &constantValue{Kind: constantString, String: "whoami"}}, {Opcode: 0x57}, {Opcode: 0xb1}}}}}},
	}
	for _, tc := range variants {
		t.Run(tc.name, func(t *testing.T) {
			data, _ := classBytes(t, tc.spec)
			tokens, err := ClassCloneTokens(data)
			if err != nil {
				t.Fatal(err)
			}
			if reflect.DeepEqual(baseTokens, tokens) {
				t.Fatalf("semantic change did not affect clone stream: %q", tokens)
			}
		})
	}
}

func TestClassCloneTokensPreserveBranchShapeAndAnnotationMetadata(t *testing.T) {
	left, _ := classBytes(t, classSpec{Methods: []classMethodSpec{{Name: "run", Code: []classInstructionSpec{{Opcode: 0x03}, {Opcode: 0x99, Operands: []byte{0, 5}}, {Opcode: 0x04}, {Opcode: 0x57}, {Opcode: 0xb1}}}}})
	right, _ := classBytes(t, classSpec{Methods: []classMethodSpec{{Name: "run", Code: []classInstructionSpec{{Opcode: 0x03}, {Opcode: 0x99, Operands: []byte{0, 4}}, {Opcode: 0x04}, {Opcode: 0x57}, {Opcode: 0xb1}}}}})
	leftTokens, err := ClassCloneTokens(left)
	if err != nil {
		t.Fatal(err)
	}
	rightTokens, err := ClassCloneTokens(right)
	if err != nil {
		t.Fatal(err)
	}
	if reflect.DeepEqual(leftTokens, rightTokens) {
		t.Fatalf("branch shape did not affect clone stream: %q", leftTokens)
	}
	plain := cloneTokenFixtureClass(t, false, false)
	annotated := cloneTokenFixtureClass(t, false, true)
	plainTokens, err := ClassCloneTokens(plain)
	if err != nil {
		t.Fatal(err)
	}
	annotatedTokens, err := ClassCloneTokens(annotated)
	if err != nil {
		t.Fatal(err)
	}
	if reflect.DeepEqual(plainTokens, annotatedTokens) {
		t.Fatalf("annotation metadata did not affect clone stream: %q", plainTokens)
	}
}

func TestClassCloneTokensPreserveSwitchValuesAndMultianewarrayDimensions(t *testing.T) {
	tests := []struct {
		name  string
		left  []byte
		right []byte
	}{
		{"tableswitch-low-range", cloneSwitchClass(t, 0xaa, []int32{1, 2}), cloneSwitchClass(t, 0xaa, []int32{2, 3})},
		{"lookupswitch-keys", cloneSwitchClass(t, 0xab, []int32{10, 20}), cloneSwitchClass(t, 0xab, []int32{10, 21})},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			left, err := ClassCloneTokens(tc.left)
			if err != nil {
				t.Fatal(err)
			}
			right, err := ClassCloneTokens(tc.right)
			if err != nil {
				t.Fatal(err)
			}
			if reflect.DeepEqual(left, right) {
				t.Fatalf("%s semantics collapsed: %q", tc.name, left)
			}
		})
	}

	left, _ := classBytes(t, classSpec{Methods: []classMethodSpec{{Name: "run", Code: []classInstructionSpec{{Opcode: 0xc5, ClassName: "[[Ljava/lang/String;", Operands: []byte{1}}, {Opcode: 0x57}, {Opcode: 0xb1}}}}})
	right, _ := classBytes(t, classSpec{Methods: []classMethodSpec{{Name: "run", Code: []classInstructionSpec{{Opcode: 0xc5, ClassName: "[[Ljava/lang/String;", Operands: []byte{2}}, {Opcode: 0x57}, {Opcode: 0xb1}}}}})
	leftTokens, err := ClassCloneTokens(left)
	if err != nil {
		t.Fatal(err)
	}
	rightTokens, err := ClassCloneTokens(right)
	if err != nil {
		t.Fatal(err)
	}
	if reflect.DeepEqual(leftTokens, rightTokens) {
		t.Fatalf("multianewarray dimensions collapsed: %q", leftTokens)
	}
}

func TestClassCloneTokensPreserveAccessFlags(t *testing.T) {
	base, _ := classBytes(t, classSpec{
		Fields:  []classFieldSpec{{Access: 0x0001, Name: "value", Descriptor: "I"}},
		Methods: []classMethodSpec{{Access: 0x0001, Name: "run", Code: []classInstructionSpec{{Opcode: 0xb1}}}},
	})
	classChanged := patchCloneClassAccess(t, base, 0x0031)
	fieldChanged, _ := classBytes(t, classSpec{
		Fields:  []classFieldSpec{{Access: 0x0009, Name: "value", Descriptor: "I"}},
		Methods: []classMethodSpec{{Access: 0x0001, Name: "run", Code: []classInstructionSpec{{Opcode: 0xb1}}}},
	})
	methodChanged, _ := classBytes(t, classSpec{
		Fields:  []classFieldSpec{{Access: 0x0001, Name: "value", Descriptor: "I"}},
		Methods: []classMethodSpec{{Access: 0x0009, Name: "run", Code: []classInstructionSpec{{Opcode: 0xb1}}}},
	})
	baseTokens, err := ClassCloneTokens(base)
	if err != nil {
		t.Fatal(err)
	}
	for name, data := range map[string][]byte{"class": classChanged, "field": fieldChanged, "method": methodChanged} {
		t.Run(name, func(t *testing.T) {
			tokens, err := ClassCloneTokens(data)
			if err != nil {
				t.Fatal(err)
			}
			if reflect.DeepEqual(baseTokens, tokens) {
				t.Fatalf("%s access flags were dropped: %q", name, tokens)
			}
		})
	}
}

func TestClassCloneTokensNormalizeGeneratedNamesInAllReferences(t *testing.T) {
	left := cloneGeneratedReferenceClass(t, "a1b2c3")
	right := cloneGeneratedReferenceClass(t, "d4e5f6")
	realType := cloneRealReferenceClass(t, "fixture/RealProxy")
	leftTokens, err := ClassCloneTokens(left)
	if err != nil {
		t.Fatal(err)
	}
	rightTokens, err := ClassCloneTokens(right)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(leftTokens, rightTokens) {
		t.Fatalf("generated suffix leaked through descriptor/reference/annotation tokens:\nleft=%q\nright=%q", leftTokens, rightTokens)
	}
	realTokens, err := ClassCloneTokens(realType)
	if err != nil {
		t.Fatal(err)
	}
	if reflect.DeepEqual(leftTokens, realTokens) {
		t.Fatalf("real type change was normalized away: %q", realTokens)
	}
}

func TestClassCloneTokensResolveInvokeDynamicBootstrapSemantics(t *testing.T) {
	first := cloneBootstrapSpec{Owner: "fixture/Bootstrap$$Proxy$$a1b2c3", Name: "link", Descriptor: "()V", Arguments: []string{"alpha"}}
	firstRenamed := cloneBootstrapSpec{Owner: "fixture/Bootstrap$$Proxy$$d4e5f6", Name: "link", Descriptor: "()V", Arguments: []string{"alpha"}}
	second := cloneBootstrapSpec{Owner: "fixture/OtherBootstrap", Name: "linkOther", Descriptor: "()V", Arguments: []string{"beta"}}

	base := cloneInvokeDynamicClass(t, []cloneBootstrapSpec{first, second}, 0)
	reordered := cloneInvokeDynamicClass(t, []cloneBootstrapSpec{second, firstRenamed}, 1)
	changedHandle := cloneInvokeDynamicClass(t, []cloneBootstrapSpec{second, first}, 0)
	changedArgument := cloneInvokeDynamicClass(t, []cloneBootstrapSpec{{
		Owner: first.Owner, Name: first.Name, Descriptor: first.Descriptor, Arguments: []string{"changed"},
	}, second}, 0)

	baseTokens, err := ClassCloneTokens(base)
	if err != nil {
		t.Fatal(err)
	}
	reorderedTokens, err := ClassCloneTokens(reordered)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(baseTokens, reorderedTokens) {
		t.Fatalf("bootstrap reorder/generated suffix changed stream:\nbase=%q\nreordered=%q", baseTokens, reorderedTokens)
	}
	for name, data := range map[string][]byte{"handle": changedHandle, "argument": changedArgument} {
		t.Run(name, func(t *testing.T) {
			tokens, err := ClassCloneTokens(data)
			if err != nil {
				t.Fatal(err)
			}
			if reflect.DeepEqual(baseTokens, tokens) {
				t.Fatalf("bootstrap %s semantics collapsed: %q", name, tokens)
			}
		})
	}
}

func TestClassCloneTokensFrameInvokeDynamicBootstrapArguments(t *testing.T) {
	twoArguments := cloneInvokeDynamicClass(t, []cloneBootstrapSpec{{
		Owner: "fixture/Bootstrap", Name: "link", Descriptor: "()V", Arguments: []string{"a", "b"},
	}}, 0)
	oneDelimiterBearingArgument := cloneInvokeDynamicClass(t, []cloneBootstrapSpec{{
		Owner: "fixture/Bootstrap", Name: "link", Descriptor: "()V", Arguments: []string{"a,string:b"},
	}}, 0)
	twoTokens, err := ClassCloneTokens(twoArguments)
	if err != nil {
		t.Fatal(err)
	}
	oneTokens, err := ClassCloneTokens(oneDelimiterBearingArgument)
	if err != nil {
		t.Fatal(err)
	}
	if reflect.DeepEqual(twoTokens, oneTokens) {
		t.Fatalf("bootstrap argument arity or boundaries collapsed: %q", twoTokens)
	}
}

func TestClassCloneTokensPreserveAnnotationStringLiterals(t *testing.T) {
	left := cloneAnnotationStringClass(t, "Lfixture/Proxy$$EnhancerByCGLIB$$a1b2c3;")
	right := cloneAnnotationStringClass(t, "Lfixture/Proxy$$EnhancerByCGLIB$$d4e5f6;")
	leftTokens, err := ClassCloneTokens(left)
	if err != nil {
		t.Fatal(err)
	}
	rightTokens, err := ClassCloneTokens(right)
	if err != nil {
		t.Fatal(err)
	}
	if reflect.DeepEqual(leftTokens, rightTokens) {
		t.Fatalf("annotation string literals were descriptor-normalized: %q", leftTokens)
	}
}

func TestClassCloneTokensPreserveAnnotationElementNames(t *testing.T) {
	left := cloneAnnotationClass(t, []cloneAnnotationElementSpec{
		{Name: "first", Value: cloneAnnotationValueSpec{Tag: 's', Text: "alpha"}},
		{Name: "second", Value: cloneAnnotationValueSpec{Tag: 's', Text: "beta"}},
	})
	right := cloneAnnotationClass(t, []cloneAnnotationElementSpec{
		{Name: "first", Value: cloneAnnotationValueSpec{Tag: 's', Text: "beta"}},
		{Name: "second", Value: cloneAnnotationValueSpec{Tag: 's', Text: "alpha"}},
	})
	leftTokens, err := ClassCloneTokens(left)
	if err != nil {
		t.Fatal(err)
	}
	rightTokens, err := ClassCloneTokens(right)
	if err != nil {
		t.Fatal(err)
	}
	if reflect.DeepEqual(leftTokens, rightTokens) {
		t.Fatalf("annotation element names lost their value association: %q", leftTokens)
	}
}

func TestClassCloneTokensCanonicalizeAnnotationElementPairOrder(t *testing.T) {
	left := cloneAnnotationClass(t, []cloneAnnotationElementSpec{
		{Name: "first", Value: cloneAnnotationValueSpec{Tag: 's', Text: "alpha"}},
		{Name: "second", Value: cloneAnnotationValueSpec{Tag: 's', Text: "beta"}},
	})
	right := cloneAnnotationClass(t, []cloneAnnotationElementSpec{
		{Name: "second", Value: cloneAnnotationValueSpec{Tag: 's', Text: "beta"}},
		{Name: "first", Value: cloneAnnotationValueSpec{Tag: 's', Text: "alpha"}},
	})

	leftTokens := mustClassCloneTokens(t, left)
	rightTokens := mustClassCloneTokens(t, right)
	if !reflect.DeepEqual(leftTokens, rightTokens) {
		t.Fatalf("annotation element-pair order changed tokens:\nleft=%q\nright=%q", leftTokens, rightTokens)
	}
}

func TestClassCloneTokensPreserveAnnotationArrayOrder(t *testing.T) {
	left := cloneAnnotationClass(t, []cloneAnnotationElementSpec{{
		Name: "value",
		Value: cloneAnnotationValueSpec{Tag: '[', Values: []cloneAnnotationValueSpec{
			{Tag: 's', Text: "alpha"},
			{Tag: 's', Text: "beta"},
		}},
	}})
	right := cloneAnnotationClass(t, []cloneAnnotationElementSpec{{
		Name: "value",
		Value: cloneAnnotationValueSpec{Tag: '[', Values: []cloneAnnotationValueSpec{
			{Tag: 's', Text: "beta"},
			{Tag: 's', Text: "alpha"},
		}},
	}})
	leftTokens, err := ClassCloneTokens(left)
	if err != nil {
		t.Fatal(err)
	}
	rightTokens, err := ClassCloneTokens(right)
	if err != nil {
		t.Fatal(err)
	}
	if reflect.DeepEqual(leftTokens, rightTokens) {
		t.Fatalf("annotation array order collapsed: %q", leftTokens)
	}
}

func TestClassCloneTokensPreserveAnnotationValueTypes(t *testing.T) {
	stringValue := cloneAnnotationClass(t, []cloneAnnotationElementSpec{{
		Name: "value", Value: cloneAnnotationValueSpec{Tag: 's', Text: "Lfixture/Mode;.ACTIVE"},
	}})
	enumValue := cloneAnnotationClass(t, []cloneAnnotationElementSpec{{
		Name: "value", Value: cloneAnnotationValueSpec{
			Tag: 'e', EnumType: "Lfixture/Mode;", EnumName: "ACTIVE",
		},
	}})
	stringTokens, err := ClassCloneTokens(stringValue)
	if err != nil {
		t.Fatal(err)
	}
	enumTokens, err := ClassCloneTokens(enumValue)
	if err != nil {
		t.Fatal(err)
	}
	if reflect.DeepEqual(stringTokens, enumTokens) {
		t.Fatalf("annotation string and enum values collapsed: %q", stringTokens)
	}
}

func TestClassCloneTokensPreservePrimitiveAnnotationValues(t *testing.T) {
	for _, tag := range []byte{'B', 'C', 'D', 'F', 'I', 'J', 'S', 'Z'} {
		t.Run(string(tag), func(t *testing.T) {
			left := cloneAnnotationClass(t, []cloneAnnotationElementSpec{{
				Name: "value", Value: cloneAnnotationValueSpec{Tag: tag, Bits: 1},
			}})
			right := cloneAnnotationClass(t, []cloneAnnotationElementSpec{{
				Name: "value", Value: cloneAnnotationValueSpec{Tag: tag, Bits: 2},
			}})
			leftTokens := mustClassCloneTokens(t, left)
			rightTokens := mustClassCloneTokens(t, right)
			if reflect.DeepEqual(leftTokens, rightTokens) {
				t.Fatalf("annotation primitive %c values collapsed: %q", tag, leftTokens)
			}
		})
	}
}

func TestClassCloneTokensPreserveClassLiteralAndNestedAnnotationValues(t *testing.T) {
	tests := []struct {
		name        string
		left, right cloneAnnotationValueSpec
	}{
		{
			name:  "class literal",
			left:  cloneAnnotationValueSpec{Tag: 'c', ClassDescriptor: "Lfixture/First;"},
			right: cloneAnnotationValueSpec{Tag: 'c', ClassDescriptor: "Lfixture/Second;"},
		},
		{
			name: "nested annotation",
			left: cloneAnnotationValueSpec{
				Tag: '@', AnnotationDescriptor: "Lfixture/Nested;",
				Elements: []cloneAnnotationElementSpec{{
					Name: "value", Value: cloneAnnotationValueSpec{Tag: 's', Text: "alpha"},
				}},
			},
			right: cloneAnnotationValueSpec{
				Tag: '@', AnnotationDescriptor: "Lfixture/Nested;",
				Elements: []cloneAnnotationElementSpec{{
					Name: "value", Value: cloneAnnotationValueSpec{Tag: 's', Text: "beta"},
				}},
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			left := cloneAnnotationClass(t, []cloneAnnotationElementSpec{{
				Name: "value", Value: test.left,
			}})
			right := cloneAnnotationClass(t, []cloneAnnotationElementSpec{{
				Name: "value", Value: test.right,
			}})
			leftTokens := mustClassCloneTokens(t, left)
			rightTokens := mustClassCloneTokens(t, right)
			if reflect.DeepEqual(leftTokens, rightTokens) {
				t.Fatalf("%s values collapsed: %q", test.name, leftTokens)
			}
		})
	}
}

func TestClassCloneTokensRejectAnnotationNestingBeyondLimit(t *testing.T) {
	value := cloneAnnotationValueSpec{Tag: 's', Text: "leaf"}
	for range DefaultOptions().Limits.MaxAnnotationDepth {
		value = cloneAnnotationValueSpec{
			Tag:                  '@',
			AnnotationDescriptor: "Lfixture/Nested;",
			Elements: []cloneAnnotationElementSpec{{
				Name: "value", Value: value,
			}},
		}
	}
	data := cloneAnnotationClass(t, []cloneAnnotationElementSpec{{
		Name: "value", Value: value,
	}})

	if _, err := ClassCloneTokens(data); err == nil ||
		!strings.Contains(err.Error(), "annotation nesting depth") {
		t.Fatalf("ClassCloneTokens error = %v, want annotation nesting depth error", err)
	}
}

func TestClassCloneTokensPreserveAnnotationVisibilityAndMemberScope(t *testing.T) {
	elements := []cloneAnnotationElementSpec{{
		Name: "value", Value: cloneAnnotationValueSpec{Tag: 's', Text: "marker"},
	}}
	visible := mustClassCloneTokens(t, cloneScopedAnnotationClass(
		t, "RuntimeVisibleAnnotations", "class", elements,
	))
	invisible := mustClassCloneTokens(t, cloneScopedAnnotationClass(
		t, "RuntimeInvisibleAnnotations", "class", elements,
	))
	field := mustClassCloneTokens(t, cloneScopedAnnotationClass(
		t, "RuntimeVisibleAnnotations", "field", elements,
	))
	method := mustClassCloneTokens(t, cloneScopedAnnotationClass(
		t, "RuntimeVisibleAnnotations", "method", elements,
	))

	if reflect.DeepEqual(visible, invisible) {
		t.Fatalf("annotation visibility collapsed: %q", visible)
	}
	if reflect.DeepEqual(visible, field) {
		t.Fatalf("class and field annotation scopes collapsed: %q", visible)
	}
	if reflect.DeepEqual(field, method) {
		t.Fatalf("field and method annotation scopes collapsed: %q", field)
	}
}

func TestClassCloneTokensRejectAnnotationWorkAmplification(t *testing.T) {
	data := cloneRepeatedAnnotationStringClass(t, strings.Repeat("x", 4_096), 8_193)

	if _, err := ClassCloneTokens(data); err == nil ||
		!strings.Contains(err.Error(), "clone annotation work budget exhausted") {
		t.Fatalf("ClassCloneTokens error = %v, want clone annotation work budget exhaustion", err)
	}
}

func TestClassCloneTokensRejectMalformedClass(t *testing.T) {
	if _, err := ClassCloneTokens([]byte{0xca, 0xfe, 0xba, 0xbe}); err == nil {
		t.Fatal("malformed class accepted")
	}
}

func FuzzClassCloneTokensNeverPanics(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0xca, 0xfe, 0xba, 0xbe})
	f.Add(methodHandleClass(52, 6, 11, "run"))
	f.Add(cloneTokenFixtureData(false, true))
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = ClassCloneTokens(data)
	})
}

func cloneSwitchClass(t *testing.T, opcode byte, values []int32) []byte {
	t.Helper()
	operands := []byte{0, 0, 0}
	switch opcode {
	case 0xaa:
		operands = appendCloneInt32(operands, 24)
		operands = appendCloneInt32(operands, values[0])
		operands = appendCloneInt32(operands, values[1])
		operands = appendCloneInt32(operands, 25)
		operands = appendCloneInt32(operands, 26)
	case 0xab:
		operands = appendCloneInt32(operands, 28)
		operands = appendCloneInt32(operands, 2)
		operands = appendCloneInt32(operands, values[0])
		operands = appendCloneInt32(operands, 29)
		operands = appendCloneInt32(operands, values[1])
		operands = appendCloneInt32(operands, 30)
	default:
		t.Fatalf("unsupported switch opcode 0x%02x", opcode)
	}
	data, _ := classBytes(t, classSpec{Methods: []classMethodSpec{{Name: "run", Code: []classInstructionSpec{
		{Opcode: opcode, Operands: operands}, {Opcode: 0xb1}, {Opcode: 0xb1}, {Opcode: 0xb1},
	}}}})
	return data
}

func appendCloneInt32(data []byte, value int32) []byte {
	var encoded [4]byte
	binary.BigEndian.PutUint32(encoded[:], uint32(value))
	return append(data, encoded[:]...)
}

func patchCloneClassAccess(t *testing.T, data []byte, access uint16) []byte {
	t.Helper()
	patched := append([]byte(nil), data...)
	reader := classReader{data: patched}
	if err := reader.skip(8); err != nil {
		t.Fatal(err)
	}
	if _, err := parseConstantPool(&reader); err != nil {
		t.Fatal(err)
	}
	binary.BigEndian.PutUint16(patched[reader.off:reader.off+2], access)
	return patched
}

func cloneGeneratedReferenceClass(t *testing.T, suffix string) []byte {
	t.Helper()
	return cloneRealReferenceClass(t, "fixture/Proxy$$EnhancerByCGLIB$$"+suffix)
}

func cloneRealReferenceClass(t *testing.T, referenced string) []byte {
	t.Helper()
	pool, thisClass, superClass := fixtureClassPool()
	descriptor := "L" + referenced + ";"
	field := memberFixture(0x0001, pool.utf8("value"), pool.utf8(descriptor))
	codeName := pool.utf8("Code")
	methodName := pool.utf8("convert")
	methodDescriptor := pool.utf8("(" + descriptor + ")" + descriptor)
	classConstant := pool.u2Entry(cpClass, pool.utf8(referenced))
	member := classMemberIndex(pool, memberReference{Owner: referenced, Name: "convert", Descriptor: "(" + descriptor + ")" + descriptor}, false)
	bytecode := []byte{0x13}
	bytecode = append(bytecode, u2Bytes(classConstant)...)
	bytecode = append(bytecode, 0x57, 0xb8)
	bytecode = append(bytecode, u2Bytes(member)...)
	bytecode = append(bytecode, 0x57, 0xb1)
	code := append(u2Bytes(2), u2Bytes(2)...)
	code = append(code, u4Bytes(uint32(len(bytecode)))...)
	code = append(code, bytecode...)
	code = append(code, 0, 0, 0, 0)
	method := memberFixture(0x0009, methodName, methodDescriptor, attributeFixture(codeName, code))
	annotationName := pool.utf8("RuntimeVisibleAnnotations")
	annotationDescriptor := pool.utf8(descriptor)
	annotation := append(u2Bytes(1), u2Bytes(annotationDescriptor)...)
	annotation = append(annotation, 0, 0)
	return classWithSections(pool, thisClass, superClass, [][]byte{field}, [][]byte{method}, [][]byte{
		attributeFixture(annotationName, annotation),
	})
}

type cloneBootstrapSpec struct {
	Owner, Name, Descriptor string
	Arguments               []string
}

func cloneInvokeDynamicClass(t *testing.T, bootstraps []cloneBootstrapSpec, selected uint16) []byte {
	t.Helper()
	pool, thisClass, superClass := fixtureClassPool()
	callName := pool.utf8("factory")
	callDescriptor := pool.utf8("()Ljava/lang/Object;")
	nameAndType := pool.pairEntry(cpNameAndType, callName, callDescriptor)
	invokeDynamic := pool.pairEntry(cpInvokeDynamic, selected, nameAndType)
	handles := make([]uint16, 0, len(bootstraps))
	arguments := make([][]uint16, 0, len(bootstraps))
	for _, bootstrap := range bootstraps {
		target := classMemberIndex(pool, memberReference{
			Owner: bootstrap.Owner, Name: bootstrap.Name, Descriptor: bootstrap.Descriptor,
		}, false)
		handles = append(handles, pool.methodHandle(6, target))
		indexes := make([]uint16, 0, len(bootstrap.Arguments))
		for _, argument := range bootstrap.Arguments {
			indexes = append(indexes, pool.u2Entry(cpString, pool.utf8(argument)))
		}
		arguments = append(arguments, indexes)
	}
	bootstrapName := pool.utf8("BootstrapMethods")
	bootstrapPayload := u2Bytes(uint16(len(bootstraps)))
	for index := range bootstraps {
		bootstrapPayload = append(bootstrapPayload, u2Bytes(handles[index])...)
		bootstrapPayload = append(bootstrapPayload, u2Bytes(uint16(len(arguments[index])))...)
		for _, argument := range arguments[index] {
			bootstrapPayload = append(bootstrapPayload, u2Bytes(argument)...)
		}
	}
	codeName := pool.utf8("Code")
	methodName := pool.utf8("run")
	methodDescriptor := pool.utf8("()V")
	bytecode := []byte{0xba}
	bytecode = append(bytecode, u2Bytes(invokeDynamic)...)
	bytecode = append(bytecode, 0, 0, 0x57, 0xb1)
	code := append(u2Bytes(1), u2Bytes(1)...)
	code = append(code, u4Bytes(uint32(len(bytecode)))...)
	code = append(code, bytecode...)
	code = append(code, 0, 0, 0, 0)
	method := memberFixture(0x0001, methodName, methodDescriptor, attributeFixture(codeName, code))
	return classWithSections(pool, thisClass, superClass, nil, [][]byte{method}, [][]byte{
		attributeFixture(bootstrapName, bootstrapPayload),
	})
}

func cloneAnnotationStringClass(t *testing.T, value string) []byte {
	t.Helper()
	return cloneAnnotationClass(t, []cloneAnnotationElementSpec{{
		Name: "value", Value: cloneAnnotationValueSpec{Tag: 's', Text: value},
	}})
}

func cloneRepeatedAnnotationStringClass(t *testing.T, value string, count uint16) []byte {
	t.Helper()
	pool, thisClass, superClass := fixtureClassPool()
	attributeName := pool.utf8("RuntimeVisibleAnnotations")
	descriptor := pool.utf8("Lfixture/Marker;")
	elementName := pool.utf8("value")
	valueIndex := pool.utf8(value)
	payload := append(u2Bytes(1), u2Bytes(descriptor)...)
	payload = append(payload, u2Bytes(1)...)
	payload = append(payload, u2Bytes(elementName)...)
	payload = append(payload, '[', byte(count>>8), byte(count))
	for range count {
		payload = append(payload, 's', byte(valueIndex>>8), byte(valueIndex))
	}
	return classWithSections(pool, thisClass, superClass, nil, nil, [][]byte{
		attributeFixture(attributeName, payload),
	})
}

type cloneAnnotationElementSpec struct {
	Name  string
	Value cloneAnnotationValueSpec
}

type cloneAnnotationValueSpec struct {
	Tag                  byte
	Text                 string
	EnumType, EnumName   string
	Bits                 uint64
	ClassDescriptor      string
	AnnotationDescriptor string
	Elements             []cloneAnnotationElementSpec
	Values               []cloneAnnotationValueSpec
}

func cloneAnnotationClass(t *testing.T, elements []cloneAnnotationElementSpec) []byte {
	t.Helper()
	pool, thisClass, superClass := fixtureClassPool()
	return classWithSections(pool, thisClass, superClass, nil, nil, [][]byte{
		cloneAnnotationAttribute(t, pool, "RuntimeVisibleAnnotations", elements),
	})
}

func cloneScopedAnnotationClass(
	t *testing.T,
	visibility, scope string,
	elements []cloneAnnotationElementSpec,
) []byte {
	t.Helper()
	pool, thisClass, superClass := fixtureClassPool()
	annotation := cloneAnnotationAttribute(t, pool, visibility, elements)
	fieldName := pool.utf8("value")
	fieldDescriptor := pool.utf8("Ljava/lang/String;")
	methodName := pool.utf8("run")
	methodDescriptor := pool.utf8("()V")
	codeName := pool.utf8("Code")
	code := append(u2Bytes(1), u2Bytes(1)...)
	code = append(code, u4Bytes(1)...)
	code = append(code, 0xb1)
	code = append(code, 0, 0, 0, 0)

	var fieldAttributes, methodAttributes, classAttributes [][]byte
	switch scope {
	case "class":
		classAttributes = append(classAttributes, annotation)
	case "field":
		fieldAttributes = append(fieldAttributes, annotation)
	case "method":
		methodAttributes = append(methodAttributes, annotation)
	default:
		t.Fatalf("unsupported annotation fixture scope %q", scope)
	}
	methodAttributes = append([][]byte{attributeFixture(codeName, code)}, methodAttributes...)
	field := memberFixture(0x0001, fieldName, fieldDescriptor, fieldAttributes...)
	method := memberFixture(0x0001, methodName, methodDescriptor, methodAttributes...)
	return classWithSections(
		pool, thisClass, superClass, [][]byte{field}, [][]byte{method}, classAttributes,
	)
}

func cloneAnnotationAttribute(
	t *testing.T,
	pool *constantPoolBuilder,
	visibility string,
	elements []cloneAnnotationElementSpec,
) []byte {
	t.Helper()
	name := pool.utf8(visibility)
	payload := append(u2Bytes(1), cloneAnnotationBody(t, pool, "Lfixture/Marker;", elements)...)
	return attributeFixture(name, payload)
}

func cloneAnnotationBody(
	t *testing.T,
	pool *constantPoolBuilder,
	descriptor string,
	elements []cloneAnnotationElementSpec,
) []byte {
	t.Helper()
	payload := append(u2Bytes(pool.utf8(descriptor)), u2Bytes(uint16(len(elements)))...)
	for _, element := range elements {
		payload = append(payload, u2Bytes(pool.utf8(element.Name))...)
		payload = appendCloneAnnotationValue(t, pool, payload, element.Value)
	}
	return payload
}

func appendCloneAnnotationValue(
	t *testing.T,
	pool *constantPoolBuilder,
	payload []byte,
	value cloneAnnotationValueSpec,
) []byte {
	t.Helper()
	payload = append(payload, value.Tag)
	switch value.Tag {
	case 'B', 'C', 'I', 'S', 'Z':
		return append(payload, u2Bytes(pool.u4Entry(cpInteger, uint32(value.Bits)))...)
	case 'F':
		return append(payload, u2Bytes(pool.u4Entry(cpFloat, uint32(value.Bits)))...)
	case 'J':
		return append(payload, u2Bytes(pool.u8Entry(cpLong, value.Bits))...)
	case 'D':
		return append(payload, u2Bytes(pool.u8Entry(cpDouble, value.Bits))...)
	case 's':
		return append(payload, u2Bytes(pool.utf8(value.Text))...)
	case 'e':
		payload = append(payload, u2Bytes(pool.utf8(value.EnumType))...)
		return append(payload, u2Bytes(pool.utf8(value.EnumName))...)
	case 'c':
		return append(payload, u2Bytes(pool.utf8(value.ClassDescriptor))...)
	case '@':
		return append(payload, cloneAnnotationBody(
			t, pool, value.AnnotationDescriptor, value.Elements,
		)...)
	case '[':
		payload = append(payload, u2Bytes(uint16(len(value.Values)))...)
		for _, child := range value.Values {
			payload = appendCloneAnnotationValue(t, pool, payload, child)
		}
		return payload
	default:
		t.Fatalf("unsupported annotation fixture tag %q", value.Tag)
		return nil
	}
}

func mustClassCloneTokens(t *testing.T, data []byte) []string {
	t.Helper()
	tokens, err := ClassCloneTokens(data)
	if err != nil {
		t.Fatal(err)
	}
	return tokens
}

func cloneTokensContain(tokens []string, want string) bool {
	for _, token := range tokens {
		if token == want {
			return true
		}
	}
	return false
}

func utf16LE(text string) []byte {
	data := make([]byte, 0, len(text)*2)
	for _, r := range text {
		data = append(data, byte(r), byte(r>>8))
	}
	return data
}

func cloneTokenFixtureClass(t *testing.T, debug, annotation bool) []byte {
	t.Helper()
	return cloneTokenFixtureData(debug, annotation)
}

func cloneTokenFixtureData(debug, annotation bool) []byte {
	pool, thisClass, superClass := fixtureClassPool()
	if debug {
		pool.utf8("unused-before-semantic-entries")
	}
	codeName := pool.utf8("Code")
	methodName := pool.utf8("run")
	methodDescriptor := pool.utf8("()V")
	code := append(u2Bytes(1), u2Bytes(1)...)
	code = append(code, u4Bytes(1)...)
	code = append(code, 0xb1)
	code = append(code, u2Bytes(0)...)
	var codeAttributes [][]byte
	if debug {
		lineNumberName := pool.utf8("LineNumberTable")
		linePayload := append(u2Bytes(1), u2Bytes(0)...)
		linePayload = append(linePayload, u2Bytes(99)...)
		codeAttributes = append(codeAttributes, attributeFixture(lineNumberName, linePayload))
	}
	code = append(code, u2Bytes(uint16(len(codeAttributes)))...)
	for _, attribute := range codeAttributes {
		code = append(code, attribute...)
	}
	method := memberFixture(0x0001, methodName, methodDescriptor, attributeFixture(codeName, code))
	var attributes [][]byte
	if debug {
		sourceName := pool.utf8("SourceFile")
		sourceFile := pool.utf8("Generated.java")
		attributes = append(attributes, attributeFixture(sourceName, u2Bytes(sourceFile)))
	}
	if annotation {
		annotationName := pool.utf8("RuntimeVisibleAnnotations")
		descriptor := pool.utf8("Ljakarta/servlet/annotation/WebServlet;")
		element := pool.utf8("value")
		value := pool.utf8("/shell")
		payload := append(u2Bytes(1), u2Bytes(descriptor)...)
		payload = append(payload, u2Bytes(1)...)
		payload = append(payload, u2Bytes(element)...)
		payload = append(payload, 's')
		payload = append(payload, u2Bytes(value)...)
		attributes = append(attributes, attributeFixture(annotationName, payload))
	}
	return classWithSections(pool, thisClass, superClass, nil, [][]byte{method}, attributes)
}
