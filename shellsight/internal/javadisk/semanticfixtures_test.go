package javadisk

import (
	"reflect"
	"strings"
	"testing"
)

var (
	fixtureRequestParameter = memberReference{
		Owner: "javax/servlet/http/HttpServletRequest", Name: "getParameter",
		Descriptor: "(Ljava/lang/String;)Ljava/lang/String;", Interface: true,
	}
	fixtureRequestParameterValues = memberReference{
		Owner: "javax/servlet/http/HttpServletRequest", Name: "getParameterValues",
		Descriptor: "(Ljava/lang/String;)[Ljava/lang/String;", Interface: true,
	}
	fixtureRuntimeGet = memberReference{
		Owner: "java/lang/Runtime", Name: "getRuntime", Descriptor: "()Ljava/lang/Runtime;",
	}
	fixtureRuntimeExec = memberReference{
		Owner: "java/lang/Runtime", Name: "exec", Descriptor: "(Ljava/lang/String;)Ljava/lang/Process;",
	}
	fixtureResponseWriter = memberReference{
		Owner: "javax/servlet/ServletResponse", Name: "getWriter",
		Descriptor: "()Ljava/io/PrintWriter;", Interface: true,
	}
	fixtureWriterPrint = memberReference{
		Owner: "java/io/PrintWriter", Name: "println", Descriptor: "(Ljava/lang/String;)V",
	}
	fixtureStringConcat = memberReference{
		Owner: "java/lang/String", Name: "concat", Descriptor: "(Ljava/lang/String;)Ljava/lang/String;",
	}
	fixtureStringValueOf = memberReference{
		Owner: "java/lang/String", Name: "valueOf", Descriptor: "(Ljava/lang/Object;)Ljava/lang/String;",
	}
	fixtureURLDecode = memberReference{
		Owner: "java/net/URLDecoder", Name: "decode",
		Descriptor: "(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;",
	}
	fixtureBase64Decode = memberReference{
		Owner: "java/util/Base64$Decoder", Name: "decode", Descriptor: "(Ljava/lang/String;)[B",
	}
	fixtureHexDecode = memberReference{
		Owner: "javax/xml/bind/DatatypeConverter", Name: "parseHexBinary", Descriptor: "(Ljava/lang/String;)[B",
	}
	fixtureLookupDefineClass = memberReference{
		Owner: "java/lang/invoke/MethodHandles$Lookup", Name: "defineClass", Descriptor: "([B)Ljava/lang/Class;",
	}
	fixtureScriptEval = memberReference{
		Owner: "javax/script/ScriptEngine", Name: "eval", Descriptor: "(Ljava/lang/String;)Ljava/lang/Object;", Interface: true,
	}
	fixtureMethodInvoke = memberReference{
		Owner: "java/lang/reflect/Method", Name: "invoke",
		Descriptor: "(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;",
	}
	fixtureJNDILookup = memberReference{
		Owner: "javax/naming/Context", Name: "lookup", Descriptor: "(Ljava/lang/String;)Ljava/lang/Object;", Interface: true,
	}
	fixtureAddServlet = memberReference{
		Owner: "javax/servlet/ServletContext", Name: "addServlet",
		Descriptor: "(Ljava/lang/String;Ljava/lang/String;)Ljavax/servlet/ServletRegistration$Dynamic;", Interface: true,
	}
	fixtureFilesWriteString = memberReference{
		Owner: "java/nio/file/Files", Name: "writeString",
		Descriptor: "(Ljava/nio/file/Path;Ljava/lang/CharSequence;[Ljava/nio/file/OpenOption;)Ljava/nio/file/Path;",
	}
)

var fixtureClasses = map[string]func() classSpec{
	"request_exec": func() classSpec {
		return classSpec{Name: "fixture/RequestExec", Super: "javax/servlet/http/HttpServlet", Methods: []classMethodSpec{{
			Name: "service", Descriptor: "(Ljavax/servlet/http/HttpServletRequest;Ljavax/servlet/http/HttpServletResponse;)V",
			MaxStack: 2, MaxLocals: 4, Code: []classInstructionSpec{
				{Opcode: 0x2b},
				{Opcode: 0x12, Constant: &constantValue{Kind: constantString, String: "cmd"}},
				{Opcode: 0xb9, Member: &fixtureRequestParameter},
				{Opcode: 0x4e},
				{Opcode: 0xb8, Member: &fixtureRuntimeGet},
				{Opcode: 0x2d},
				{Opcode: 0xb6, Member: &fixtureRuntimeExec},
				{Opcode: 0x57},
				{Opcode: 0xb1},
			},
		}}}
	},
	"hardcoded_exec": func() classSpec {
		return classSpec{Name: "fixture/HardcodedExec", Methods: []classMethodSpec{{
			Access: 0x0009, Name: "run", Descriptor: "()V", MaxStack: 2, MaxLocals: 0,
			Code: []classInstructionSpec{
				{Opcode: 0xb8, Member: &fixtureRuntimeGet},
				{Opcode: 0x12, Constant: &constantValue{Kind: constantString, String: "echo ok"}},
				{Opcode: 0xb6, Member: &fixtureRuntimeExec},
				{Opcode: 0x57}, {Opcode: 0xb1},
			},
		}}}
	},
	"request_render": func() classSpec {
		return classSpec{Name: "fixture/RequestRender", Super: "javax/servlet/http/HttpServlet", Methods: []classMethodSpec{{
			Name: "service", Descriptor: "(Ljavax/servlet/http/HttpServletRequest;Ljavax/servlet/http/HttpServletResponse;)V",
			MaxStack: 2, MaxLocals: 4, Code: []classInstructionSpec{
				{Opcode: 0x2b},
				{Opcode: 0x12, Constant: &constantValue{Kind: constantString, String: "cmd"}},
				{Opcode: 0xb9, Member: &fixtureRequestParameter},
				{Opcode: 0x4e},
				{Opcode: 0x2c},
				{Opcode: 0xb9, Member: &fixtureResponseWriter},
				{Opcode: 0x2d},
				{Opcode: 0xb6, Member: &fixtureWriterPrint},
				{Opcode: 0xb1},
			},
		}}}
	},
	"bad_stack": func() classSpec {
		return classSpec{Name: "fixture/BadStack", Methods: []classMethodSpec{{
			Access: 0x0009, Name: "run", Descriptor: "()V", MaxStack: 1,
			Code: []classInstructionSpec{{Opcode: 0x57}, {Opcode: 0xb1}},
		}}}
	},
	"branch_join": func() classSpec {
		return classSpec{Name: "fixture/BranchJoin", Super: "javax/servlet/http/HttpServlet", Major: 49, Methods: []classMethodSpec{{
			Name: "service", Descriptor: "(Ljavax/servlet/http/HttpServletRequest;Ljavax/servlet/http/HttpServletResponse;)V",
			MaxStack: 2, MaxLocals: 4, Code: []classInstructionSpec{
				{Opcode: 0x2b},
				{Opcode: 0x12, Constant: &constantValue{Kind: constantString, String: "cmd"}},
				{Opcode: 0xb9, Member: &fixtureRequestParameter},
				{Opcode: 0x4e},
				{Opcode: 0xb8, Member: &fixtureRuntimeGet},
				{Opcode: 0x03},
				{Opcode: 0x99, Operands: []byte{0x00, 0x07}},
				{Opcode: 0x2d},
				{Opcode: 0xa7, Operands: []byte{0x00, 0x04}},
				{Opcode: 0x2d},
				{Opcode: 0xb6, Member: &fixtureRuntimeExec},
				{Opcode: 0x57}, {Opcode: 0xb1},
			},
		}}}
	},
}

type artifactFixtureClass struct {
	LogicalPath string
	Spec        classSpec
	Bytes       func(*testing.T) []byte
}

func artifactClass(path string, spec classSpec) artifactFixtureClass {
	return artifactFixtureClass{LogicalPath: path, Spec: spec}
}

func staticSinkMethod(_ string, name string) classMethodSpec {
	return classMethodSpec{
		Access: 0x0009, Name: name, Descriptor: "(Ljava/lang/String;)V", MaxStack: 2, MaxLocals: 1,
		Code: []classInstructionSpec{
			{Opcode: 0xb8, Member: &fixtureRuntimeGet}, {Opcode: 0x2a},
			{Opcode: 0xb6, Member: &fixtureRuntimeExec}, {Opcode: 0x57}, {Opcode: 0xb1},
		},
	}
}

func requestToStaticCallClass(name string, target memberReference) classSpec {
	return classSpec{Name: name, Super: "javax/servlet/http/HttpServlet", Methods: []classMethodSpec{{
		Name: "service", Descriptor: "(Ljavax/servlet/http/HttpServletRequest;Ljavax/servlet/http/HttpServletResponse;)V",
		MaxStack: 2, MaxLocals: 3, Code: []classInstructionSpec{
			{Opcode: 0x2b}, {Opcode: 0x12, Constant: &constantValue{Kind: constantString, String: "cmd"}},
			{Opcode: 0xb9, Member: &fixtureRequestParameter}, {Opcode: 0xb8, Member: &target}, {Opcode: 0xb1},
		},
	}}}
}

func requestToReturningHelperClass(name string, target memberReference) classSpec {
	return classSpec{Name: name, Super: "javax/servlet/http/HttpServlet", Methods: []classMethodSpec{{
		Name: "service", Descriptor: "(Ljavax/servlet/http/HttpServletRequest;Ljavax/servlet/http/HttpServletResponse;)V",
		MaxStack: 2, MaxLocals: 4, Code: []classInstructionSpec{
			{Opcode: 0x2b}, {Opcode: 0x12, Constant: &constantValue{Kind: constantString, String: "cmd"}},
			{Opcode: 0xb9, Member: &fixtureRequestParameter}, {Opcode: 0xb8, Member: &target}, {Opcode: 0x4e},
			{Opcode: 0xb8, Member: &fixtureRuntimeGet}, {Opcode: 0x2d},
			{Opcode: 0xb6, Member: &fixtureRuntimeExec}, {Opcode: 0x57}, {Opcode: 0xb1},
		},
	}}}
}

func sourceHelperCallerClass(name string, target memberReference) classSpec {
	return classSpec{Name: name, Super: "javax/servlet/http/HttpServlet", Methods: []classMethodSpec{{
		Name: "service", Descriptor: "(Ljavax/servlet/http/HttpServletRequest;Ljavax/servlet/http/HttpServletResponse;)V",
		MaxStack: 2, MaxLocals: 4, Code: []classInstructionSpec{
			{Opcode: 0x2b}, {Opcode: 0xb8, Member: &target}, {Opcode: 0x4e},
			{Opcode: 0xb8, Member: &fixtureRuntimeGet}, {Opcode: 0x2d},
			{Opcode: 0xb6, Member: &fixtureRuntimeExec}, {Opcode: 0x57}, {Opcode: 0xb1},
		},
	}}}
}

var artifactFixtures = map[string]func(*testing.T) []artifactFixtureClass{
	"request_exec_helper": func(_ *testing.T) []artifactFixtureClass {
		target := memberReference{Owner: "fixture/Helper", Name: "exec", Descriptor: "(Ljava/lang/String;)V"}
		return []artifactFixtureClass{
			artifactClass("WEB-INF/classes/fixture/Entry.class", requestToStaticCallClass("fixture/Entry", target)),
			artifactClass("WEB-INF/classes/fixture/Helper.class", classSpec{Name: "fixture/Helper", Methods: []classMethodSpec{staticSinkMethod("fixture/Helper", "exec")}}),
		}
	},
	"request_helper_return": func(_ *testing.T) []artifactFixtureClass {
		target := memberReference{Owner: "fixture/Identity", Name: "pass", Descriptor: "(Ljava/lang/String;)Ljava/lang/String;"}
		return []artifactFixtureClass{
			artifactClass("fixture/Entry.class", requestToReturningHelperClass("fixture/ReturnEntry", target)),
			artifactClass("fixture/Identity.class", classSpec{Name: "fixture/Identity", Methods: []classMethodSpec{{
				Access: 0x0009, Name: "pass", Descriptor: "(Ljava/lang/String;)Ljava/lang/String;", MaxStack: 1, MaxLocals: 1,
				Code: []classInstructionSpec{{Opcode: 0x2a}, {Opcode: 0xb0}},
			}}}),
		}
	},
	"request_helper_source": func(_ *testing.T) []artifactFixtureClass {
		target := memberReference{Owner: "fixture/Source", Name: "read", Descriptor: "(Ljavax/servlet/http/HttpServletRequest;)Ljava/lang/String;"}
		return []artifactFixtureClass{
			artifactClass("fixture/Entry.class", sourceHelperCallerClass("fixture/SourceEntry", target)),
			artifactClass("fixture/Source.class", classSpec{Name: "fixture/Source", Methods: []classMethodSpec{{
				Access: 0x0009, Name: "read", Descriptor: target.Descriptor, MaxStack: 2, MaxLocals: 1,
				Code: []classInstructionSpec{
					{Opcode: 0x2a}, {Opcode: 0x12, Constant: &constantValue{Kind: constantString, String: "cmd"}},
					{Opcode: 0xb9, Member: &fixtureRequestParameter}, {Opcode: 0xb0},
				},
			}}}),
		}
	},
	"helper_exec_sink": func(_ *testing.T) []artifactFixtureClass {
		target := memberReference{Owner: "fixture/Sink", Name: "exec", Descriptor: "(Ljava/lang/String;)V"}
		return []artifactFixtureClass{
			artifactClass("fixture/Entry.class", requestToStaticCallClass("fixture/SinkEntry", target)),
			artifactClass("fixture/Sink.class", classSpec{Name: "fixture/Sink", Methods: []classMethodSpec{staticSinkMethod("fixture/Sink", "exec")}}),
		}
	},
	"summary_three_method_chain": threeMethodChainFixture,
	"summary_round_cap":          summaryRoundCapFixture,
	"summary_recursion": func(_ *testing.T) []artifactFixtureClass {
		recurse := memberReference{Owner: "fixture/Recursive", Name: "exec", Descriptor: "(Ljava/lang/String;)V"}
		method := staticSinkMethod("fixture/Recursive", "exec")
		method.Code = append([]classInstructionSpec{{Opcode: 0x2a}, {Opcode: 0xb8, Member: &recurse}}, method.Code...)
		return []artifactFixtureClass{
			artifactClass("fixture/Entry.class", requestToStaticCallClass("fixture/RecursiveEntry", recurse)),
			artifactClass("fixture/Recursive.class", classSpec{Name: "fixture/Recursive", Methods: []classMethodSpec{method}}),
		}
	},
	"summary_interface_dispatch": interfaceDispatchFixture,
	"summary_target_cap":         interfaceDispatchFixture,
	"summary_external_return": func(_ *testing.T) []artifactFixtureClass {
		target := memberReference{Owner: "external/Library", Name: "clean", Descriptor: "(Ljava/lang/String;)Ljava/lang/String;"}
		return []artifactFixtureClass{artifactClass("fixture/ExternalEntry.class", requestToReturningHelperClass("fixture/ExternalEntry", target))}
	},
	"summary_duplicate_binary_name": duplicateBinaryFixture,
	"summary_lambda_local": func(t *testing.T) []artifactFixtureClass {
		return lambdaArtifactFixture(t, "fixture/LambdaTarget", true, false)
	},
	"summary_lambda_external": func(t *testing.T) []artifactFixtureClass {
		return lambdaArtifactFixture(t, "external/LambdaTarget", false, false)
	},
	"summary_lambda_ambiguous": func(t *testing.T) []artifactFixtureClass {
		return lambdaArtifactFixture(t, "fixture/LambdaTarget", true, true)
	},
	"summary_review_external_unproven_return":       externalUnprovenSummaryFixture,
	"summary_review_invokespecial_exact":            invokeSpecialSummaryFixture,
	"summary_review_direct_mixed_untainted_summary": directMixedSummaryFixture,
	"summary_review_lambda_many_captures":           manyCaptureLambdaFixture,
	"summary_second_review_marker_collision":        markerCollisionSummaryFixture,
	"summary_second_review_returned_array":          returnedArraySummaryFixture,
	"summary_second_review_array_argument":          arrayArgumentSummaryFixture,
	"large_benign_before_request_exec":              largeBenignFixture,
}

func markerCollisionSummaryFixture(_ *testing.T) []artifactFixtureClass {
	hostile := memberReference{Owner: "fixture/MarkerBase", Name: "\x00virtual:run", Descriptor: "(Ljava/lang/String;Ljava/lang/String;)V"}
	run := memberReference{Owner: "fixture/MarkerBase", Name: "run", Descriptor: hostile.Descriptor}
	entry := classSpec{Name: "fixture/MarkerEntry", Super: "javax/servlet/http/HttpServlet", Methods: []classMethodSpec{{
		Name: "service", Descriptor: "(Ljavax/servlet/http/HttpServletRequest;Ljavax/servlet/http/HttpServletResponse;)V",
		MaxStack: 3, MaxLocals: 3, Code: []classInstructionSpec{
			{Opcode: 0x12, Constant: &constantValue{Kind: constantString, String: "benign"}},
			{Opcode: 0x2b}, {Opcode: 0x12, Constant: &constantValue{Kind: constantString, String: "cmd"}},
			{Opcode: 0xb9, Member: &fixtureRequestParameter}, {Opcode: 0xb8, Member: &hostile}, {Opcode: 0xb1},
		},
	}}}
	return []artifactFixtureClass{
		artifactClass("fixture/MarkerEntry.class", entry),
		artifactClass("fixture/MarkerBase.class", classSpec{Name: "fixture/MarkerBase", Methods: []classMethodSpec{
			{Name: run.Name, Descriptor: run.Descriptor, MaxStack: 0, MaxLocals: 3, Code: []classInstructionSpec{{Opcode: 0xb1}}},
			{Access: 0x0009, Name: hostile.Name, Descriptor: hostile.Descriptor, MaxStack: 0, MaxLocals: 2, Code: []classInstructionSpec{{Opcode: 0xb1}}},
		}}),
		artifactClass("fixture/MarkerOverride.class", classSpec{Name: "fixture/MarkerOverride", Super: "fixture/MarkerBase", Methods: []classMethodSpec{{
			Name: run.Name, Descriptor: run.Descriptor, MaxStack: 2, MaxLocals: 3,
			Code: []classInstructionSpec{
				{Opcode: 0xb8, Member: &fixtureRuntimeGet}, {Opcode: 0x2b},
				{Opcode: 0xb6, Member: &fixtureRuntimeExec}, {Opcode: 0x57}, {Opcode: 0xb1},
			},
		}}}),
	}
}

func returnedArraySummaryFixture(_ *testing.T) []artifactFixtureClass {
	pass := memberReference{Owner: "fixture/ArrayIdentity", Name: "pass", Descriptor: "([Ljava/lang/String;)[Ljava/lang/String;"}
	entry := classSpec{Name: "fixture/ReturnedArrayEntry", Super: "javax/servlet/http/HttpServlet", Methods: []classMethodSpec{{
		Name: "service", Descriptor: "(Ljavax/servlet/http/HttpServletRequest;Ljavax/servlet/http/HttpServletResponse;)V",
		MaxStack: 2, MaxLocals: 4, Code: []classInstructionSpec{
			{Opcode: 0x2b}, {Opcode: 0x12, Constant: &constantValue{Kind: constantString, String: "cmd"}},
			{Opcode: 0xb9, Member: &fixtureRequestParameterValues}, {Opcode: 0xb8, Member: &pass},
			{Opcode: 0x03}, {Opcode: 0x32}, {Opcode: 0x4e}, {Opcode: 0xb8, Member: &fixtureRuntimeGet},
			{Opcode: 0x2d}, {Opcode: 0xb6, Member: &fixtureRuntimeExec}, {Opcode: 0x57}, {Opcode: 0xb1},
		},
	}}}
	return []artifactFixtureClass{
		artifactClass("fixture/ReturnedArrayEntry.class", entry),
		artifactClass("fixture/ArrayIdentity.class", classSpec{Name: "fixture/ArrayIdentity", Methods: []classMethodSpec{{
			Access: 0x0009, Name: pass.Name, Descriptor: pass.Descriptor, MaxStack: 1, MaxLocals: 1,
			Code: []classInstructionSpec{{Opcode: 0x2a}, {Opcode: 0xb0}},
		}}}),
	}
}

func arrayArgumentSummaryFixture(_ *testing.T) []artifactFixtureClass {
	first := memberReference{Owner: "fixture/ArrayReader", Name: "first", Descriptor: "([Ljava/lang/String;)Ljava/lang/String;"}
	entry := classSpec{Name: "fixture/ArrayArgumentEntry", Super: "javax/servlet/http/HttpServlet", Methods: []classMethodSpec{{
		Name: "service", Descriptor: "(Ljavax/servlet/http/HttpServletRequest;Ljavax/servlet/http/HttpServletResponse;)V",
		MaxStack: 2, MaxLocals: 4, Code: []classInstructionSpec{
			{Opcode: 0x2b}, {Opcode: 0x12, Constant: &constantValue{Kind: constantString, String: "cmd"}},
			{Opcode: 0xb9, Member: &fixtureRequestParameterValues}, {Opcode: 0xb8, Member: &first}, {Opcode: 0x4e},
			{Opcode: 0xb8, Member: &fixtureRuntimeGet}, {Opcode: 0x2d},
			{Opcode: 0xb6, Member: &fixtureRuntimeExec}, {Opcode: 0x57}, {Opcode: 0xb1},
		},
	}}}
	return []artifactFixtureClass{
		artifactClass("fixture/ArrayArgumentEntry.class", entry),
		artifactClass("fixture/ArrayReader.class", classSpec{Name: "fixture/ArrayReader", Methods: []classMethodSpec{{
			Access: 0x0009, Name: first.Name, Descriptor: first.Descriptor, MaxStack: 2, MaxLocals: 1,
			Code: []classInstructionSpec{{Opcode: 0x2a}, {Opcode: 0x03}, {Opcode: 0x32}, {Opcode: 0xb0}},
		}}}),
	}
}

func externalUnprovenSummaryFixture(_ *testing.T) []artifactFixtureClass {
	read := memberReference{Owner: "fixture/ReviewSource", Name: "read", Descriptor: "(Ljavax/servlet/http/HttpServletRequest;)Ljava/lang/String;"}
	external := memberReference{Owner: "external/Library", Name: "clean", Descriptor: "(Ljava/lang/String;)Ljava/lang/String;"}
	return []artifactFixtureClass{
		artifactClass("fixture/ReviewEntry.class", sourceHelperCallerClass("fixture/ReviewEntry", read)),
		artifactClass("fixture/ReviewSource.class", classSpec{Name: "fixture/ReviewSource", Methods: []classMethodSpec{{
			Access: 0x0009, Name: "read", Descriptor: read.Descriptor, MaxStack: 2, MaxLocals: 1,
			Code: []classInstructionSpec{
				{Opcode: 0x2a}, {Opcode: 0x12, Constant: &constantValue{Kind: constantString, String: "cmd"}},
				{Opcode: 0xb9, Member: &fixtureRequestParameter}, {Opcode: 0xb8, Member: &external}, {Opcode: 0xb0},
			},
		}}}),
	}
}

func invokeSpecialSummaryFixture(_ *testing.T) []artifactFixtureClass {
	baseRun := memberReference{Owner: "fixture/ReviewBase", Name: "run", Descriptor: "(Ljava/lang/String;)V"}
	entry := classSpec{Name: "fixture/ReviewSpecialEntry", Super: "fixture/ReviewBase", Methods: []classMethodSpec{{
		Name: "service", Descriptor: "(Ljavax/servlet/http/HttpServletRequest;)V", MaxStack: 3, MaxLocals: 2,
		Code: []classInstructionSpec{
			{Opcode: 0x2a}, {Opcode: 0x2b}, {Opcode: 0x12, Constant: &constantValue{Kind: constantString, String: "cmd"}},
			{Opcode: 0xb9, Member: &fixtureRequestParameter}, {Opcode: 0xb7, Member: &baseRun}, {Opcode: 0xb1},
		},
	}}}
	return []artifactFixtureClass{
		artifactClass("fixture/ReviewBase.class", classSpec{Name: "fixture/ReviewBase", Methods: []classMethodSpec{{
			Name: "run", Descriptor: baseRun.Descriptor, MaxStack: 0, MaxLocals: 2, Code: []classInstructionSpec{{Opcode: 0xb1}},
		}}}),
		artifactClass("fixture/ReviewOverride.class", classSpec{Name: "fixture/ReviewOverride", Super: "fixture/ReviewBase", Methods: []classMethodSpec{{
			Name: "run", Descriptor: baseRun.Descriptor, MaxStack: 2, MaxLocals: 2,
			Code: []classInstructionSpec{
				{Opcode: 0xb8, Member: &fixtureRuntimeGet}, {Opcode: 0x2b},
				{Opcode: 0xb6, Member: &fixtureRuntimeExec}, {Opcode: 0x57}, {Opcode: 0xb1},
			},
		}}}),
		artifactClass("fixture/ReviewSpecialEntry.class", entry),
	}
}

func directMixedSummaryFixture(_ *testing.T) []artifactFixtureClass {
	pass := memberReference{Owner: "fixture/ReviewIdentity", Name: "pass", Descriptor: "(Ljava/lang/String;)Ljava/lang/String;"}
	entry := classSpec{Name: "fixture/ReviewMixedEntry", Super: "javax/servlet/http/HttpServlet", Methods: []classMethodSpec{{
		Name: "service", Descriptor: "(Ljavax/servlet/http/HttpServletRequest;Ljavax/servlet/http/HttpServletResponse;)V",
		MaxStack: 2, MaxLocals: 4, Code: []classInstructionSpec{
			{Opcode: 0x2b}, {Opcode: 0x12, Constant: &constantValue{Kind: constantString, String: "cmd"}},
			{Opcode: 0xb9, Member: &fixtureRequestParameter}, {Opcode: 0x4e}, {Opcode: 0x2d},
			{Opcode: 0x12, Constant: &constantValue{Kind: constantString, String: " suffix"}}, {Opcode: 0xb8, Member: &pass},
			{Opcode: 0xb6, Member: &fixtureStringConcat}, {Opcode: 0x4e}, {Opcode: 0xb8, Member: &fixtureRuntimeGet},
			{Opcode: 0x2d}, {Opcode: 0xb6, Member: &fixtureRuntimeExec}, {Opcode: 0x57}, {Opcode: 0xb1},
		},
	}}}
	return []artifactFixtureClass{
		artifactClass("fixture/ReviewMixedEntry.class", entry),
		artifactClass("fixture/ReviewIdentity.class", classSpec{Name: "fixture/ReviewIdentity", Methods: []classMethodSpec{{
			Access: 0x0009, Name: "pass", Descriptor: pass.Descriptor, MaxStack: 1, MaxLocals: 1,
			Code: []classInstructionSpec{{Opcode: 0x2a}, {Opcode: 0xb0}},
		}}}),
	}
}

func manyCaptureLambdaFixture(t *testing.T) []artifactFixtureClass {
	t.Helper()
	const captures = 32
	descriptor := "(" + strings.Repeat("Ljava/lang/String;", captures) + ")V"
	target := classMethodSpec{
		Access: 0x0009, Name: "run", Descriptor: descriptor, MaxStack: 2, MaxLocals: captures,
		Code: []classInstructionSpec{
			{Opcode: 0xb8, Member: &fixtureRuntimeGet}, {Opcode: 0x19, Operands: []byte{captures - 1}},
			{Opcode: 0xb6, Member: &fixtureRuntimeExec}, {Opcode: 0x57}, {Opcode: 0xb1},
		},
	}
	return []artifactFixtureClass{
		{LogicalPath: "fixture/ReviewManyCaptureFactory.class", Bytes: task11ManyCaptureLambdaFactoryBytes},
		artifactClass("fixture/ReviewManyCaptureTarget.class", classSpec{Name: "fixture/ReviewManyCaptureTarget", Methods: []classMethodSpec{target}}),
	}
}

func threeMethodChainFixture(_ *testing.T) []artifactFixtureClass {
	middle := memberReference{Owner: "fixture/Middle", Name: "pass", Descriptor: "(Ljava/lang/String;)Ljava/lang/String;"}
	sink := memberReference{Owner: "fixture/Sink", Name: "exec", Descriptor: "(Ljava/lang/String;)V"}
	return []artifactFixtureClass{
		artifactClass("fixture/Entry.class", requestToReturningHelperClass("fixture/ChainEntry", middle)),
		artifactClass("fixture/Middle.class", classSpec{Name: "fixture/Middle", Methods: []classMethodSpec{{
			Access: 0x0009, Name: "pass", Descriptor: middle.Descriptor, MaxStack: 1, MaxLocals: 1,
			Code: []classInstructionSpec{{Opcode: 0x2a}, {Opcode: 0xb8, Member: &sink}, {Opcode: 0x2a}, {Opcode: 0xb0}},
		}}}),
		artifactClass("fixture/Sink.class", classSpec{Name: "fixture/Sink", Methods: []classMethodSpec{staticSinkMethod("fixture/Sink", "exec")}}),
	}
}

func summaryRoundCapFixture(_ *testing.T) []artifactFixtureClass {
	first := memberReference{Owner: "fixture/First", Name: "pass", Descriptor: "(Ljava/lang/String;)Ljava/lang/String;"}
	second := memberReference{Owner: "fixture/Second", Name: "pass", Descriptor: first.Descriptor}
	return []artifactFixtureClass{
		artifactClass("fixture/Entry.class", requestToReturningHelperClass("fixture/RoundEntry", first)),
		artifactClass("fixture/First.class", classSpec{Name: "fixture/First", Methods: []classMethodSpec{{
			Access: 0x0009, Name: "pass", Descriptor: first.Descriptor, MaxStack: 1, MaxLocals: 1,
			Code: []classInstructionSpec{{Opcode: 0x2a}, {Opcode: 0xb8, Member: &second}, {Opcode: 0xb0}},
		}}}),
		artifactClass("fixture/Second.class", classSpec{Name: "fixture/Second", Methods: []classMethodSpec{{
			Access: 0x0009, Name: "pass", Descriptor: second.Descriptor, MaxStack: 1, MaxLocals: 1,
			Code: []classInstructionSpec{{Opcode: 0x2a}, {Opcode: 0xb0}},
		}}}),
	}
}

func interfaceDispatchFixture(_ *testing.T) []artifactFixtureClass {
	runner := memberReference{Owner: "fixture/Runner", Name: "run", Descriptor: "(Ljava/lang/String;)V", Interface: true}
	entry := requestToStaticCallClass("fixture/Unused", runner)
	entry.Name = "fixture/RunnerEntry"
	entry.Interfaces = []string{"fixture/Runner"}
	entry.Methods[0].Code = []classInstructionSpec{
		{Opcode: 0x2a}, {Opcode: 0x2b}, {Opcode: 0x12, Constant: &constantValue{Kind: constantString, String: "cmd"}},
		{Opcode: 0xb9, Member: &fixtureRequestParameter}, {Opcode: 0xb9, Member: &runner}, {Opcode: 0xb1},
	}
	entry.Methods[0].MaxStack = 3
	entry.Methods = append(entry.Methods, classMethodSpec{
		Name: "run", Descriptor: runner.Descriptor, MaxStack: 0, MaxLocals: 2,
		Code: []classInstructionSpec{{Opcode: 0xb1}},
	})
	return []artifactFixtureClass{
		artifactClass("fixture/Runner.class", classSpec{Name: "fixture/Runner", Methods: []classMethodSpec{{
			Access: 0x0401, Name: "run", Descriptor: runner.Descriptor, NoCode: true,
		}}}),
		artifactClass("fixture/RunnerEntry.class", entry),
		artifactClass("fixture/RunnerImpl.class", classSpec{Name: "fixture/RunnerImpl", Interfaces: []string{"fixture/Runner"}, Methods: []classMethodSpec{{
			Name: "run", Descriptor: runner.Descriptor, MaxStack: 2, MaxLocals: 2,
			Code: []classInstructionSpec{
				{Opcode: 0xb8, Member: &fixtureRuntimeGet}, {Opcode: 0x2b},
				{Opcode: 0xb6, Member: &fixtureRuntimeExec}, {Opcode: 0x57}, {Opcode: 0xb1},
			},
		}}}),
	}
}

func duplicateBinaryFixture(_ *testing.T) []artifactFixtureClass {
	duplicateCall := memberReference{Owner: "fixture/Duplicate", Name: "exec", Descriptor: "(Ljava/lang/String;)V"}
	direct := classMethodSpec{
		Access: 0x0009, Name: "direct", Descriptor: "(Ljavax/servlet/http/HttpServletRequest;)V", MaxStack: 2, MaxLocals: 2,
		Code: []classInstructionSpec{
			{Opcode: 0x2a}, {Opcode: 0x12, Constant: &constantValue{Kind: constantString, String: "cmd"}},
			{Opcode: 0xb9, Member: &fixtureRequestParameter}, {Opcode: 0x4c}, {Opcode: 0xb8, Member: &fixtureRuntimeGet},
			{Opcode: 0x2b}, {Opcode: 0xb6, Member: &fixtureRuntimeExec}, {Opcode: 0x57}, {Opcode: 0xb1},
		},
	}
	return []artifactFixtureClass{
		artifactClass("base/fixture/Duplicate.class", classSpec{Name: "fixture/Duplicate", Methods: []classMethodSpec{direct, staticSinkMethod("fixture/Duplicate", "exec")}}),
		artifactClass("META-INF/versions/11/fixture/Duplicate.class", classSpec{Name: "fixture/Duplicate", Methods: []classMethodSpec{{
			Access: 0x0009, Name: "exec", Descriptor: duplicateCall.Descriptor, MaxStack: 0, MaxLocals: 1,
			Code: []classInstructionSpec{{Opcode: 0xb1}},
		}}}),
		artifactClass("fixture/DuplicateCaller.class", requestToStaticCallClass("fixture/DuplicateCaller", duplicateCall)),
	}
}

func largeBenignFixture(_ *testing.T) []artifactFixtureClass {
	benignCode := make([]classInstructionSpec, 50)
	for index := range benignCode {
		benignCode[index] = classInstructionSpec{Opcode: 0x00}
	}
	benignCode = append(benignCode, classInstructionSpec{Opcode: 0xb1})
	return []artifactFixtureClass{
		artifactClass("000/Benign.class", classSpec{Name: "fixture/Benign", Methods: []classMethodSpec{{
			Access: 0x0009, Name: "run", MaxStack: 0, MaxLocals: 0, Code: benignCode,
		}}}),
		artifactClass("zzz/RequestExec.class", fixtureClasses["request_exec"]()),
	}
}

func lambdaArtifactFixture(t *testing.T, targetOwner string, includeTarget, duplicateTarget bool) []artifactFixtureClass {
	t.Helper()
	result := []artifactFixtureClass{{
		LogicalPath: "fixture/LambdaFactory.class",
		Bytes:       func(t *testing.T) []byte { return task11LambdaFactoryBytes(t, targetOwner) },
	}}
	if includeTarget {
		target := artifactClass("fixture/LambdaTarget.class", classSpec{Name: targetOwner, Methods: []classMethodSpec{staticSinkMethod(targetOwner, "run")}})
		result = append(result, target)
		if duplicateTarget {
			result = append(result, artifactClass("META-INF/versions/11/fixture/LambdaTarget.class", target.Spec))
		}
	}
	return result
}

func task11LambdaFactoryBytes(t *testing.T, targetOwner string) []byte {
	t.Helper()
	pool := newConstantPoolBuilder()
	thisClass := pool.u2Entry(cpClass, pool.utf8("fixture/LambdaFactory"))
	superClass := pool.u2Entry(cpClass, pool.utf8("java/lang/Object"))
	codeName := pool.utf8("Code")
	bootstrapName := pool.utf8("BootstrapMethods")
	bootstrap := memberReference{
		Owner: "java/lang/invoke/LambdaMetafactory", Name: "metafactory",
		Descriptor: "(Ljava/lang/invoke/MethodHandles$Lookup;Ljava/lang/String;Ljava/lang/invoke/MethodType;Ljava/lang/invoke/MethodType;Ljava/lang/invoke/MethodHandle;Ljava/lang/invoke/MethodType;)Ljava/lang/invoke/CallSite;",
	}
	bootstrapHandle := pool.methodHandle(6, classMemberIndex(pool, bootstrap, false))
	samMethodType := pool.u2Entry(cpMethodType, pool.utf8("()V"))
	target := memberReference{Owner: targetOwner, Name: "run", Descriptor: "(Ljava/lang/String;)V"}
	targetHandle := pool.methodHandle(6, classMemberIndex(pool, target, false))
	instantiatedMethodType := pool.u2Entry(cpMethodType, pool.utf8("()V"))
	dynamicNameType := pool.pairEntry(cpNameAndType, pool.utf8("run"), pool.utf8("(Ljava/lang/String;)Ljava/lang/Runnable;"))
	dynamicIndex := pool.pairEntry(cpInvokeDynamic, 0, dynamicNameType)
	requestParameter := classMemberIndex(pool, fixtureRequestParameter, false)
	runnableRun := memberReference{Owner: "java/lang/Runnable", Name: "run", Descriptor: "()V", Interface: true}
	runnableIndex := classMemberIndex(pool, runnableRun, false)
	payloadIndex := classConstantIndex(t, pool, constantValue{Kind: constantString, String: "cmd"})

	bytecode := []byte{0x2a, 0x12, byte(payloadIndex), 0xb9}
	bytecode = append(bytecode, u2Bytes(requestParameter)...)
	bytecode = append(bytecode, structuralInvokeInterfaceCount(t, fixtureRequestParameter.Descriptor), 0, 0xba)
	bytecode = append(bytecode, u2Bytes(dynamicIndex)...)
	bytecode = append(bytecode, 0, 0, 0xb9)
	bytecode = append(bytecode, u2Bytes(runnableIndex)...)
	bytecode = append(bytecode, 1, 0, 0xb1)
	code := append(u2Bytes(2), u2Bytes(1)...)
	code = append(code, u4Bytes(uint32(len(bytecode)))...)
	code = append(code, bytecode...)
	code = append(code, 0, 0, 0, 0)
	service := memberFixture(0x0009, pool.utf8("service"), pool.utf8("(Ljavax/servlet/http/HttpServletRequest;)V"), attributeFixture(codeName, code))

	bootstrapPayload := append(u2Bytes(1), u2Bytes(bootstrapHandle)...)
	bootstrapPayload = append(bootstrapPayload, u2Bytes(3)...)
	bootstrapPayload = append(bootstrapPayload, u2Bytes(samMethodType)...)
	bootstrapPayload = append(bootstrapPayload, u2Bytes(targetHandle)...)
	bootstrapPayload = append(bootstrapPayload, u2Bytes(instantiatedMethodType)...)
	data := finishClass(0, 55, pool, thisClass, superClass, nil)
	data = data[:len(data)-6]
	data = append(data, 0, 0, 0, 1)
	data = append(data, service...)
	data = append(data, 0, 1)
	data = append(data, attributeFixture(bootstrapName, bootstrapPayload)...)
	return data
}

func task11ManyCaptureLambdaFactoryBytes(t *testing.T) []byte {
	t.Helper()
	const captures = 32
	parameterDescriptor := strings.Repeat("Ljava/lang/String;", captures)
	pool := newConstantPoolBuilder()
	thisClass := pool.u2Entry(cpClass, pool.utf8("fixture/ReviewManyCaptureFactory"))
	superClass := pool.u2Entry(cpClass, pool.utf8("java/lang/Object"))
	codeName := pool.utf8("Code")
	bootstrapName := pool.utf8("BootstrapMethods")
	bootstrap := memberReference{
		Owner: "java/lang/invoke/LambdaMetafactory", Name: "metafactory",
		Descriptor: "(Ljava/lang/invoke/MethodHandles$Lookup;Ljava/lang/String;Ljava/lang/invoke/MethodType;Ljava/lang/invoke/MethodType;Ljava/lang/invoke/MethodHandle;Ljava/lang/invoke/MethodType;)Ljava/lang/invoke/CallSite;",
	}
	bootstrapHandle := pool.methodHandle(6, classMemberIndex(pool, bootstrap, false))
	samMethodType := pool.u2Entry(cpMethodType, pool.utf8("()V"))
	target := memberReference{Owner: "fixture/ReviewManyCaptureTarget", Name: "run", Descriptor: "(" + parameterDescriptor + ")V"}
	targetHandle := pool.methodHandle(6, classMemberIndex(pool, target, false))
	instantiatedMethodType := pool.u2Entry(cpMethodType, pool.utf8("()V"))
	dynamicNameType := pool.pairEntry(cpNameAndType, pool.utf8("run"), pool.utf8("("+parameterDescriptor+")Ljava/lang/Runnable;"))
	dynamicIndex := pool.pairEntry(cpInvokeDynamic, 0, dynamicNameType)
	requestParameter := classMemberIndex(pool, fixtureRequestParameter, false)
	runnableRun := memberReference{Owner: "java/lang/Runnable", Name: "run", Descriptor: "()V", Interface: true}
	runnableIndex := classMemberIndex(pool, runnableRun, false)
	benignIndex := classConstantIndex(t, pool, constantValue{Kind: constantString, String: "benign"})
	payloadIndex := classConstantIndex(t, pool, constantValue{Kind: constantString, String: "cmd"})

	bytecode := make([]byte, 0, captures*2+24)
	for index := 0; index < captures-1; index++ {
		bytecode = append(bytecode, 0x12, byte(benignIndex))
	}
	bytecode = append(bytecode, 0x2a, 0x12, byte(payloadIndex), 0xb9)
	bytecode = append(bytecode, u2Bytes(requestParameter)...)
	bytecode = append(bytecode, structuralInvokeInterfaceCount(t, fixtureRequestParameter.Descriptor), 0, 0xba)
	bytecode = append(bytecode, u2Bytes(dynamicIndex)...)
	bytecode = append(bytecode, 0, 0, 0xb9)
	bytecode = append(bytecode, u2Bytes(runnableIndex)...)
	bytecode = append(bytecode, 1, 0, 0xb1)
	code := append(u2Bytes(captures+1), u2Bytes(1)...)
	code = append(code, u4Bytes(uint32(len(bytecode)))...)
	code = append(code, bytecode...)
	code = append(code, 0, 0, 0, 0)
	service := memberFixture(0x0009, pool.utf8("service"), pool.utf8("(Ljavax/servlet/http/HttpServletRequest;)V"), attributeFixture(codeName, code))

	bootstrapPayload := append(u2Bytes(1), u2Bytes(bootstrapHandle)...)
	bootstrapPayload = append(bootstrapPayload, u2Bytes(3)...)
	bootstrapPayload = append(bootstrapPayload, u2Bytes(samMethodType)...)
	bootstrapPayload = append(bootstrapPayload, u2Bytes(targetHandle)...)
	bootstrapPayload = append(bootstrapPayload, u2Bytes(instantiatedMethodType)...)
	data := finishClass(0, 55, pool, thisClass, superClass, nil)
	data = data[:len(data)-6]
	data = append(data, 0, 0, 0, 1)
	data = append(data, service...)
	data = append(data, 0, 1)
	data = append(data, attributeFixture(bootstrapName, bootstrapPayload)...)
	return data
}

func fixtureArtifact(t *testing.T, name string) map[string]*classModel {
	t.Helper()
	build, ok := artifactFixtures[name]
	if !ok {
		t.Fatalf("unknown artifact fixture %q", name)
	}
	result := make(map[string]*classModel)
	for _, entry := range build(t) {
		if _, duplicate := result[entry.LogicalPath]; duplicate {
			t.Fatalf("duplicate fixture logical path %q", entry.LogicalPath)
		}
		data := entry.Bytes
		var classBytesData []byte
		if data != nil {
			classBytesData = data(t)
		} else {
			classBytesData, _ = classBytes(t, entry.Spec)
		}
		class, err := parseClass(classBytesData, DefaultOptions().Limits)
		if err != nil {
			t.Fatalf("parse fixture %s path %s: %v", name, entry.LogicalPath, err)
		}
		result[entry.LogicalPath] = class
	}
	return result
}

func fixtureClass(t *testing.T, name string) []byte {
	t.Helper()
	build, ok := fixtureClasses[name]
	if !ok {
		t.Fatalf("unknown class fixture %q", name)
	}
	data, _ := classBytes(t, build())
	return data
}

func TestBytecodeRequestToRuntimeExec(t *testing.T) {
	res := AnalyzeArtifact("Shell.class", fixtureClass(t, "request_exec"), DefaultOptions())
	finding := findingByRule(res.Findings, "javadisk:class-request-exec")
	if finding == nil || finding.Score != 85 ||
		!strings.Contains(finding.Evidence, "getParameter") ||
		!strings.Contains(finding.Evidence, "Runtime.exec") {
		t.Fatalf("result=%+v", res)
	}
	if findingByRule(res.Findings, "javadisk:class-request-exec-structure") == nil {
		t.Fatalf("Task 8 structural finding was not retained: %+v", res)
	}
}

func TestBytecodeRequestFlowThroughBranchJoin(t *testing.T) {
	res := AnalyzeArtifact("Branch.class", fixtureClass(t, "branch_join"), DefaultOptions())
	if finding := findingByRule(res.Findings, "javadisk:class-request-exec"); finding == nil || finding.Score != 85 {
		t.Fatalf("result=%+v", res)
	}
}

func TestBytecodeHardcodedExecAndResponseRenderingDoNotPromote(t *testing.T) {
	for _, name := range []string{"hardcoded_exec", "request_render"} {
		t.Run(name, func(t *testing.T) {
			res := AnalyzeArtifact(name+".class", fixtureClass(t, name), DefaultOptions())
			if findingByRule(res.Findings, "javadisk:class-request-exec") != nil {
				t.Fatalf("result=%+v", res)
			}
		})
	}
}

func TestBytecodeStackUnderflowFallsBackWithDiagnostic(t *testing.T) {
	res := AnalyzeArtifact("Bad.class", fixtureClass(t, "bad_stack"), DefaultOptions())
	if len(res.Diagnostics) != 1 || res.Diagnostics[0].Code != diagBytecodeUnsupported {
		t.Fatalf("result=%+v", res)
	}
}

func TestBytecodeAnalysisIsDeterministic(t *testing.T) {
	data := fixtureClass(t, "branch_join")
	want := AnalyzeArtifact("Stable.class", data, DefaultOptions())
	for i := 0; i < 20; i++ {
		if got := AnalyzeArtifact("Stable.class", data, DefaultOptions()); !reflect.DeepEqual(got, want) {
			t.Fatalf("iteration %d got=%+v want=%+v", i, got, want)
		}
	}
}

func TestBytecodeStateMergeBudgetKeepsStructuralFallback(t *testing.T) {
	opts := DefaultOptions()
	opts.Limits.MaxStateMerges = 1
	result := AnalyzeArtifact("Budget.class", fixtureClass(t, "branch_join"), opts)
	if !hasDiagnosticCode(result.Diagnostics, diagAnalysisBudget) ||
		findingByRule(result.Findings, "javadisk:class-request-exec") != nil ||
		findingByRule(result.Findings, "javadisk:class-request-exec-structure") == nil {
		t.Fatalf("result=%+v", result)
	}
}

func TestBytecodeEvidenceAlwaysContainsBoundedSourceAndSink(t *testing.T) {
	longName := strings.Repeat("HostileName", 400)
	data, _ := classBytes(t, classSpec{Name: "fixture/" + longName, Methods: []classMethodSpec{{
		Access: 0x0009, Name: longName, Descriptor: "(Ljavax/servlet/http/HttpServletRequest;)V", MaxStack: 2, MaxLocals: 2,
		Code: []classInstructionSpec{
			{Opcode: 0x2a},
			{Opcode: 0x12, Constant: &constantValue{Kind: constantString, String: "cmd"}},
			{Opcode: 0xb9, Member: &fixtureRequestParameter}, {Opcode: 0x4c},
			{Opcode: 0xb8, Member: &fixtureRuntimeGet}, {Opcode: 0x2b},
			{Opcode: 0xb6, Member: &fixtureRuntimeExec}, {Opcode: 0x57}, {Opcode: 0xb1},
		},
	}}})
	opts := DefaultOptions()
	opts.Limits.MaxProvenanceSteps = 1
	result := AnalyzeArtifact("Long.class", data, opts)
	finding := findingByRule(result.Findings, "javadisk:class-request-exec")
	if finding == nil || len(finding.Evidence) > maxDiagnosticTextBytes ||
		!strings.Contains(finding.Evidence, "getParameter") || !strings.Contains(finding.Evidence, "Runtime.exec") {
		t.Fatalf("result=%+v", result)
	}
}

func TestBytecodeMalformedReachableInvokeIsDiagnostic(t *testing.T) {
	data, _ := classBytes(t, classSpec{Name: "fixture/MalformedInvoke", Methods: []classMethodSpec{{
		Access: 0x0009, Name: "run", MaxStack: 1, Code: []classInstructionSpec{
			{Opcode: 0xb8, Member: &fixtureRuntimeGet},
			{Opcode: 0xb6, Member: &fixtureRuntimeExec}, {Opcode: 0x57}, {Opcode: 0xb1},
		},
	}}})
	result := AnalyzeArtifact("MalformedInvoke.class", data, DefaultOptions())
	if !hasDiagnosticCode(result.Diagnostics, diagBytecodeUnsupported) ||
		findingByRule(result.Findings, "javadisk:class-request-exec") != nil {
		t.Fatalf("result=%+v", result)
	}
}

func TestBytecodeReachableJSRRetKeepsStructuralFallbackWithoutPromotion(t *testing.T) {
	request := fixtureRequestParameter
	runtimeGet := fixtureRuntimeGet
	runtimeExec := fixtureRuntimeExec
	data, _ := classBytes(t, classSpec{
		Name: "fixture/Legacy", Super: "javax/servlet/http/HttpServlet",
		Methods: []classMethodSpec{{
			Name: "service", Descriptor: "(Ljavax/servlet/http/HttpServletRequest;)V",
			MaxStack: 2, MaxLocals: 4, Code: []classInstructionSpec{
				{Opcode: 0x2b},
				{Opcode: 0x12, Constant: &constantValue{Kind: constantString, String: "cmd"}},
				{Opcode: 0xb9, Member: &request}, {Opcode: 0x4d},
				{Opcode: 0xa8, Operands: []byte{0x00, 0x0c}},
				{Opcode: 0xb8, Member: &runtimeGet}, {Opcode: 0x2c},
				{Opcode: 0xb6, Member: &runtimeExec}, {Opcode: 0x57}, {Opcode: 0xb1},
				{Opcode: 0x4e}, {Opcode: 0xa9, Operands: []byte{0x03}},
			},
		}},
	})
	result := AnalyzeArtifact("Legacy.class", data, DefaultOptions())
	if !hasDiagnosticCode(result.Diagnostics, diagBytecodeUnsupported) ||
		findingByRule(result.Findings, "javadisk:class-request-exec") != nil ||
		findingByRule(result.Findings, "javadisk:class-request-exec-structure") == nil {
		t.Fatalf("result=%+v", result)
	}
}

func modernStackMapFlowSpec(major uint16, stackMap []stackMapFrameSpec, raw []byte) classSpec {
	return classSpec{Name: "fixture/ModernFrames", Major: major, Methods: []classMethodSpec{{
		Access: 0x0009, Name: "run",
		Descriptor: "(Ljavax/servlet/http/HttpServletRequest;I)V", MaxStack: 2, MaxLocals: 3,
		Code: []classInstructionSpec{
			{Opcode: 0x2a}, {Opcode: 0x12, Constant: &constantValue{Kind: constantString, String: "cmd"}},
			{Opcode: 0xb9, Member: &fixtureRequestParameter}, {Opcode: 0x4d},
			{Opcode: 0x1b}, {Opcode: 0x99, Operands: []byte{0x00, 0x06}},
			{Opcode: 0xa7, Operands: []byte{0x00, 0x06}},
			{Opcode: 0xa7, Operands: []byte{0x00, 0x03}},
			{Opcode: 0xb8, Member: &fixtureRuntimeGet}, {Opcode: 0x2c},
			{Opcode: 0xb6, Member: &fixtureRuntimeExec}, {Opcode: 0x57}, {Opcode: 0xb1},
		},
		StackMap: stackMap, StackMapRaw: raw,
	}}}
}

func TestBytecodeModernStackMapControlsSemanticEligibility(t *testing.T) {
	validFrames := []stackMapFrameSpec{
		{Offset: 16, Locals: []string{"javax/servlet/http/HttpServletRequest", "I", "java/lang/String"}},
		{Offset: 19, Locals: []string{"javax/servlet/http/HttpServletRequest", "I", "java/lang/String"}},
	}
	for _, tt := range []struct {
		name     string
		spec     classSpec
		wantExec bool
		wantDiag string
	}{
		{"modern missing", modernStackMapFlowSpec(52, nil, nil), false, diagBytecodeUnsupported},
		{"modern malformed", modernStackMapFlowSpec(52, nil, []byte{0x00, 0x01, 0xff}), false, diagClassMalformed},
		{"modern inconsistent", modernStackMapFlowSpec(52, []stackMapFrameSpec{
			{Offset: 16, Locals: []string{"java/lang/Runtime", "I", "java/lang/String"}},
			{Offset: 19, Locals: []string{"java/lang/Runtime", "I", "java/lang/String"}},
		}, nil), false, diagBytecodeUnsupported},
		{"modern valid", modernStackMapFlowSpec(52, validFrames, nil), true, ""},
		{"legacy valid", modernStackMapFlowSpec(49, nil, nil), true, ""},
	} {
		t.Run(tt.name, func(t *testing.T) {
			data, _ := classBytes(t, tt.spec)
			result := AnalyzeArtifact(tt.name+".class", data, DefaultOptions())
			got := findingByRule(result.Findings, "javadisk:class-request-exec") != nil
			if got != tt.wantExec || tt.wantDiag != "" && !hasDiagnosticCode(result.Diagnostics, tt.wantDiag) {
				t.Fatalf("finding=%v want=%v result=%+v", got, tt.wantExec, result)
			}
		})
	}
}

func TestBytecodeInvalidModernMethodSuppressesEarlierClassFlow(t *testing.T) {
	flow := modernStackMapFlowSpec(52, nil, nil).Methods[0]
	flow.Code = []classInstructionSpec{
		{Opcode: 0x2a}, {Opcode: 0x12, Constant: &constantValue{Kind: constantString, String: "cmd"}},
		{Opcode: 0xb9, Member: &fixtureRequestParameter}, {Opcode: 0x4d},
		{Opcode: 0xb8, Member: &fixtureRuntimeGet}, {Opcode: 0x2c},
		{Opcode: 0xb6, Member: &fixtureRuntimeExec}, {Opcode: 0x57}, {Opcode: 0xb1},
	}
	flow.Descriptor = "(Ljavax/servlet/http/HttpServletRequest;I)V"
	flow.MaxLocals = 3
	invalid := classMethodSpec{
		Access: 0x0009, Name: "zInvalid", Descriptor: "(I)V", MaxStack: 0, MaxLocals: 1,
		Code: []classInstructionSpec{
			{Opcode: 0x1a}, {Opcode: 0x99, Operands: []byte{0x00, 0x04}},
			{Opcode: 0xb1}, {Opcode: 0xb1},
		},
	}
	data, _ := classBytes(t, classSpec{Name: "fixture/ClassWideFrames", Major: 52, Methods: []classMethodSpec{flow, invalid}})
	result := AnalyzeArtifact("ClassWideFrames.class", data, DefaultOptions())
	if findingByRule(result.Findings, "javadisk:class-request-exec") != nil ||
		findingByRule(result.Findings, "javadisk:class-request-exec-structure") == nil ||
		!hasDiagnosticCode(result.Diagnostics, diagBytecodeUnsupported) {
		t.Fatalf("result=%+v", result)
	}
}

func TestBytecodeInvalidMethodCodeFormsRejectWholeClassSemanticFlow(t *testing.T) {
	requestFlow := []classInstructionSpec{
		{Opcode: 0x2a}, {Opcode: 0x12, Constant: &constantValue{Kind: constantString, String: "cmd"}},
		{Opcode: 0xb9, Member: &fixtureRequestParameter}, {Opcode: 0x4c},
		{Opcode: 0xb8, Member: &fixtureRuntimeGet}, {Opcode: 0x2b},
		{Opcode: 0xb6, Member: &fixtureRuntimeExec}, {Opcode: 0x57}, {Opcode: 0xb1},
	}
	for _, tt := range []struct {
		name   string
		method classMethodSpec
	}{
		{
			name: "abstract with Code",
			method: classMethodSpec{
				Access: 0x0401, Name: "run", Descriptor: "(Ljavax/servlet/http/HttpServletRequest;)V",
				MaxStack: 2, MaxLocals: 2, Code: requestFlow,
			},
		},
		{
			name: "native with Code",
			method: classMethodSpec{
				Access: 0x0101, Name: "run", Descriptor: "(Ljavax/servlet/http/HttpServletRequest;)V",
				MaxStack: 2, MaxLocals: 2, Code: requestFlow,
			},
		},
		{
			name:   "concrete without Code",
			method: classMethodSpec{Access: 0x0009, Name: "run", Descriptor: "()V", NoCode: true},
		},
		{
			name:   "abstract final without Code",
			method: classMethodSpec{Access: 0x0411, Name: "run", Descriptor: "()V", NoCode: true},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			data, _ := classBytes(t, classSpec{Name: "fixture/BadCodeForm", Major: 49, Methods: []classMethodSpec{tt.method}})
			result := AnalyzeArtifact(tt.name+".class", data, DefaultOptions())
			if len(result.Findings) != 0 || !hasDiagnosticCode(result.Diagnostics, diagClassMalformed) {
				t.Fatalf("invalid method Code form result=%+v", result)
			}
		})
	}
}

func TestBytecodeVerifierInvalidMethodSuppressesClassSemanticFlowInAnyOrder(t *testing.T) {
	flow := classMethodSpec{
		Name: "service", Descriptor: "(Ljavax/servlet/http/HttpServletRequest;Ljavax/servlet/http/HttpServletResponse;)V",
		MaxStack: 3, MaxLocals: 4, Code: []classInstructionSpec{
			{Opcode: 0x2b}, {Opcode: 0x12, Constant: &constantValue{Kind: constantString, String: "cmd"}},
			{Opcode: 0xb9, Member: &fixtureRequestParameter}, {Opcode: 0x4e},
			{Opcode: 0xb8, Member: &fixtureRuntimeGet}, {Opcode: 0x2d},
			{Opcode: 0xb6, Member: &fixtureRuntimeExec}, {Opcode: 0x57}, {Opcode: 0xb1},
		},
	}
	instanceField := memberReference{Owner: "fixture/ClassVerifierInvalid", Name: "value", Descriptor: "Ljava/lang/Object;"}
	invalidInvoke := memberReference{Owner: "java/lang/Runtime", Name: "exec", Descriptor: "(Ljava/lang/String;)Ljava/lang/Process;"}
	invalidShapes := []struct {
		name       string
		descriptor string
		maxStack   uint16
		code       []classInstructionSpec
	}{
		{"return", "()I", 0, []classInstructionSpec{{Opcode: 0xb1}}},
		{"operand", "()Ljava/lang/Object;", 1, []classInstructionSpec{{Opcode: 0x03}, {Opcode: 0xb0}}},
		{"field", "()V", 1, []classInstructionSpec{{Opcode: 0x01}, {Opcode: 0xb2, Field: &instanceField}, {Opcode: 0x57}, {Opcode: 0xb1}}},
		{"invoke", "()V", 1, []classInstructionSpec{{Opcode: 0x01}, {Opcode: 0xb8, Member: &invalidInvoke}, {Opcode: 0x57}, {Opcode: 0xb1}}},
	}
	for _, shape := range invalidShapes {
		for _, prefix := range []string{"aInvalid", "zInvalid"} {
			t.Run(shape.name+"/"+prefix, func(t *testing.T) {
				invalid := classMethodSpec{
					Access: 0x0009, Name: prefix + shape.name, Descriptor: shape.descriptor,
					MaxStack: shape.maxStack, MaxLocals: 1, Code: shape.code,
				}
				data, _ := classBytes(t, classSpec{
					Name: "fixture/ClassVerifierInvalid", Super: "javax/servlet/http/HttpServlet", Major: 49,
					Fields:  []classFieldSpec{{Name: "value", Descriptor: "Ljava/lang/Object;"}},
					Methods: []classMethodSpec{flow, invalid},
				})
				result := AnalyzeArtifact(shape.name+"-"+prefix+".class", data, DefaultOptions())
				if findingByRule(result.Findings, "javadisk:class-request-exec") != nil ||
					findingByRule(result.Findings, "javadisk:class-request-exec-structure") == nil ||
					!hasDiagnosticCode(result.Diagnostics, diagBytecodeUnsupported) {
					t.Fatalf("verifier-invalid method did not suppress class semantic flow: %+v", result)
				}
			})
		}
	}
}

func TestBytecodeInvalidCFGMethodSuppressesClassSemanticFlow(t *testing.T) {
	flow := classMethodSpec{
		Name: "service", Descriptor: "(Ljavax/servlet/http/HttpServletRequest;Ljavax/servlet/http/HttpServletResponse;)V",
		MaxStack: 3, MaxLocals: 4, Code: []classInstructionSpec{
			{Opcode: 0x2b}, {Opcode: 0x12, Constant: &constantValue{Kind: constantString, String: "cmd"}},
			{Opcode: 0xb9, Member: &fixtureRequestParameter}, {Opcode: 0x4e},
			{Opcode: 0xb8, Member: &fixtureRuntimeGet}, {Opcode: 0x2d},
			{Opcode: 0xb6, Member: &fixtureRuntimeExec}, {Opcode: 0x57}, {Opcode: 0xb1},
		},
	}
	invalid := classMethodSpec{
		Access: 0x0009, Name: "zInvalidCFG", MaxStack: 0, MaxLocals: 0,
		Code: []classInstructionSpec{{Opcode: 0xa7, Operands: []byte{0x00, 0x01}}, {Opcode: 0xb1}},
	}
	data, _ := classBytes(t, classSpec{
		Name: "fixture/ClassInvalidCFG", Super: "javax/servlet/http/HttpServlet", Major: 49,
		Methods: []classMethodSpec{flow, invalid},
	})
	result := AnalyzeArtifact("ClassInvalidCFG.class", data, DefaultOptions())
	if findingByRule(result.Findings, "javadisk:class-request-exec") != nil ||
		findingByRule(result.Findings, "javadisk:class-request-exec-structure") == nil ||
		!hasDiagnosticCode(result.Diagnostics, diagBytecodeUnsupported) {
		t.Fatalf("invalid CFG method did not suppress class semantic flow: %+v", result)
	}
}

func TestBytecodeValidUnsupportedAndBudgetedMethodsDoNotInvalidateClassFlow(t *testing.T) {
	flow := classMethodSpec{
		Name: "service", Descriptor: "(Ljavax/servlet/http/HttpServletRequest;Ljavax/servlet/http/HttpServletResponse;)V",
		MaxStack: 3, MaxLocals: 4, Code: []classInstructionSpec{
			{Opcode: 0x2b}, {Opcode: 0x12, Constant: &constantValue{Kind: constantString, String: "cmd"}},
			{Opcode: 0xb9, Member: &fixtureRequestParameter}, {Opcode: 0x4e},
			{Opcode: 0xb8, Member: &fixtureRuntimeGet}, {Opcode: 0x2d},
			{Opcode: 0xb6, Member: &fixtureRuntimeExec}, {Opcode: 0x57}, {Opcode: 0xb1},
		},
	}
	tests := []struct {
		name   string
		method classMethodSpec
		opts   Options
		diag   string
	}{
		{
			name: "legacy subroutine",
			method: classMethodSpec{
				Access: 0x0009, Name: "zLegacy", MaxStack: 1, MaxLocals: 1,
				Code: []classInstructionSpec{
					{Opcode: 0xa8, Operands: []byte{0x00, 0x04}}, {Opcode: 0xb1},
					{Opcode: 0x4b}, {Opcode: 0xa9, Operands: []byte{0x00}},
				},
			},
			opts: DefaultOptions(), diag: diagBytecodeUnsupported,
		},
		{
			name: "abstract budget",
			method: classMethodSpec{
				Access: 0x0009, Name: "zBudget", MaxStack: 0, MaxLocals: 4000,
				Code: []classInstructionSpec{{Opcode: 0xb1}},
			},
			opts: func() Options {
				opts := DefaultOptions()
				opts.Limits.MaxStateMerges = 5000
				return opts
			}(),
			diag: diagAnalysisBudget,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, _ := classBytes(t, classSpec{
				Name: "fixture/ClassValidFallback", Super: "javax/servlet/http/HttpServlet", Major: 49,
				Methods: []classMethodSpec{flow, tt.method},
			})
			result := AnalyzeArtifact(tt.name+".class", data, tt.opts)
			if findingByRule(result.Findings, "javadisk:class-request-exec") == nil ||
				!hasDiagnosticCode(result.Diagnostics, tt.diag) {
				t.Fatalf("valid fallback method invalidated class semantic flow: %+v", result)
			}
		})
	}
}
