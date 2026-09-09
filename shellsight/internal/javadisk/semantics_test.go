package javadisk

import (
	"strings"
	"testing"
)

const task10RequestDescriptor = "Ljavax/servlet/http/HttpServletRequest;"

func task10Artifact(t *testing.T, className, descriptor string, maxStack, maxLocals uint16, code []classInstructionSpec) Result {
	t.Helper()
	data, _ := classBytes(t, classSpec{
		Name: className, Super: "javax/servlet/http/HttpServlet", Major: 49,
		Methods: []classMethodSpec{{
			Access: 0x0009, Name: "service", Descriptor: descriptor,
			MaxStack: maxStack, MaxLocals: maxLocals, Code: code,
		}},
	})
	return AnalyzeArtifact(className+".class", data, DefaultOptions())
}

func task10RequestString() []classInstructionSpec {
	return []classInstructionSpec{
		{Opcode: 0x2a},
		{Opcode: 0x12, Constant: &constantValue{Kind: constantString, String: "payload"}},
		{Opcode: 0xb9, Member: &fixtureRequestParameter},
	}
}

func task10AssertFinding(t *testing.T, result Result, rule string, score int, sink string) {
	t.Helper()
	finding := findingByRule(result.Findings, rule)
	if finding == nil || finding.Score != score {
		t.Fatalf("rule %s score=%d result=%+v", rule, score, result)
	}
	for _, want := range []string{"class=fixture/", "method=service", sink} {
		if !strings.Contains(finding.Evidence, want) {
			t.Fatalf("rule %s evidence %q lacks %q", rule, finding.Evidence, want)
		}
	}
	if len(finding.Evidence) > 1024 || strings.Contains(finding.Evidence, strings.Repeat("decoded-payload", 80)) {
		t.Fatalf("rule %s retained unbounded evidence: %q", rule, finding.Evidence)
	}
}

func task10AssertNoFinding(t *testing.T, result Result, rule string) {
	t.Helper()
	if findingByRule(result.Findings, rule) != nil {
		t.Fatalf("rule %s unexpectedly present: %+v", rule, result)
	}
}

func task10PushInt(value int) classInstructionSpec {
	if value >= 0 && value <= 5 {
		return classInstructionSpec{Opcode: byte(0x03 + value)}
	}
	return classInstructionSpec{Opcode: 0x10, Operands: []byte{byte(value)}}
}

func task10StringArray(values ...string) []classInstructionSpec {
	code := []classInstructionSpec{
		task10PushInt(len(values)),
		{Opcode: 0xbd, ClassName: "java/lang/String"},
	}
	for index, value := range values {
		code = append(code,
			classInstructionSpec{Opcode: 0x59},
			task10PushInt(index),
			classInstructionSpec{Opcode: 0x12, Constant: &constantValue{Kind: constantString, String: value}},
			classInstructionSpec{Opcode: 0x53},
		)
	}
	return code
}

func task10PathComponentWrite(t *testing.T, className string, first string, rest []string, tainted bool) Result {
	t.Helper()
	pathsGet := memberReference{Owner: "java/nio/file/Paths", Name: "get", Descriptor: "(Ljava/lang/String;[Ljava/lang/String;)Ljava/nio/file/Path;"}
	code := []classInstructionSpec{{Opcode: 0x12, Constant: &constantValue{Kind: constantString, String: first}}}
	code = append(code, task10StringArray(rest...)...)
	code = append(code, classInstructionSpec{Opcode: 0xb8, Member: &pathsGet})
	if tainted {
		code = append(code, task10RequestString()...)
	} else {
		code = append(code, classInstructionSpec{Opcode: 0x12, Constant: &constantValue{Kind: constantString, String: "safe"}})
	}
	code = append(code,
		classInstructionSpec{Opcode: 0x03}, classInstructionSpec{Opcode: 0xbd, ClassName: "java/nio/file/OpenOption"},
		classInstructionSpec{Opcode: 0xb8, Member: &fixtureFilesWriteString}, classInstructionSpec{Opcode: 0x57}, classInstructionSpec{Opcode: 0xb1},
	)
	return task10Artifact(t, className, "("+task10RequestDescriptor+")V", 6, 1, code)
}

func task10StringConcatRecipeWrite(t *testing.T, recipe string) Result {
	t.Helper()
	pool := newConstantPoolBuilder()
	thisName := pool.utf8("fixture/StringConcatRecipe")
	thisClass := pool.u2Entry(cpClass, thisName)
	superName := pool.utf8("javax/servlet/http/HttpServlet")
	superClass := pool.u2Entry(cpClass, superName)
	codeName := pool.utf8("Code")
	bootstrapName := pool.utf8("BootstrapMethods")
	methodName := pool.utf8("service")
	methodDescriptor := pool.utf8("(" + task10RequestDescriptor + ")V")

	stringConcatBootstrap := memberReference{
		Owner: "java/lang/invoke/StringConcatFactory", Name: "makeConcatWithConstants",
		Descriptor: "(Ljava/lang/invoke/MethodHandles$Lookup;Ljava/lang/String;Ljava/lang/invoke/MethodType;Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/invoke/CallSite;",
	}
	bootstrapRef := classMemberIndex(pool, stringConcatBootstrap, false)
	bootstrapHandle := pool.methodHandle(6, bootstrapRef)
	recipeIndex := classConstantIndex(t, pool, constantValue{Kind: constantString, String: recipe})
	dynamicName := pool.utf8("makePath")
	dynamicDescriptor := pool.utf8("(Ljava/lang/String;)Ljava/lang/String;")
	dynamicNameAndType := pool.pairEntry(cpNameAndType, dynamicName, dynamicDescriptor)
	dynamicIndex := pool.pairEntry(cpInvokeDynamic, 0, dynamicNameAndType)

	shellIndex := classConstantIndex(t, pool, constantValue{Kind: constantString, String: "Shell.jsp"})
	payloadIndex := classConstantIndex(t, pool, constantValue{Kind: constantString, String: "payload"})
	stringClass := pool.u2Entry(cpClass, pool.utf8("java/lang/String"))
	openOptionClass := pool.u2Entry(cpClass, pool.utf8("java/nio/file/OpenOption"))
	pathsGet := classMemberIndex(pool, memberReference{
		Owner: "java/nio/file/Paths", Name: "get",
		Descriptor: "(Ljava/lang/String;[Ljava/lang/String;)Ljava/nio/file/Path;",
	}, false)
	filesWrite := classMemberIndex(pool, fixtureFilesWriteString, false)
	requestParameter := classMemberIndex(pool, fixtureRequestParameter, false)

	var bytecode []byte
	ldc := func(index uint16) {
		if index > 255 {
			t.Fatalf("ldc constant index %d exceeds u1", index)
		}
		bytecode = append(bytecode, 0x12, byte(index))
	}
	invokeStatic := func(index uint16) {
		bytecode = append(bytecode, 0xb8)
		bytecode = append(bytecode, u2Bytes(index)...)
	}
	ldc(shellIndex)
	bytecode = append(bytecode, 0xba)
	bytecode = append(bytecode, u2Bytes(dynamicIndex)...)
	bytecode = append(bytecode, 0, 0)
	bytecode = append(bytecode, 0x03)
	bytecode = append(bytecode, 0xbd)
	bytecode = append(bytecode, u2Bytes(stringClass)...)
	invokeStatic(pathsGet)
	bytecode = append(bytecode, 0x2a)
	ldc(payloadIndex)
	bytecode = append(bytecode, 0xb9)
	bytecode = append(bytecode, u2Bytes(requestParameter)...)
	bytecode = append(bytecode, structuralInvokeInterfaceCount(t, fixtureRequestParameter.Descriptor), 0)
	bytecode = append(bytecode, 0x03, 0xbd)
	bytecode = append(bytecode, u2Bytes(openOptionClass)...)
	invokeStatic(filesWrite)
	bytecode = append(bytecode, 0x57, 0xb1)

	code := append(u2Bytes(6), u2Bytes(1)...)
	code = append(code, u4Bytes(uint32(len(bytecode)))...)
	code = append(code, bytecode...)
	code = append(code, 0, 0, 0, 0)
	method := memberFixture(0x0009, methodName, methodDescriptor, attributeFixture(codeName, code))
	bootstrapPayload := append(u2Bytes(1), u2Bytes(bootstrapHandle)...)
	bootstrapPayload = append(bootstrapPayload, u2Bytes(1)...)
	bootstrapPayload = append(bootstrapPayload, u2Bytes(recipeIndex)...)
	bootstrapAttribute := attributeFixture(bootstrapName, bootstrapPayload)

	data := finishClass(0, 55, pool, thisClass, superClass, nil)
	data = data[:len(data)-6]
	data = append(data, 0, 0, 0, 1)
	data = append(data, method...)
	data = append(data, 0, 1)
	data = append(data, bootstrapAttribute...)
	return AnalyzeArtifact("StringConcatRecipe.class", data, DefaultOptions())
}

func task10LambdaMetafactoryClass(t *testing.T) []byte {
	t.Helper()
	pool := newConstantPoolBuilder()
	thisName := pool.utf8("fixture/LambdaFactory")
	thisClass := pool.u2Entry(cpClass, thisName)
	superName := pool.utf8("java/lang/Object")
	superClass := pool.u2Entry(cpClass, superName)
	codeName := pool.utf8("Code")
	bootstrapName := pool.utf8("BootstrapMethods")

	bootstrap := memberReference{
		Owner: "java/lang/invoke/LambdaMetafactory", Name: "metafactory",
		Descriptor: "(Ljava/lang/invoke/MethodHandles$Lookup;Ljava/lang/String;Ljava/lang/invoke/MethodType;Ljava/lang/invoke/MethodType;Ljava/lang/invoke/MethodHandle;Ljava/lang/invoke/MethodType;)Ljava/lang/invoke/CallSite;",
	}
	bootstrapHandle := pool.methodHandle(6, classMemberIndex(pool, bootstrap, false))
	samMethodType := pool.u2Entry(cpMethodType, pool.utf8("()V"))
	target := memberReference{Owner: "fixture/LambdaFactory", Name: "run", Descriptor: "(Ljava/lang/String;)V"}
	targetHandle := pool.methodHandle(6, classMemberIndex(pool, target, false))
	instantiatedMethodType := pool.u2Entry(cpMethodType, pool.utf8("()V"))
	dynamicNameAndType := pool.pairEntry(cpNameAndType, pool.utf8("run"), pool.utf8("(Ljava/lang/String;)Ljava/lang/Runnable;"))
	dynamicIndex := pool.pairEntry(cpInvokeDynamic, 0, dynamicNameAndType)
	requestParameter := classMemberIndex(pool, fixtureRequestParameter, false)
	payloadIndex := classConstantIndex(t, pool, constantValue{Kind: constantString, String: "payload"})

	lambdaCode := []byte{0x2a, 0x12, byte(payloadIndex), 0xb9}
	lambdaCode = append(lambdaCode, u2Bytes(requestParameter)...)
	lambdaCode = append(lambdaCode, structuralInvokeInterfaceCount(t, fixtureRequestParameter.Descriptor), 0, 0xba)
	lambdaCode = append(lambdaCode, u2Bytes(dynamicIndex)...)
	lambdaCode = append(lambdaCode, 0, 0, 0x4c, 0x03, 0x99, 0x00, 0x04, 0xb1, 0xb1)
	serviceCode := append(u2Bytes(2), u2Bytes(2)...)
	serviceCode = append(serviceCode, u4Bytes(uint32(len(lambdaCode)))...)
	serviceCode = append(serviceCode, lambdaCode...)
	serviceCode = append(serviceCode, 0, 0)
	serviceStackMap := attributeFixture(pool.utf8("StackMapTable"), stackMapTableFixture(t, pool, []stackMapFrameSpec{{
		Offset: 19, Locals: []string{"javax/servlet/http/HttpServletRequest", "java/lang/Runnable"},
	}}))
	serviceCode = append(serviceCode, 0, 1)
	serviceCode = append(serviceCode, serviceStackMap...)
	service := memberFixture(0x0009, pool.utf8("service"), pool.utf8("("+task10RequestDescriptor+")V"), attributeFixture(codeName, serviceCode))

	runCode := []byte{0xb1}
	runAttribute := append(u2Bytes(0), u2Bytes(1)...)
	runAttribute = append(runAttribute, u4Bytes(uint32(len(runCode)))...)
	runAttribute = append(runAttribute, runCode...)
	runAttribute = append(runAttribute, 0, 0, 0, 0)
	run := memberFixture(0x0009, pool.utf8("run"), pool.utf8("(Ljava/lang/String;)V"), attributeFixture(codeName, runAttribute))

	bootstrapPayload := append(u2Bytes(1), u2Bytes(bootstrapHandle)...)
	bootstrapPayload = append(bootstrapPayload, u2Bytes(3)...)
	bootstrapPayload = append(bootstrapPayload, u2Bytes(samMethodType)...)
	bootstrapPayload = append(bootstrapPayload, u2Bytes(targetHandle)...)
	bootstrapPayload = append(bootstrapPayload, u2Bytes(instantiatedMethodType)...)
	bootstrapAttribute := attributeFixture(bootstrapName, bootstrapPayload)

	data := finishClass(0, 55, pool, thisClass, superClass, nil)
	data = data[:len(data)-6]
	data = append(data, 0, 0, 0, 2)
	data = append(data, service...)
	data = append(data, run...)
	data = append(data, 0, 1)
	data = append(data, bootstrapAttribute...)
	return data
}

func task10LambdaMetafactoryArtifact(t *testing.T) Result {
	t.Helper()
	return AnalyzeArtifact("LambdaFactory.class", task10LambdaMetafactoryClass(t), DefaultOptions())
}

func task10LambdaMetafactoryAnalysis(t *testing.T) methodAnalysis {
	t.Helper()
	opts := DefaultOptions()
	cf, err := parseClass(task10LambdaMetafactoryClass(t), opts.Limits)
	if err != nil {
		t.Fatal(err)
	}
	for index := range cf.Methods {
		method := &cf.Methods[index]
		if method.Name != "service" {
			continue
		}
		instructions, err := decodeInstructions(method.Code.Bytes, 10_000)
		if err != nil {
			t.Fatal(err)
		}
		cfg, err := buildCFG(method.Code, instructions)
		if err != nil {
			t.Fatal(err)
		}
		return analyzeMethod(cf, method, cfg, opts, summarySet{})
	}
	t.Fatal("service method not found")
	return methodAnalysis{}
}

func task10InvokeDynamicEval(t *testing.T, className string, bootstrap memberReference, dynamicDescriptor string, args []constantValue) Result {
	t.Helper()
	pool := newConstantPoolBuilder()
	thisName := pool.utf8(className)
	thisClass := pool.u2Entry(cpClass, thisName)
	superName := pool.utf8("javax/servlet/http/HttpServlet")
	superClass := pool.u2Entry(cpClass, superName)
	codeName := pool.utf8("Code")
	bootstrapName := pool.utf8("BootstrapMethods")
	bootstrapHandle := pool.methodHandle(6, classMemberIndex(pool, bootstrap, false))
	dynamicNameAndType := pool.pairEntry(cpNameAndType, pool.utf8("make"), pool.utf8(dynamicDescriptor))
	dynamicIndex := pool.pairEntry(cpInvokeDynamic, 0, dynamicNameAndType)
	requestParameter := classMemberIndex(pool, fixtureRequestParameter, false)
	scriptEval := classMemberIndex(pool, fixtureScriptEval, false)
	payloadIndex := classConstantIndex(t, pool, constantValue{Kind: constantString, String: "payload"})

	bytecode := []byte{0x2b, 0x2a, 0x12, byte(payloadIndex), 0xb9}
	bytecode = append(bytecode, u2Bytes(requestParameter)...)
	bytecode = append(bytecode, structuralInvokeInterfaceCount(t, fixtureRequestParameter.Descriptor), 0, 0xba)
	bytecode = append(bytecode, u2Bytes(dynamicIndex)...)
	bytecode = append(bytecode, 0, 0, 0xb9)
	bytecode = append(bytecode, u2Bytes(scriptEval)...)
	bytecode = append(bytecode, structuralInvokeInterfaceCount(t, fixtureScriptEval.Descriptor), 0, 0x57, 0xb1)

	code := append(u2Bytes(4), u2Bytes(2)...)
	code = append(code, u4Bytes(uint32(len(bytecode)))...)
	code = append(code, bytecode...)
	code = append(code, 0, 0, 0, 0)
	method := memberFixture(0x0009, pool.utf8("service"), pool.utf8("("+task10RequestDescriptor+"Ljavax/script/ScriptEngine;)V"), attributeFixture(codeName, code))
	bootstrapPayload := append(u2Bytes(1), u2Bytes(bootstrapHandle)...)
	bootstrapPayload = append(bootstrapPayload, u2Bytes(uint16(len(args)))...)
	for _, arg := range args {
		bootstrapPayload = append(bootstrapPayload, u2Bytes(classConstantIndex(t, pool, arg))...)
	}
	bootstrapAttribute := attributeFixture(bootstrapName, bootstrapPayload)

	data := finishClass(0, 55, pool, thisClass, superClass, nil)
	data = data[:len(data)-6]
	data = append(data, 0, 0, 0, 1)
	data = append(data, method...)
	data = append(data, 0, 1)
	data = append(data, bootstrapAttribute...)
	return AnalyzeArtifact(className+".class", data, DefaultOptions())
}

func task10KindCorrectLambdaReaderEval(t *testing.T) Result {
	t.Helper()
	pool := newConstantPoolBuilder()
	className := "fixture/KindCorrectReaderLambda"
	thisName := pool.utf8(className)
	thisClass := pool.u2Entry(cpClass, thisName)
	superName := pool.utf8("javax/servlet/http/HttpServlet")
	superClass := pool.u2Entry(cpClass, superName)
	codeName := pool.utf8("Code")
	bootstrapName := pool.utf8("BootstrapMethods")
	bootstrap := memberReference{
		Owner: "java/lang/invoke/LambdaMetafactory", Name: "metafactory",
		Descriptor: "(Ljava/lang/invoke/MethodHandles$Lookup;Ljava/lang/String;Ljava/lang/invoke/MethodType;Ljava/lang/invoke/MethodType;Ljava/lang/invoke/MethodHandle;Ljava/lang/invoke/MethodType;)Ljava/lang/invoke/CallSite;",
	}
	bootstrapHandle := pool.methodHandle(6, classMemberIndex(pool, bootstrap, false))
	samMethodType := pool.u2Entry(cpMethodType, pool.utf8("()Ljava/io/Reader;"))
	target := memberReference{Owner: className, Name: "read", Descriptor: "(Ljava/lang/String;)Ljava/io/Reader;"}
	targetHandle := pool.methodHandle(6, classMemberIndex(pool, target, false))
	instantiatedMethodType := pool.u2Entry(cpMethodType, pool.utf8("()Ljava/io/Reader;"))
	dynamicNameAndType := pool.pairEntry(cpNameAndType, pool.utf8("read"), pool.utf8("(Ljava/lang/String;)Ljava/io/Reader;"))
	dynamicIndex := pool.pairEntry(cpInvokeDynamic, 0, dynamicNameAndType)
	requestParameter := classMemberIndex(pool, fixtureRequestParameter, false)
	scriptEvalReader := memberReference{Owner: "javax/script/ScriptEngine", Name: "eval", Descriptor: "(Ljava/io/Reader;)Ljava/lang/Object;", Interface: true}
	scriptEval := classMemberIndex(pool, scriptEvalReader, false)
	payloadIndex := classConstantIndex(t, pool, constantValue{Kind: constantString, String: "payload"})

	bytecode := []byte{0x2b, 0x2a, 0x12, byte(payloadIndex), 0xb9}
	bytecode = append(bytecode, u2Bytes(requestParameter)...)
	bytecode = append(bytecode, structuralInvokeInterfaceCount(t, fixtureRequestParameter.Descriptor), 0, 0xba)
	bytecode = append(bytecode, u2Bytes(dynamicIndex)...)
	bytecode = append(bytecode, 0, 0, 0xb9)
	bytecode = append(bytecode, u2Bytes(scriptEval)...)
	bytecode = append(bytecode, structuralInvokeInterfaceCount(t, scriptEvalReader.Descriptor), 0, 0x57, 0xb1)
	serviceCode := append(u2Bytes(4), u2Bytes(2)...)
	serviceCode = append(serviceCode, u4Bytes(uint32(len(bytecode)))...)
	serviceCode = append(serviceCode, bytecode...)
	serviceCode = append(serviceCode, 0, 0, 0, 0)
	service := memberFixture(0x0009, pool.utf8("service"), pool.utf8("("+task10RequestDescriptor+"Ljavax/script/ScriptEngine;)V"), attributeFixture(codeName, serviceCode))

	readCode := []byte{0x01, 0xb0}
	readAttribute := append(u2Bytes(1), u2Bytes(1)...)
	readAttribute = append(readAttribute, u4Bytes(uint32(len(readCode)))...)
	readAttribute = append(readAttribute, readCode...)
	readAttribute = append(readAttribute, 0, 0, 0, 0)
	read := memberFixture(0x0009, pool.utf8("read"), pool.utf8("(Ljava/lang/String;)Ljava/io/Reader;"), attributeFixture(codeName, readAttribute))

	bootstrapPayload := append(u2Bytes(1), u2Bytes(bootstrapHandle)...)
	bootstrapPayload = append(bootstrapPayload, u2Bytes(3)...)
	bootstrapPayload = append(bootstrapPayload, u2Bytes(samMethodType)...)
	bootstrapPayload = append(bootstrapPayload, u2Bytes(targetHandle)...)
	bootstrapPayload = append(bootstrapPayload, u2Bytes(instantiatedMethodType)...)
	bootstrapAttribute := attributeFixture(bootstrapName, bootstrapPayload)

	data := finishClass(0, 55, pool, thisClass, superClass, nil)
	data = data[:len(data)-6]
	data = append(data, 0, 0, 0, 2)
	data = append(data, service...)
	data = append(data, read...)
	data = append(data, 0, 1)
	data = append(data, bootstrapAttribute...)
	return AnalyzeArtifact("KindCorrectReaderLambda.class", data, DefaultOptions())
}

type task10RunnableLambdaFixture struct {
	ClassName        string
	ClassAccess      uint16
	BootstrapName    string
	Target           memberReference
	IncludeTarget    bool
	TargetAccess     uint16
	HookRegistration bool
	AltFlags         int64
	AltTrailingArgs  []constantValue
}

func task10RunnableLambdaClass(t *testing.T, fixture task10RunnableLambdaFixture) []byte {
	t.Helper()
	if fixture.ClassName == "" {
		fixture.ClassName = "fixture/RunnableLambda"
	}
	if fixture.ClassAccess == 0 {
		fixture.ClassAccess = 0x0021
	}
	if fixture.BootstrapName == "" {
		fixture.BootstrapName = "metafactory"
	}
	if fixture.Target.Owner == "" {
		fixture.Target = memberReference{Owner: fixture.ClassName, Name: "run", Descriptor: "(Ljava/lang/String;)V"}
	}
	if fixture.TargetAccess == 0 {
		fixture.TargetAccess = 0x0009
	}

	pool := newConstantPoolBuilder()
	thisName := pool.utf8(fixture.ClassName)
	thisClass := pool.u2Entry(cpClass, thisName)
	superName := pool.utf8("javax/servlet/http/HttpServlet")
	superClass := pool.u2Entry(cpClass, superName)
	codeName := pool.utf8("Code")
	bootstrapName := pool.utf8("BootstrapMethods")

	bootstrapDescriptor := "(Ljava/lang/invoke/MethodHandles$Lookup;Ljava/lang/String;Ljava/lang/invoke/MethodType;Ljava/lang/invoke/MethodType;Ljava/lang/invoke/MethodHandle;Ljava/lang/invoke/MethodType;)Ljava/lang/invoke/CallSite;"
	if fixture.BootstrapName == "altMetafactory" {
		bootstrapDescriptor = "(Ljava/lang/invoke/MethodHandles$Lookup;Ljava/lang/String;Ljava/lang/invoke/MethodType;[Ljava/lang/Object;)Ljava/lang/invoke/CallSite;"
	}
	bootstrap := memberReference{Owner: "java/lang/invoke/LambdaMetafactory", Name: fixture.BootstrapName, Descriptor: bootstrapDescriptor}
	bootstrapHandle := pool.methodHandle(6, classMemberIndex(pool, bootstrap, false))
	samMethodType := pool.u2Entry(cpMethodType, pool.utf8("()V"))
	targetHandle := pool.methodHandle(6, classMemberIndex(pool, fixture.Target, false))
	instantiatedMethodType := pool.u2Entry(cpMethodType, pool.utf8("()V"))
	dynamicNameAndType := pool.pairEntry(cpNameAndType, pool.utf8("run"), pool.utf8("(Ljava/lang/String;)Ljava/lang/Runnable;"))
	dynamicIndex := pool.pairEntry(cpInvokeDynamic, 0, dynamicNameAndType)
	requestParameter := classMemberIndex(pool, fixtureRequestParameter, false)
	payloadIndex := classConstantIndex(t, pool, constantValue{Kind: constantString, String: "payload"})

	var serviceBytecode []byte
	maxStack, maxLocals := uint16(2), uint16(2)
	serviceDescriptor := "(" + task10RequestDescriptor + ")V"
	if fixture.HookRegistration {
		registerHandler := memberReference{
			Owner: "org/springframework/web/servlet/handler/AbstractUrlHandlerMapping", Name: "registerHandler",
			Descriptor: "(Ljava/lang/String;Ljava/lang/Object;)V",
		}
		registerHandlerIndex := classMemberIndex(pool, registerHandler, false)
		pathIndex := classConstantIndex(t, pool, constantValue{Kind: constantString, String: "/shell"})
		serviceBytecode = []byte{0x2b, 0x12, byte(pathIndex), 0x2a, 0x12, byte(payloadIndex), 0xb9}
		serviceBytecode = append(serviceBytecode, u2Bytes(requestParameter)...)
		serviceBytecode = append(serviceBytecode, structuralInvokeInterfaceCount(t, fixtureRequestParameter.Descriptor), 0, 0xba)
		serviceBytecode = append(serviceBytecode, u2Bytes(dynamicIndex)...)
		serviceBytecode = append(serviceBytecode, 0, 0, 0xb6)
		serviceBytecode = append(serviceBytecode, u2Bytes(registerHandlerIndex)...)
		serviceBytecode = append(serviceBytecode, 0xb1)
		maxStack, maxLocals = 4, 2
		serviceDescriptor = "(" + task10RequestDescriptor + "Lorg/springframework/web/servlet/handler/AbstractUrlHandlerMapping;)V"
	} else {
		serviceBytecode = []byte{0x2a, 0x12, byte(payloadIndex), 0xb9}
		serviceBytecode = append(serviceBytecode, u2Bytes(requestParameter)...)
		serviceBytecode = append(serviceBytecode, structuralInvokeInterfaceCount(t, fixtureRequestParameter.Descriptor), 0, 0xba)
		serviceBytecode = append(serviceBytecode, u2Bytes(dynamicIndex)...)
		serviceBytecode = append(serviceBytecode, 0, 0, 0x4c, 0x03, 0x99, 0x00, 0x04, 0xb1, 0xb1)
	}
	serviceCode := append(u2Bytes(maxStack), u2Bytes(maxLocals)...)
	serviceCode = append(serviceCode, u4Bytes(uint32(len(serviceBytecode)))...)
	serviceCode = append(serviceCode, serviceBytecode...)
	serviceCode = append(serviceCode, 0, 0)
	if !fixture.HookRegistration {
		serviceStackMap := attributeFixture(pool.utf8("StackMapTable"), stackMapTableFixture(t, pool, []stackMapFrameSpec{{
			Offset: 19, Locals: []string{"javax/servlet/http/HttpServletRequest", "java/lang/Runnable"},
		}}))
		serviceCode = append(serviceCode, 0, 1)
		serviceCode = append(serviceCode, serviceStackMap...)
	} else {
		serviceCode = append(serviceCode, 0, 0)
	}
	service := memberFixture(0x0009, pool.utf8("service"), pool.utf8(serviceDescriptor), attributeFixture(codeName, serviceCode))

	methods := [][]byte{service}
	if fixture.IncludeTarget {
		targetCode := []byte{0xb1}
		targetLocals := uint16(1)
		if fixture.TargetAccess&0x0008 == 0 {
			targetLocals = 2
		}
		targetAttribute := append(u2Bytes(0), u2Bytes(targetLocals)...)
		targetAttribute = append(targetAttribute, u4Bytes(uint32(len(targetCode)))...)
		targetAttribute = append(targetAttribute, targetCode...)
		targetAttribute = append(targetAttribute, 0, 0, 0, 0)
		methods = append(methods, memberFixture(fixture.TargetAccess, pool.utf8(fixture.Target.Name), pool.utf8(fixture.Target.Descriptor), attributeFixture(codeName, targetAttribute)))
	}

	bootstrapPayload := append(u2Bytes(1), u2Bytes(bootstrapHandle)...)
	bootstrapArgs := []uint16{samMethodType, targetHandle, instantiatedMethodType}
	if fixture.BootstrapName == "altMetafactory" {
		bootstrapArgs = append(bootstrapArgs, classConstantIndex(t, pool, constantValue{Kind: constantInteger, Integer: fixture.AltFlags}))
		for _, arg := range fixture.AltTrailingArgs {
			bootstrapArgs = append(bootstrapArgs, classConstantIndex(t, pool, arg))
		}
	}
	bootstrapPayload = append(bootstrapPayload, u2Bytes(uint16(len(bootstrapArgs)))...)
	for _, arg := range bootstrapArgs {
		bootstrapPayload = append(bootstrapPayload, u2Bytes(arg)...)
	}
	bootstrapAttribute := attributeFixture(bootstrapName, bootstrapPayload)

	data := finishClass(0, 55, pool, thisClass, superClass, nil)
	accessOffset := 10
	for _, entry := range pool.entries {
		accessOffset += len(entry)
	}
	data[accessOffset] = byte(fixture.ClassAccess >> 8)
	data[accessOffset+1] = byte(fixture.ClassAccess)
	data = data[:len(data)-6]
	data = append(data, 0, 0)
	data = append(data, u2Bytes(uint16(len(methods)))...)
	for _, method := range methods {
		data = append(data, method...)
	}
	data = append(data, 0, 1)
	data = append(data, bootstrapAttribute...)
	return data
}

func task10AnalyzeServiceData(t *testing.T, data []byte) methodAnalysis {
	t.Helper()
	opts := DefaultOptions()
	cf, err := parseClass(data, opts.Limits)
	if err != nil {
		t.Fatal(err)
	}
	for index := range cf.Methods {
		method := &cf.Methods[index]
		if method.Name != "service" {
			continue
		}
		instructions, err := decodeInstructions(method.Code.Bytes, 10_000)
		if err != nil {
			t.Fatal(err)
		}
		cfg, err := buildCFG(method.Code, instructions)
		if err != nil {
			t.Fatal(err)
		}
		return analyzeMethod(cf, method, cfg, opts, summarySet{})
	}
	t.Fatal("service method not found")
	return methodAnalysis{}
}

func task10AssertRunnableLambdaMaterialized(t *testing.T, analysis methodAnalysis, target memberReference) {
	t.Helper()
	for _, frame := range analysis.Frames {
		for _, object := range frame.Heap {
			for _, lambda := range object.Lambda {
				if lambda.Target.Owner == target.Owner && lambda.Target.Name == target.Name &&
					lambda.Target.Descriptor == target.Descriptor && len(lambda.Captured) == 1 &&
					isExecutionTainted(lambda.Captured[0].Taint) {
					return
				}
			}
		}
	}
	t.Fatalf("lambda callable with captured request taint not materialized: %+v", analysis)
}

func task10AssertNoRunnableLambdaMaterialized(t *testing.T, analysis methodAnalysis, target memberReference) {
	t.Helper()
	for _, frame := range analysis.Frames {
		for _, object := range frame.Heap {
			for _, lambda := range object.Lambda {
				if lambda.Target.Owner == target.Owner && lambda.Target.Name == target.Name &&
					lambda.Target.Descriptor == target.Descriptor {
					t.Fatalf("unexpected lambda callable materialized: %+v", analysis)
				}
			}
		}
	}
}

func task10UnknownReceiverAndValidScriptClass(t *testing.T) Result {
	t.Helper()
	stringBytes := memberReference{Owner: "java/lang/String", Name: "getBytes", Descriptor: "(Ljava/lang/String;)[B"}
	badCode := []classInstructionSpec{{Opcode: 0x2b}}
	badCode = append(badCode, task10RequestString()...)
	badCode = append(badCode,
		classInstructionSpec{Opcode: 0x12, Constant: &constantValue{Kind: constantString, String: "UTF-8"}},
		classInstructionSpec{Opcode: 0xb6, Member: &stringBytes},
		classInstructionSpec{Opcode: 0xb6, Member: &fixtureLookupDefineClass},
		classInstructionSpec{Opcode: 0x57}, classInstructionSpec{Opcode: 0xb1},
	)
	goodCode := []classInstructionSpec{{Opcode: 0x2b}}
	goodCode = append(goodCode, task10RequestString()...)
	goodCode = append(goodCode,
		classInstructionSpec{Opcode: 0xb9, Member: &fixtureScriptEval},
		classInstructionSpec{Opcode: 0x57}, classInstructionSpec{Opcode: 0xb1},
	)
	data, _ := classBytes(t, classSpec{
		Name: "fixture/UnknownReceiverKeepsValidFinding", Super: "javax/servlet/http/HttpServlet", Major: 49,
		Methods: []classMethodSpec{
			{Access: 0x0009, Name: "bad", Descriptor: "(" + task10RequestDescriptor + "Lattacker/Foo;)V", MaxStack: 4, MaxLocals: 2, Code: badCode},
			{Access: 0x0009, Name: "service", Descriptor: "(" + task10RequestDescriptor + "Ljavax/script/ScriptEngine;)V", MaxStack: 3, MaxLocals: 2, Code: goodCode},
		},
	})
	return AnalyzeArtifact("UnknownReceiverKeepsValidFinding.class", data, DefaultOptions())
}

func TestTransformStringFamiliesPreserveRequestTaint(t *testing.T) {
	stringBuilderAppend := memberReference{Owner: "java/lang/StringBuilder", Name: "append", Descriptor: "(Ljava/lang/String;)Ljava/lang/StringBuilder;"}
	stringBuilderString := memberReference{Owner: "java/lang/StringBuilder", Name: "toString", Descriptor: "()Ljava/lang/String;"}
	stringBufferAppend := memberReference{Owner: "java/lang/StringBuffer", Name: "append", Descriptor: "(Ljava/lang/String;)Ljava/lang/StringBuffer;"}
	stringBufferString := memberReference{Owner: "java/lang/StringBuffer", Name: "toString", Descriptor: "()Ljava/lang/String;"}
	tests := []struct {
		name       string
		descriptor string
		code       []classInstructionSpec
	}{
		{
			name: "String.concat", descriptor: "(" + task10RequestDescriptor + "Ljavax/script/ScriptEngine;)V",
			code: append([]classInstructionSpec{{Opcode: 0x2b}}, append(task10RequestString(),
				classInstructionSpec{Opcode: 0x12, Constant: &constantValue{Kind: constantString, String: " suffix"}},
				classInstructionSpec{Opcode: 0xb6, Member: &fixtureStringConcat}, classInstructionSpec{Opcode: 0xb9, Member: &fixtureScriptEval},
				classInstructionSpec{Opcode: 0x57}, classInstructionSpec{Opcode: 0xb1})...),
		},
		{
			name: "String.valueOf", descriptor: "(" + task10RequestDescriptor + "Ljavax/script/ScriptEngine;)V",
			code: append([]classInstructionSpec{{Opcode: 0x2b}}, append(task10RequestString(),
				classInstructionSpec{Opcode: 0xb8, Member: &fixtureStringValueOf}, classInstructionSpec{Opcode: 0xb9, Member: &fixtureScriptEval},
				classInstructionSpec{Opcode: 0x57}, classInstructionSpec{Opcode: 0xb1})...),
		},
		{
			name: "URL decode", descriptor: "(" + task10RequestDescriptor + "Ljavax/script/ScriptEngine;)V",
			code: append([]classInstructionSpec{{Opcode: 0x2b}}, append(task10RequestString(),
				classInstructionSpec{Opcode: 0x12, Constant: &constantValue{Kind: constantString, String: "UTF-8"}},
				classInstructionSpec{Opcode: 0xb8, Member: &fixtureURLDecode}, classInstructionSpec{Opcode: 0xb9, Member: &fixtureScriptEval},
				classInstructionSpec{Opcode: 0x57}, classInstructionSpec{Opcode: 0xb1})...),
		},
		{
			name: "StringBuilder", descriptor: "(" + task10RequestDescriptor + "Ljavax/script/ScriptEngine;Ljava/lang/StringBuilder;)V",
			code: append([]classInstructionSpec{{Opcode: 0x2b}, {Opcode: 0x2c}}, append(task10RequestString(),
				classInstructionSpec{Opcode: 0xb6, Member: &stringBuilderAppend}, classInstructionSpec{Opcode: 0xb6, Member: &stringBuilderString},
				classInstructionSpec{Opcode: 0xb9, Member: &fixtureScriptEval}, classInstructionSpec{Opcode: 0x57}, classInstructionSpec{Opcode: 0xb1})...),
		},
		{
			name: "StringBuffer", descriptor: "(" + task10RequestDescriptor + "Ljavax/script/ScriptEngine;Ljava/lang/StringBuffer;)V",
			code: append([]classInstructionSpec{{Opcode: 0x2b}, {Opcode: 0x2c}}, append(task10RequestString(),
				classInstructionSpec{Opcode: 0xb6, Member: &stringBufferAppend}, classInstructionSpec{Opcode: 0xb6, Member: &stringBufferString},
				classInstructionSpec{Opcode: 0xb9, Member: &fixtureScriptEval}, classInstructionSpec{Opcode: 0x57}, classInstructionSpec{Opcode: 0xb1})...),
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			classSuffix := strings.NewReplacer(" ", "", ".", "").Replace(test.name)
			result := task10Artifact(t, "fixture/Transform"+classSuffix, test.descriptor, 5, 3, test.code)
			task10AssertFinding(t, result, "javadisk:class-script-eval", 85, "eval")
		})
	}
}

func TestTransformDecodeCharsetAndXORFamiliesPreserveRequestTaint(t *testing.T) {
	stringBytes := memberReference{Owner: "java/lang/String", Name: "getBytes", Descriptor: "(Ljava/lang/String;)[B"}
	decodeCases := []struct {
		name       string
		descriptor string
		prefix     []classInstructionSpec
		transform  []classInstructionSpec
	}{
		{"Base64", "(" + task10RequestDescriptor + "Ljava/lang/invoke/MethodHandles$Lookup;Ljava/util/Base64$Decoder;)V", []classInstructionSpec{{Opcode: 0x2b}, {Opcode: 0x2c}}, []classInstructionSpec{{Opcode: 0xb6, Member: &fixtureBase64Decode}}},
		{"hex", "(" + task10RequestDescriptor + "Ljava/lang/invoke/MethodHandles$Lookup;)V", []classInstructionSpec{{Opcode: 0x2b}}, []classInstructionSpec{{Opcode: 0xb8, Member: &fixtureHexDecode}}},
		{"charset bytes", "(" + task10RequestDescriptor + "Ljava/lang/invoke/MethodHandles$Lookup;)V", []classInstructionSpec{{Opcode: 0x2b}}, []classInstructionSpec{{Opcode: 0x12, Constant: &constantValue{Kind: constantString, String: "UTF-8"}}, {Opcode: 0xb6, Member: &stringBytes}}},
	}
	for _, test := range decodeCases {
		t.Run(test.name, func(t *testing.T) {
			code := append([]classInstructionSpec{}, test.prefix...)
			code = append(code, task10RequestString()...)
			code = append(code, test.transform...)
			code = append(code, classInstructionSpec{Opcode: 0xb6, Member: &fixtureLookupDefineClass}, classInstructionSpec{Opcode: 0x57}, classInstructionSpec{Opcode: 0xb1})
			result := task10Artifact(t, "fixture/Transform"+strings.ReplaceAll(test.name, " ", ""), test.descriptor, 5, 3, code)
			task10AssertFinding(t, result, "javadisk:class-dynamic-classload", 85, "defineClass")
		})
	}

	// Array loads/stores and integer XOR must preserve the request provenance on class bytes.
	code := append(task10RequestString(), classInstructionSpec{Opcode: 0x12, Constant: &constantValue{Kind: constantString, String: "UTF-8"}}, classInstructionSpec{Opcode: 0xb6, Member: &stringBytes}, classInstructionSpec{Opcode: 0x4d})
	code = append(code,
		classInstructionSpec{Opcode: 0x2c}, classInstructionSpec{Opcode: 0x03}, classInstructionSpec{Opcode: 0x2c}, classInstructionSpec{Opcode: 0x03},
		classInstructionSpec{Opcode: 0x33}, classInstructionSpec{Opcode: 0x10, Operands: []byte{0x5a}}, classInstructionSpec{Opcode: 0x82}, classInstructionSpec{Opcode: 0x54},
		classInstructionSpec{Opcode: 0x2b}, classInstructionSpec{Opcode: 0x2c}, classInstructionSpec{Opcode: 0xb6, Member: &fixtureLookupDefineClass},
		classInstructionSpec{Opcode: 0x57}, classInstructionSpec{Opcode: 0xb1},
	)
	result := task10Artifact(t, "fixture/TransformXOR", "("+task10RequestDescriptor+"Ljava/lang/invoke/MethodHandles$Lookup;)V", 6, 3, code)
	task10AssertFinding(t, result, "javadisk:class-dynamic-classload", 85, "defineClass")
}

func TestTransformCompressionStreamsPreserveRequestTaint(t *testing.T) {
	stringBytes := memberReference{Owner: "java/lang/String", Name: "getBytes", Descriptor: "(Ljava/lang/String;)[B"}
	byteArrayInputInit := memberReference{Owner: "java/io/ByteArrayInputStream", Name: "<init>", Descriptor: "([B)V"}
	gzipInputInit := memberReference{Owner: "java/util/zip/GZIPInputStream", Name: "<init>", Descriptor: "(Ljava/io/InputStream;)V"}
	gzipReadAll := memberReference{Owner: "java/util/zip/GZIPInputStream", Name: "readAllBytes", Descriptor: "()[B"}

	code := []classInstructionSpec{{Opcode: 0x2b}, {Opcode: 0xbb, ClassName: "java/io/ByteArrayInputStream"}, {Opcode: 0x59}}
	code = append(code, task10RequestString()...)
	code = append(code,
		classInstructionSpec{Opcode: 0x12, Constant: &constantValue{Kind: constantString, String: "UTF-8"}},
		classInstructionSpec{Opcode: 0xb6, Member: &stringBytes},
		classInstructionSpec{Opcode: 0xb7, Member: &byteArrayInputInit},
		classInstructionSpec{Opcode: 0x4d},
		classInstructionSpec{Opcode: 0xbb, ClassName: "java/util/zip/GZIPInputStream"},
		classInstructionSpec{Opcode: 0x59},
		classInstructionSpec{Opcode: 0x2c},
		classInstructionSpec{Opcode: 0xb7, Member: &gzipInputInit},
		classInstructionSpec{Opcode: 0xb6, Member: &gzipReadAll},
		classInstructionSpec{Opcode: 0xb6, Member: &fixtureLookupDefineClass},
		classInstructionSpec{Opcode: 0x57},
		classInstructionSpec{Opcode: 0xb1},
	)
	result := task10Artifact(t, "fixture/TransformCompression", "("+task10RequestDescriptor+"Ljava/lang/invoke/MethodHandles$Lookup;)V", 5, 3, code)
	task10AssertFinding(t, result, "javadisk:class-dynamic-classload", 85, "defineClass")
}

func TestTransformStreamsAndCollectionsPreserveRequestTaint(t *testing.T) {
	listAdd := memberReference{Owner: "java/util/List", Name: "add", Descriptor: "(Ljava/lang/Object;)Z", Interface: true}
	listGet := memberReference{Owner: "java/util/List", Name: "get", Descriptor: "(I)Ljava/lang/Object;", Interface: true}
	mapPut := memberReference{Owner: "java/util/Map", Name: "put", Descriptor: "(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;", Interface: true}
	mapGet := memberReference{Owner: "java/util/Map", Name: "get", Descriptor: "(Ljava/lang/Object;)Ljava/lang/Object;", Interface: true}
	writerWrite := memberReference{Owner: "java/io/StringWriter", Name: "write", Descriptor: "(Ljava/lang/String;)V"}
	writerString := memberReference{Owner: "java/io/StringWriter", Name: "toString", Descriptor: "()Ljava/lang/String;"}
	tests := []struct {
		name       string
		descriptor string
		code       []classInstructionSpec
	}{
		{"List", "(" + task10RequestDescriptor + "Ljavax/script/ScriptEngine;Ljava/util/List;)V", append([]classInstructionSpec{{Opcode: 0x2c}}, append(task10RequestString(),
			classInstructionSpec{Opcode: 0xb9, Member: &listAdd}, classInstructionSpec{Opcode: 0x57}, classInstructionSpec{Opcode: 0x2b}, classInstructionSpec{Opcode: 0x2c},
			classInstructionSpec{Opcode: 0x03}, classInstructionSpec{Opcode: 0xb9, Member: &listGet}, classInstructionSpec{Opcode: 0xc0, ClassName: "java/lang/String"},
			classInstructionSpec{Opcode: 0xb9, Member: &fixtureScriptEval}, classInstructionSpec{Opcode: 0x57}, classInstructionSpec{Opcode: 0xb1})...)},
		{"Map", "(" + task10RequestDescriptor + "Ljavax/script/ScriptEngine;Ljava/util/Map;)V", append([]classInstructionSpec{{Opcode: 0x2c}, {Opcode: 0x12, Constant: &constantValue{Kind: constantString, String: "k"}}}, append(task10RequestString(),
			classInstructionSpec{Opcode: 0xb9, Member: &mapPut}, classInstructionSpec{Opcode: 0x57}, classInstructionSpec{Opcode: 0x2b}, classInstructionSpec{Opcode: 0x2c},
			classInstructionSpec{Opcode: 0x12, Constant: &constantValue{Kind: constantString, String: "k"}}, classInstructionSpec{Opcode: 0xb9, Member: &mapGet},
			classInstructionSpec{Opcode: 0xc0, ClassName: "java/lang/String"}, classInstructionSpec{Opcode: 0xb9, Member: &fixtureScriptEval},
			classInstructionSpec{Opcode: 0x57}, classInstructionSpec{Opcode: 0xb1})...)},
		{"writer", "(" + task10RequestDescriptor + "Ljavax/script/ScriptEngine;Ljava/io/StringWriter;)V", append([]classInstructionSpec{{Opcode: 0x2c}}, append(task10RequestString(),
			classInstructionSpec{Opcode: 0xb6, Member: &writerWrite}, classInstructionSpec{Opcode: 0x2b}, classInstructionSpec{Opcode: 0x2c},
			classInstructionSpec{Opcode: 0xb6, Member: &writerString}, classInstructionSpec{Opcode: 0xb9, Member: &fixtureScriptEval},
			classInstructionSpec{Opcode: 0x57}, classInstructionSpec{Opcode: 0xb1})...)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := task10Artifact(t, "fixture/Transform"+test.name, test.descriptor, 6, 3, test.code)
			task10AssertFinding(t, result, "javadisk:class-script-eval", 85, "eval")
		})
	}
}

func TestDynamicClassloadRequiresTaintedClassBytes(t *testing.T) {
	code := []classInstructionSpec{{Opcode: 0x2b}, {Opcode: 0x2c}}
	code = append(code, task10RequestString()...)
	code = append(code, classInstructionSpec{Opcode: 0xb6, Member: &fixtureBase64Decode}, classInstructionSpec{Opcode: 0xb6, Member: &fixtureLookupDefineClass}, classInstructionSpec{Opcode: 0x57}, classInstructionSpec{Opcode: 0xb1})
	result := task10Artifact(t, "fixture/DynamicClassload", "("+task10RequestDescriptor+"Ljava/lang/invoke/MethodHandles$Lookup;Ljava/util/Base64$Decoder;)V", 4, 3, code)
	task10AssertFinding(t, result, "javadisk:class-dynamic-classload", 85, "defineClass")

	benign := task10Artifact(t, "fixture/BenignClassload", "(Ljava/lang/invoke/MethodHandles$Lookup;[B)V", 2, 2, []classInstructionSpec{
		{Opcode: 0x2a}, {Opcode: 0x2b}, {Opcode: 0xb6, Member: &fixtureLookupDefineClass}, {Opcode: 0x57}, {Opcode: 0xb1},
	})
	if findingByRule(benign.Findings, "javadisk:class-dynamic-classload") != nil {
		t.Fatalf("untainted class bytes promoted: %+v", benign)
	}
}

func TestScriptEvalRequiresTaintedScript(t *testing.T) {
	code := []classInstructionSpec{{Opcode: 0x2b}}
	code = append(code, task10RequestString()...)
	code = append(code, classInstructionSpec{Opcode: 0xb9, Member: &fixtureScriptEval}, classInstructionSpec{Opcode: 0x57}, classInstructionSpec{Opcode: 0xb1})
	result := task10Artifact(t, "fixture/ScriptEval", "("+task10RequestDescriptor+"Ljavax/script/ScriptEngine;)V", 3, 2, code)
	task10AssertFinding(t, result, "javadisk:class-script-eval", 85, "eval")

	benign := task10Artifact(t, "fixture/BenignScript", "(Ljavax/script/ScriptEngine;)V", 2, 1, []classInstructionSpec{
		{Opcode: 0x2a}, {Opcode: 0x12, Constant: &constantValue{Kind: constantString, String: "1 + 1"}},
		{Opcode: 0xb9, Member: &fixtureScriptEval}, {Opcode: 0x57}, {Opcode: 0xb1},
	})
	if findingByRule(benign.Findings, "javadisk:class-script-eval") != nil {
		t.Fatalf("constant script promoted: %+v", benign)
	}
}

func TestExecutableWriteRequiresTaintedContentAndDangerousConstantPath(t *testing.T) {
	pathsGet := memberReference{Owner: "java/nio/file/Paths", Name: "get", Descriptor: "(Ljava/lang/String;[Ljava/lang/String;)Ljava/nio/file/Path;"}
	build := func(path string, tainted bool) Result {
		code := []classInstructionSpec{
			{Opcode: 0x12, Constant: &constantValue{Kind: constantString, String: path}}, {Opcode: 0x03}, {Opcode: 0xbd, ClassName: "java/lang/String"},
			{Opcode: 0xb8, Member: &pathsGet},
		}
		if tainted {
			code = append(code, task10RequestString()...)
		} else {
			code = append(code, classInstructionSpec{Opcode: 0x12, Constant: &constantValue{Kind: constantString, String: "safe"}})
		}
		code = append(code, classInstructionSpec{Opcode: 0x03}, classInstructionSpec{Opcode: 0xbd, ClassName: "java/nio/file/OpenOption"},
			classInstructionSpec{Opcode: 0xb8, Member: &fixtureFilesWriteString}, classInstructionSpec{Opcode: 0x57}, classInstructionSpec{Opcode: 0xb1})
		return task10Artifact(t, "fixture/ExecutableWrite", "("+task10RequestDescriptor+")V", 5, 1, code)
	}
	task10AssertFinding(t, build("web/WEB-INF/classes/Shell.class", true), "javadisk:class-executable-write", 85, "Files.writeString")
	for _, result := range []Result{build("web/readme.txt", true), build("web/Shell.jsp", false)} {
		if findingByRule(result.Findings, "javadisk:class-executable-write") != nil {
			t.Fatalf("unsafe write near-neighbor promoted: %+v", result)
		}
	}
}

func TestReflectionExecRequiresTaintedInvocationArguments(t *testing.T) {
	code := []classInstructionSpec{{Opcode: 0x2b}, {Opcode: 0x01}, {Opcode: 0x04}, {Opcode: 0xbd, ClassName: "java/lang/Object"}, {Opcode: 0x59}, {Opcode: 0x03}}
	code = append(code, task10RequestString()...)
	code = append(code, classInstructionSpec{Opcode: 0x53}, classInstructionSpec{Opcode: 0xb6, Member: &fixtureMethodInvoke}, classInstructionSpec{Opcode: 0x57}, classInstructionSpec{Opcode: 0xb1})
	result := task10Artifact(t, "fixture/ReflectionExec", "("+task10RequestDescriptor+"Ljava/lang/reflect/Method;)V", 7, 2, code)
	task10AssertFinding(t, result, "javadisk:class-reflection-exec", 85, "Method.invoke")
}

func TestDeserializationJNDIRemoteFlowAndConstantFallbackScores(t *testing.T) {
	taintedCode := []classInstructionSpec{{Opcode: 0x2b}}
	taintedCode = append(taintedCode, task10RequestString()...)
	taintedCode = append(taintedCode, classInstructionSpec{Opcode: 0xb9, Member: &fixtureJNDILookup}, classInstructionSpec{Opcode: 0x57}, classInstructionSpec{Opcode: 0xb1})
	tainted := task10Artifact(t, "fixture/TaintedJNDI", "("+task10RequestDescriptor+"Ljavax/naming/Context;)V", 3, 2, taintedCode)
	task10AssertFinding(t, tainted, "javadisk:class-deserialization-jndi", 75, "lookup")

	constant := task10Artifact(t, "fixture/ConstantJNDI", "(Ljavax/naming/Context;)V", 2, 1, []classInstructionSpec{
		{Opcode: 0x2a}, {Opcode: 0x12, Constant: &constantValue{Kind: constantString, String: "ldap://127.0.0.1/Object"}},
		{Opcode: 0xb9, Member: &fixtureJNDILookup}, {Opcode: 0x57}, {Opcode: 0xb1},
	})
	task10AssertFinding(t, constant, "javadisk:class-deserialization-jndi", 60, "lookup")

	local := task10Artifact(t, "fixture/LocalJNDI", "(Ljavax/naming/Context;)V", 2, 1, []classInstructionSpec{
		{Opcode: 0x2a}, {Opcode: 0x12, Constant: &constantValue{Kind: constantString, String: "java:comp/env/jdbc/main"}},
		{Opcode: 0xb9, Member: &fixtureJNDILookup}, {Opcode: 0x57}, {Opcode: 0xb1},
	})
	if findingByRule(local.Findings, "javadisk:class-deserialization-jndi") != nil {
		t.Fatalf("local JNDI lookup promoted: %+v", local)
	}
}

func TestHookRegistrationScoresDynamicAndResolvedConstantMutation(t *testing.T) {
	dynamicCode := []classInstructionSpec{{Opcode: 0x2b}, {Opcode: 0x12, Constant: &constantValue{Kind: constantString, String: "shell"}}}
	dynamicCode = append(dynamicCode, task10RequestString()...)
	dynamicCode = append(dynamicCode, classInstructionSpec{Opcode: 0xb9, Member: &fixtureAddServlet}, classInstructionSpec{Opcode: 0x57}, classInstructionSpec{Opcode: 0xb1})
	dynamic := task10Artifact(t, "fixture/DynamicHook", "("+task10RequestDescriptor+"Ljavax/servlet/ServletContext;)V", 4, 2, dynamicCode)
	task10AssertFinding(t, dynamic, "javadisk:class-hook-registration", 75, "addServlet")

	constant := task10Artifact(t, "fixture/ConstantHook", "(Ljavax/servlet/ServletContext;)V", 3, 1, []classInstructionSpec{
		{Opcode: 0x2a}, {Opcode: 0x12, Constant: &constantValue{Kind: constantString, String: "health"}},
		{Opcode: 0x12, Constant: &constantValue{Kind: constantString, String: "example.HealthServlet"}},
		{Opcode: 0xb9, Member: &fixtureAddServlet}, {Opcode: 0x57}, {Opcode: 0xb1},
	})
	task10AssertFinding(t, constant, "javadisk:class-hook-registration", 60, "addServlet")
}

func TestHookAndResponseHandlingKeepIndependentBoundedResults(t *testing.T) {
	responseOnly := AnalyzeArtifact("Render.class", fixtureClass(t, "request_render"), DefaultOptions())
	for _, rule := range []string{
		"javadisk:class-request-exec", "javadisk:class-dynamic-classload", "javadisk:class-script-eval",
		"javadisk:class-executable-write", "javadisk:class-reflection-exec", "javadisk:class-deserialization-jndi",
		"javadisk:class-hook-registration",
	} {
		if findingByRule(responseOnly.Findings, rule) != nil {
			t.Fatalf("response handling created %s: %+v", rule, responseOnly)
		}
	}

	code := []classInstructionSpec{{Opcode: 0x2b}}
	code = append(code, task10RequestString()...)
	code = append(code, classInstructionSpec{Opcode: 0xb9, Member: &fixtureScriptEval}, classInstructionSpec{Opcode: 0x57}, classInstructionSpec{Opcode: 0x2c})
	code = append(code, task10RequestString()...)
	code = append(code, classInstructionSpec{Opcode: 0xb9, Member: &fixtureJNDILookup}, classInstructionSpec{Opcode: 0x57}, classInstructionSpec{Opcode: 0xb1})
	multiple := task10Artifact(t, "fixture/MultiSink", "("+task10RequestDescriptor+"Ljavax/script/ScriptEngine;Ljavax/naming/Context;)V", 4, 3, code)
	task10AssertFinding(t, multiple, "javadisk:class-script-eval", 85, "eval")
	task10AssertFinding(t, multiple, "javadisk:class-deserialization-jndi", 75, "lookup")
}

func TestReviewInvalidTask10CallShapesDoNotCreateProvenFlow(t *testing.T) {
	stringBytes := memberReference{Owner: "java/lang/String", Name: "getBytes", Descriptor: "(Ljava/lang/String;)[B"}
	t.Run("static instance class definition", func(t *testing.T) {
		code := append(task10RequestString(),
			classInstructionSpec{Opcode: 0x12, Constant: &constantValue{Kind: constantString, String: "UTF-8"}},
			classInstructionSpec{Opcode: 0xb6, Member: &stringBytes},
			classInstructionSpec{Opcode: 0xb8, Member: &fixtureLookupDefineClass},
			classInstructionSpec{Opcode: 0x57}, classInstructionSpec{Opcode: 0xb1},
		)
		result := task10Artifact(t, "fixture/InvalidStaticDefineClass", "("+task10RequestDescriptor+")V", 4, 1, code)
		task10AssertNoFinding(t, result, "javadisk:class-dynamic-classload")
	})

	t.Run("invented builder append descriptor", func(t *testing.T) {
		badAppend := memberReference{Owner: "java/lang/StringBuilder", Name: "append", Descriptor: "(Ljava/lang/String;)Ljava/lang/Object;"}
		toString := memberReference{Owner: "java/lang/StringBuilder", Name: "toString", Descriptor: "()Ljava/lang/String;"}
		code := append([]classInstructionSpec{{Opcode: 0x2b}, {Opcode: 0x2c}}, append(task10RequestString(),
			classInstructionSpec{Opcode: 0xb6, Member: &badAppend}, classInstructionSpec{Opcode: 0xb6, Member: &toString},
			classInstructionSpec{Opcode: 0xb9, Member: &fixtureScriptEval}, classInstructionSpec{Opcode: 0x57}, classInstructionSpec{Opcode: 0xb1})...)
		result := task10Artifact(t, "fixture/InvalidBuilderAppend", "("+task10RequestDescriptor+"Ljavax/script/ScriptEngine;Ljava/lang/StringBuilder;)V", 5, 3, code)
		task10AssertNoFinding(t, result, "javadisk:class-script-eval")
	})

	t.Run("static script eval", func(t *testing.T) {
		staticEval := memberReference{Owner: "javax/script/ScriptEngine", Name: "eval", Descriptor: "(Ljava/lang/String;)Ljava/lang/Object;"}
		code := append(task10RequestString(),
			classInstructionSpec{Opcode: 0xb8, Member: &staticEval}, classInstructionSpec{Opcode: 0x57}, classInstructionSpec{Opcode: 0xb1},
		)
		result := task10Artifact(t, "fixture/InvalidStaticScriptEval", "("+task10RequestDescriptor+")V", 3, 1, code)
		task10AssertNoFinding(t, result, "javadisk:class-script-eval")
	})
}

func TestReviewSecondUnresolvedReceiverDoesNotCreateProvenFlow(t *testing.T) {
	stringBytes := memberReference{Owner: "java/lang/String", Name: "getBytes", Descriptor: "(Ljava/lang/String;)[B"}
	code := []classInstructionSpec{{Opcode: 0x2b}}
	code = append(code, task10RequestString()...)
	code = append(code,
		classInstructionSpec{Opcode: 0x12, Constant: &constantValue{Kind: constantString, String: "UTF-8"}},
		classInstructionSpec{Opcode: 0xb6, Member: &stringBytes},
		classInstructionSpec{Opcode: 0xb6, Member: &fixtureLookupDefineClass},
		classInstructionSpec{Opcode: 0x57}, classInstructionSpec{Opcode: 0xb1},
	)
	result := task10Artifact(t, "fixture/UnknownReceiverDefineClass", "("+task10RequestDescriptor+"Lattacker/Foo;)V", 4, 2, code)
	task10AssertNoFinding(t, result, "javadisk:class-dynamic-classload")
}

func TestReviewSecondMalformedRecognizedBootstrapsDoNotPreserveProvenFlow(t *testing.T) {
	t.Run("concat recipe marker mismatch", func(t *testing.T) {
		concatBootstrap := memberReference{
			Owner: "java/lang/invoke/StringConcatFactory", Name: "makeConcatWithConstants",
			Descriptor: "(Ljava/lang/invoke/MethodHandles$Lookup;Ljava/lang/String;Ljava/lang/invoke/MethodType;Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/invoke/CallSite;",
		}
		concat := task10InvokeDynamicEval(t, "fixture/MalformedConcatBootstrap", concatBootstrap, "(Ljava/lang/String;)Ljava/lang/String;", []constantValue{
			{Kind: constantString, String: "\u0001\u0001"},
		})
		task10AssertNoFinding(t, concat, "javadisk:class-script-eval")
	})

	t.Run("lambda missing bootstrap arguments", func(t *testing.T) {
		lambdaBootstrap := memberReference{
			Owner: "java/lang/invoke/LambdaMetafactory", Name: "metafactory",
			Descriptor: "(Ljava/lang/invoke/MethodHandles$Lookup;Ljava/lang/String;Ljava/lang/invoke/MethodType;Ljava/lang/invoke/MethodType;Ljava/lang/invoke/MethodHandle;Ljava/lang/invoke/MethodType;)Ljava/lang/invoke/CallSite;",
		}
		lambda := task10InvokeDynamicEval(t, "fixture/MalformedLambdaBootstrap", lambdaBootstrap, "(Ljava/lang/String;)Ljava/lang/String;", nil)
		task10AssertNoFinding(t, lambda, "javadisk:class-script-eval")
	})
}

func TestReviewSecondUnknownIndexPathArrayWriteInvalidatesExactProof(t *testing.T) {
	pathsGet := memberReference{Owner: "java/nio/file/Paths", Name: "get", Descriptor: "(Ljava/lang/String;[Ljava/lang/String;)Ljava/nio/file/Path;"}
	code := []classInstructionSpec{
		{Opcode: 0x12, Constant: &constantValue{Kind: constantString, String: "web"}},
		{Opcode: 0x04}, {Opcode: 0xbd, ClassName: "java/lang/String"},
		{Opcode: 0x59}, {Opcode: 0x03}, {Opcode: 0x12, Constant: &constantValue{Kind: constantString, String: "Shell.jsp"}}, {Opcode: 0x53},
		{Opcode: 0x59}, {Opcode: 0x1b}, {Opcode: 0x12, Constant: &constantValue{Kind: constantString, String: "safe.txt"}}, {Opcode: 0x53},
		{Opcode: 0xb8, Member: &pathsGet},
	}
	code = append(code, task10RequestString()...)
	code = append(code,
		classInstructionSpec{Opcode: 0x03}, classInstructionSpec{Opcode: 0xbd, ClassName: "java/nio/file/OpenOption"},
		classInstructionSpec{Opcode: 0xb8, Member: &fixtureFilesWriteString}, classInstructionSpec{Opcode: 0x57}, classInstructionSpec{Opcode: 0xb1},
	)
	result := task10Artifact(t, "fixture/UnknownIndexPathComponent", "("+task10RequestDescriptor+"I)V", 6, 2, code)
	task10AssertNoFinding(t, result, "javadisk:class-executable-write")
}

func TestReviewSecondHeapSlotsCountAggregateStateUnits(t *testing.T) {
	heap := map[uint32]heapObject{
		1: {Stream: abstractValue{Width: 1, Provenance: []provenanceStep{{API: "source"}, {API: "sink"}}}},
		2: {List: []abstractValue{{Width: 1, Provenance: []provenanceStep{{API: "list"}}}}},
	}
	want := len(heap)
	for _, object := range heap {
		want += heapObjectStateUnits(object)
	}
	if got := heapSlots(heap); got != want {
		t.Fatalf("heapSlots=%d want aggregate state units %d", got, want)
	}
}

func TestReviewThirdLambdaMetafactoryRejectsUnlinkableReaderCallSite(t *testing.T) {
	result := task10KindCorrectLambdaReaderEval(t)
	task10AssertNoFinding(t, result, "javadisk:class-script-eval")
}

func TestReviewThirdUnknownReceiverDoesNotSuppressUnrelatedValidFinding(t *testing.T) {
	result := task10UnknownReceiverAndValidScriptClass(t)
	task10AssertFinding(t, result, "javadisk:class-script-eval", 85, "eval")
	task10AssertNoFinding(t, result, "javadisk:class-dynamic-classload")
}

func TestReviewThirdFrameMergeEnforcesAggregateHeapBudget(t *testing.T) {
	limits := DefaultOptions().Limits
	limits.MaxFrameSlots = 10
	left := frame{
		Locals: []abstractValue{{Width: 1}},
		Heap: map[uint32]heapObject{
			1: {Stream: abstractValue{Width: 1, Provenance: []provenanceStep{{API: "a"}, {API: "b"}, {API: "c"}, {API: "d"}}}},
		},
	}
	right := frame{
		Locals: []abstractValue{{Width: 1}},
		Heap: map[uint32]heapObject{
			2: {Stream: abstractValue{Width: 1, Provenance: []provenanceStep{{API: "e"}, {API: "f"}, {API: "g"}, {API: "h"}}}},
		},
	}
	if _, _, err := mergeFrames(left, right, limits, &abstractBudget{limit: 10_000}); err == nil {
		t.Fatalf("mergeFrames accepted aggregate heap state above MaxFrameSlots")
	}
}

func TestReviewFourthLambdaImplementationTargetMustResolveStaticInArtifact(t *testing.T) {
	t.Run("same class instance implementation is unproven", func(t *testing.T) {
		className := "fixture/FourthLambdaInstanceTarget"
		target := memberReference{Owner: className, Name: "run", Descriptor: "(Ljava/lang/String;)V"}
		data := task10RunnableLambdaClass(t, task10RunnableLambdaFixture{
			ClassName: className, Target: target, IncludeTarget: true, TargetAccess: 0x0001, HookRegistration: true,
		})
		result := AnalyzeArtifact("FourthLambdaInstanceTarget.class", data, DefaultOptions())
		task10AssertFinding(t, result, "javadisk:class-hook-registration", 60, "registerHandle")
	})

	t.Run("same class absent implementation is unproven", func(t *testing.T) {
		className := "fixture/FourthLambdaAbsentTarget"
		target := memberReference{Owner: className, Name: "run", Descriptor: "(Ljava/lang/String;)V"}
		data := task10RunnableLambdaClass(t, task10RunnableLambdaFixture{
			ClassName: className, Target: target, IncludeTarget: false, HookRegistration: true,
		})
		result := AnalyzeArtifact("FourthLambdaAbsentTarget.class", data, DefaultOptions())
		task10AssertFinding(t, result, "javadisk:class-hook-registration", 60, "registerHandle")
	})

	t.Run("external implementation is unproven", func(t *testing.T) {
		data := task10RunnableLambdaClass(t, task10RunnableLambdaFixture{
			ClassName: "fixture/FourthLambdaExternalTarget",
			Target: memberReference{
				Owner: "external/FourthLambdaTarget", Name: "run", Descriptor: "(Ljava/lang/String;)V",
			},
			IncludeTarget: false, HookRegistration: true,
		})
		result := AnalyzeArtifact("FourthLambdaExternalTarget.class", data, DefaultOptions())
		task10AssertFinding(t, result, "javadisk:class-hook-registration", 60, "registerHandle")
	})

	t.Run("same artifact static implementation still materializes", func(t *testing.T) {
		className := "fixture/FourthLambdaStaticTarget"
		target := memberReference{Owner: className, Name: "run", Descriptor: "(Ljava/lang/String;)V"}
		data := task10RunnableLambdaClass(t, task10RunnableLambdaFixture{
			ClassName: className, Target: target, IncludeTarget: true, TargetAccess: 0x0009,
		})
		result := AnalyzeArtifact("FourthLambdaStaticTarget.class", data, DefaultOptions())
		if len(result.Diagnostics) != 0 || len(result.Findings) != 0 {
			t.Fatalf("static lambda target should materialize without findings/diagnostics: %+v", result)
		}
		task10AssertRunnableLambdaMaterialized(t, task10AnalyzeServiceData(t, data), target)
	})
}

func TestReviewFourthAltMetafactoryFlagsZeroMaterialization(t *testing.T) {
	t.Run("flags zero materializes", func(t *testing.T) {
		className := "fixture/FourthAltLambdaStaticTarget"
		target := memberReference{Owner: className, Name: "run", Descriptor: "(Ljava/lang/String;)V"}
		data := task10RunnableLambdaClass(t, task10RunnableLambdaFixture{
			ClassName: className, BootstrapName: "altMetafactory", Target: target, IncludeTarget: true, TargetAccess: 0x0009,
		})
		result := AnalyzeArtifact("FourthAltLambdaStaticTarget.class", data, DefaultOptions())
		if len(result.Diagnostics) != 0 || len(result.Findings) != 0 {
			t.Fatalf("altMetafactory flags-zero lambda should materialize without findings/diagnostics: %+v", result)
		}
		task10AssertRunnableLambdaMaterialized(t, task10AnalyzeServiceData(t, data), target)
	})

	t.Run("flags and trailing args are unproven", func(t *testing.T) {
		className := "fixture/FourthAltLambdaMalformed"
		target := memberReference{Owner: className, Name: "run", Descriptor: "(Ljava/lang/String;)V"}
		data := task10RunnableLambdaClass(t, task10RunnableLambdaFixture{
			ClassName: className, BootstrapName: "altMetafactory", Target: target, IncludeTarget: true, TargetAccess: 0x0009,
			HookRegistration: true, AltFlags: 1, AltTrailingArgs: []constantValue{{Kind: constantInteger, Integer: 1}},
		})
		result := AnalyzeArtifact("FourthAltLambdaMalformed.class", data, DefaultOptions())
		task10AssertFinding(t, result, "javadisk:class-hook-registration", 60, "registerHandle")
	})
}

func TestReviewFifthLambdaImplementationReferenceKindMustMatchOwnerKind(t *testing.T) {
	t.Run("class target via interface methodref is unproven", func(t *testing.T) {
		className := "fixture/FifthLambdaClassViaInterfaceRef"
		target := memberReference{Owner: className, Name: "run", Descriptor: "(Ljava/lang/String;)V", Interface: true}
		data := task10RunnableLambdaClass(t, task10RunnableLambdaFixture{
			ClassName: className, Target: target, IncludeTarget: true, TargetAccess: 0x0009, HookRegistration: true,
		})
		result := AnalyzeArtifact("FifthLambdaClassViaInterfaceRef.class", data, DefaultOptions())
		task10AssertFinding(t, result, "javadisk:class-hook-registration", 60, "registerHandle")
	})

	t.Run("interface target via methodref is unproven", func(t *testing.T) {
		className := "fixture/FifthLambdaInterfaceViaMethodRef"
		target := memberReference{Owner: className, Name: "run", Descriptor: "(Ljava/lang/String;)V"}
		data := task10RunnableLambdaClass(t, task10RunnableLambdaFixture{
			ClassName: className, ClassAccess: 0x0601, Target: target, IncludeTarget: true, TargetAccess: 0x0009, HookRegistration: true,
		})
		result := AnalyzeArtifact("FifthLambdaInterfaceViaMethodRef.class", data, DefaultOptions())
		task10AssertFinding(t, result, "javadisk:class-hook-registration", 60, "registerHandle")
	})
}

func TestReviewFifthAltMetafactoryTrailingOnlyIsUnprovenAndUnmaterialized(t *testing.T) {
	className := "fixture/FifthAltTrailingOnly"
	target := memberReference{Owner: className, Name: "run", Descriptor: "(Ljava/lang/String;)V"}
	data := task10RunnableLambdaClass(t, task10RunnableLambdaFixture{
		ClassName: className, BootstrapName: "altMetafactory", Target: target, IncludeTarget: true, TargetAccess: 0x0009,
		HookRegistration: true, AltFlags: 0, AltTrailingArgs: []constantValue{{Kind: constantInteger, Integer: 1}},
	})
	result := AnalyzeArtifact("FifthAltTrailingOnly.class", data, DefaultOptions())
	task10AssertFinding(t, result, "javadisk:class-hook-registration", 60, "registerHandle")
	task10AssertNoRunnableLambdaMaterialized(t, task10AnalyzeServiceData(t, data), target)
}

func TestReviewExecutablePathConstantsRequireExactComponentsAndRecipes(t *testing.T) {
	t.Run("component join can make dangerous destination", func(t *testing.T) {
		result := task10PathComponentWrite(t, "fixture/PathComponentsDangerous", "web", []string{"WEB-INF", "classes", "Shell.class"}, true)
		task10AssertFinding(t, result, "javadisk:class-executable-write", 85, "Files.writeString")
	})
	t.Run("component join can make benign destination", func(t *testing.T) {
		result := task10PathComponentWrite(t, "fixture/PathComponentsBenign", "Shell.jsp", []string{"safe.txt"}, true)
		task10AssertNoFinding(t, result, "javadisk:class-executable-write")
	})
	t.Run("string concat recipe controls constant proof", func(t *testing.T) {
		result := task10StringConcatRecipeWrite(t, "\u0001.txt")
		task10AssertNoFinding(t, result, "javadisk:class-executable-write")
	})
}

func TestReviewHookRegistrationScoresOnlyCodeRolesAsDynamic(t *testing.T) {
	taintedName := []classInstructionSpec{{Opcode: 0x2b}}
	taintedName = append(taintedName, task10RequestString()...)
	taintedName = append(taintedName,
		classInstructionSpec{Opcode: 0x12, Constant: &constantValue{Kind: constantString, String: "example.HealthServlet"}},
		classInstructionSpec{Opcode: 0xb9, Member: &fixtureAddServlet}, classInstructionSpec{Opcode: 0x57}, classInstructionSpec{Opcode: 0xb1},
	)
	result := task10Artifact(t, "fixture/HookTaintedNameOnly", "("+task10RequestDescriptor+"Ljavax/servlet/ServletContext;)V", 4, 2, taintedName)
	task10AssertFinding(t, result, "javadisk:class-hook-registration", 60, "addServlet")

	addFilter := memberReference{
		Owner: "javax/servlet/ServletContext", Name: "addFilter",
		Descriptor: "(Ljava/lang/String;Ljava/lang/String;)Ljavax/servlet/FilterRegistration$Dynamic;", Interface: true,
	}
	filterCode := []classInstructionSpec{{Opcode: 0x2b}, {Opcode: 0x12, Constant: &constantValue{Kind: constantString, String: "filter"}}}
	filterCode = append(filterCode, task10RequestString()...)
	filterCode = append(filterCode, classInstructionSpec{Opcode: 0xb9, Member: &addFilter}, classInstructionSpec{Opcode: 0x57}, classInstructionSpec{Opcode: 0xb1})
	filter := task10Artifact(t, "fixture/HookDynamicFilter", "("+task10RequestDescriptor+"Ljavax/servlet/ServletContext;)V", 4, 2, filterCode)
	task10AssertFinding(t, filter, "javadisk:class-hook-registration", 75, "addFilter")
}

func TestReviewReaderWriterAndInputStreamCoveragePreservesTaint(t *testing.T) {
	stringBytes := memberReference{Owner: "java/lang/String", Name: "getBytes", Descriptor: "(Ljava/lang/String;)[B"}

	t.Run("ByteArrayInputStream readAllBytes", func(t *testing.T) {
		byteArrayInputInit := memberReference{Owner: "java/io/ByteArrayInputStream", Name: "<init>", Descriptor: "([B)V"}
		byteArrayReadAll := memberReference{Owner: "java/io/ByteArrayInputStream", Name: "readAllBytes", Descriptor: "()[B"}
		code := []classInstructionSpec{{Opcode: 0xbb, ClassName: "java/io/ByteArrayInputStream"}, {Opcode: 0x59}}
		code = append(code, task10RequestString()...)
		code = append(code,
			classInstructionSpec{Opcode: 0x12, Constant: &constantValue{Kind: constantString, String: "UTF-8"}},
			classInstructionSpec{Opcode: 0xb6, Member: &stringBytes},
			classInstructionSpec{Opcode: 0xb7, Member: &byteArrayInputInit}, classInstructionSpec{Opcode: 0x4d},
			classInstructionSpec{Opcode: 0x2b}, classInstructionSpec{Opcode: 0x2c}, classInstructionSpec{Opcode: 0xb6, Member: &byteArrayReadAll},
			classInstructionSpec{Opcode: 0xb6, Member: &fixtureLookupDefineClass}, classInstructionSpec{Opcode: 0x57}, classInstructionSpec{Opcode: 0xb1},
		)
		result := task10Artifact(t, "fixture/ByteArrayInputRead", "("+task10RequestDescriptor+"Ljava/lang/invoke/MethodHandles$Lookup;)V", 5, 3, code)
		task10AssertFinding(t, result, "javadisk:class-dynamic-classload", 85, "defineClass")
	})

	t.Run("BufferedReader readLine", func(t *testing.T) {
		stringReaderInit := memberReference{Owner: "java/io/StringReader", Name: "<init>", Descriptor: "(Ljava/lang/String;)V"}
		bufferedReaderInit := memberReference{Owner: "java/io/BufferedReader", Name: "<init>", Descriptor: "(Ljava/io/Reader;)V"}
		readLine := memberReference{Owner: "java/io/BufferedReader", Name: "readLine", Descriptor: "()Ljava/lang/String;"}
		code := []classInstructionSpec{{Opcode: 0xbb, ClassName: "java/io/StringReader"}, {Opcode: 0x59}}
		code = append(code, task10RequestString()...)
		code = append(code,
			classInstructionSpec{Opcode: 0xb7, Member: &stringReaderInit}, classInstructionSpec{Opcode: 0x4e},
			classInstructionSpec{Opcode: 0xbb, ClassName: "java/io/BufferedReader"}, classInstructionSpec{Opcode: 0x59},
			classInstructionSpec{Opcode: 0x2d}, classInstructionSpec{Opcode: 0xb7, Member: &bufferedReaderInit},
			classInstructionSpec{Opcode: 0x3a, Operands: []byte{0x04}},
			classInstructionSpec{Opcode: 0x2b}, classInstructionSpec{Opcode: 0x19, Operands: []byte{0x04}},
			classInstructionSpec{Opcode: 0xb6, Member: &readLine}, classInstructionSpec{Opcode: 0xb9, Member: &fixtureScriptEval},
			classInstructionSpec{Opcode: 0x57}, classInstructionSpec{Opcode: 0xb1},
		)
		result := task10Artifact(t, "fixture/BufferedReaderFlow", "("+task10RequestDescriptor+"Ljavax/script/ScriptEngine;)V", 5, 5, code)
		task10AssertFinding(t, result, "javadisk:class-script-eval", 85, "eval")
	})

	t.Run("BufferedWriter delegates to StringWriter", func(t *testing.T) {
		stringWriterInit := memberReference{Owner: "java/io/StringWriter", Name: "<init>", Descriptor: "()V"}
		bufferedWriterInit := memberReference{Owner: "java/io/BufferedWriter", Name: "<init>", Descriptor: "(Ljava/io/Writer;)V"}
		bufferedWriterWrite := memberReference{Owner: "java/io/BufferedWriter", Name: "write", Descriptor: "(Ljava/lang/String;)V"}
		writerString := memberReference{Owner: "java/io/StringWriter", Name: "toString", Descriptor: "()Ljava/lang/String;"}
		code := []classInstructionSpec{
			{Opcode: 0xbb, ClassName: "java/io/StringWriter"}, {Opcode: 0x59}, {Opcode: 0xb7, Member: &stringWriterInit}, {Opcode: 0x4e},
			{Opcode: 0xbb, ClassName: "java/io/BufferedWriter"}, {Opcode: 0x59}, {Opcode: 0x2d}, {Opcode: 0xb7, Member: &bufferedWriterInit},
			{Opcode: 0x3a, Operands: []byte{0x04}}, {Opcode: 0x19, Operands: []byte{0x04}},
		}
		code = append(code, task10RequestString()...)
		code = append(code,
			classInstructionSpec{Opcode: 0xb6, Member: &bufferedWriterWrite},
			classInstructionSpec{Opcode: 0x2b}, classInstructionSpec{Opcode: 0x2d}, classInstructionSpec{Opcode: 0xb6, Member: &writerString},
			classInstructionSpec{Opcode: 0xb9, Member: &fixtureScriptEval}, classInstructionSpec{Opcode: 0x57}, classInstructionSpec{Opcode: 0xb1},
		)
		result := task10Artifact(t, "fixture/BufferedWriterFlow", "("+task10RequestDescriptor+"Ljavax/script/ScriptEngine;)V", 6, 5, code)
		task10AssertFinding(t, result, "javadisk:class-script-eval", 85, "eval")
	})

	t.Run("OutputStreamWriter delegates to ByteArrayOutputStream", func(t *testing.T) {
		byteArrayOutputInit := memberReference{Owner: "java/io/ByteArrayOutputStream", Name: "<init>", Descriptor: "()V"}
		outputStreamWriterInit := memberReference{Owner: "java/io/OutputStreamWriter", Name: "<init>", Descriptor: "(Ljava/io/OutputStream;)V"}
		outputStreamWriterWrite := memberReference{Owner: "java/io/OutputStreamWriter", Name: "write", Descriptor: "(Ljava/lang/String;)V"}
		outputString := memberReference{Owner: "java/io/ByteArrayOutputStream", Name: "toString", Descriptor: "()Ljava/lang/String;"}
		code := []classInstructionSpec{
			{Opcode: 0xbb, ClassName: "java/io/ByteArrayOutputStream"}, {Opcode: 0x59}, {Opcode: 0xb7, Member: &byteArrayOutputInit}, {Opcode: 0x4e},
			{Opcode: 0xbb, ClassName: "java/io/OutputStreamWriter"}, {Opcode: 0x59}, {Opcode: 0x2d}, {Opcode: 0xb7, Member: &outputStreamWriterInit},
			{Opcode: 0x3a, Operands: []byte{0x04}}, {Opcode: 0x19, Operands: []byte{0x04}},
		}
		code = append(code, task10RequestString()...)
		code = append(code,
			classInstructionSpec{Opcode: 0xb6, Member: &outputStreamWriterWrite},
			classInstructionSpec{Opcode: 0x2b}, classInstructionSpec{Opcode: 0x2d}, classInstructionSpec{Opcode: 0xb6, Member: &outputString},
			classInstructionSpec{Opcode: 0xb9, Member: &fixtureScriptEval}, classInstructionSpec{Opcode: 0x57}, classInstructionSpec{Opcode: 0xb1},
		)
		result := task10Artifact(t, "fixture/OutputStreamWriterFlow", "("+task10RequestDescriptor+"Ljavax/script/ScriptEngine;)V", 6, 5, code)
		task10AssertFinding(t, result, "javadisk:class-script-eval", 85, "eval")
	})
}

func TestReviewInflaterAndLambdaCoverage(t *testing.T) {
	t.Run("InflaterInputStream readAllBytes", func(t *testing.T) {
		stringBytes := memberReference{Owner: "java/lang/String", Name: "getBytes", Descriptor: "(Ljava/lang/String;)[B"}
		byteArrayInputInit := memberReference{Owner: "java/io/ByteArrayInputStream", Name: "<init>", Descriptor: "([B)V"}
		inflaterInputInit := memberReference{Owner: "java/util/zip/InflaterInputStream", Name: "<init>", Descriptor: "(Ljava/io/InputStream;)V"}
		inflaterReadAll := memberReference{Owner: "java/util/zip/InflaterInputStream", Name: "readAllBytes", Descriptor: "()[B"}
		code := []classInstructionSpec{{Opcode: 0x2b}, {Opcode: 0xbb, ClassName: "java/io/ByteArrayInputStream"}, {Opcode: 0x59}}
		code = append(code, task10RequestString()...)
		code = append(code,
			classInstructionSpec{Opcode: 0x12, Constant: &constantValue{Kind: constantString, String: "UTF-8"}},
			classInstructionSpec{Opcode: 0xb6, Member: &stringBytes},
			classInstructionSpec{Opcode: 0xb7, Member: &byteArrayInputInit}, classInstructionSpec{Opcode: 0x4d},
			classInstructionSpec{Opcode: 0xbb, ClassName: "java/util/zip/InflaterInputStream"}, classInstructionSpec{Opcode: 0x59},
			classInstructionSpec{Opcode: 0x2c}, classInstructionSpec{Opcode: 0xb7, Member: &inflaterInputInit},
			classInstructionSpec{Opcode: 0xb6, Member: &inflaterReadAll}, classInstructionSpec{Opcode: 0xb6, Member: &fixtureLookupDefineClass},
			classInstructionSpec{Opcode: 0x57}, classInstructionSpec{Opcode: 0xb1},
		)
		result := task10Artifact(t, "fixture/InflaterInputFlow", "("+task10RequestDescriptor+"Ljava/lang/invoke/MethodHandles$Lookup;)V", 5, 3, code)
		task10AssertFinding(t, result, "javadisk:class-dynamic-classload", 85, "defineClass")
	})

	t.Run("LambdaMetafactory materializes without SAM execution", func(t *testing.T) {
		result := task10LambdaMetafactoryArtifact(t)
		if len(result.Diagnostics) != 0 || len(result.Findings) != 0 {
			t.Fatalf("lambda materialization crossed Task 11 boundary or failed parsing: %+v", result)
		}
		analysis := task10LambdaMetafactoryAnalysis(t)
		found := false
		for _, frame := range analysis.Frames {
			for _, object := range frame.Heap {
				for _, lambda := range object.Lambda {
					if lambda.Target.Owner == "fixture/LambdaFactory" && lambda.Target.Name == "run" &&
						lambda.Target.Descriptor == "(Ljava/lang/String;)V" && len(lambda.Captured) == 1 &&
						isExecutionTainted(lambda.Captured[0].Taint) {
						found = true
					}
				}
			}
		}
		if !found {
			t.Fatalf("lambda callable with captured request taint not materialized: %+v", analysis)
		}
	})
}

func TestReviewHookRegistrationCoversRequiredFamilies(t *testing.T) {
	t.Run("listener dynamic class name", func(t *testing.T) {
		addListener := memberReference{
			Owner: "javax/servlet/ServletContext", Name: "addListener",
			Descriptor: "(Ljava/lang/String;)V", Interface: true,
		}
		code := []classInstructionSpec{{Opcode: 0x2b}}
		code = append(code, task10RequestString()...)
		code = append(code, classInstructionSpec{Opcode: 0xb9, Member: &addListener}, classInstructionSpec{Opcode: 0xb1})
		result := task10Artifact(t, "fixture/HookListener", "("+task10RequestDescriptor+"Ljavax/servlet/ServletContext;)V", 3, 2, code)
		task10AssertFinding(t, result, "javadisk:class-hook-registration", 75, "addListener")
	})

	t.Run("websocket endpoint constant", func(t *testing.T) {
		addEndpoint := memberReference{
			Owner: "javax/websocket/server/ServerContainer", Name: "addEndpoint",
			Descriptor: "(Ljava/lang/Class;)V", Interface: true,
		}
		result := task10Artifact(t, "fixture/HookWebSocket", "(Ljavax/websocket/server/ServerContainer;)V", 2, 1, []classInstructionSpec{
			{Opcode: 0x2a}, {Opcode: 0x12, Constant: &constantValue{Kind: constantClass, String: "fixture/Endpoint"}},
			{Opcode: 0xb9, Member: &addEndpoint}, {Opcode: 0xb1},
		})
		task10AssertFinding(t, result, "javadisk:class-hook-registration", 60, "addEndpoint")
	})

	t.Run("tomcat valve constant object", func(t *testing.T) {
		addValve := memberReference{
			Owner: "org/apache/catalina/Pipeline", Name: "addValve",
			Descriptor: "(Lorg/apache/catalina/Valve;)V",
		}
		result := task10Artifact(t, "fixture/HookValve", "(Lorg/apache/catalina/Pipeline;Lorg/apache/catalina/Valve;)V", 2, 2, []classInstructionSpec{
			{Opcode: 0x2a}, {Opcode: 0x2b}, {Opcode: 0xb6, Member: &addValve}, {Opcode: 0xb1},
		})
		task10AssertFinding(t, result, "javadisk:class-hook-registration", 60, "addValve")
	})

	t.Run("spring handler dynamic object", func(t *testing.T) {
		registerHandler := memberReference{
			Owner: "org/springframework/web/servlet/handler/AbstractUrlHandlerMapping", Name: "registerHandler",
			Descriptor: "(Ljava/lang/String;Ljava/lang/Object;)V",
		}
		code := []classInstructionSpec{{Opcode: 0x2b}, {Opcode: 0x12, Constant: &constantValue{Kind: constantString, String: "/shell"}}}
		code = append(code, task10RequestString()...)
		code = append(code, classInstructionSpec{Opcode: 0xb6, Member: &registerHandler}, classInstructionSpec{Opcode: 0xb1})
		result := task10Artifact(t, "fixture/HookSpring", "("+task10RequestDescriptor+"Lorg/springframework/web/servlet/handler/AbstractUrlHandlerMapping;)V", 4, 2, code)
		task10AssertFinding(t, result, "javadisk:class-hook-registration", 75, "registerHandle")
	})
}

func TestReviewCustomResolveClassRemoteJNDICoverage(t *testing.T) {
	initialContextInit := memberReference{Owner: "javax/naming/InitialContext", Name: "<init>", Descriptor: "()V"}
	initialContextLookup := memberReference{Owner: "javax/naming/InitialContext", Name: "lookup", Descriptor: "(Ljava/lang/String;)Ljava/lang/Object;"}
	data, _ := classBytes(t, classSpec{
		Name: "fixture/ResolveClassJNDI", Super: "java/io/ObjectInputStream", Major: 49,
		Methods: []classMethodSpec{{
			Access: 0x0004, Name: "resolveClass", Descriptor: "(Ljava/io/ObjectStreamClass;)Ljava/lang/Class;",
			MaxStack: 3, MaxLocals: 2, Code: []classInstructionSpec{
				{Opcode: 0xbb, ClassName: "javax/naming/InitialContext"}, {Opcode: 0x59}, {Opcode: 0xb7, Member: &initialContextInit},
				{Opcode: 0x12, Constant: &constantValue{Kind: constantString, String: "rmi://127.0.0.1/Resolver"}},
				{Opcode: 0xb6, Member: &initialContextLookup}, {Opcode: 0x57}, {Opcode: 0x01}, {Opcode: 0xb0},
			},
		}},
	})
	result := AnalyzeArtifact("ResolveClassJNDI.class", data, DefaultOptions())
	finding := findingByRule(result.Findings, "javadisk:class-deserialization-jndi")
	if finding == nil || finding.Score != 60 || !strings.Contains(finding.Evidence, "method=resolveClass") ||
		!strings.Contains(finding.Evidence, "lookup") {
		t.Fatalf("custom resolveClass remote JNDI result=%+v", result)
	}
}

func TestReviewEvidencePayloadSafetyUsesRealPayloadConstant(t *testing.T) {
	longPayload := strings.Repeat("decoded-payload", 80)
	code := append([]classInstructionSpec{{Opcode: 0x2b}}, append(task10RequestString(),
		classInstructionSpec{Opcode: 0x12, Constant: &constantValue{Kind: constantString, String: longPayload}},
		classInstructionSpec{Opcode: 0xb6, Member: &fixtureStringConcat}, classInstructionSpec{Opcode: 0xb9, Member: &fixtureScriptEval},
		classInstructionSpec{Opcode: 0x57}, classInstructionSpec{Opcode: 0xb1})...)
	result := task10Artifact(t, "fixture/LongPayloadEvidence", "("+task10RequestDescriptor+"Ljavax/script/ScriptEngine;)V", 4, 2, code)
	finding := findingByRule(result.Findings, "javadisk:class-script-eval")
	if finding == nil || strings.Contains(finding.Evidence, longPayload) || strings.Contains(finding.Evidence, strings.Repeat("decoded-payload", 40)) {
		t.Fatalf("payload evidence leaked or finding missing: %+v", result)
	}
}
