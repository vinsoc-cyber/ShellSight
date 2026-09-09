package javadisk

import (
	"encoding/binary"
	"strings"
	"testing"
	"unicode/utf8"
)

func u4Bytes(value uint32) []byte {
	return []byte{byte(value >> 24), byte(value >> 16), byte(value >> 8), byte(value)}
}

func attributeFixture(name uint16, payload []byte) []byte {
	data := append([]byte{}, u2Bytes(name)...)
	data = append(data, u4Bytes(uint32(len(payload)))...)
	return append(data, payload...)
}

func memberFixture(access, name, descriptor uint16, attributes ...[]byte) []byte {
	data := append([]byte{}, u2Bytes(access)...)
	data = append(data, u2Bytes(name)...)
	data = append(data, u2Bytes(descriptor)...)
	data = append(data, u2Bytes(uint16(len(attributes)))...)
	for _, attribute := range attributes {
		data = append(data, attribute...)
	}
	return data
}

func classWithSections(
	pool *constantPoolBuilder,
	thisClass, superClass uint16,
	fields, methods, attributes [][]byte,
) []byte {
	data := finishClass(0, 70, pool, thisClass, superClass, nil)
	data = data[:len(data)-6]
	data = append(data, u2Bytes(uint16(len(fields)))...)
	for _, field := range fields {
		data = append(data, field...)
	}
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

func fixtureClassPool() (*constantPoolBuilder, uint16, uint16) {
	pool := newConstantPoolBuilder()
	thisName := pool.utf8("fixture/Attributes")
	thisClass := pool.u2Entry(cpClass, thisName)
	superName := pool.utf8("java/lang/Object")
	superClass := pool.u2Entry(cpClass, superName)
	return pool, thisClass, superClass
}

func annotationFixture(descriptor, elementName uint16, value []byte) []byte {
	payload := append(u2Bytes(1), u2Bytes(descriptor)...)
	payload = append(payload, u2Bytes(1)...)
	payload = append(payload, u2Bytes(elementName)...)
	return append(payload, value...)
}

func annotationArrayFixture(values ...[]byte) []byte {
	payload := append([]byte{'['}, u2Bytes(uint16(len(values)))...)
	for _, value := range values {
		payload = append(payload, value...)
	}
	return payload
}

func retainedAnnotationCost(annotations []annotationModel) (count, cost int) {
	for _, annotation := range annotations {
		for _, value := range annotation.Values {
			count++
			cost += len(value) + 1
		}
	}
	return count, cost
}

func allAnnotations(cf *classModel) []annotationModel {
	annotations := append([]annotationModel{}, cf.Annotations...)
	for _, field := range cf.Fields {
		annotations = append(annotations, field.Annotations...)
	}
	for _, method := range cf.Methods {
		annotations = append(annotations, method.Annotations...)
	}
	return annotations
}

func TestUnknownAttributeIsSkippedByDeclaredLength(t *testing.T) {
	pool, thisClass, superClass := fixtureClassPool()
	unknownName := pool.utf8("FutureAttribute")
	fieldName := pool.utf8("flag")
	fieldDescriptor := pool.utf8("I")
	data := classWithSections(pool, thisClass, superClass,
		[][]byte{memberFixture(0x0019, fieldName, fieldDescriptor)}, nil,
		[][]byte{attributeFixture(unknownName, []byte{0xde, 0xad, 0xbe, 0xef})},
	)

	cf, err := parseClass(data, DefaultOptions().Limits)
	if err != nil {
		t.Fatal(err)
	}
	if len(cf.Fields) != 1 || cf.Fields[0].Name != "flag" {
		t.Fatalf("class=%+v", cf)
	}
}

func TestParseClassFieldsRetainConstantValueAndAnnotations(t *testing.T) {
	pool, thisClass, superClass := fixtureClassPool()
	fieldName := pool.utf8("command")
	fieldDescriptor := pool.utf8("Ljava/lang/String;")
	constantValueName := pool.utf8("ConstantValue")
	constantText := pool.utf8(strings.Repeat("x", 20))
	constantIndex := pool.u2Entry(cpString, constantText)
	annotationsName := pool.utf8("RuntimeVisibleAnnotations")
	annotationDescriptor := pool.utf8("Ljakarta/servlet/annotation/WebServlet;")
	elementName := pool.utf8("value")
	annotationText := pool.utf8("/shell")
	annotationPayload := append(u2Bytes(1), u2Bytes(annotationDescriptor)...)
	annotationPayload = append(annotationPayload, u2Bytes(1)...)
	annotationPayload = append(annotationPayload, u2Bytes(elementName)...)
	annotationPayload = append(annotationPayload, 's')
	annotationPayload = append(annotationPayload, u2Bytes(annotationText)...)
	field := memberFixture(0x0019, fieldName, fieldDescriptor,
		attributeFixture(constantValueName, u2Bytes(constantIndex)),
		attributeFixture(annotationsName, annotationPayload),
	)
	data := classWithSections(pool, thisClass, superClass, [][]byte{field}, nil, nil)
	limits := DefaultOptions().Limits
	limits.MaxConstantBytes = 8

	cf, err := parseClass(data, limits)
	if err != nil {
		t.Fatal(err)
	}
	if len(cf.Fields) != 1 {
		t.Fatalf("fields=%+v", cf.Fields)
	}
	got := cf.Fields[0]
	if got.Access != 0x0019 || got.Name != "command" || got.Descriptor != "Ljava/lang/String;" ||
		got.Constant == nil || got.Constant.Kind != constantString || got.Constant.String != "xxxxxxxx" {
		t.Fatalf("field=%+v", got)
	}
	if len(got.Annotations) != 1 || got.Annotations[0].Descriptor != "Ljakarta/servlet/annotation/WebServlet;" ||
		len(got.Annotations[0].Values) != 1 || got.Annotations[0].Values[0] != "/shell" {
		t.Fatalf("annotations=%+v", got.Annotations)
	}
}

func TestParseClassCodeCapturesBodyHandlersLinesAndMethodAnnotations(t *testing.T) {
	pool, thisClass, superClass := fixtureClassPool()
	methodName := pool.utf8("service")
	methodDescriptor := pool.utf8("()V")
	codeName := pool.utf8("Code")
	lineName := pool.utf8("LineNumberTable")
	unknownName := pool.utf8("UnknownCodeAttribute")
	catchName := pool.utf8("java/lang/Exception")
	catchClass := pool.u2Entry(cpClass, catchName)
	annotationsName := pool.utf8("RuntimeInvisibleAnnotations")
	annotationDescriptor := pool.utf8("Lorg/springframework/web/bind/annotation/ResponseBody;")

	lines := append(u2Bytes(1), u2Bytes(0)...)
	lines = append(lines, u2Bytes(42)...)
	code := append(u2Bytes(2), u2Bytes(3)...)
	code = append(code, u4Bytes(2)...)
	code = append(code, 0x00, 0xb1)
	code = append(code, u2Bytes(1)...)
	for _, value := range []uint16{0, 1, 1, catchClass} {
		code = append(code, u2Bytes(value)...)
	}
	code = append(code, u2Bytes(2)...)
	code = append(code, attributeFixture(unknownName, []byte{0, 1})...)
	code = append(code, attributeFixture(lineName, lines)...)
	annotationPayload := append(u2Bytes(1), u2Bytes(annotationDescriptor)...)
	annotationPayload = append(annotationPayload, u2Bytes(0)...)
	method := memberFixture(0x0001, methodName, methodDescriptor,
		attributeFixture(codeName, code),
		attributeFixture(annotationsName, annotationPayload),
	)
	data := classWithSections(pool, thisClass, superClass, nil, [][]byte{method}, nil)

	cf, err := parseClass(data, DefaultOptions().Limits)
	if err != nil {
		t.Fatal(err)
	}
	if len(cf.Methods) != 1 || cf.Methods[0].Code == nil {
		t.Fatalf("methods=%+v", cf.Methods)
	}
	got := cf.Methods[0]
	if got.Access != 1 || got.Name != "service" || got.Descriptor != "()V" || len(got.Annotations) != 1 {
		t.Fatalf("method=%+v", got)
	}
	if code := got.Code; code.MaxStack != 2 || code.MaxLocals != 3 || string(code.Bytes) != "\x00\xb1" ||
		len(code.Handlers) != 1 || code.Handlers[0].Start != 0 || code.Handlers[0].End != 1 ||
		code.Handlers[0].Handler != 1 || code.Handlers[0].CatchType != "java/lang/Exception" ||
		len(code.Lines) != 1 || code.Lines[0].Offset != 0 || code.Lines[0].Line != 42 {
		t.Fatalf("code=%+v", code)
	}
}

func TestParseClassBootstrapMethodsResolveHandlesArgumentsAndIndexes(t *testing.T) {
	pool, thisClass, superClass := fixtureClassPool()
	methodName := pool.utf8("bootstrap")
	methodDescriptor := pool.utf8("()V")
	nameAndType := pool.pairEntry(cpNameAndType, methodName, methodDescriptor)
	methodRef := pool.pairEntry(cpMethodref, thisClass, nameAndType)
	handle := pool.methodHandle(6, methodRef)
	text := pool.utf8("recipe")
	stringArg := pool.u2Entry(cpString, text)
	integerArg := pool.u4Entry(cpInteger, 7)
	callName := pool.utf8("call")
	callDescriptor := pool.utf8("()Ljava/lang/String;")
	callNameAndType := pool.pairEntry(cpNameAndType, callName, callDescriptor)
	callSite := pool.pairEntry(cpInvokeDynamic, 0, callNameAndType)
	bootstrapName := pool.utf8("BootstrapMethods")
	payload := append(u2Bytes(1), u2Bytes(handle)...)
	payload = append(payload, u2Bytes(2)...)
	payload = append(payload, u2Bytes(stringArg)...)
	payload = append(payload, u2Bytes(integerArg)...)
	data := classWithSections(pool, thisClass, superClass, nil, nil,
		[][]byte{attributeFixture(bootstrapName, payload)},
	)

	cf, err := parseClass(data, DefaultOptions().Limits)
	if err != nil {
		t.Fatal(err)
	}
	if len(cf.Bootstraps) != 1 || cf.Bootstraps[0].Handle.Name != "bootstrap" ||
		len(cf.Bootstraps[0].Arguments) != 2 || cf.Bootstraps[0].Arguments[0].String != "recipe" ||
		cf.Bootstraps[0].Arguments[1].Integer != 7 {
		t.Fatalf("bootstraps=%+v", cf.Bootstraps)
	}
	call, err := cf.invokeDynamic(callSite)
	if err != nil || call.Bootstrap != 0 {
		t.Fatalf("call=%+v err=%v", call, err)
	}
}

func TestParseClassRejectsBootstrapFieldHandle(t *testing.T) {
	pool, thisClass, superClass := fixtureClassPool()
	fieldNameType := pool.pairEntry(cpNameAndType, pool.utf8("value"), pool.utf8("I"))
	fieldRef := pool.pairEntry(cpFieldref, thisClass, fieldNameType)
	fieldHandle := pool.methodHandle(2, fieldRef)
	dynamicNameType := pool.pairEntry(cpNameAndType, pool.utf8("constant"), pool.utf8("I"))
	pool.pairEntry(cpDynamic, 0, dynamicNameType)
	payload := append(u2Bytes(1), u2Bytes(fieldHandle)...)
	payload = append(payload, 0, 0)
	data := classWithSections(pool, thisClass, superClass, nil, nil,
		[][]byte{attributeFixture(pool.utf8("BootstrapMethods"), payload)},
	)
	if _, err := parseClass(data, DefaultOptions().Limits); err == nil {
		t.Fatal("accepted field access method handle as bootstrap method")
	}
}

func TestParseClassRejectsDynamicWithoutBootstrapMethods(t *testing.T) {
	for _, test := range []struct {
		name string
		tag  byte
	}{{"dynamic", cpDynamic}, {"invokedynamic", cpInvokeDynamic}} {
		t.Run(test.name, func(t *testing.T) {
			pool, thisClass, superClass := fixtureClassPool()
			name := pool.utf8("call")
			descriptor := pool.utf8("()V")
			nameAndType := pool.pairEntry(cpNameAndType, name, descriptor)
			pool.pairEntry(test.tag, 0, nameAndType)
			data := classWithSections(pool, thisClass, superClass, nil, nil, nil)
			if _, err := parseClass(data, DefaultOptions().Limits); err == nil {
				t.Fatalf("constant-pool tag %d parsed without BootstrapMethods", test.tag)
			}
		})
	}
}

func TestParseClassAllowsNoDynamicConstantsWithoutBootstrapMethods(t *testing.T) {
	pool, thisClass, superClass := fixtureClassPool()
	data := classWithSections(pool, thisClass, superClass, nil, nil, nil)
	if _, err := parseClass(data, DefaultOptions().Limits); err != nil {
		t.Fatal(err)
	}
}

func TestParseClassConstantValueDescriptorCompatibility(t *testing.T) {
	valid := []struct {
		descriptor string
		kind       constantKind
	}{
		{"B", constantInteger}, {"C", constantInteger}, {"I", constantInteger},
		{"S", constantInteger}, {"Z", constantInteger}, {"J", constantLong},
		{"F", constantFloat}, {"D", constantDouble}, {"Ljava/lang/String;", constantString},
	}
	for _, test := range valid {
		t.Run("valid-"+test.descriptor, func(t *testing.T) {
			data := constantValueClassFixture(test.descriptor, test.kind)
			if _, err := parseClass(data, DefaultOptions().Limits); err != nil {
				t.Fatalf("valid ConstantValue rejected: %v", err)
			}
		})
	}

	invalid := []struct {
		descriptor string
		kind       constantKind
	}{
		{"B", constantString}, {"J", constantInteger}, {"F", constantDouble},
		{"D", constantFloat}, {"Ljava/lang/String;", constantInteger},
		{"[I", constantInteger}, {"[Ljava/lang/String;", constantString},
		{"Ljava/lang/Object;", constantString}, {"V", constantInteger}, {"()I", constantInteger},
	}
	for _, test := range invalid {
		t.Run("invalid-"+test.descriptor, func(t *testing.T) {
			data := constantValueClassFixture(test.descriptor, test.kind)
			if _, err := parseClass(data, DefaultOptions().Limits); err == nil {
				t.Fatal("incompatible ConstantValue parsed")
			}
		})
	}
}

func constantValueClassFixture(descriptor string, kind constantKind) []byte {
	pool, thisClass, superClass := fixtureClassPool()
	fieldName := pool.utf8("value")
	fieldDescriptor := pool.utf8(descriptor)
	attributeName := pool.utf8("ConstantValue")
	var constantIndex uint16
	switch kind {
	case constantInteger:
		constantIndex = pool.u4Entry(cpInteger, 1)
	case constantFloat:
		constantIndex = pool.u4Entry(cpFloat, 1)
	case constantLong:
		constantIndex = pool.u8Entry(cpLong, 1)
	case constantDouble:
		constantIndex = pool.u8Entry(cpDouble, 1)
	case constantString:
		constantIndex = pool.u2Entry(cpString, pool.utf8("x"))
	default:
		panic("unsupported fixture constant kind")
	}
	field := memberFixture(0x0019, fieldName, fieldDescriptor,
		attributeFixture(attributeName, u2Bytes(constantIndex)))
	return classWithSections(pool, thisClass, superClass, [][]byte{field}, nil, nil)
}

func TestParseClassAnnotationRetentionBoundsHostileEnumReferences(t *testing.T) {
	pool, thisClass, superClass := fixtureClassPool()
	attributeName := pool.utf8("RuntimeVisibleAnnotations")
	descriptor := pool.utf8("Lfixture/EnumValues;")
	elementName := pool.utf8("value")
	largeType := pool.utf8(strings.Repeat("界", 10_000))
	largeName := pool.utf8(strings.Repeat("値", 10_000))
	enumValue := append([]byte{'e'}, u2Bytes(largeType)...)
	enumValue = append(enumValue, u2Bytes(largeName)...)
	values := make([][]byte, 512)
	for i := range values {
		values[i] = enumValue
	}
	payload := annotationFixture(descriptor, elementName, annotationArrayFixture(values...))
	data := classWithSections(pool, thisClass, superClass, nil, nil,
		[][]byte{attributeFixture(attributeName, payload)})
	limits := DefaultOptions().Limits
	limits.MaxConstantBytes = 32

	var cf *classModel
	var parseErr error
	allocations := testing.AllocsPerRun(1, func() {
		cf, parseErr = parseClass(data, limits)
	})
	if parseErr != nil {
		t.Fatal(parseErr)
	}
	count, cost := retainedAnnotationCost(cf.Annotations)
	t.Logf("hostile enum references: allocations=%.0f retained_values=%d retained_cost=%d budget=%d", allocations, count, cost, limits.MaxConstantBytes+1)
	if cost > limits.MaxConstantBytes+1 {
		t.Errorf("retained %d values costing %d units; budget=%d", count, cost, limits.MaxConstantBytes+1)
	}
	if allocations > 64 {
		t.Errorf("hostile repeated enum references allocated %.0f objects; want at most 64", allocations)
	}
	for _, annotation := range cf.Annotations {
		for _, value := range annotation.Values {
			if !utf8.ValidString(value) {
				t.Errorf("retained invalid UTF-8 %x", value)
			}
		}
	}
}

func TestParseClassAnnotationRetentionChargesEmptyAndDeepValues(t *testing.T) {
	for _, depth := range []int{0, 8} {
		t.Run(string(rune('0'+depth)), func(t *testing.T) {
			pool, thisClass, superClass := fixtureClassPool()
			attributeName := pool.utf8("RuntimeVisibleAnnotations")
			descriptor := pool.utf8("Lfixture/EmptyValues;")
			elementName := pool.utf8("value")
			empty := pool.utf8("")
			values := make([][]byte, 128)
			for i := range values {
				values[i] = append([]byte{'s'}, u2Bytes(empty)...)
			}
			value := annotationArrayFixture(values...)
			for range depth {
				value = annotationArrayFixture(value)
			}
			payload := annotationFixture(descriptor, elementName, value)
			data := classWithSections(pool, thisClass, superClass, nil, nil,
				[][]byte{attributeFixture(attributeName, payload)})
			limits := DefaultOptions().Limits
			limits.MaxConstantBytes = 8
			limits.MaxAnnotationDepth = 16
			cf, err := parseClass(data, limits)
			if err != nil {
				t.Fatal(err)
			}
			count, cost := retainedAnnotationCost(cf.Annotations)
			if cost > limits.MaxConstantBytes+1 || count > limits.MaxConstantBytes+1 {
				t.Fatalf("depth=%d retained %d empty values costing %d units", depth, count, cost)
			}
		})
	}
}

func TestParseClassAnnotationRetentionBudgetIsSharedAcrossClass(t *testing.T) {
	pool, thisClass, superClass := fixtureClassPool()
	attributeName := pool.utf8("RuntimeVisibleAnnotations")
	descriptor := pool.utf8("Lfixture/SharedBudget;")
	elementName := pool.utf8("value")
	empty := pool.utf8("")
	values := make([][]byte, 8)
	for i := range values {
		values[i] = append([]byte{'s'}, u2Bytes(empty)...)
	}
	annotation := attributeFixture(attributeName,
		annotationFixture(descriptor, elementName, annotationArrayFixture(values...)))
	fieldName := pool.utf8("field")
	fieldDescriptor := pool.utf8("I")
	methodName := pool.utf8("method")
	methodDescriptor := pool.utf8("()V")
	field := memberFixture(1, fieldName, fieldDescriptor, annotation)
	method := memberFixture(0x0401, methodName, methodDescriptor, annotation)
	data := classWithSections(pool, thisClass, superClass,
		[][]byte{field}, [][]byte{method}, [][]byte{annotation})
	limits := DefaultOptions().Limits
	limits.MaxConstantBytes = 4
	cf, err := parseClass(data, limits)
	if err != nil {
		t.Fatal(err)
	}
	annotations := allAnnotations(cf)
	count, cost := retainedAnnotationCost(annotations)
	if len(annotations) != 3 {
		t.Fatalf("descriptors were not retained: %+v", annotations)
	}
	if cost > limits.MaxConstantBytes+1 || count > limits.MaxConstantBytes+1 {
		t.Fatalf("class retained %d values costing %d units", count, cost)
	}
}

func TestParseClassAnnotationValidatesAfterRetentionExhaustion(t *testing.T) {
	pool, thisClass, superClass := fixtureClassPool()
	attributeName := pool.utf8("RuntimeVisibleAnnotations")
	descriptor := pool.utf8("Lfixture/ValidateAll;")
	elementName := pool.utf8("value")
	empty := pool.utf8("")
	values := make([][]byte, 32)
	for i := range values {
		values[i] = append([]byte{'s'}, u2Bytes(empty)...)
	}
	values = append(values, []byte{'!'})
	payload := annotationFixture(descriptor, elementName, annotationArrayFixture(values...))
	data := classWithSections(pool, thisClass, superClass, nil, nil,
		[][]byte{attributeFixture(attributeName, payload)})
	limits := DefaultOptions().Limits
	limits.MaxConstantBytes = 2
	if _, err := parseClass(data, limits); err == nil {
		t.Fatal("malformed value after retention exhaustion was not validated")
	}
}

func TestParseClassRejectsInvalidBootstrapIndexOnceAttributeIsAvailable(t *testing.T) {
	pool, thisClass, superClass := fixtureClassPool()
	methodName := pool.utf8("bootstrap")
	descriptor := pool.utf8("()V")
	nameAndType := pool.pairEntry(cpNameAndType, methodName, descriptor)
	methodRef := pool.pairEntry(cpMethodref, thisClass, nameAndType)
	handle := pool.methodHandle(6, methodRef)
	pool.pairEntry(cpInvokeDynamic, 1, nameAndType)
	bootstrapName := pool.utf8("BootstrapMethods")
	payload := append(u2Bytes(1), u2Bytes(handle)...)
	payload = append(payload, u2Bytes(0)...)
	data := classWithSections(pool, thisClass, superClass, nil, nil,
		[][]byte{attributeFixture(bootstrapName, payload)},
	)
	if _, err := parseClass(data, DefaultOptions().Limits); err == nil {
		t.Fatal("invalid bootstrap index parsed")
	}
}

func TestParseClassRejectsTruncatedCompleteClassSuffix(t *testing.T) {
	pool, thisClass, superClass := fixtureClassPool()
	methodName := pool.utf8("run")
	descriptor := pool.utf8("()V")
	codeName := pool.utf8("Code")
	code := append(u2Bytes(1), u2Bytes(1)...)
	code = append(code, u4Bytes(1)...)
	code = append(code, 0xb1)
	code = append(code, 0, 0, 0, 0)
	data := classWithSections(pool, thisClass, superClass, nil,
		[][]byte{memberFixture(1, methodName, descriptor, attributeFixture(codeName, code))}, nil,
	)
	for n := 0; n < len(data); n++ {
		if _, err := parseClass(data[:n], DefaultOptions().Limits); err == nil {
			t.Fatalf("prefix %d unexpectedly parsed", n)
		}
	}
}

func TestParseClassRejectsAttributeLengthMismatchesAndTrailingBytes(t *testing.T) {
	pool, thisClass, superClass := fixtureClassPool()
	fieldName := pool.utf8("value")
	descriptor := pool.utf8("I")
	constantName := pool.utf8("ConstantValue")
	constantIndex := pool.u4Entry(cpInteger, 1)

	tooLongKnown := classWithSections(pool, thisClass, superClass,
		[][]byte{memberFixture(1, fieldName, descriptor,
			attributeFixture(constantName, append(u2Bytes(constantIndex), 0)))}, nil, nil)
	truncatedUnknown := finishClass(0, 70, pool, thisClass, superClass, nil)
	truncatedUnknown = truncatedUnknown[:len(truncatedUnknown)-2]
	truncatedUnknown = append(truncatedUnknown, 0, 1)
	truncatedUnknown = append(truncatedUnknown, u2Bytes(constantName)...)
	truncatedUnknown = append(truncatedUnknown, u4Bytes(10)...)
	truncatedUnknown = append(truncatedUnknown, 1)
	valid := finishClass(0, 70, pool, thisClass, superClass, nil)
	withTrailing := append(append([]byte{}, valid...), 0)

	for name, data := range map[string][]byte{
		"known-extra-byte":  tooLongKnown,
		"unknown-truncated": truncatedUnknown,
		"trailing-byte":     withTrailing,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := parseClass(data, DefaultOptions().Limits); err == nil {
				t.Fatal("malformed class parsed")
			}
		})
	}
}

func TestParseClassEnforcesMethodFrameCodeAndDeclaredCountLimits(t *testing.T) {
	pool, thisClass, superClass := fixtureClassPool()
	methodName := pool.utf8("run")
	descriptor := pool.utf8("()V")
	codeName := pool.utf8("Code")
	code := append(u2Bytes(4), u2Bytes(5)...)
	code = append(code, u4Bytes(1)...)
	code = append(code, 0xb1, 0, 0, 0, 0)
	method := memberFixture(1, methodName, descriptor, attributeFixture(codeName, code))
	data := classWithSections(pool, thisClass, superClass, nil, [][]byte{method, method}, nil)

	methodLimits := DefaultOptions().Limits
	methodLimits.MaxMethods = 1
	if _, err := parseClass(data, methodLimits); err == nil {
		t.Fatal("method count over limit parsed")
	}
	frameLimits := DefaultOptions().Limits
	frameLimits.MaxFrameSlots = 8
	oneMethod := classWithSections(pool, thisClass, superClass, nil, [][]byte{method}, nil)
	if _, err := parseClass(oneMethod, frameLimits); err == nil {
		t.Fatal("frame slots over limit parsed")
	}

	largeCode := append(u2Bytes(1), u2Bytes(1)...)
	largeCode = append(largeCode, u4Bytes(65536)...)
	largeCode = append(largeCode, make([]byte, 65536)...)
	largeCode = append(largeCode, 0, 0, 0, 0)
	largeMethod := memberFixture(1, methodName, descriptor, attributeFixture(codeName, largeCode))
	if _, err := parseClass(classWithSections(pool, thisClass, superClass, nil, [][]byte{largeMethod}, nil), DefaultOptions().Limits); err == nil {
		t.Fatal("code_length 65536 parsed")
	}

	declaredCount := finishClass(0, 70, pool, thisClass, superClass, nil)
	declaredCount = declaredCount[:len(declaredCount)-6]
	declaredCount = append(declaredCount, 0xff, 0xff)
	if _, err := parseClass(declaredCount, DefaultOptions().Limits); err == nil {
		t.Fatal("impossible declared field count parsed")
	}
}

func TestParseClassRejectsInvalidNestedIndexesAndCodeRanges(t *testing.T) {
	pool, thisClass, superClass := fixtureClassPool()
	methodName := pool.utf8("run")
	descriptor := pool.utf8("()V")
	codeName := pool.utf8("Code")
	lineName := pool.utf8("LineNumberTable")
	wrongTag := pool.u4Entry(cpInteger, 1)

	makeCode := func(catchType, start, end, handler, line uint16) []byte {
		lines := append(u2Bytes(1), u2Bytes(line)...)
		lines = append(lines, u2Bytes(7)...)
		code := append(u2Bytes(1), u2Bytes(1)...)
		code = append(code, u4Bytes(1)...)
		code = append(code, 0xb1)
		code = append(code, u2Bytes(1)...)
		for _, value := range []uint16{start, end, handler, catchType} {
			code = append(code, u2Bytes(value)...)
		}
		code = append(code, u2Bytes(1)...)
		return append(code, attributeFixture(lineName, lines)...)
	}

	for name, code := range map[string][]byte{
		"catch-type-wrong-tag": makeCode(wrongTag, 0, 1, 0, 0),
		"empty-handler-range":  makeCode(0, 1, 1, 0, 0),
		"handler-out-of-range": makeCode(0, 0, 1, 1, 0),
		"line-out-of-range":    makeCode(0, 0, 1, 0, 1),
	} {
		t.Run(name, func(t *testing.T) {
			method := memberFixture(1, methodName, descriptor, attributeFixture(codeName, code))
			data := classWithSections(pool, thisClass, superClass, nil, [][]byte{method}, nil)
			if _, err := parseClass(data, DefaultOptions().Limits); err == nil {
				t.Fatal("invalid nested Code value parsed")
			}
		})
	}
}

func TestParseClassRejectsMalformedAnnotationsAndDepth(t *testing.T) {
	pool, thisClass, superClass := fixtureClassPool()
	annotationsName := pool.utf8("RuntimeVisibleAnnotations")
	descriptor := pool.utf8("Lfixture/Nested;")
	elementName := pool.utf8("value")
	stringValue := pool.utf8("x")

	annotation := func(value []byte) []byte {
		payload := append(u2Bytes(1), u2Bytes(descriptor)...)
		payload = append(payload, u2Bytes(1)...)
		payload = append(payload, u2Bytes(elementName)...)
		return append(payload, value...)
	}
	nested := append([]byte{'@'}, u2Bytes(descriptor)...)
	nested = append(nested, u2Bytes(0)...)
	tooDeep := append([]byte{'['}, u2Bytes(1)...)
	tooDeep = append(tooDeep, nested...)

	malformed := map[string][]byte{
		"unknown-element-tag": {'!'},
		"truncated-string":    {'s', byte(stringValue >> 8)},
		"wrong-string-index":  append([]byte{'s'}, u2Bytes(thisClass)...),
	}
	for name, value := range malformed {
		t.Run(name, func(t *testing.T) {
			data := classWithSections(pool, thisClass, superClass, nil, nil,
				[][]byte{attributeFixture(annotationsName, annotation(value))})
			if _, err := parseClass(data, DefaultOptions().Limits); err == nil {
				t.Fatal("malformed annotation parsed")
			}
		})
	}

	limits := DefaultOptions().Limits
	limits.MaxAnnotationDepth = 2
	data := classWithSections(pool, thisClass, superClass, nil, nil,
		[][]byte{attributeFixture(annotationsName, annotation(tooDeep))})
	if _, err := parseClass(data, limits); err == nil {
		t.Fatal("annotation over recursion limit parsed")
	}
}

func TestParseClassAllowsScalarAtAnnotationDepthOne(t *testing.T) {
	pool, thisClass, superClass := fixtureClassPool()
	annotationsName := pool.utf8("RuntimeVisibleAnnotations")
	descriptor := pool.utf8("Lfixture/Scalar;")
	elementName := pool.utf8("value")
	stringValue := pool.utf8("x")
	payload := append(u2Bytes(1), u2Bytes(descriptor)...)
	payload = append(payload, u2Bytes(1)...)
	payload = append(payload, u2Bytes(elementName)...)
	payload = append(payload, 's')
	payload = append(payload, u2Bytes(stringValue)...)
	data := classWithSections(pool, thisClass, superClass, nil, nil,
		[][]byte{attributeFixture(annotationsName, payload)})
	limits := DefaultOptions().Limits
	limits.MaxAnnotationDepth = 1
	cf, err := parseClass(data, limits)
	if err != nil {
		t.Fatal(err)
	}
	if len(cf.Annotations) != 1 || len(cf.Annotations[0].Values) != 1 || cf.Annotations[0].Values[0] != "x" {
		t.Fatalf("annotations=%+v", cf.Annotations)
	}
}

func TestParseClassKnownNestedAttributeMustBeFullyConsumed(t *testing.T) {
	pool, thisClass, superClass := fixtureClassPool()
	methodName := pool.utf8("run")
	descriptor := pool.utf8("()V")
	codeName := pool.utf8("Code")
	lineName := pool.utf8("LineNumberTable")
	lines := append(u2Bytes(0), 0)
	code := append(u2Bytes(1), u2Bytes(1)...)
	code = append(code, u4Bytes(1)...)
	code = append(code, 0xb1, 0, 0)
	code = append(code, u2Bytes(1)...)
	code = append(code, attributeFixture(lineName, lines)...)
	method := memberFixture(1, methodName, descriptor, attributeFixture(codeName, code))
	data := classWithSections(pool, thisClass, superClass, nil, [][]byte{method}, nil)
	if _, err := parseClass(data, DefaultOptions().Limits); err == nil {
		t.Fatal("LineNumberTable with unconsumed byte parsed")
	}
}

func TestClassAttributeFixtureLengthsUseBigEndian(t *testing.T) {
	got := attributeFixture(3, []byte{1, 2, 3})
	if binary.BigEndian.Uint32(got[2:6]) != 3 {
		t.Fatalf("fixture length=%x", got[2:6])
	}
}
