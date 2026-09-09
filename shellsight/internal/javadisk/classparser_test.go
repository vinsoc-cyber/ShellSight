package javadisk

import (
	"encoding/binary"
	"errors"
	"math"
	"strconv"
	"strings"
	"testing"
)

type classSpec struct {
	Minor       uint16
	Major       uint16
	Name        string
	Super       string
	Interfaces  []string
	Fields      []classFieldSpec
	Methods     []classMethodSpec
	MethodOwner string
	MethodName  string
	MethodDesc  string
}

type classFieldSpec struct {
	Access     uint16
	Name       string
	Descriptor string
	Constant   *constantValue
}

type classMethodSpec struct {
	Access      uint16
	Name        string
	Descriptor  string
	MaxStack    uint16
	MaxLocals   uint16
	Code        []classInstructionSpec
	Handlers    []exceptionHandler
	NoCode      bool
	StackMap    []stackMapFrameSpec
	StackMapRaw []byte
}

type stackMapFrameSpec struct {
	Offset uint16
	Locals []string
	Stack  []string
}

type classInstructionSpec struct {
	Opcode    byte
	Operands  []byte
	Member    *memberReference
	Field     *memberReference
	Constant  *constantValue
	ClassName string
}

type constantPoolBuilder struct {
	entries [][]byte
	next    uint16
}

func newConstantPoolBuilder() *constantPoolBuilder {
	return &constantPoolBuilder{next: 1}
}

func (b *constantPoolBuilder) add(tag byte, payload []byte) uint16 {
	index := b.next
	entry := append([]byte{tag}, payload...)
	b.entries = append(b.entries, entry)
	b.next++
	if tag == 5 || tag == 6 {
		b.next++
	}
	return index
}

func (b *constantPoolBuilder) utf8(value string) uint16 {
	encoded := []byte(strings.ReplaceAll(value, "\x00", "\xc0\x80"))
	payload := make([]byte, 2+len(encoded))
	binary.BigEndian.PutUint16(payload, uint16(len(encoded)))
	copy(payload[2:], encoded)
	return b.add(1, payload)
}

func (b *constantPoolBuilder) utf8Raw(value []byte) uint16 {
	payload := make([]byte, 2+len(value))
	binary.BigEndian.PutUint16(payload, uint16(len(value)))
	copy(payload[2:], value)
	return b.add(1, payload)
}

func (b *constantPoolBuilder) u2Entry(tag byte, index uint16) uint16 {
	return b.add(tag, u2Bytes(index))
}

func (b *constantPoolBuilder) pairEntry(tag byte, a, c uint16) uint16 {
	payload := make([]byte, 4)
	binary.BigEndian.PutUint16(payload, a)
	binary.BigEndian.PutUint16(payload[2:], c)
	return b.add(tag, payload)
}

func (b *constantPoolBuilder) u4Entry(tag byte, bits uint32) uint16 {
	payload := make([]byte, 4)
	binary.BigEndian.PutUint32(payload, bits)
	return b.add(tag, payload)
}

func (b *constantPoolBuilder) u8Entry(tag byte, bits uint64) uint16 {
	payload := make([]byte, 8)
	binary.BigEndian.PutUint64(payload, bits)
	return b.add(tag, payload)
}

func (b *constantPoolBuilder) methodHandle(kind byte, index uint16) uint16 {
	payload := []byte{kind, 0, 0}
	binary.BigEndian.PutUint16(payload[1:], index)
	return b.add(15, payload)
}

func u2Bytes(value uint16) []byte {
	return []byte{byte(value >> 8), byte(value)}
}

func classBytes(t *testing.T, spec classSpec) ([]byte, uint16) {
	t.Helper()
	if spec.Major == 0 {
		spec.Major = 70
	}
	if spec.Name == "" {
		spec.Name = "fixture/Test"
	}
	if spec.Super == "" {
		spec.Super = "java/lang/Object"
	}
	pool := newConstantPoolBuilder()
	thisName := pool.utf8(spec.Name)
	thisClass := pool.u2Entry(7, thisName)
	superName := pool.utf8(spec.Super)
	superClass := pool.u2Entry(7, superName)
	interfaces := make([]uint16, 0, len(spec.Interfaces))
	for _, name := range spec.Interfaces {
		interfaces = append(interfaces, pool.u2Entry(cpClass, pool.utf8(name)))
	}

	var refIndex uint16
	if spec.MethodOwner != "" {
		ownerName := pool.utf8(spec.MethodOwner)
		ownerClass := pool.u2Entry(7, ownerName)
		methodName := pool.utf8(spec.MethodName)
		methodDesc := pool.utf8(spec.MethodDesc)
		nameAndType := pool.pairEntry(12, methodName, methodDesc)
		refIndex = pool.pairEntry(10, ownerClass, nameAndType)
	}

	fields := make([][]byte, 0, len(spec.Fields))
	for _, field := range spec.Fields {
		access := field.Access
		if access == 0 {
			access = 0x0001
		}
		var attributes [][]byte
		if field.Constant != nil {
			name := pool.utf8("ConstantValue")
			index := classConstantIndex(t, pool, *field.Constant)
			attributes = append(attributes, attributeFixture(name, u2Bytes(index)))
		}
		fields = append(fields, memberFixture(
			access, pool.utf8(field.Name), pool.utf8(field.Descriptor), attributes...,
		))
	}

	codeName := uint16(0)
	if len(spec.Methods) != 0 {
		codeName = pool.utf8("Code")
	}
	methods := make([][]byte, 0, len(spec.Methods))
	for _, method := range spec.Methods {
		access := method.Access
		if access == 0 {
			access = 0x0001
		}
		descriptor := method.Descriptor
		if descriptor == "" {
			descriptor = "()V"
		}
		var bytecode []byte
		for _, instruction := range method.Code {
			bytecode = append(bytecode, instruction.Opcode)
			switch {
			case instruction.Member != nil:
				index := classMemberIndex(pool, *instruction.Member, false)
				bytecode = append(bytecode, u2Bytes(index)...)
				if instruction.Opcode == 0xb9 {
					bytecode = append(bytecode, structuralInvokeInterfaceCount(t, instruction.Member.Descriptor), 0)
				}
			case instruction.Field != nil:
				bytecode = append(bytecode, u2Bytes(classMemberIndex(pool, *instruction.Field, true))...)
			case instruction.Constant != nil:
				index := classConstantIndex(t, pool, *instruction.Constant)
				if instruction.Opcode == 0x12 {
					if index > 255 {
						t.Fatalf("ldc constant index %d exceeds u1", index)
					}
					bytecode = append(bytecode, byte(index))
				} else {
					bytecode = append(bytecode, u2Bytes(index)...)
				}
			case instruction.ClassName != "":
				index := pool.u2Entry(cpClass, pool.utf8(instruction.ClassName))
				bytecode = append(bytecode, u2Bytes(index)...)
				if instruction.Opcode == 0xc5 {
					bytecode = append(bytecode, instruction.Operands...)
				}
			default:
				bytecode = append(bytecode, instruction.Operands...)
			}
		}
		var methodAttributes [][]byte
		if !method.NoCode {
			maxStack := method.MaxStack
			if maxStack == 0 {
				maxStack = 8
			}
			maxLocals := method.MaxLocals
			if maxLocals == 0 {
				maxLocals = 8
			}
			code := append(u2Bytes(maxStack), u2Bytes(maxLocals)...)
			code = append(code, u4Bytes(uint32(len(bytecode)))...)
			code = append(code, bytecode...)
			code = append(code, u2Bytes(uint16(len(method.Handlers)))...)
			for _, handler := range method.Handlers {
				code = append(code, u2Bytes(uint16(handler.Start))...)
				code = append(code, u2Bytes(uint16(handler.End))...)
				code = append(code, u2Bytes(uint16(handler.Handler))...)
				catch := uint16(0)
				if handler.CatchType != "" {
					catch = pool.u2Entry(cpClass, pool.utf8(handler.CatchType))
				}
				code = append(code, u2Bytes(catch)...)
			}
			var codeAttributes [][]byte
			if method.StackMapRaw != nil {
				codeAttributes = append(codeAttributes, attributeFixture(pool.utf8("StackMapTable"), method.StackMapRaw))
			} else if method.StackMap != nil {
				codeAttributes = append(codeAttributes, attributeFixture(
					pool.utf8("StackMapTable"), stackMapTableFixture(t, pool, method.StackMap),
				))
			}
			code = append(code, u2Bytes(uint16(len(codeAttributes)))...)
			for _, attribute := range codeAttributes {
				code = append(code, attribute...)
			}
			methodAttributes = append(methodAttributes, attributeFixture(codeName, code))
		}
		methods = append(methods, memberFixture(
			access, pool.utf8(method.Name), pool.utf8(descriptor), methodAttributes...,
		))
	}

	data := finishClass(spec.Minor, spec.Major, pool, thisClass, superClass, interfaces)
	data = data[:len(data)-6]
	data = append(data, u2Bytes(uint16(len(fields)))...)
	for _, field := range fields {
		data = append(data, field...)
	}
	data = append(data, u2Bytes(uint16(len(methods)))...)
	for _, method := range methods {
		data = append(data, method...)
	}
	data = append(data, 0, 0)
	return data, refIndex
}

func stackMapTableFixture(t *testing.T, pool *constantPoolBuilder, frames []stackMapFrameSpec) []byte {
	t.Helper()
	payload := u2Bytes(uint16(len(frames)))
	previous := -1
	for _, frame := range frames {
		delta := int(frame.Offset)
		if previous >= 0 {
			delta -= previous + 1
		}
		if delta < 0 || delta > math.MaxUint16 {
			t.Fatalf("invalid stack-map frame offset %d after %d", frame.Offset, previous)
		}
		payload = append(payload, 255)
		payload = append(payload, u2Bytes(uint16(delta))...)
		payload = append(payload, u2Bytes(uint16(len(frame.Locals)))...)
		for _, value := range frame.Locals {
			payload = append(payload, verificationTypeFixture(t, pool, value)...)
		}
		payload = append(payload, u2Bytes(uint16(len(frame.Stack)))...)
		for _, value := range frame.Stack {
			payload = append(payload, verificationTypeFixture(t, pool, value)...)
		}
		previous = int(frame.Offset)
	}
	return payload
}

func verificationTypeFixture(t *testing.T, pool *constantPoolBuilder, value string) []byte {
	t.Helper()
	switch value {
	case "Top":
		return []byte{0}
	case "I":
		return []byte{1}
	case "F":
		return []byte{2}
	case "D":
		return []byte{3}
	case "J":
		return []byte{4}
	case "N":
		return []byte{5}
	case "UThis":
		return []byte{6}
	}
	if strings.HasPrefix(value, "@") {
		offset, err := strconv.ParseUint(strings.TrimPrefix(value, "@"), 10, 16)
		if err != nil {
			t.Fatalf("invalid uninitialized stack-map value %q", value)
		}
		return append([]byte{8}, u2Bytes(uint16(offset))...)
	}
	name := value
	if strings.HasPrefix(value, "L") && strings.HasSuffix(value, ";") {
		name = value[1 : len(value)-1]
	}
	return append([]byte{7}, u2Bytes(pool.u2Entry(cpClass, pool.utf8(name)))...)
}

func classMemberIndex(pool *constantPoolBuilder, reference memberReference, field bool) uint16 {
	owner := pool.u2Entry(cpClass, pool.utf8(reference.Owner))
	nameAndType := pool.pairEntry(
		cpNameAndType, pool.utf8(reference.Name), pool.utf8(reference.Descriptor),
	)
	tag := byte(cpMethodref)
	if field {
		tag = cpFieldref
	} else if reference.Interface {
		tag = cpInterfaceMethodref
	}
	return pool.pairEntry(tag, owner, nameAndType)
}

func classConstantIndex(t *testing.T, pool *constantPoolBuilder, value constantValue) uint16 {
	t.Helper()
	switch value.Kind {
	case constantString:
		return pool.u2Entry(cpString, pool.utf8(value.String))
	case constantInteger:
		return pool.u4Entry(cpInteger, uint32(value.Integer))
	case constantFloat:
		return pool.u4Entry(cpFloat, uint32(value.Integer))
	case constantLong:
		return pool.u8Entry(cpLong, uint64(value.Integer))
	case constantDouble:
		return pool.u8Entry(cpDouble, uint64(value.Integer))
	case constantClass:
		return pool.u2Entry(cpClass, pool.utf8(value.String))
	default:
		t.Fatalf("unsupported fixture constant kind %d", value.Kind)
		return 0
	}
}

func finishClass(minor, major uint16, pool *constantPoolBuilder, thisClass, superClass uint16, interfaces []uint16) []byte {
	data := make([]byte, 0, 16)
	data = append(data, 0xca, 0xfe, 0xba, 0xbe)
	data = append(data, u2Bytes(minor)...)
	data = append(data, u2Bytes(major)...)
	data = append(data, u2Bytes(pool.next)...)
	for _, entry := range pool.entries {
		data = append(data, entry...)
	}
	data = append(data, 0x00, 0x21)
	data = append(data, u2Bytes(thisClass)...)
	data = append(data, u2Bytes(superClass)...)
	data = append(data, u2Bytes(uint16(len(interfaces)))...)
	for _, index := range interfaces {
		data = append(data, u2Bytes(index)...)
	}
	data = append(data, 0, 0, 0, 0, 0, 0)
	return data
}

func finishClassWithBootstrapMethods(
	minor, major uint16,
	pool *constantPoolBuilder,
	thisClass, superClass uint16,
	count uint16,
) []byte {
	attributeName := pool.utf8("BootstrapMethods")
	methodName := pool.utf8("bootstrap")
	methodDescriptor := pool.utf8("()V")
	nameAndType := pool.pairEntry(cpNameAndType, methodName, methodDescriptor)
	methodReference := pool.pairEntry(cpMethodref, thisClass, nameAndType)
	handle := pool.methodHandle(6, methodReference)
	payload := append([]byte{}, u2Bytes(count)...)
	for range count {
		payload = append(payload, u2Bytes(handle)...)
		payload = append(payload, 0, 0)
	}
	data := finishClass(minor, major, pool, thisClass, superClass, nil)
	data = data[:len(data)-6]
	data = append(data, 0, 0, 0, 0, 0, 1)
	return append(data, attributeFixture(attributeName, payload)...)
}

func methodHandleClass(major uint16, kind byte, targetTag byte, name string) []byte {
	pool := newConstantPoolBuilder()
	thisName := pool.utf8("handles/Test")
	thisClass := pool.u2Entry(7, thisName)
	superName := pool.utf8("java/lang/Object")
	superClass := pool.u2Entry(7, superName)
	memberName := pool.utf8(name)
	descriptor := "()V"
	if targetTag == 9 {
		descriptor = "I"
	}
	memberDescriptor := pool.utf8(descriptor)
	nameAndType := pool.pairEntry(12, memberName, memberDescriptor)
	target := pool.pairEntry(targetTag, thisClass, nameAndType)
	pool.methodHandle(kind, target)
	return finishClass(0, major, pool, thisClass, superClass, nil)
}

func invalidPoolIndex(pool *constantPoolBuilder, kind string) uint16 {
	switch kind {
	case "zero":
		return 0
	case "out-of-range":
		return 0xffff
	case "unusable":
		return pool.u8Entry(5, 1) + 1
	case "wrong-tag":
		return pool.u4Entry(3, 1)
	default:
		panic("unknown invalid pool index kind: " + kind)
	}
}

func TestParseClassValidatesMethodHandleTargets(t *testing.T) {
	valid := []struct {
		name      string
		major     uint16
		kind, tag byte
		member    string
	}{
		{"get-field", 51, 1, 9, "value"},
		{"get-static", 51, 2, 9, "value"},
		{"put-field", 51, 3, 9, "value"},
		{"put-static", 51, 4, 9, "value"},
		{"invoke-virtual", 51, 5, 10, "run"},
		{"invoke-static-method-pre-52", 51, 6, 10, "run"},
		{"invoke-static-interface-at-52", 52, 6, 11, "run"},
		{"invoke-special-method-pre-52", 51, 7, 10, "run"},
		{"invoke-special-interface-at-52", 52, 7, 11, "run"},
		{"new-invoke-special-init", 51, 8, 10, "<init>"},
		{"invoke-interface", 51, 9, 11, "run"},
	}
	for _, test := range valid {
		t.Run("valid-"+test.name, func(t *testing.T) {
			if _, err := parseClass(
				methodHandleClass(test.major, test.kind, test.tag, test.member),
				DefaultOptions().Limits,
			); err != nil {
				t.Fatalf("valid method handle rejected: %v", err)
			}
		})
	}

	invalid := []struct {
		name      string
		major     uint16
		kind, tag byte
		member    string
	}{
		{"get-field-method", 51, 1, 10, "run"},
		{"get-static-method", 51, 2, 10, "run"},
		{"put-field-method", 51, 3, 10, "run"},
		{"put-static-method", 51, 4, 10, "run"},
		{"invoke-virtual-interface", 51, 5, 11, "run"},
		{"invoke-static-interface-pre-52", 51, 6, 11, "run"},
		{"invoke-special-interface-pre-52", 51, 7, 11, "run"},
		{"new-invoke-special-interface", 52, 8, 11, "<init>"},
		{"invoke-interface-method", 51, 9, 10, "run"},
		{"new-invoke-special-non-init", 51, 8, 10, "run"},
	}
	for _, kind := range []byte{5, 6, 7, 9} {
		tag := byte(10)
		if kind == 9 {
			tag = 11
		}
		for _, name := range []string{"<init>", "<clinit>"} {
			invalid = append(invalid, struct {
				name      string
				major     uint16
				kind, tag byte
				member    string
			}{
				name:  "kind-" + strconv.Itoa(int(kind)) + "-" + name,
				major: 52, kind: kind, tag: tag, member: name,
			})
		}
	}
	for _, test := range invalid {
		t.Run("invalid-"+test.name, func(t *testing.T) {
			if _, err := parseClass(
				methodHandleClass(test.major, test.kind, test.tag, test.member),
				DefaultOptions().Limits,
			); err == nil {
				t.Fatal("invalid method handle parsed")
			}
		})
	}
}

func TestParseClassResolvesMethodRef(t *testing.T) {
	data, refIndex := classBytes(t, classSpec{
		MethodOwner: "java/lang/Runtime", MethodName: "exec",
		MethodDesc: "(Ljava/lang/String;)Ljava/lang/Process;",
	})
	cf, err := parseClass(data, DefaultOptions().Limits)
	if err != nil {
		t.Fatal(err)
	}
	ref, err := cf.memberRef(refIndex)
	if err != nil {
		t.Fatal(err)
	}
	if ref.Owner != "java/lang/Runtime" || ref.Name != "exec" ||
		ref.Descriptor != "(Ljava/lang/String;)Ljava/lang/Process;" || ref.Interface {
		t.Fatalf("member ref=%+v", ref)
	}
}

func TestParseClassResolvesInvokeDynamic(t *testing.T) {
	pool := newConstantPoolBuilder()
	thisName := pool.utf8("dynamic/Test")
	thisClass := pool.u2Entry(7, thisName)
	superName := pool.utf8("java/lang/Object")
	superClass := pool.u2Entry(7, superName)
	callName := pool.utf8("bootstrapCall")
	callDescriptor := pool.utf8("(I)Ljava/lang/String;")
	nameAndTypeIndex := pool.pairEntry(12, callName, callDescriptor)
	invokeDynamicIndex := pool.pairEntry(18, 7, nameAndTypeIndex)
	data := finishClassWithBootstrapMethods(0, 51, pool, thisClass, superClass, 8)

	cf, err := parseClass(data, DefaultOptions().Limits)
	if err != nil {
		t.Fatal(err)
	}
	nameAndType, err := cf.nameAndType(nameAndTypeIndex)
	if err != nil {
		t.Fatal(err)
	}
	if nameAndType.Name != "bootstrapCall" ||
		nameAndType.Descriptor != "(I)Ljava/lang/String;" {
		t.Fatalf("name and type=%+v", nameAndType)
	}
	callSite, err := cf.invokeDynamic(invokeDynamicIndex)
	if err != nil {
		t.Fatal(err)
	}
	if callSite.Bootstrap != 7 || callSite.Name != "bootstrapCall" ||
		callSite.Descriptor != "(I)Ljava/lang/String;" {
		t.Fatalf("invokedynamic=%+v", callSite)
	}
}

func TestParseClassRejectsMalformedNestedConstantPoolReferences(t *testing.T) {
	type fixture func(*constantPoolBuilder, uint16)
	var tests []struct {
		name string
		add  fixture
	}
	for _, kind := range []string{"zero", "out-of-range", "unusable", "wrong-tag"} {
		kind := kind
		tests = append(tests,
			struct {
				name string
				add  fixture
			}{
				"member-owner-" + kind,
				func(pool *constantPoolBuilder, _ uint16) {
					name := pool.utf8("run")
					descriptor := pool.utf8("()V")
					nameAndType := pool.pairEntry(12, name, descriptor)
					pool.pairEntry(10, invalidPoolIndex(pool, kind), nameAndType)
				},
			},
			struct {
				name string
				add  fixture
			}{
				"member-name-and-type-" + kind,
				func(pool *constantPoolBuilder, owner uint16) {
					pool.pairEntry(10, owner, invalidPoolIndex(pool, kind))
				},
			},
			struct {
				name string
				add  fixture
			}{
				"string-utf8-" + kind,
				func(pool *constantPoolBuilder, _ uint16) {
					pool.u2Entry(8, invalidPoolIndex(pool, kind))
				},
			},
			struct {
				name string
				add  fixture
			}{
				"method-type-utf8-" + kind,
				func(pool *constantPoolBuilder, _ uint16) {
					pool.u2Entry(16, invalidPoolIndex(pool, kind))
				},
			},
			struct {
				name string
				add  fixture
			}{
				"dynamic-name-and-type-" + kind,
				func(pool *constantPoolBuilder, _ uint16) {
					pool.pairEntry(17, 0, invalidPoolIndex(pool, kind))
				},
			},
			struct {
				name string
				add  fixture
			}{
				"invokedynamic-name-and-type-" + kind,
				func(pool *constantPoolBuilder, _ uint16) {
					pool.pairEntry(18, 0, invalidPoolIndex(pool, kind))
				},
			},
		)
	}
	for _, kind := range []string{"out-of-range", "wrong-tag"} {
		kind := kind
		tests = append(tests,
			struct {
				name string
				add  fixture
			}{
				"member-owner-class-name-utf8-" + kind,
				func(pool *constantPoolBuilder, _ uint16) {
					owner := pool.u2Entry(7, invalidPoolIndex(pool, kind))
					name := pool.utf8("run")
					descriptor := pool.utf8("()V")
					nameAndType := pool.pairEntry(12, name, descriptor)
					pool.pairEntry(10, owner, nameAndType)
				},
			},
			struct {
				name string
				add  fixture
			}{
				"member-name-and-type-name-utf8-" + kind,
				func(pool *constantPoolBuilder, owner uint16) {
					descriptor := pool.utf8("()V")
					nameAndType := pool.pairEntry(12, invalidPoolIndex(pool, kind), descriptor)
					pool.pairEntry(10, owner, nameAndType)
				},
			},
			struct {
				name string
				add  fixture
			}{
				"member-name-and-type-descriptor-utf8-" + kind,
				func(pool *constantPoolBuilder, owner uint16) {
					name := pool.utf8("run")
					nameAndType := pool.pairEntry(12, name, invalidPoolIndex(pool, kind))
					pool.pairEntry(10, owner, nameAndType)
				},
			},
		)
		for _, tag := range []byte{17, 18} {
			tag := tag
			label := "dynamic"
			if tag == 18 {
				label = "invokedynamic"
			}
			tests = append(tests,
				struct {
					name string
					add  fixture
				}{
					label + "-name-and-type-name-utf8-" + kind,
					func(pool *constantPoolBuilder, _ uint16) {
						descriptor := pool.utf8("()V")
						nameAndType := pool.pairEntry(12, invalidPoolIndex(pool, kind), descriptor)
						pool.pairEntry(tag, 0, nameAndType)
					},
				},
				struct {
					name string
					add  fixture
				}{
					label + "-name-and-type-descriptor-utf8-" + kind,
					func(pool *constantPoolBuilder, _ uint16) {
						name := pool.utf8("call")
						nameAndType := pool.pairEntry(12, name, invalidPoolIndex(pool, kind))
						pool.pairEntry(tag, 0, nameAndType)
					},
				},
			)
		}
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			pool := newConstantPoolBuilder()
			thisName := pool.utf8("nested/Test")
			thisClass := pool.u2Entry(7, thisName)
			superName := pool.utf8("java/lang/Object")
			superClass := pool.u2Entry(7, superName)
			test.add(pool, thisClass)
			data := finishClass(0, 70, pool, thisClass, superClass, nil)
			if _, err := parseClass(data, DefaultOptions().Limits); err == nil {
				t.Fatal("class with malformed nested constant-pool reference parsed")
			}
		})
	}
}

func TestParseClassEnforcesConstantPoolTagVersions(t *testing.T) {
	tests := []struct {
		name       string
		tag        byte
		minVersion uint16
		add        func(*constantPoolBuilder, uint16)
	}{
		{
			name: "method-handle", tag: 15, minVersion: 51,
			add: func(pool *constantPoolBuilder, owner uint16) {
				name := pool.utf8("run")
				descriptor := pool.utf8("()V")
				nameAndType := pool.pairEntry(12, name, descriptor)
				target := pool.pairEntry(10, owner, nameAndType)
				pool.methodHandle(6, target)
			},
		},
		{
			name: "method-type", tag: 16, minVersion: 51,
			add: func(pool *constantPoolBuilder, _ uint16) {
				pool.u2Entry(16, pool.utf8("()V"))
			},
		},
		{
			name: "invokedynamic", tag: 18, minVersion: 51,
			add: func(pool *constantPoolBuilder, _ uint16) {
				name := pool.utf8("call")
				descriptor := pool.utf8("()V")
				pool.pairEntry(18, 0, pool.pairEntry(12, name, descriptor))
			},
		},
		{
			name: "module", tag: 19, minVersion: 53,
			add: func(pool *constantPoolBuilder, _ uint16) {
				pool.u2Entry(19, pool.utf8("fixture.module"))
			},
		},
		{
			name: "package", tag: 20, minVersion: 53,
			add: func(pool *constantPoolBuilder, _ uint16) {
				pool.u2Entry(20, pool.utf8("fixture/package"))
			},
		},
		{
			name: "dynamic", tag: 17, minVersion: 55,
			add: func(pool *constantPoolBuilder, _ uint16) {
				name := pool.utf8("constant")
				descriptor := pool.utf8("Ljava/lang/String;")
				pool.pairEntry(17, 0, pool.pairEntry(12, name, descriptor))
			},
		},
	}
	for _, test := range tests {
		for _, version := range []struct {
			name  string
			major uint16
			valid bool
		}{
			{"below", test.minVersion - 1, false},
			{"at", test.minVersion, true},
		} {
			t.Run(test.name+"-"+version.name, func(t *testing.T) {
				pool := newConstantPoolBuilder()
				thisName := pool.utf8("versions/Test")
				thisClass := pool.u2Entry(7, thisName)
				superName := pool.utf8("java/lang/Object")
				superClass := pool.u2Entry(7, superName)
				test.add(pool, thisClass)
				var data []byte
				if test.tag == cpDynamic || test.tag == cpInvokeDynamic {
					data = finishClassWithBootstrapMethods(0, version.major, pool, thisClass, superClass, 1)
				} else {
					data = finishClass(0, version.major, pool, thisClass, superClass, nil)
				}
				_, err := parseClass(data, DefaultOptions().Limits)
				if version.valid && err != nil {
					t.Fatalf("tag %d rejected at version %d: %v", test.tag, version.major, err)
				}
				if !version.valid && err == nil {
					t.Fatalf("tag %d parsed below version %d", test.tag, test.minVersion)
				}
			})
		}
	}
}

func TestParseClassRejectsLongAndDoubleInFinalPoolSlot(t *testing.T) {
	for _, tag := range []byte{5, 6} {
		t.Run(strconv.Itoa(int(tag)), func(t *testing.T) {
			data := []byte{
				0xca, 0xfe, 0xba, 0xbe,
				0, 0, 0, 70,
				0, 2,
				tag, 0, 0, 0, 0, 0, 0, 0, 1,
			}
			if _, err := parseClass(data, DefaultOptions().Limits); err == nil {
				t.Fatalf("tag %d parsed without its unusable slot", tag)
			}
		})
	}
}

func TestParseClassHeaderAndInterfaces(t *testing.T) {
	pool := newConstantPoolBuilder()
	thisName := pool.utf8("p/Child")
	thisClass := pool.u2Entry(7, thisName)
	superName := pool.utf8("p/Parent")
	superClass := pool.u2Entry(7, superName)
	interfaceName := pool.utf8("p/Contract")
	interfaceClass := pool.u2Entry(7, interfaceName)
	data := finishClass(0, 70, pool, thisClass, superClass, []uint16{interfaceClass})

	cf, err := parseClass(data, DefaultOptions().Limits)
	if err != nil {
		t.Fatal(err)
	}
	if cf.Minor != 0 || cf.Major != 70 || cf.Access != 0x21 ||
		cf.Name != "p/Child" || cf.Super != "p/Parent" ||
		len(cf.Interfaces) != 1 || cf.Interfaces[0] != "p/Contract" {
		t.Fatalf("class=%+v", cf)
	}
}

func TestParseClassAcceptsSupportedMajorVersions(t *testing.T) {
	for major := uint16(45); major <= 70; major++ {
		major := major
		t.Run(strconv.Itoa(int(major)), func(t *testing.T) {
			data, _ := classBytes(t, classSpec{Major: major})
			if _, err := parseClass(data, DefaultOptions().Limits); err != nil {
				t.Fatalf("major %d: %v", major, err)
			}
		})
	}
}

func TestParseClassRejectsUnsupportedVersionsWithTypedError(t *testing.T) {
	for _, version := range []struct{ minor, major uint16 }{
		{0, 44}, {0, 71}, {1, 56}, {12345, 70},
	} {
		data, _ := classBytes(t, classSpec{Minor: version.minor, Major: version.major})
		_, err := parseClass(data, DefaultOptions().Limits)
		var versionErr *unsupportedClassVersionError
		if !errors.As(err, &versionErr) {
			t.Fatalf("version %d.%d error %T %v is not typed", version.major, version.minor, err, err)
		}
		if !strings.Contains(err.Error(), diagClassUnsupported) {
			t.Fatalf("version error %q omits diagnostic code", err)
		}
	}
}

func TestParseClassAppliesMinorVersionRules(t *testing.T) {
	for _, version := range []struct{ minor, major uint16 }{
		{65535, 45}, {12345, 55}, {0, 56}, {65535, 56}, {0, 70}, {65535, 70},
	} {
		data, _ := classBytes(t, classSpec{Minor: version.minor, Major: version.major})
		if _, err := parseClass(data, DefaultOptions().Limits); err != nil {
			t.Fatalf("version %d.%d: %v", version.major, version.minor, err)
		}
	}
}

func TestParseClassRejectsBadMagicAndTags(t *testing.T) {
	data, _ := classBytes(t, classSpec{})
	data[0] = 0
	if _, err := parseClass(data, DefaultOptions().Limits); err == nil {
		t.Fatal("bad magic parsed")
	}

	data, _ = classBytes(t, classSpec{})
	data[10] = 2
	if _, err := parseClass(data, DefaultOptions().Limits); err == nil {
		t.Fatal("reserved constant-pool tag parsed")
	}
}

func TestParseClassParsesEveryRequiredConstantPoolTag(t *testing.T) {
	pool := newConstantPoolBuilder()
	thisName := pool.utf8("all/Tags")
	thisClass := pool.u2Entry(7, thisName)
	superName := pool.utf8("java/lang/Object")
	superClass := pool.u2Entry(7, superName)
	stringText := pool.utf8("value")
	descriptor := pool.utf8("()V")
	memberName := pool.utf8("run")
	nameAndType := pool.pairEntry(12, memberName, descriptor)
	fieldDescriptor := pool.utf8("I")
	fieldNameAndType := pool.pairEntry(12, stringText, fieldDescriptor)
	dynamicName := pool.utf8("constant")
	dynamicNameAndType := pool.pairEntry(12, dynamicName, fieldDescriptor)
	integerIndex := pool.u4Entry(3, 0xffff_fffe)
	floatIndex := pool.u4Entry(4, math.Float32bits(1.5))
	longIndex := pool.u8Entry(5, 0xffff_ffff_ffff_fffd)
	doubleIndex := pool.u8Entry(6, math.Float64bits(2.5))
	stringIndex := pool.u2Entry(8, stringText)
	fieldIndex := pool.pairEntry(9, thisClass, fieldNameAndType)
	methodIndex := pool.pairEntry(10, thisClass, nameAndType)
	interfaceIndex := pool.pairEntry(11, thisClass, nameAndType)
	handleIndex := pool.methodHandle(6, methodIndex)
	methodTypeIndex := pool.u2Entry(16, descriptor)
	dynamicIndex := pool.pairEntry(17, 0, dynamicNameAndType)
	invokeDynamicIndex := pool.pairEntry(18, 0, nameAndType)
	moduleName := pool.utf8("fixture.module")
	moduleIndex := pool.u2Entry(19, moduleName)
	packageName := pool.utf8("fixture/package")
	packageIndex := pool.u2Entry(20, packageName)
	data := finishClassWithBootstrapMethods(0, 70, pool, thisClass, superClass, 1)

	cf, err := parseClass(data, DefaultOptions().Limits)
	if err != nil {
		t.Fatal(err)
	}
	wantTags := map[uint16]uint8{
		thisName: 1, integerIndex: 3, floatIndex: 4, longIndex: 5, doubleIndex: 6,
		thisClass: 7, stringIndex: 8, fieldIndex: 9, methodIndex: 10,
		interfaceIndex: 11, nameAndType: 12, handleIndex: 15, methodTypeIndex: 16,
		dynamicIndex: 17, invokeDynamicIndex: 18, moduleIndex: 19, packageIndex: 20,
	}
	for index, want := range wantTags {
		if got := cf.Pool[index].tag; got != want {
			t.Errorf("pool[%d].tag=%d want %d", index, got, want)
		}
	}
	if cf.Pool[longIndex+1].tag != 0 || cf.Pool[doubleIndex+1].tag != 0 {
		t.Fatal("long and double do not reserve unusable slots")
	}
	for _, index := range []uint16{longIndex + 1, doubleIndex + 1} {
		if _, err := cf.utf8(index); err == nil {
			t.Errorf("utf8(%d) accepted unusable slot", index)
		}
		if _, err := cf.memberRef(index); err == nil {
			t.Errorf("memberRef(%d) accepted unusable slot", index)
		}
		if _, err := cf.constantValue(index); err == nil {
			t.Errorf("constantValue(%d) accepted unusable slot", index)
		}
	}

	values := []struct {
		index uint16
		kind  constantKind
	}{
		{stringIndex, constantString}, {integerIndex, constantInteger},
		{floatIndex, constantFloat}, {longIndex, constantLong}, {doubleIndex, constantDouble},
		{thisClass, constantClass}, {methodTypeIndex, constantMethodType},
		{handleIndex, constantMethodHandle}, {dynamicIndex, constantDynamic},
	}
	for _, test := range values {
		value, err := cf.constantValue(test.index)
		if err != nil {
			t.Errorf("constantValue(%d): %v", test.index, err)
			continue
		}
		if value.Kind != test.kind {
			t.Errorf("constantValue(%d).Kind=%d want %d", test.index, value.Kind, test.kind)
		}
	}
	stringValue, _ := cf.constantValue(stringIndex)
	integerValue, _ := cf.constantValue(integerIndex)
	longValue, _ := cf.constantValue(longIndex)
	classValue, _ := cf.constantValue(thisClass)
	methodTypeValue, _ := cf.constantValue(methodTypeIndex)
	handleValue, _ := cf.constantValue(handleIndex)
	if stringValue.String != "value" || integerValue.Integer != -2 || longValue.Integer != -3 ||
		classValue.String != "all/Tags" || methodTypeValue.String != "()V" ||
		handleValue.Reference == nil || handleValue.Reference.Name != "run" {
		t.Fatalf("resolved constants: string=%+v int=%+v long=%+v class=%+v methodType=%+v handle=%+v",
			stringValue, integerValue, longValue, classValue, methodTypeValue, handleValue)
	}

	methodRef, err := cf.memberRef(methodIndex)
	if err != nil || methodRef.Interface {
		t.Fatalf("method ref=%+v err=%v", methodRef, err)
	}
	interfaceRef, err := cf.memberRef(interfaceIndex)
	if err != nil || !interfaceRef.Interface {
		t.Fatalf("interface ref=%+v err=%v", interfaceRef, err)
	}
	fieldRef, err := cf.memberRef(fieldIndex)
	if err != nil || fieldRef.Interface || fieldRef.Name != "value" || fieldRef.Descriptor != "I" {
		t.Fatalf("field ref=%+v err=%v", fieldRef, err)
	}
}

func TestParseClassResolversRejectInvalidIndexesAndTags(t *testing.T) {
	data, methodIndex := classBytes(t, classSpec{MethodOwner: "x/Y", MethodName: "z", MethodDesc: "()V"})
	cf, err := parseClass(data, DefaultOptions().Limits)
	if err != nil {
		t.Fatal(err)
	}
	longPool := newConstantPoolBuilder()
	longIndex := longPool.u8Entry(5, 1)
	longData := finishClass(0, 70, longPool, longIndex, 0, nil)
	longCF, err := parseClass(longData, DefaultOptions().Limits)
	if err == nil || longCF != nil {
		t.Fatal("class header unexpectedly accepted a long as this_class")
	}

	indexes := []uint16{0, uint16(len(cf.Pool)), methodIndex}
	for _, index := range indexes {
		if _, err := cf.utf8(index); err == nil {
			t.Errorf("utf8(%d) succeeded", index)
		}
		if _, err := cf.className(index); err == nil {
			t.Errorf("className(%d) succeeded", index)
		}
		if _, err := cf.constantValue(index); err == nil {
			t.Errorf("constantValue(%d) succeeded", index)
		}
	}
	for _, index := range []uint16{0, uint16(len(cf.Pool)), 1} {
		if _, err := cf.memberRef(index); err == nil {
			t.Errorf("memberRef(%d) succeeded", index)
		}
	}
}

func TestParseClassRejectsMalformedReferencedIndexes(t *testing.T) {
	for _, mutate := range []func([]byte){
		func(data []byte) { data[len(data)-12], data[len(data)-11] = 0, 0 },
		func(data []byte) { data[len(data)-10], data[len(data)-9] = 0xff, 0xff },
	} {
		data, _ := classBytes(t, classSpec{})
		mutate(data)
		if _, err := parseClass(data, DefaultOptions().Limits); err == nil {
			t.Fatal("malformed class index parsed")
		}
	}
}

func TestParseClassRejectsArtifactOverLimit(t *testing.T) {
	data := make([]byte, (32<<20)+1)
	copy(data, []byte{0xca, 0xfe, 0xba, 0xbe})
	if _, err := parseClass(data, DefaultOptions().Limits); err == nil {
		t.Fatal("artifact over 32 MiB parsed")
	}

	valid, _ := classBytes(t, classSpec{})
	limits := DefaultOptions().Limits
	limits.MaxArtifactBytes = int64(len(valid) - 1)
	if _, err := parseClass(valid, limits); err == nil {
		t.Fatal("artifact over custom limit parsed")
	}
}

func sharedUTF8Class(payloadBytes, references int) ([]byte, uint16) {
	pool := newConstantPoolBuilder()
	thisName := pool.utf8("shared/Test")
	thisClass := pool.u2Entry(7, thisName)
	superName := pool.utf8("java/lang/Object")
	superClass := pool.u2Entry(7, superName)
	shared := pool.utf8(strings.Repeat("x", payloadBytes))
	for range references {
		pool.u2Entry(7, shared)
	}
	return finishClass(0, 70, pool, thisClass, superClass, nil), shared
}

func TestParseClassSharedUTF8ReferenceAmplificationIsBounded(t *testing.T) {
	data, _ := sharedUTF8Class(8<<10, 2_048)
	var parseErr error
	allocations := testing.AllocsPerRun(1, func() {
		_, parseErr = parseClass(data, DefaultOptions().Limits)
	})
	if parseErr != nil {
		t.Fatal(parseErr)
	}
	if allocations > 32 {
		t.Fatalf("shared UTF-8 parse allocated %.0f objects; want at most 32", allocations)
	}
}

func TestParseClassUTF8ResolverReusesDecodedValue(t *testing.T) {
	data, shared := sharedUTF8Class(8<<10, 1)
	cf, err := parseClass(data, DefaultOptions().Limits)
	if err != nil {
		t.Fatal(err)
	}
	var got string
	var resolveErr error
	allocations := testing.AllocsPerRun(100, func() {
		got, resolveErr = cf.utf8(shared)
	})
	if resolveErr != nil {
		t.Fatal(resolveErr)
	}
	if got != strings.Repeat("x", 8<<10) {
		t.Fatalf("resolved UTF-8 length=%d", len(got))
	}
	if allocations != 0 {
		t.Fatalf("repeated UTF-8 resolution allocated %.0f objects; want zero", allocations)
	}
}

func TestParseClassRejectsInvalidModifiedUTF8DuringParse(t *testing.T) {
	pool := newConstantPoolBuilder()
	thisName := pool.utf8("invalid/Test")
	thisClass := pool.u2Entry(7, thisName)
	superName := pool.utf8("java/lang/Object")
	superClass := pool.u2Entry(7, superName)
	pool.utf8Raw([]byte{0})
	data := finishClass(0, 70, pool, thisClass, superClass, nil)
	if _, err := parseClass(data, DefaultOptions().Limits); err == nil {
		t.Fatal("class with invalid unused modified UTF-8 parsed")
	}
}

func TestParseClassRejectsTruncationWithoutPanic(t *testing.T) {
	data, _ := classBytes(t, classSpec{MethodOwner: "x/Y", MethodName: "z", MethodDesc: "()V"})
	for n := 0; n < len(data); n++ {
		if _, err := parseClass(data[:n], DefaultOptions().Limits); err == nil {
			t.Fatalf("prefix %d unexpectedly parsed", n)
		}
	}
}

func TestParseClassRejectsTruncatedConstantPayload(t *testing.T) {
	data := []byte{
		0xca, 0xfe, 0xba, 0xbe, 0, 0, 0, 70,
		0, 2, 1, 0xff, 0xff,
	}
	if _, err := parseClass(data, DefaultOptions().Limits); err == nil {
		t.Fatal("truncated UTF-8 payload parsed")
	}
}

func TestParseClassReaderUsesCheckedBoundedReads(t *testing.T) {
	r := classReader{data: []byte{1, 2, 3, 4, 5, 6, 7, 8}}
	if got, err := r.u1(); err != nil || got != 1 {
		t.Fatalf("u1=%d err=%v", got, err)
	}
	if got, err := r.u2(); err != nil || got != 0x0203 {
		t.Fatalf("u2=%x err=%v", got, err)
	}
	if got, err := r.bytes(2); err != nil || string(got) != "\x04\x05" {
		t.Fatalf("bytes=%x err=%v", got, err)
	}
	if err := r.skip(3); err != nil || r.remaining() != 0 {
		t.Fatalf("skip err=%v remaining=%d", err, r.remaining())
	}
	if _, err := r.u4(); err == nil || !strings.Contains(err.Error(), "offset 8") {
		t.Fatalf("u4 error=%v", err)
	}
	r = classReader{data: []byte{1}}
	if _, err := r.bytes(math.MaxUint32); err == nil || r.off != 0 {
		t.Fatalf("oversized read error=%v offset=%d", err, r.off)
	}
	if err := r.skip(math.MaxUint32); err == nil || r.off != 0 {
		t.Fatalf("oversized skip error=%v offset=%d", err, r.off)
	}
	r = classReader{data: []byte{1, 2, 3, 4, 5, 6, 7, 8}}
	if got, err := r.u8(); err != nil || got != 0x0102030405060708 {
		t.Fatalf("u8=%x err=%v", got, err)
	}
}

func TestModifiedUTF8DecodesModifiedNULAndSurrogatePair(t *testing.T) {
	data := []byte{'a', 0xc0, 0x80, 0xed, 0xa0, 0xbd, 0xed, 0xb8, 0x80}
	got, err := decodeModifiedUTF8(data)
	if err != nil {
		t.Fatal(err)
	}
	if got != "a\x00\U0001F600" {
		t.Fatalf("decoded %q", got)
	}
}

func TestModifiedUTF8AcceptsOneTwoAndThreeByteForms(t *testing.T) {
	got, err := decodeModifiedUTF8([]byte{'A', 0xc2, 0xa2, 0xe2, 0x82, 0xac})
	if err != nil || got != "A\u00a2\u20ac" {
		t.Fatalf("decoded %q err=%v", got, err)
	}
}

func TestModifiedUTF8RejectsMalformedEncodings(t *testing.T) {
	for _, data := range [][]byte{
		{0}, {0x80}, {0xc0}, {0xc0, 0x81}, {0xc1, 0x81}, {0xc2, 0x20},
		{0xe0, 0x80, 0x80}, {0xe0, 0xa0}, {0xe1, 0x80, 0x20},
		{0xf0, 0x9f, 0x98, 0x80}, {0xed, 0xa0, 0x80}, {0xed, 0xb0, 0x80},
		{0xed, 0xa0, 0x80, 'x'},
	} {
		if got, err := decodeModifiedUTF8(data); err == nil {
			t.Errorf("decoded malformed %x as %q", data, got)
		}
	}
}

func TestParseClassDecodesModifiedUTF8Constants(t *testing.T) {
	pool := newConstantPoolBuilder()
	nameIndex := pool.utf8Raw([]byte{'p', '/', 'N', 0xc0, 0x80, 0xed, 0xa0, 0xbd, 0xed, 0xb8, 0x80})
	thisClass := pool.u2Entry(7, nameIndex)
	data := finishClass(0, 70, pool, thisClass, 0, nil)
	cf, err := parseClass(data, DefaultOptions().Limits)
	if err != nil {
		t.Fatal(err)
	}
	if cf.Name != "p/N\x00\U0001F600" {
		t.Fatalf("name=%q", cf.Name)
	}
}

func TestClassParserRejectsInvalidNamesAndDescriptorKinds(t *testing.T) {
	for _, tt := range []struct {
		name string
		spec classSpec
	}{
		{"class name", classSpec{Name: "fixture.Bad"}},
		{"field name", classSpec{Fields: []classFieldSpec{{Name: "bad/name", Descriptor: "I"}}}},
		{"field descriptor", classSpec{Fields: []classFieldSpec{{Name: "bad", Descriptor: "()V"}}}},
		{"method name", classSpec{Methods: []classMethodSpec{{Access: 0x0009, Name: "bad/name", Code: []classInstructionSpec{{Opcode: 0xb1}}}}}},
		{"method descriptor", classSpec{Methods: []classMethodSpec{{Access: 0x0009, Name: "bad", Descriptor: "I", Code: []classInstructionSpec{{Opcode: 0xb1}}}}}},
		{"constructor return", classSpec{Methods: []classMethodSpec{{Name: "<init>", Descriptor: "()I", Code: []classInstructionSpec{{Opcode: 0x03}, {Opcode: 0xac}}}}}},
		{"clinit signature", classSpec{Methods: []classMethodSpec{{Name: "<clinit>", Descriptor: "(I)V", Code: []classInstructionSpec{{Opcode: 0xb1}}}}}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			data, _ := classBytes(t, tt.spec)
			if _, err := parseClass(data, DefaultOptions().Limits); err == nil {
				t.Fatalf("accepted invalid class/member form: %+v", tt.spec)
			}
		})
	}
}

func TestClassParserRejectsInvalidMethodTypeDescriptor(t *testing.T) {
	pool := newConstantPoolBuilder()
	thisClass := pool.u2Entry(cpClass, pool.utf8("fixture/BadMethodType"))
	superClass := pool.u2Entry(cpClass, pool.utf8("java/lang/Object"))
	pool.u2Entry(cpMethodType, pool.utf8("I"))
	data := finishClass(0, 51, pool, thisClass, superClass, nil)
	if _, err := parseClass(data, DefaultOptions().Limits); err == nil {
		t.Fatal("accepted CONSTANT_MethodType with field descriptor")
	}
}

func TestClassParserRejectsInvalidConstantPoolClassAndDynamicForms(t *testing.T) {
	for _, tt := range []struct {
		name string
		add  func(*constantPoolBuilder, uint16)
	}{
		{"unused class name", func(pool *constantPoolBuilder, _ uint16) {
			pool.u2Entry(cpClass, pool.utf8("bad.name"))
		}},
		{"member owner", func(pool *constantPoolBuilder, _ uint16) {
			owner := pool.u2Entry(cpClass, pool.utf8("bad.name"))
			nameType := pool.pairEntry(cpNameAndType, pool.utf8("run"), pool.utf8("()V"))
			pool.pairEntry(cpMethodref, owner, nameType)
		}},
		{"dynamic method descriptor", func(pool *constantPoolBuilder, _ uint16) {
			nameType := pool.pairEntry(cpNameAndType, pool.utf8("constant"), pool.utf8("()V"))
			pool.pairEntry(cpDynamic, 0, nameType)
		}},
		{"invokedynamic field descriptor", func(pool *constantPoolBuilder, _ uint16) {
			nameType := pool.pairEntry(cpNameAndType, pool.utf8("call"), pool.utf8("I"))
			pool.pairEntry(cpInvokeDynamic, 0, nameType)
		}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			pool := newConstantPoolBuilder()
			thisClass := pool.u2Entry(cpClass, pool.utf8("fixture/BadPoolForm"))
			superClass := pool.u2Entry(cpClass, pool.utf8("java/lang/Object"))
			tt.add(pool, thisClass)
			data := finishClassWithBootstrapMethods(0, 55, pool, thisClass, superClass, 1)
			if _, err := parseClass(data, DefaultOptions().Limits); err == nil {
				t.Fatal("accepted invalid constant-pool class/member form")
			}
		})
	}
}

func FuzzParseClassNeverPanics(f *testing.F) {
	f.Add([]byte{0xca, 0xfe, 0xba, 0xbe})
	f.Add(methodHandleClass(52, 6, 11, "run"))
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = parseClass(data, DefaultOptions().Limits)
	})
}
