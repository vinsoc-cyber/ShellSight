package javadisk

import "fmt"

const (
	cpUtf8               = 1
	cpInteger            = 3
	cpFloat              = 4
	cpLong               = 5
	cpDouble             = 6
	cpClass              = 7
	cpString             = 8
	cpFieldref           = 9
	cpMethodref          = 10
	cpInterfaceMethodref = 11
	cpNameAndType        = 12
	cpMethodHandle       = 15
	cpMethodType         = 16
	cpDynamic            = 17
	cpInvokeDynamic      = 18
	cpModule             = 19
	cpPackage            = 20
)

type cpEntry struct {
	tag  uint8
	a, b uint16
	bits uint64
	text string
}

type memberReference struct {
	Owner, Name, Descriptor string
	Interface               bool
}

type nameAndTypeReference struct {
	Name, Descriptor string
}

type invokeDynamicReference struct {
	Bootstrap        uint16
	Name, Descriptor string
}

type constantKind uint8

const (
	constantInvalid constantKind = iota
	constantString
	constantInteger
	constantFloat
	constantLong
	constantDouble
	constantClass
	constantMethodType
	constantMethodHandle
	constantDynamic
)

type constantValue struct {
	Kind       constantKind
	String     string
	Integer    int64
	Reference  *memberReference
	Bootstrap  uint16
	HandleKind uint16
}

type fieldModel struct {
	Access      uint16
	Name        string
	Descriptor  string
	Constant    *constantValue
	Annotations []annotationModel
}

type methodModel struct {
	Access      uint16
	Name        string
	Descriptor  string
	Code        *codeModel
	Annotations []annotationModel
}

type codeModel struct {
	MaxStack        uint16
	MaxLocals       uint16
	Bytes           []byte
	Handlers        []exceptionHandler
	Lines           []lineNumber
	StackMapPresent bool
	StackMapFrames  []stackMapFrame
}

type stackMapVerification struct {
	Tag       byte
	ClassName string
	Offset    uint16
}

type stackMapFrame struct {
	Offset uint32
	Locals []stackMapVerification
	Stack  []stackMapVerification
}

type exceptionHandler struct {
	Start     uint32
	End       uint32
	Handler   uint32
	CatchType string
}

type lineNumber struct {
	Offset uint32
	Line   uint16
}

type annotationModel struct {
	Descriptor string
	Values     []string
}

type bootstrapMethod struct {
	Handle          memberReference
	HandleKind      uint16
	Arguments       []constantValue
	ArgumentIndexes []uint16
}

type classModel struct {
	Minor, Major      uint16
	Access            uint16
	Name, Super       string
	Interfaces        []string
	Pool              []cpEntry
	Fields            []fieldModel
	Methods           []methodModel
	Bootstraps        []bootstrapMethod
	BootstrapFailures []bool
	Annotations       []annotationModel
}

func computeBootstrapFailures(cf *classModel) []bool {
	if cf == nil {
		return nil
	}
	failures := make([]bool, len(cf.Pool))
	states := make([]byte, len(cf.Pool))
	var visit func(uint16) bool
	visit = func(index uint16) bool {
		if int(index) >= len(cf.Pool) {
			return true
		}
		entry := cf.Pool[index]
		if entry.tag != cpDynamic && entry.tag != cpInvokeDynamic {
			return false
		}
		if states[index] == 1 {
			return true
		}
		if states[index] == 2 {
			return failures[index]
		}
		states[index] = 1
		failed := int(entry.a) >= len(cf.Bootstraps)
		if !failed {
			for _, argument := range cf.Bootstraps[entry.a].ArgumentIndexes {
				if visit(argument) {
					failed = true
					break
				}
			}
		}
		states[index] = 2
		failures[index] = failed
		return failed
	}
	for index, entry := range cf.Pool {
		if entry.tag == cpDynamic || entry.tag == cpInvokeDynamic {
			visit(uint16(index))
		}
	}
	return failures
}

func (cf *classModel) validateConstantPoolReferences() error {
	for index, entry := range cf.Pool {
		if entry.tag == 0 {
			continue
		}
		if minimum := minimumClassVersion(entry.tag); minimum != 0 && cf.Major < minimum {
			return fmt.Errorf(
				"constant-pool index %d tag %d requires class version %d or newer, got %d",
				index, entry.tag, minimum, cf.Major,
			)
		}
		var err error
		switch entry.tag {
		case cpUtf8, cpInteger, cpFloat, cpLong, cpDouble:
			continue
		case cpClass:
			var name string
			name, err = cf.className(uint16(index))
			if err == nil {
				err = validateClassConstantName(name)
			}
		case cpString:
			_, err = cf.utf8(entry.a)
		case cpFieldref, cpMethodref, cpInterfaceMethodref:
			var reference memberReference
			reference, err = cf.memberRef(uint16(index))
			if err == nil {
				err = validateMemberReference(entry.tag, reference)
			}
		case cpNameAndType:
			_, err = cf.nameAndType(uint16(index))
		case cpMethodHandle:
			_, err = cf.methodHandle(uint16(index))
		case cpMethodType:
			var descriptor string
			descriptor, err = cf.utf8(entry.a)
			if err == nil {
				_, err = parseMethodDescriptor(descriptor)
			}
		case cpDynamic:
			var value constantValue
			value, err = cf.constantValue(uint16(index))
			if err == nil {
				err = validateDynamicConstant(value)
			}
		case cpInvokeDynamic:
			var dynamic invokeDynamicReference
			dynamic, err = cf.invokeDynamic(uint16(index))
			if err == nil {
				err = validateInvokeDynamicReference(dynamic)
			}
		case cpModule, cpPackage:
			_, err = cf.utf8(entry.a)
		}
		if err != nil {
			return fmt.Errorf("constant-pool index %d tag %d: %w", index, entry.tag, err)
		}
	}
	return nil
}

func validateMemberReference(tag uint8, reference memberReference) error {
	if err := validateInternalClassName(reference.Owner); err != nil {
		return fmt.Errorf("member owner: %w", err)
	}
	if tag == cpFieldref {
		if err := validateUnqualifiedName(reference.Name, false); err != nil {
			return err
		}
		_, err := parseFieldDescriptor(reference.Descriptor)
		return err
	}
	parsed, err := parseMethodDescriptor(reference.Descriptor)
	if err != nil {
		return err
	}
	if reference.Name == "<clinit>" {
		return fmt.Errorf("constant-pool method reference cannot name <clinit>")
	}
	if reference.Name == "<init>" {
		if tag != cpMethodref || !parsed.Return.Void {
			return fmt.Errorf("constructor reference must be Methodref returning void")
		}
		return nil
	}
	return validateUnqualifiedName(reference.Name, true)
}

func validateClassConstantName(name string) error {
	if len(name) != 0 && name[0] == '[' {
		descriptor, err := parseFieldDescriptor(name)
		if err != nil {
			return err
		}
		if !descriptor.Array {
			return fmt.Errorf("class constant is not an array descriptor")
		}
		return nil
	}
	return validateInternalClassName(name)
}

func validateDynamicConstant(value constantValue) error {
	if value.Reference == nil {
		return fmt.Errorf("dynamic constant has no name and type")
	}
	if value.Reference.Name == "<init>" || value.Reference.Name == "<clinit>" {
		return fmt.Errorf("dynamic constant cannot name %s", value.Reference.Name)
	}
	if err := validateUnqualifiedName(value.Reference.Name, false); err != nil {
		return err
	}
	_, err := parseFieldDescriptor(value.Reference.Descriptor)
	return err
}

func validateInvokeDynamicReference(reference invokeDynamicReference) error {
	if err := validateUnqualifiedName(reference.Name, true); err != nil {
		return err
	}
	_, err := parseMethodDescriptor(reference.Descriptor)
	return err
}

func minimumClassVersion(tag uint8) uint16 {
	switch tag {
	case cpMethodHandle, cpMethodType, cpInvokeDynamic:
		return 51
	case cpModule, cpPackage:
		return 53
	case cpDynamic:
		return 55
	default:
		return 0
	}
}

func (cf *classModel) poolEntry(index uint16) (cpEntry, error) {
	if index == 0 {
		return cpEntry{}, fmt.Errorf("constant-pool index zero is invalid")
	}
	if int(index) >= len(cf.Pool) {
		return cpEntry{}, fmt.Errorf("constant-pool index %d is out of range (size %d)", index, len(cf.Pool))
	}
	entry := cf.Pool[index]
	if entry.tag == 0 {
		return cpEntry{}, fmt.Errorf("constant-pool index %d is an unusable slot", index)
	}
	return entry, nil
}

func (cf *classModel) poolEntryWithTag(index uint16, tag uint8) (cpEntry, error) {
	entry, err := cf.poolEntry(index)
	if err != nil {
		return cpEntry{}, err
	}
	if entry.tag != tag {
		return cpEntry{}, fmt.Errorf("constant-pool index %d has tag %d, expected %d", index, entry.tag, tag)
	}
	return entry, nil
}

func (cf *classModel) utf8(index uint16) (string, error) {
	entry, err := cf.poolEntryWithTag(index, cpUtf8)
	if err != nil {
		return "", err
	}
	return entry.text, nil
}

func (cf *classModel) className(index uint16) (string, error) {
	entry, err := cf.poolEntryWithTag(index, cpClass)
	if err != nil {
		return "", err
	}
	name, err := cf.utf8(entry.a)
	if err != nil {
		return "", fmt.Errorf("class constant at index %d: %w", index, err)
	}
	return name, nil
}

func (cf *classModel) nameAndType(index uint16) (nameAndTypeReference, error) {
	entry, err := cf.poolEntryWithTag(index, cpNameAndType)
	if err != nil {
		return nameAndTypeReference{}, err
	}
	name, err := cf.utf8(entry.a)
	if err != nil {
		return nameAndTypeReference{}, fmt.Errorf("name-and-type at index %d name: %w", index, err)
	}
	descriptor, err := cf.utf8(entry.b)
	if err != nil {
		return nameAndTypeReference{}, fmt.Errorf("name-and-type at index %d descriptor: %w", index, err)
	}
	return nameAndTypeReference{Name: name, Descriptor: descriptor}, nil
}

func (cf *classModel) memberRef(index uint16) (memberReference, error) {
	entry, err := cf.poolEntry(index)
	if err != nil {
		return memberReference{}, err
	}
	if entry.tag != cpFieldref && entry.tag != cpMethodref && entry.tag != cpInterfaceMethodref {
		return memberReference{}, fmt.Errorf(
			"constant-pool index %d has tag %d, expected a member reference", index, entry.tag,
		)
	}
	owner, err := cf.className(entry.a)
	if err != nil {
		return memberReference{}, fmt.Errorf("member reference at index %d: %w", index, err)
	}
	nameAndType, err := cf.nameAndType(entry.b)
	if err != nil {
		return memberReference{}, fmt.Errorf("member reference at index %d: %w", index, err)
	}
	return memberReference{
		Owner: owner, Name: nameAndType.Name, Descriptor: nameAndType.Descriptor,
		Interface: entry.tag == cpInterfaceMethodref,
	}, nil
}

func (cf *classModel) invokeDynamic(index uint16) (invokeDynamicReference, error) {
	entry, err := cf.poolEntryWithTag(index, cpInvokeDynamic)
	if err != nil {
		return invokeDynamicReference{}, err
	}
	nameAndType, err := cf.nameAndType(entry.b)
	if err != nil {
		return invokeDynamicReference{}, fmt.Errorf("invokedynamic at index %d: %w", index, err)
	}
	return invokeDynamicReference{
		Bootstrap: entry.a, Name: nameAndType.Name, Descriptor: nameAndType.Descriptor,
	}, nil
}

func (cf *classModel) constantValue(index uint16) (constantValue, error) {
	entry, err := cf.poolEntry(index)
	if err != nil {
		return constantValue{}, err
	}
	switch entry.tag {
	case cpString:
		value, err := cf.utf8(entry.a)
		if err != nil {
			return constantValue{}, fmt.Errorf("string constant at index %d: %w", index, err)
		}
		return constantValue{Kind: constantString, String: value}, nil
	case cpInteger:
		return constantValue{Kind: constantInteger, Integer: int64(int32(uint32(entry.bits)))}, nil
	case cpFloat:
		return constantValue{Kind: constantFloat, Integer: int64(int32(uint32(entry.bits)))}, nil
	case cpLong:
		return constantValue{Kind: constantLong, Integer: int64(entry.bits)}, nil
	case cpDouble:
		return constantValue{Kind: constantDouble, Integer: int64(entry.bits)}, nil
	case cpClass:
		name, err := cf.className(index)
		if err != nil {
			return constantValue{}, err
		}
		return constantValue{Kind: constantClass, String: name}, nil
	case cpMethodType:
		descriptor, err := cf.utf8(entry.a)
		if err != nil {
			return constantValue{}, fmt.Errorf("method type at index %d: %w", index, err)
		}
		return constantValue{Kind: constantMethodType, String: descriptor}, nil
	case cpMethodHandle:
		ref, err := cf.methodHandle(index)
		if err != nil {
			return constantValue{}, err
		}
		handle, err := cf.poolEntryWithTag(index, cpMethodHandle)
		if err != nil {
			return constantValue{}, err
		}
		return constantValue{Kind: constantMethodHandle, Reference: &ref, HandleKind: handle.a}, nil
	case cpDynamic:
		nameAndType, err := cf.nameAndType(entry.b)
		if err != nil {
			return constantValue{}, fmt.Errorf("dynamic constant at index %d: %w", index, err)
		}
		return constantValue{
			Kind:      constantDynamic,
			Reference: &memberReference{Name: nameAndType.Name, Descriptor: nameAndType.Descriptor},
			Bootstrap: entry.a,
		}, nil
	default:
		return constantValue{}, fmt.Errorf("constant-pool index %d has unsupported constant tag %d", index, entry.tag)
	}
}

func (cf *classModel) methodHandle(index uint16) (memberReference, error) {
	entry, err := cf.poolEntryWithTag(index, cpMethodHandle)
	if err != nil {
		return memberReference{}, err
	}
	if entry.a < 1 || entry.a > 9 {
		return memberReference{}, fmt.Errorf("method handle at index %d has invalid reference kind %d", index, entry.a)
	}
	ref, err := cf.memberRef(entry.b)
	if err != nil {
		return memberReference{}, fmt.Errorf("method handle at index %d: %w", index, err)
	}
	if err := validateMethodHandleTarget(cf.Major, entry.a, cf.Pool[entry.b].tag, ref.Name); err != nil {
		return memberReference{}, fmt.Errorf("method handle at index %d: %w", index, err)
	}
	return ref, nil
}

func validateMethodHandleTarget(major, kind uint16, tag uint8, name string) error {
	valid := false
	switch kind {
	case 1, 2, 3, 4:
		valid = tag == cpFieldref
	case 5:
		valid = tag == cpMethodref
	case 6, 7:
		valid = tag == cpMethodref || (major >= 52 && tag == cpInterfaceMethodref)
	case 8:
		valid = tag == cpMethodref
	case 9:
		valid = tag == cpInterfaceMethodref
	}
	if !valid {
		return fmt.Errorf("reference kind %d cannot target constant-pool tag %d", kind, tag)
	}
	if kind == 8 && name != "<init>" {
		return fmt.Errorf("reference kind 8 must target <init>, got %q", name)
	}
	if (kind == 5 || kind == 6 || kind == 7 || kind == 9) &&
		(name == "<init>" || name == "<clinit>") {
		return fmt.Errorf("reference kind %d cannot target %s", kind, name)
	}
	return nil
}
