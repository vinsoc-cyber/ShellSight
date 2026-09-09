package javadisk

import (
	"fmt"
	"math"
	"strconv"
	"strings"
	"unicode/utf8"
)

const classMagic = 0xcafebabe

type unsupportedClassVersionError struct {
	Minor, Major uint16
}

func (e *unsupportedClassVersionError) Error() string {
	return fmt.Sprintf("%s: unsupported Java class version %d.%d", diagClassUnsupported, e.Major, e.Minor)
}

func parseClass(data []byte, limits Limits) (*classModel, error) {
	limits = normalizeOptions(Options{Limits: limits}).Limits
	maxBytes := limits.MaxArtifactBytes
	if int64(len(data)) > maxBytes {
		return nil, fmt.Errorf("class artifact is %d bytes, exceeding limit %d", len(data), maxBytes)
	}

	r := classReader{data: data}
	magic, err := r.u4()
	if err != nil {
		return nil, err
	}
	if magic != classMagic {
		return nil, fmt.Errorf("invalid Java class magic 0x%08x", magic)
	}
	minor, err := r.u2()
	if err != nil {
		return nil, err
	}
	major, err := r.u2()
	if err != nil {
		return nil, err
	}
	if major < 45 || major > 70 || (major >= 56 && minor != 0 && minor != 0xffff) {
		return nil, &unsupportedClassVersionError{Minor: minor, Major: major}
	}

	pool, err := parseConstantPool(&r)
	if err != nil {
		return nil, err
	}
	cf := &classModel{Minor: minor, Major: major, Pool: pool}
	if err := cf.validateConstantPoolReferences(); err != nil {
		return nil, err
	}
	cf.Access, err = r.u2()
	if err != nil {
		return nil, err
	}
	thisClass, err := r.u2()
	if err != nil {
		return nil, err
	}
	superClass, err := r.u2()
	if err != nil {
		return nil, err
	}
	interfaceCount, err := r.u2()
	if err != nil {
		return nil, err
	}
	if int(interfaceCount) > r.remaining()/2 {
		return nil, fmt.Errorf("class read at byte offset %d needs %d interface bytes, only %d remain", r.off, uint32(interfaceCount)*2, r.remaining())
	}

	cf.Name, err = cf.className(thisClass)
	if err != nil {
		return nil, fmt.Errorf("this_class: %w", err)
	}
	if err := validateInternalClassName(cf.Name); err != nil {
		return nil, fmt.Errorf("this_class: %w", err)
	}
	if superClass != 0 {
		cf.Super, err = cf.className(superClass)
		if err != nil {
			return nil, fmt.Errorf("super_class: %w", err)
		}
		if err := validateInternalClassName(cf.Super); err != nil {
			return nil, fmt.Errorf("super_class: %w", err)
		}
	}
	cf.Interfaces = make([]string, 0, interfaceCount)
	for i := uint16(0); i < interfaceCount; i++ {
		index, err := r.u2()
		if err != nil {
			return nil, err
		}
		name, err := cf.className(index)
		if err != nil {
			return nil, fmt.Errorf("interface %d: %w", i, err)
		}
		if err := validateInternalClassName(name); err != nil {
			return nil, fmt.Errorf("interface %d: %w", i, err)
		}
		cf.Interfaces = append(cf.Interfaces, name)
	}
	annotationBudget := newAnnotationRetentionBudget(limits.MaxConstantBytes)
	if err := parseFields(&r, cf, limits, &annotationBudget); err != nil {
		return nil, err
	}
	if err := parseMethods(&r, cf, limits, &annotationBudget); err != nil {
		return nil, err
	}
	_, err = parseClassAttributes(&r, cf, limits, &annotationBudget)
	if err != nil {
		return nil, err
	}
	if err := cf.validateBootstrapIndexes(); err != nil {
		return nil, err
	}
	cf.BootstrapFailures = computeBootstrapFailures(cf)
	if r.remaining() != 0 {
		return nil, fmt.Errorf("Java class has %d trailing bytes", r.remaining())
	}
	return cf, nil
}

func parseFields(r *classReader, cf *classModel, limits Limits, annotationBudget *annotationRetentionBudget) error {
	count, err := r.u2()
	if err != nil {
		return fmt.Errorf("fields_count: %w", err)
	}
	if err := ensureCountFits(r, count, 8, "fields"); err != nil {
		return err
	}
	cf.Fields = make([]fieldModel, 0, count)
	for i := uint16(0); i < count; i++ {
		field, err := parseField(r, cf, limits, annotationBudget)
		if err != nil {
			return fmt.Errorf("field %d: %w", i, err)
		}
		cf.Fields = append(cf.Fields, field)
	}
	return nil
}

func parseField(r *classReader, cf *classModel, limits Limits, annotationBudget *annotationRetentionBudget) (fieldModel, error) {
	var field fieldModel
	var err error
	if field.Access, err = r.u2(); err != nil {
		return field, err
	}
	nameIndex, err := r.u2()
	if err != nil {
		return field, err
	}
	descriptorIndex, err := r.u2()
	if err != nil {
		return field, err
	}
	field.Name, err = cf.utf8(nameIndex)
	if err != nil {
		return field, fmt.Errorf("name_index: %w", err)
	}
	field.Descriptor, err = cf.utf8(descriptorIndex)
	if err != nil {
		return field, fmt.Errorf("descriptor_index: %w", err)
	}
	if err := validateUnqualifiedName(field.Name, false); err != nil {
		return field, fmt.Errorf("name_index: %w", err)
	}
	if _, err := parseFieldDescriptor(field.Descriptor); err != nil {
		return field, fmt.Errorf("descriptor_index: %w", err)
	}
	attributeCount, err := r.u2()
	if err != nil {
		return field, err
	}
	if err := ensureCountFits(r, attributeCount, 6, "field attributes"); err != nil {
		return field, err
	}
	for i := uint16(0); i < attributeCount; i++ {
		name, attribute, err := readAttribute(r, cf)
		if err != nil {
			return field, fmt.Errorf("attribute %d: %w", i, err)
		}
		switch name {
		case "ConstantValue":
			if field.Constant != nil {
				return field, fmt.Errorf("duplicate ConstantValue attribute")
			}
			index, err := attribute.u2()
			if err != nil {
				return field, fmt.Errorf("ConstantValue: %w", err)
			}
			value, err := cf.constantValue(index)
			if err != nil {
				return field, fmt.Errorf("ConstantValue: %w", err)
			}
			if !isFieldConstant(field.Descriptor, value.Kind) {
				return field, fmt.Errorf("ConstantValue index %d kind %d is incompatible with field descriptor %q", index, value.Kind, field.Descriptor)
			}
			value = boundedConstantValue(value, limits.MaxConstantBytes)
			field.Constant = &value
			if err := ensureAttributeConsumed(name, attribute); err != nil {
				return field, err
			}
		case "RuntimeVisibleAnnotations", "RuntimeInvisibleAnnotations":
			annotations, err := parseAnnotations(attribute, cf, limits, annotationBudget)
			if err != nil {
				return field, fmt.Errorf("%s: %w", name, err)
			}
			field.Annotations = append(field.Annotations, annotations...)
			if err := ensureAttributeConsumed(name, attribute); err != nil {
				return field, err
			}
		}
	}
	return field, nil
}

func parseMethods(r *classReader, cf *classModel, limits Limits, annotationBudget *annotationRetentionBudget) error {
	count, err := r.u2()
	if err != nil {
		return fmt.Errorf("methods_count: %w", err)
	}
	if int(count) > limits.MaxMethods {
		return fmt.Errorf("methods_count %d exceeds limit %d", count, limits.MaxMethods)
	}
	if err := ensureCountFits(r, count, 8, "methods"); err != nil {
		return err
	}
	cf.Methods = make([]methodModel, 0, count)
	for i := uint16(0); i < count; i++ {
		method, err := parseMethod(r, cf, limits, annotationBudget)
		if err != nil {
			return fmt.Errorf("method %d: %w", i, err)
		}
		cf.Methods = append(cf.Methods, method)
	}
	return nil
}

func validateInternalClassName(name string) error {
	if name == "" || strings.HasPrefix(name, "[") {
		return fmt.Errorf("invalid internal class name %q", name)
	}
	componentStart := true
	for index := 0; index < len(name); index++ {
		value := name[index]
		if value == '/' {
			if componentStart {
				return fmt.Errorf("invalid empty class-name component in %q", name)
			}
			componentStart = true
			continue
		}
		if value == '.' || value == ';' || value == '[' {
			return fmt.Errorf("invalid class-name byte 0x%02x in %q", value, name)
		}
		componentStart = false
	}
	if componentStart {
		return fmt.Errorf("invalid empty class-name component in %q", name)
	}
	return nil
}

func validateUnqualifiedName(name string, method bool) error {
	if name == "" {
		return fmt.Errorf("empty member name")
	}
	for _, value := range []byte(name) {
		if value == '.' || value == ';' || value == '[' || value == '/' || method && (value == '<' || value == '>') {
			return fmt.Errorf("invalid member-name byte 0x%02x in %q", value, name)
		}
	}
	return nil
}

func validateMethodNameAndDescriptor(name, descriptor string, access uint16) error {
	parsed, err := parseMethodDescriptor(descriptor)
	if err != nil {
		return fmt.Errorf("descriptor_index: %w", err)
	}
	if access&0x0400 != 0 && access&(0x0002|0x0008|0x0010|0x0020|0x0100|0x0800) != 0 {
		return fmt.Errorf("abstract method has incompatible access flags 0x%04x", access)
	}
	switch name {
	case "<init>":
		if access&0x0008 != 0 || !parsed.Return.Void {
			return fmt.Errorf("constructor must be nonstatic and return void")
		}
	case "<clinit>":
		if access&0x0008 == 0 || descriptor != "()V" {
			return fmt.Errorf("class initializer must be static with descriptor ()V")
		}
	default:
		if err := validateUnqualifiedName(name, true); err != nil {
			return fmt.Errorf("name_index: %w", err)
		}
	}
	return nil
}

func parseMethod(r *classReader, cf *classModel, limits Limits, annotationBudget *annotationRetentionBudget) (methodModel, error) {
	var method methodModel
	var err error
	if method.Access, err = r.u2(); err != nil {
		return method, err
	}
	nameIndex, err := r.u2()
	if err != nil {
		return method, err
	}
	descriptorIndex, err := r.u2()
	if err != nil {
		return method, err
	}
	method.Name, err = cf.utf8(nameIndex)
	if err != nil {
		return method, fmt.Errorf("name_index: %w", err)
	}
	method.Descriptor, err = cf.utf8(descriptorIndex)
	if err != nil {
		return method, fmt.Errorf("descriptor_index: %w", err)
	}
	if err := validateMethodNameAndDescriptor(method.Name, method.Descriptor, method.Access); err != nil {
		return method, err
	}
	attributeCount, err := r.u2()
	if err != nil {
		return method, err
	}
	if err := ensureCountFits(r, attributeCount, 6, "method attributes"); err != nil {
		return method, err
	}
	for i := uint16(0); i < attributeCount; i++ {
		name, attribute, err := readAttribute(r, cf)
		if err != nil {
			return method, fmt.Errorf("attribute %d: %w", i, err)
		}
		switch name {
		case "Code":
			if method.Code != nil {
				return method, fmt.Errorf("duplicate Code attribute")
			}
			method.Code, err = parseCode(attribute, cf, &method, limits)
			if err != nil {
				return method, fmt.Errorf("Code: %w", err)
			}
			if err := ensureAttributeConsumed(name, attribute); err != nil {
				return method, err
			}
		case "RuntimeVisibleAnnotations", "RuntimeInvisibleAnnotations":
			annotations, err := parseAnnotations(attribute, cf, limits, annotationBudget)
			if err != nil {
				return method, fmt.Errorf("%s: %w", name, err)
			}
			method.Annotations = append(method.Annotations, annotations...)
			if err := ensureAttributeConsumed(name, attribute); err != nil {
				return method, err
			}
		}
	}
	withoutCode := method.Access&(0x0100|0x0400) != 0
	if withoutCode && method.Code != nil {
		return method, fmt.Errorf("abstract/native method %s%s must not have Code", method.Name, method.Descriptor)
	}
	if !withoutCode && method.Code == nil {
		return method, fmt.Errorf("concrete method %s%s requires Code", method.Name, method.Descriptor)
	}
	return method, nil
}

func parseCode(r *classReader, cf *classModel, method *methodModel, limits Limits) (*codeModel, error) {
	maxStack, err := r.u2()
	if err != nil {
		return nil, err
	}
	maxLocals, err := r.u2()
	if err != nil {
		return nil, err
	}
	if int(maxStack)+int(maxLocals) > limits.MaxFrameSlots {
		return nil, fmt.Errorf("max_stack plus max_locals exceeds frame-slot limit %d", limits.MaxFrameSlots)
	}
	codeLength, err := r.u4()
	if err != nil {
		return nil, err
	}
	if codeLength == 0 || codeLength >= 65536 {
		return nil, fmt.Errorf("invalid code_length %d; must be between 1 and 65535", codeLength)
	}
	bytes, err := r.bytes(codeLength)
	if err != nil {
		return nil, err
	}
	code := &codeModel{
		MaxStack: maxStack, MaxLocals: maxLocals,
		Bytes: append([]byte(nil), bytes...),
	}
	exceptionCount, err := r.u2()
	if err != nil {
		return nil, err
	}
	if err := ensureCountFits(r, exceptionCount, 8, "exception handlers"); err != nil {
		return nil, err
	}
	code.Handlers = make([]exceptionHandler, 0, exceptionCount)
	for i := uint16(0); i < exceptionCount; i++ {
		start, err := r.u2()
		if err != nil {
			return nil, err
		}
		end, err := r.u2()
		if err != nil {
			return nil, err
		}
		handler, err := r.u2()
		if err != nil {
			return nil, err
		}
		catchIndex, err := r.u2()
		if err != nil {
			return nil, err
		}
		if start >= end || uint32(end) > codeLength || uint32(handler) >= codeLength {
			return nil, fmt.Errorf("exception handler %d has invalid range %d..%d or target %d for code length %d", i, start, end, handler, codeLength)
		}
		var catchType string
		if catchIndex != 0 {
			catchType, err = cf.className(catchIndex)
			if err != nil {
				return nil, fmt.Errorf("exception handler %d catch_type: %w", i, err)
			}
		}
		code.Handlers = append(code.Handlers, exceptionHandler{
			Start: uint32(start), End: uint32(end), Handler: uint32(handler), CatchType: catchType,
		})
	}
	attributeCount, err := r.u2()
	if err != nil {
		return nil, err
	}
	if err := ensureCountFits(r, attributeCount, 6, "Code attributes"); err != nil {
		return nil, err
	}
	seenLines := false
	seenStackMap := false
	for i := uint16(0); i < attributeCount; i++ {
		name, attribute, err := readAttribute(r, cf)
		if err != nil {
			return nil, fmt.Errorf("Code attribute %d: %w", i, err)
		}
		switch name {
		case "LineNumberTable":
			if seenLines {
				return nil, fmt.Errorf("duplicate LineNumberTable attribute")
			}
			seenLines = true
			code.Lines, err = parseLineNumberTable(attribute, codeLength)
		case "StackMapTable":
			if seenStackMap {
				return nil, fmt.Errorf("duplicate StackMapTable attribute")
			}
			seenStackMap = true
			code.StackMapPresent = true
			code.StackMapFrames, err = parseStackMapTable(
				attribute, cf, method, codeLength, code.MaxLocals, code.MaxStack, limits,
			)
		default:
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
		}
		if err := ensureAttributeConsumed(name, attribute); err != nil {
			return nil, err
		}
	}
	return code, nil
}

func parseStackMapTable(
	r *classReader,
	cf *classModel,
	method *methodModel,
	codeLength uint32,
	maxLocals, maxStack uint16,
	limits Limits,
) ([]stackMapFrame, error) {
	count, err := r.u2()
	if err != nil {
		return nil, err
	}
	if err := ensureCountFits(r, count, 1, "stack-map frames"); err != nil {
		return nil, err
	}
	locals, err := initialStackMapLocals(cf, method)
	if err != nil {
		return nil, err
	}
	frames := make([]stackMapFrame, 0, count)
	previousOffset := int64(-1)
	for index := uint16(0); index < count; index++ {
		frameType, readErr := r.u1()
		if readErr != nil {
			return nil, fmt.Errorf("frame %d: %w", index, readErr)
		}
		offsetDelta := uint16(0)
		stack := []stackMapVerification(nil)
		switch {
		case frameType <= 63:
			offsetDelta = uint16(frameType)
		case frameType <= 127:
			offsetDelta = uint16(frameType - 64)
			value, valueErr := parseStackMapVerification(r, cf, codeLength)
			if valueErr != nil {
				return nil, fmt.Errorf("frame %d stack: %w", index, valueErr)
			}
			stack = []stackMapVerification{value}
		case frameType == 247:
			offsetDelta, err = r.u2()
			if err == nil {
				var value stackMapVerification
				value, err = parseStackMapVerification(r, cf, codeLength)
				stack = []stackMapVerification{value}
			}
		case frameType >= 248 && frameType <= 250:
			offsetDelta, err = r.u2()
			chop := int(251 - frameType)
			if err == nil && chop > len(locals) {
				err = fmt.Errorf("chop count %d exceeds %d locals", chop, len(locals))
			}
			if err == nil {
				locals = append([]stackMapVerification(nil), locals[:len(locals)-chop]...)
			}
		case frameType == 251:
			offsetDelta, err = r.u2()
		case frameType >= 252 && frameType <= 254:
			offsetDelta, err = r.u2()
			appendCount := int(frameType - 251)
			for added := 0; err == nil && added < appendCount; added++ {
				var value stackMapVerification
				value, err = parseStackMapVerification(r, cf, codeLength)
				if err == nil {
					locals = append(locals, value)
				}
			}
		case frameType == 255:
			offsetDelta, err = r.u2()
			var localCount uint16
			if err == nil {
				localCount, err = r.u2()
			}
			if err == nil && int(localCount) > limits.MaxFrameSlots {
				err = fmt.Errorf("locals count %d exceeds frame limit %d", localCount, limits.MaxFrameSlots)
			}
			locals = make([]stackMapVerification, 0, localCount)
			for local := uint16(0); err == nil && local < localCount; local++ {
				var value stackMapVerification
				value, err = parseStackMapVerification(r, cf, codeLength)
				if err == nil {
					locals = append(locals, value)
				}
			}
			var stackCount uint16
			if err == nil {
				stackCount, err = r.u2()
			}
			if err == nil && int(stackCount) > limits.MaxFrameSlots {
				err = fmt.Errorf("stack count %d exceeds frame limit %d", stackCount, limits.MaxFrameSlots)
			}
			stack = make([]stackMapVerification, 0, stackCount)
			for item := uint16(0); err == nil && item < stackCount; item++ {
				var value stackMapVerification
				value, err = parseStackMapVerification(r, cf, codeLength)
				if err == nil {
					stack = append(stack, value)
				}
			}
		default:
			err = fmt.Errorf("reserved frame_type %d", frameType)
		}
		if err != nil {
			return nil, fmt.Errorf("frame %d: %w", index, err)
		}
		offset := previousOffset + int64(offsetDelta) + 1
		if offset < 0 || offset >= int64(codeLength) {
			return nil, fmt.Errorf("frame %d offset %d outside code length %d", index, offset, codeLength)
		}
		if stackMapSlots(locals) > int(maxLocals) || stackMapSlots(stack) > int(maxStack) {
			return nil, fmt.Errorf("frame %d exceeds max_locals/max_stack", index)
		}
		frames = append(frames, stackMapFrame{
			Offset: uint32(offset), Locals: append([]stackMapVerification(nil), locals...),
			Stack: append([]stackMapVerification(nil), stack...),
		})
		previousOffset = offset
	}
	return frames, nil
}

func initialStackMapLocals(cf *classModel, method *methodModel) ([]stackMapVerification, error) {
	parsed, err := parseMethodDescriptor(method.Descriptor)
	if err != nil {
		return nil, err
	}
	locals := []stackMapVerification(nil)
	if method.Access&0x0008 == 0 {
		if method.Name == "<init>" {
			locals = append(locals, stackMapVerification{Tag: 6})
		} else {
			locals = append(locals, stackMapVerification{Tag: 7, ClassName: cf.Name})
		}
	}
	for _, parameter := range parsed.Parameters {
		locals = append(locals, descriptorStackMapVerification(parameter))
	}
	return locals, nil
}

func descriptorStackMapVerification(value descriptorType) stackMapVerification {
	switch value.Descriptor[0] {
	case 'B', 'C', 'I', 'S', 'Z':
		return stackMapVerification{Tag: 1}
	case 'F':
		return stackMapVerification{Tag: 2}
	case 'D':
		return stackMapVerification{Tag: 3}
	case 'J':
		return stackMapVerification{Tag: 4}
	case 'L':
		return stackMapVerification{Tag: 7, ClassName: value.Object}
	default:
		return stackMapVerification{Tag: 7, ClassName: value.Descriptor}
	}
}

func parseStackMapVerification(r *classReader, cf *classModel, codeLength uint32) (stackMapVerification, error) {
	tag, err := r.u1()
	if err != nil {
		return stackMapVerification{}, err
	}
	value := stackMapVerification{Tag: tag}
	switch tag {
	case 0, 1, 2, 3, 4, 5, 6:
		return value, nil
	case 7:
		index, indexErr := r.u2()
		if indexErr != nil {
			return stackMapVerification{}, indexErr
		}
		value.ClassName, err = cf.className(index)
		return value, err
	case 8:
		value.Offset, err = r.u2()
		if err == nil && uint32(value.Offset) >= codeLength {
			err = fmt.Errorf("uninitialized offset %d outside code length %d", value.Offset, codeLength)
		}
		return value, err
	default:
		return stackMapVerification{}, fmt.Errorf("invalid verification_type_info tag %d", tag)
	}
}

func stackMapSlots(values []stackMapVerification) int {
	slots := 0
	for _, value := range values {
		slots++
		if value.Tag == 3 || value.Tag == 4 {
			slots++
		}
	}
	return slots
}

func parseLineNumberTable(r *classReader, codeLength uint32) ([]lineNumber, error) {
	count, err := r.u2()
	if err != nil {
		return nil, err
	}
	if err := ensureCountFits(r, count, 4, "line numbers"); err != nil {
		return nil, err
	}
	lines := make([]lineNumber, 0, count)
	for i := uint16(0); i < count; i++ {
		offset, err := r.u2()
		if err != nil {
			return nil, err
		}
		line, err := r.u2()
		if err != nil {
			return nil, err
		}
		if uint32(offset) >= codeLength {
			return nil, fmt.Errorf("line number %d has offset %d outside code length %d", i, offset, codeLength)
		}
		lines = append(lines, lineNumber{Offset: uint32(offset), Line: line})
	}
	return lines, nil
}

func parseClassAttributes(r *classReader, cf *classModel, limits Limits, annotationBudget *annotationRetentionBudget) (bool, error) {
	count, err := r.u2()
	if err != nil {
		return false, fmt.Errorf("class attributes_count: %w", err)
	}
	if err := ensureCountFits(r, count, 6, "class attributes"); err != nil {
		return false, err
	}
	hasBootstraps := false
	for i := uint16(0); i < count; i++ {
		name, attribute, err := readAttribute(r, cf)
		if err != nil {
			return false, fmt.Errorf("class attribute %d: %w", i, err)
		}
		switch name {
		case "BootstrapMethods":
			if hasBootstraps {
				return false, fmt.Errorf("duplicate BootstrapMethods attribute")
			}
			hasBootstraps = true
			cf.Bootstraps, err = parseBootstrapMethods(attribute, cf, limits)
			if err != nil {
				return false, fmt.Errorf("BootstrapMethods: %w", err)
			}
			if err := ensureAttributeConsumed(name, attribute); err != nil {
				return false, err
			}
		case "RuntimeVisibleAnnotations", "RuntimeInvisibleAnnotations":
			annotations, err := parseAnnotations(attribute, cf, limits, annotationBudget)
			if err != nil {
				return false, fmt.Errorf("%s: %w", name, err)
			}
			cf.Annotations = append(cf.Annotations, annotations...)
			if err := ensureAttributeConsumed(name, attribute); err != nil {
				return false, err
			}
		}
	}
	return hasBootstraps, nil
}

func parseBootstrapMethods(r *classReader, cf *classModel, limits Limits) ([]bootstrapMethod, error) {
	count, err := r.u2()
	if err != nil {
		return nil, err
	}
	if err := ensureCountFits(r, count, 4, "bootstrap methods"); err != nil {
		return nil, err
	}
	methods := make([]bootstrapMethod, 0, count)
	for i := uint16(0); i < count; i++ {
		handleIndex, err := r.u2()
		if err != nil {
			return nil, err
		}
		handle, err := cf.methodHandle(handleIndex)
		if err != nil {
			return nil, fmt.Errorf("bootstrap method %d handle: %w", i, err)
		}
		handleEntry, err := cf.poolEntryWithTag(handleIndex, cpMethodHandle)
		if err != nil {
			return nil, fmt.Errorf("bootstrap method %d handle: %w", i, err)
		}
		if handleEntry.a != 6 && handleEntry.a != 8 {
			return nil, fmt.Errorf("bootstrap method %d handle kind %d is not invokeStatic/newInvokeSpecial", i, handleEntry.a)
		}
		argumentCount, err := r.u2()
		if err != nil {
			return nil, err
		}
		if err := ensureCountFits(r, argumentCount, 2, "bootstrap arguments"); err != nil {
			return nil, err
		}
		method := bootstrapMethod{
			Handle: handle, HandleKind: handleEntry.a, Arguments: make([]constantValue, 0, argumentCount),
			ArgumentIndexes: make([]uint16, 0, argumentCount),
		}
		for j := uint16(0); j < argumentCount; j++ {
			index, err := r.u2()
			if err != nil {
				return nil, err
			}
			value, err := cf.constantValue(index)
			if err != nil {
				return nil, fmt.Errorf("bootstrap method %d argument %d: %w", i, j, err)
			}
			method.Arguments = append(method.Arguments, boundedConstantValue(value, limits.MaxConstantBytes))
			method.ArgumentIndexes = append(method.ArgumentIndexes, index)
		}
		methods = append(methods, method)
	}
	return methods, nil
}

func (cf *classModel) validateBootstrapIndexes() error {
	for index, entry := range cf.Pool {
		if entry.tag != cpDynamic && entry.tag != cpInvokeDynamic {
			continue
		}
		if int(entry.a) >= len(cf.Bootstraps) {
			return fmt.Errorf("constant-pool index %d has bootstrap method index %d, but only %d bootstrap methods exist", index, entry.a, len(cf.Bootstraps))
		}
	}
	return nil
}

const annotationValueOverhead = 1

type annotationRetentionBudget struct {
	remaining     int
	maxValueBytes int
}

func newAnnotationRetentionBudget(maxConstantBytes int) annotationRetentionBudget {
	remaining := maxConstantBytes
	if remaining < int(^uint(0)>>1) {
		remaining += annotationValueOverhead
	}
	return annotationRetentionBudget{remaining: remaining, maxValueBytes: maxConstantBytes}
}

func (b *annotationRetentionBudget) canRetainNonEmpty() bool {
	return b.remaining > annotationValueOverhead && b.maxValueBytes > 0
}

func (b *annotationRetentionBudget) valueByteLimit() int {
	limit := b.remaining - annotationValueOverhead
	if limit > b.maxValueBytes {
		limit = b.maxValueBytes
	}
	if limit < 0 {
		return 0
	}
	return limit
}

func (b *annotationRetentionBudget) retainText(values *[]string, value string) {
	if b.remaining < annotationValueOverhead {
		return
	}
	retained := boundedConstantText(value, b.valueByteLimit())
	if value != "" && retained == "" {
		return
	}
	*values = append(*values, retained)
	b.remaining -= len(retained) + annotationValueOverhead
}

func (b *annotationRetentionBudget) retainJoined(values *[]string, left, separator, right string) {
	if !b.canRetainNonEmpty() {
		return
	}
	limit := b.valueByteLimit()
	var retained strings.Builder
	for _, part := range [...]string{left, separator, right} {
		if !writeBoundedUTF8(&retained, part, limit) {
			break
		}
	}
	if retained.Len() == 0 {
		return
	}
	value := retained.String()
	*values = append(*values, value)
	b.remaining -= len(value) + annotationValueOverhead
}

func writeBoundedUTF8(builder *strings.Builder, value string, limit int) bool {
	for _, r := range value {
		size := utf8.RuneLen(r)
		if builder.Len()+size > limit {
			return false
		}
		builder.WriteRune(r)
	}
	return true
}

func parseAnnotations(
	r *classReader,
	cf *classModel,
	limits Limits,
	retention *annotationRetentionBudget,
) ([]annotationModel, error) {
	count, err := r.u2()
	if err != nil {
		return nil, err
	}
	if err := ensureCountFits(r, count, 4, "annotations"); err != nil {
		return nil, err
	}
	annotations := make([]annotationModel, 0, count)
	for i := uint16(0); i < count; i++ {
		var annotation annotationModel
		annotation.Descriptor, err = parseAnnotation(r, cf, limits, retention, 1, &annotation.Values)
		if err != nil {
			return nil, fmt.Errorf("annotation %d: %w", i, err)
		}
		annotations = append(annotations, annotation)
	}
	return annotations, nil
}

func parseAnnotation(
	r *classReader,
	cf *classModel,
	limits Limits,
	retention *annotationRetentionBudget,
	depth int,
	values *[]string,
) (string, error) {
	if depth > limits.MaxAnnotationDepth {
		return "", fmt.Errorf("annotation nesting depth %d exceeds limit %d", depth, limits.MaxAnnotationDepth)
	}
	descriptorIndex, err := r.u2()
	if err != nil {
		return "", err
	}
	descriptor, err := cf.utf8(descriptorIndex)
	if err != nil {
		return "", fmt.Errorf("type_index: %w", err)
	}
	pairCount, err := r.u2()
	if err != nil {
		return "", err
	}
	if err := ensureCountFits(r, pairCount, 3, "annotation element pairs"); err != nil {
		return "", err
	}
	for i := uint16(0); i < pairCount; i++ {
		nameIndex, err := r.u2()
		if err != nil {
			return "", err
		}
		if _, err := cf.utf8(nameIndex); err != nil {
			return "", fmt.Errorf("element pair %d name_index: %w", i, err)
		}
		if err := parseAnnotationElementValue(r, cf, limits, retention, depth, values); err != nil {
			return "", fmt.Errorf("element pair %d: %w", i, err)
		}
	}
	return descriptor, nil
}

func parseAnnotationElementValue(
	r *classReader,
	cf *classModel,
	limits Limits,
	retention *annotationRetentionBudget,
	depth int,
	values *[]string,
) error {
	if depth > limits.MaxAnnotationDepth {
		return fmt.Errorf("annotation nesting depth %d exceeds limit %d", depth, limits.MaxAnnotationDepth)
	}
	tag, err := r.u1()
	if err != nil {
		return err
	}
	switch tag {
	case 'B', 'C', 'D', 'F', 'I', 'J', 'S', 'Z':
		index, err := r.u2()
		if err != nil {
			return err
		}
		value, err := annotationPrimitive(cf, index, tag)
		if err != nil {
			return err
		}
		if retention.canRetainNonEmpty() {
			retention.retainText(values, formatAnnotationPrimitive(value, tag))
		}
		return nil
	case 's':
		index, err := r.u2()
		if err != nil {
			return err
		}
		value, err := cf.utf8(index)
		if err != nil {
			return fmt.Errorf("string const_value_index: %w", err)
		}
		retention.retainText(values, value)
		return nil
	case 'e':
		typeIndex, err := r.u2()
		if err != nil {
			return err
		}
		nameIndex, err := r.u2()
		if err != nil {
			return err
		}
		typeName, err := cf.utf8(typeIndex)
		if err != nil {
			return fmt.Errorf("enum type_name_index: %w", err)
		}
		name, err := cf.utf8(nameIndex)
		if err != nil {
			return fmt.Errorf("enum const_name_index: %w", err)
		}
		retention.retainJoined(values, typeName, ".", name)
		return nil
	case 'c':
		index, err := r.u2()
		if err != nil {
			return err
		}
		classInfo, err := cf.utf8(index)
		if err != nil {
			return fmt.Errorf("class_info_index: %w", err)
		}
		retention.retainText(values, classInfo)
		return nil
	case '@':
		_, err := parseAnnotation(r, cf, limits, retention, depth+1, values)
		return err
	case '[':
		if depth+1 > limits.MaxAnnotationDepth {
			return fmt.Errorf("annotation nesting depth %d exceeds limit %d", depth+1, limits.MaxAnnotationDepth)
		}
		count, err := r.u2()
		if err != nil {
			return err
		}
		if err := ensureCountFits(r, count, 1, "annotation array values"); err != nil {
			return err
		}
		for i := uint16(0); i < count; i++ {
			if err := parseAnnotationElementValue(r, cf, limits, retention, depth+1, values); err != nil {
				return fmt.Errorf("array element %d: %w", i, err)
			}
		}
		return nil
	default:
		return fmt.Errorf("invalid annotation element tag 0x%02x", tag)
	}
}

func annotationPrimitive(cf *classModel, index uint16, tag uint8) (constantValue, error) {
	value, err := cf.constantValue(index)
	if err != nil {
		return constantValue{}, fmt.Errorf("const_value_index: %w", err)
	}
	switch tag {
	case 'B', 'C', 'I', 'S', 'Z':
		if value.Kind != constantInteger {
			return constantValue{}, fmt.Errorf("annotation tag %c requires an integer constant", tag)
		}
	case 'J':
		if value.Kind != constantLong {
			return constantValue{}, fmt.Errorf("annotation tag J requires a long constant")
		}
	case 'F':
		if value.Kind != constantFloat {
			return constantValue{}, fmt.Errorf("annotation tag F requires a float constant")
		}
	case 'D':
		if value.Kind != constantDouble {
			return constantValue{}, fmt.Errorf("annotation tag D requires a double constant")
		}
	default:
		return constantValue{}, fmt.Errorf("invalid primitive annotation tag %c", tag)
	}
	return value, nil
}

func formatAnnotationPrimitive(value constantValue, tag uint8) string {
	switch tag {
	case 'B', 'C', 'I', 'S', 'Z', 'J':
		return strconv.FormatInt(value.Integer, 10)
	case 'F':
		return strconv.FormatFloat(float64(math.Float32frombits(uint32(value.Integer))), 'g', -1, 32)
	case 'D':
		return strconv.FormatFloat(math.Float64frombits(uint64(value.Integer)), 'g', -1, 64)
	default:
		panic("validated annotation primitive has invalid tag")
	}
}

func readAttribute(r *classReader, cf *classModel) (string, *classReader, error) {
	nameIndex, err := r.u2()
	if err != nil {
		return "", nil, err
	}
	name, err := cf.utf8(nameIndex)
	if err != nil {
		return "", nil, fmt.Errorf("attribute_name_index: %w", err)
	}
	length, err := r.u4()
	if err != nil {
		return "", nil, err
	}
	payload, err := r.bytes(length)
	if err != nil {
		return "", nil, fmt.Errorf("attribute %q length %d: %w", name, length, err)
	}
	return name, &classReader{data: payload}, nil
}

func ensureAttributeConsumed(name string, r *classReader) error {
	if r.remaining() != 0 {
		return fmt.Errorf("attribute %q has %d unconsumed bytes", name, r.remaining())
	}
	return nil
}

func ensureCountFits(r *classReader, count uint16, minimumBytes int, what string) error {
	if int(count) > r.remaining()/minimumBytes {
		return fmt.Errorf("%s count %d cannot fit in %d remaining bytes", what, count, r.remaining())
	}
	return nil
}

func isFieldConstant(descriptor string, kind constantKind) bool {
	switch descriptor {
	case "B", "C", "I", "S", "Z":
		return kind == constantInteger
	case "J":
		return kind == constantLong
	case "F":
		return kind == constantFloat
	case "D":
		return kind == constantDouble
	case "Ljava/lang/String;":
		return kind == constantString
	default:
		return false
	}
}

func boundedConstantValue(value constantValue, maxBytes int) constantValue {
	value.String = boundedConstantText(value.String, maxBytes)
	return value
}

func boundedConstantText(value string, maxBytes int) string {
	if len(value) <= maxBytes {
		return value
	}
	end := maxBytes
	for end > 0 && !utf8.RuneStart(value[end]) {
		end--
	}
	return value[:end]
}

func parseConstantPool(r *classReader) ([]cpEntry, error) {
	count, err := r.u2()
	if err != nil {
		return nil, err
	}
	if count == 0 {
		return nil, fmt.Errorf("constant_pool_count must be at least one")
	}
	pool := make([]cpEntry, count)
	for index := uint16(1); index < count; index++ {
		tag, err := r.u1()
		if err != nil {
			return nil, fmt.Errorf("constant-pool index %d: %w", index, err)
		}
		entry := cpEntry{tag: tag}
		switch tag {
		case cpUtf8:
			length, err := r.u2()
			if err != nil {
				return nil, fmt.Errorf("constant-pool UTF-8 index %d: %w", index, err)
			}
			payload, err := r.bytes(uint32(length))
			if err != nil {
				return nil, fmt.Errorf("constant-pool UTF-8 index %d: %w", index, err)
			}
			entry.text, err = decodeModifiedUTF8(payload)
			if err != nil {
				return nil, fmt.Errorf("constant-pool UTF-8 index %d: %w", index, err)
			}
		case cpInteger, cpFloat:
			bits, err := r.u4()
			if err != nil {
				return nil, fmt.Errorf("constant-pool index %d tag %d: %w", index, tag, err)
			}
			entry.bits = uint64(bits)
		case cpLong, cpDouble:
			if index+1 >= count {
				return nil, fmt.Errorf("constant-pool index %d tag %d has no required unusable slot", index, tag)
			}
			entry.bits, err = r.u8()
			if err != nil {
				return nil, fmt.Errorf("constant-pool index %d tag %d: %w", index, tag, err)
			}
			pool[index] = entry
			index++
			continue
		case cpClass, cpString, cpMethodType, cpModule, cpPackage:
			entry.a, err = r.u2()
			if err != nil {
				return nil, fmt.Errorf("constant-pool index %d tag %d: %w", index, tag, err)
			}
		case cpFieldref, cpMethodref, cpInterfaceMethodref, cpNameAndType, cpDynamic, cpInvokeDynamic:
			entry.a, err = r.u2()
			if err == nil {
				entry.b, err = r.u2()
			}
			if err != nil {
				return nil, fmt.Errorf("constant-pool index %d tag %d: %w", index, tag, err)
			}
		case cpMethodHandle:
			kind, readErr := r.u1()
			if readErr == nil {
				entry.b, readErr = r.u2()
			}
			if readErr != nil {
				return nil, fmt.Errorf("constant-pool method handle index %d: %w", index, readErr)
			}
			if kind < 1 || kind > 9 {
				return nil, fmt.Errorf("constant-pool method handle index %d has invalid reference kind %d", index, kind)
			}
			entry.a = uint16(kind)
		default:
			return nil, fmt.Errorf("constant-pool index %d has invalid tag %d", index, tag)
		}
		pool[index] = entry
	}
	return pool, nil
}
