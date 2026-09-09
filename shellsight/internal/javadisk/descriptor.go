package javadisk

import "fmt"

const (
	maxJVMDescriptorBytes = 65_535
	maxJVMArrayDimensions = 255
	maxJVMParameterSlots  = 255
)

type descriptorType struct {
	Descriptor string
	Object     string
	Width      uint8
	Array      bool
	Void       bool
}

type methodDescriptor struct {
	Parameters     []descriptorType
	Return         descriptorType
	ParameterSlots int
}

type descriptorParser struct {
	value string
	index int
}

func parseFieldDescriptor(value string) (descriptorType, error) {
	if len(value) == 0 || len(value) > maxJVMDescriptorBytes {
		return descriptorType{}, fmt.Errorf("invalid field descriptor length %d", len(value))
	}
	parser := descriptorParser{value: value}
	result, err := parser.parseType(false)
	if err != nil {
		return descriptorType{}, err
	}
	if parser.index != len(value) {
		return descriptorType{}, fmt.Errorf("trailing input at descriptor byte %d", parser.index)
	}
	return result, nil
}

func parseMethodDescriptor(value string) (methodDescriptor, error) {
	if len(value) < 3 || len(value) > maxJVMDescriptorBytes || value[0] != '(' {
		return methodDescriptor{}, fmt.Errorf("invalid method descriptor")
	}
	parser := descriptorParser{value: value, index: 1}
	result := methodDescriptor{}
	for {
		if parser.index >= len(value) {
			return methodDescriptor{}, fmt.Errorf("unterminated method parameters")
		}
		if value[parser.index] == ')' {
			parser.index++
			break
		}
		parameter, err := parser.parseType(false)
		if err != nil {
			return methodDescriptor{}, fmt.Errorf("parameter %d: %w", len(result.Parameters), err)
		}
		result.ParameterSlots += int(parameter.Width)
		if result.ParameterSlots > maxJVMParameterSlots {
			return methodDescriptor{}, fmt.Errorf("parameter slots %d exceed JVM limit %d", result.ParameterSlots, maxJVMParameterSlots)
		}
		result.Parameters = append(result.Parameters, parameter)
	}
	returnType, err := parser.parseType(true)
	if err != nil {
		return methodDescriptor{}, fmt.Errorf("return type: %w", err)
	}
	if parser.index != len(value) {
		return methodDescriptor{}, fmt.Errorf("trailing input at descriptor byte %d", parser.index)
	}
	result.Return = returnType
	return result, nil
}

func invokeStackEffect(value string, static bool) (pop, push int, err error) {
	descriptor, err := parseMethodDescriptor(value)
	if err != nil {
		return 0, 0, err
	}
	pop = descriptor.ParameterSlots
	if !static {
		pop++
		if pop > maxJVMParameterSlots {
			return 0, 0, fmt.Errorf("receiver and parameter slots %d exceed JVM limit %d", pop, maxJVMParameterSlots)
		}
	}
	return pop, int(descriptor.Return.Width), nil
}

func (p *descriptorParser) parseType(allowVoid bool) (descriptorType, error) {
	start := p.index
	if p.index >= len(p.value) {
		return descriptorType{}, fmt.Errorf("missing type at descriptor byte %d", p.index)
	}
	switch p.value[p.index] {
	case 'V':
		if !allowVoid {
			return descriptorType{}, fmt.Errorf("void is not valid here")
		}
		p.index++
		return descriptorType{Descriptor: "V", Void: true}, nil
	case 'B', 'C', 'F', 'I', 'S', 'Z':
		p.index++
		return descriptorType{Descriptor: p.value[start:p.index], Width: 1}, nil
	case 'J', 'D':
		p.index++
		return descriptorType{Descriptor: p.value[start:p.index], Width: 2}, nil
	case 'L':
		return p.parseObject(start, false)
	case '[':
		dimensions := 0
		for p.index < len(p.value) && p.value[p.index] == '[' {
			dimensions++
			if dimensions > maxJVMArrayDimensions {
				return descriptorType{}, fmt.Errorf("array dimensions exceed JVM limit %d", maxJVMArrayDimensions)
			}
			p.index++
		}
		if p.index >= len(p.value) || p.value[p.index] == 'V' || p.value[p.index] == '[' {
			return descriptorType{}, fmt.Errorf("invalid array component at descriptor byte %d", p.index)
		}
		var component descriptorType
		var err error
		if p.value[p.index] == 'L' {
			component, err = p.parseObject(p.index, false)
		} else {
			component, err = p.parseType(false)
		}
		if err != nil {
			return descriptorType{}, err
		}
		return descriptorType{
			Descriptor: p.value[start:p.index], Object: component.Object, Width: 1, Array: true,
		}, nil
	default:
		return descriptorType{}, fmt.Errorf("invalid type byte 0x%02x at descriptor byte %d", p.value[p.index], p.index)
	}
}

func (p *descriptorParser) parseObject(start int, array bool) (descriptorType, error) {
	p.index++
	nameStart := p.index
	componentStart := p.index
	for p.index < len(p.value) && p.value[p.index] != ';' {
		value := p.value[p.index]
		if value == '.' || value == '[' {
			return descriptorType{}, fmt.Errorf("invalid object name byte 0x%02x at descriptor byte %d", value, p.index)
		}
		if value == '/' {
			if p.index == componentStart {
				return descriptorType{}, fmt.Errorf("empty object name component at descriptor byte %d", p.index)
			}
			componentStart = p.index + 1
		}
		p.index++
	}
	if p.index >= len(p.value) {
		return descriptorType{}, fmt.Errorf("unterminated object type at descriptor byte %d", start)
	}
	if p.index == nameStart || p.index == componentStart {
		return descriptorType{}, fmt.Errorf("empty object name at descriptor byte %d", nameStart)
	}
	name := p.value[nameStart:p.index]
	p.index++
	return descriptorType{
		Descriptor: p.value[start:p.index], Object: name, Width: 1, Array: array,
	}, nil
}
