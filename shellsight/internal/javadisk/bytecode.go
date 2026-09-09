package javadisk

import (
	"encoding/binary"
	"fmt"
	"math"
)

const (
	invalidOperandWidth  int8 = -1
	variableOperandWidth int8 = -2
)

// opcodeOperandWidths classifies every byte value. Rows correspond to the
// hexadecimal high nibble, making reserved values visible during review.
var opcodeOperandWidths = [256]int8{
	// 0x00-0x0f
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	// 0x10-0x1f
	1, 2, 1, 2, 2, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0,
	// 0x20-0x2f
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	// 0x30-0x3f
	0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0,
	// 0x40-0x4f
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	// 0x50-0x5f
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	// 0x60-0x6f
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	// 0x70-0x7f
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	// 0x80-0x8f
	0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	// 0x90-0x9f
	0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 2, 2, 2, 2, 2, 2,
	// 0xa0-0xaf
	2, 2, 2, 2, 2, 2, 2, 2, 2, 1, -2, -2, 0, 0, 0, 0,
	// 0xb0-0xbf
	0, 0, 2, 2, 2, 2, 2, 2, 2, 4, 4, 2, 1, 2, 0, 0,
	// 0xc0-0xcf
	2, 2, 0, 0, -2, 3, 2, 2, 4, 4, -1, -1, -1, -1, -1, -1,
	// 0xd0-0xdf
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	// 0xe0-0xef
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	// 0xf0-0xff
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
}

type instruction struct {
	Offset      uint32
	Opcode      byte
	Operands    []byte
	Targets     []uint32
	Fallthrough bool
}

type instructionLimitError struct {
	Limit  int
	Offset uint64
}

func (e *instructionLimitError) Error() string {
	return fmt.Sprintf("instruction limit %d exceeded at bytecode offset %d", e.Limit, e.Offset)
}

func decodeInstructions(code []byte, limit int) ([]instruction, error) {
	instructions, _, err := decodeInstructionsCounted(code, limit)
	return instructions, err
}

func decodeInstructionsCounted(code []byte, limit int) ([]instruction, int, error) {
	codeLength := uint64(len(code))
	if codeLength > math.MaxUint32 {
		return nil, 0, fmt.Errorf("bytecode length %d exceeds uint32 offsets", codeLength)
	}

	var instructions []instruction
	for offset := uint64(0); offset < codeLength; {
		if limit < 0 || len(instructions) >= limit {
			return nil, len(instructions), &instructionLimitError{Limit: limit, Offset: offset}
		}

		opcode := code[int(offset)]
		width := opcodeOperandWidths[opcode]
		if width == invalidOperandWidth {
			return nil, len(instructions), fmt.Errorf("invalid or reserved opcode 0x%02x at bytecode offset %d", opcode, offset)
		}

		var (
			ins  instruction
			next uint64
			err  error
		)
		if width == variableOperandWidth {
			switch opcode {
			case 0xaa, 0xab:
				ins, next, err = decodeSwitchInstruction(code, offset, opcode)
			case 0xc4:
				ins, next, err = decodeWideInstruction(code, offset)
			default:
				err = fmt.Errorf("unsupported variable-width opcode 0x%02x at bytecode offset %d", opcode, offset)
			}
		} else {
			ins, next, err = decodeFixedInstruction(code, offset, opcode, uint64(width))
		}
		if err != nil {
			return nil, len(instructions), err
		}
		instructions = append(instructions, ins)
		offset = next
	}
	return instructions, len(instructions), nil
}

func decodeFixedInstruction(code []byte, offset uint64, opcode byte, width uint64) (instruction, uint64, error) {
	next, ok := checkedAddUint64(offset, 1)
	if !ok {
		return instruction{}, 0, fmt.Errorf("opcode 0x%02x offset overflow", opcode)
	}
	next, ok = checkedAddUint64(next, width)
	if !ok || next > uint64(len(code)) {
		return instruction{}, 0, fmt.Errorf("truncated operands for opcode 0x%02x at bytecode offset %d", opcode, offset)
	}

	operands := cloneByteRange(code, offset+1, next)
	ins := instruction{
		Offset:      uint32(offset),
		Opcode:      opcode,
		Operands:    operands,
		Fallthrough: opcodeFallsThrough(opcode),
	}

	switch {
	case isBranch16(opcode):
		delta := int64(int16(binary.BigEndian.Uint16(operands)))
		target, err := resolveAbsoluteTarget(offset, delta)
		if err != nil {
			return instruction{}, 0, fmt.Errorf("opcode 0x%02x at bytecode offset %d: %w", opcode, offset, err)
		}
		ins.Targets = []uint32{target}
	case isBranch32(opcode):
		delta := int64(int32(binary.BigEndian.Uint32(operands)))
		target, err := resolveAbsoluteTarget(offset, delta)
		if err != nil {
			return instruction{}, 0, fmt.Errorf("opcode 0x%02x at bytecode offset %d: %w", opcode, offset, err)
		}
		ins.Targets = []uint32{target}
	}

	if err := validateFixedOperands(opcode, operands); err != nil {
		return instruction{}, 0, fmt.Errorf("opcode 0x%02x at bytecode offset %d: %w", opcode, offset, err)
	}
	return ins, next, nil
}

func decodeWideInstruction(code []byte, offset uint64) (instruction, uint64, error) {
	subopcodeOffset, ok := checkedAddUint64(offset, 1)
	if !ok || subopcodeOffset >= uint64(len(code)) {
		return instruction{}, 0, fmt.Errorf("truncated wide opcode at bytecode offset %d", offset)
	}
	subopcode := code[int(subopcodeOffset)]
	operandWidth := uint64(3)
	if subopcode == 0x84 {
		operandWidth = 5
	} else if !isLegalWideIndexOpcode(subopcode) {
		return instruction{}, 0, fmt.Errorf("illegal wide opcode 0x%02x at bytecode offset %d", subopcode, offset)
	}

	next, ok := checkedAddUint64(offset, 1)
	if !ok {
		return instruction{}, 0, fmt.Errorf("wide instruction offset overflow at bytecode offset %d", offset)
	}
	next, ok = checkedAddUint64(next, operandWidth)
	if !ok || next > uint64(len(code)) {
		return instruction{}, 0, fmt.Errorf("truncated wide opcode 0x%02x at bytecode offset %d", subopcode, offset)
	}
	return instruction{
		Offset:      uint32(offset),
		Opcode:      0xc4,
		Operands:    cloneByteRange(code, offset+1, next),
		Fallthrough: subopcode != 0xa9,
	}, next, nil
}

func decodeSwitchInstruction(code []byte, offset uint64, opcode byte) (instruction, uint64, error) {
	afterOpcode, ok := checkedAddUint64(offset, 1)
	if !ok {
		return instruction{}, 0, fmt.Errorf("switch offset overflow at bytecode offset %d", offset)
	}
	padding := (4 - afterOpcode%4) % 4
	body, ok := checkedAddUint64(afterOpcode, padding)
	if !ok || body > uint64(len(code)) {
		return instruction{}, 0, fmt.Errorf("truncated switch padding at bytecode offset %d", offset)
	}
	for position := afterOpcode; position < body; position++ {
		if code[int(position)] != 0 {
			return instruction{}, 0, fmt.Errorf("nonzero switch padding at bytecode offset %d", position)
		}
	}

	defaultDelta, err := readInt32(code, body)
	if err != nil {
		return instruction{}, 0, fmt.Errorf("truncated switch default at bytecode offset %d", offset)
	}
	defaultTarget, err := resolveAbsoluteTarget(offset, int64(defaultDelta))
	if err != nil {
		return instruction{}, 0, fmt.Errorf("switch at bytecode offset %d: %w", offset, err)
	}
	targets := []uint32{defaultTarget}

	var next uint64
	switch opcode {
	case 0xaa:
		lowPos, ok := checkedAddUint64(body, 4)
		if !ok {
			return instruction{}, 0, fmt.Errorf("tableswitch header overflow at bytecode offset %d", offset)
		}
		highPos, ok := checkedAddUint64(body, 8)
		if !ok {
			return instruction{}, 0, fmt.Errorf("tableswitch header overflow at bytecode offset %d", offset)
		}
		entries, ok := checkedAddUint64(body, 12)
		if !ok {
			return instruction{}, 0, fmt.Errorf("tableswitch header overflow at bytecode offset %d", offset)
		}
		low, lowErr := readInt32(code, lowPos)
		high, highErr := readInt32(code, highPos)
		if lowErr != nil || highErr != nil {
			return instruction{}, 0, fmt.Errorf("truncated tableswitch header at bytecode offset %d", offset)
		}
		if high < low {
			return instruction{}, 0, fmt.Errorf("invalid tableswitch range %d..%d at bytecode offset %d", low, high, offset)
		}
		count := uint64(int64(high) - int64(low) + 1)
		payloadBytes, ok := checkedMulUint64(count, 4)
		if !ok {
			return instruction{}, 0, fmt.Errorf("tableswitch entry count overflow at bytecode offset %d", offset)
		}
		next, ok = checkedAddUint64(entries, payloadBytes)
		if !ok || next > uint64(len(code)) {
			return instruction{}, 0, fmt.Errorf("truncated tableswitch entries at bytecode offset %d", offset)
		}
		if count > uint64(maxInt()-1) {
			return instruction{}, 0, fmt.Errorf("tableswitch entry count too large at bytecode offset %d", offset)
		}
		targets = make([]uint32, 1, int(count)+1)
		targets[0] = defaultTarget
		for i, pos := uint64(0), entries; i < count; i, pos = i+1, pos+4 {
			delta, _ := readInt32(code, pos)
			target, targetErr := resolveAbsoluteTarget(offset, int64(delta))
			if targetErr != nil {
				return instruction{}, 0, fmt.Errorf("tableswitch target %d at bytecode offset %d: %w", i, offset, targetErr)
			}
			targets = append(targets, target)
		}
	case 0xab:
		countPos, ok := checkedAddUint64(body, 4)
		if !ok {
			return instruction{}, 0, fmt.Errorf("lookupswitch header overflow at bytecode offset %d", offset)
		}
		pairs, ok := checkedAddUint64(body, 8)
		if !ok {
			return instruction{}, 0, fmt.Errorf("lookupswitch header overflow at bytecode offset %d", offset)
		}
		signedCount, countErr := readInt32(code, countPos)
		if countErr != nil {
			return instruction{}, 0, fmt.Errorf("truncated lookupswitch header at bytecode offset %d", offset)
		}
		if signedCount < 0 {
			return instruction{}, 0, fmt.Errorf("negative lookupswitch pair count %d at bytecode offset %d", signedCount, offset)
		}
		count := uint64(signedCount)
		payloadBytes, ok := checkedMulUint64(count, 8)
		if !ok {
			return instruction{}, 0, fmt.Errorf("lookupswitch pair count overflow at bytecode offset %d", offset)
		}
		next, ok = checkedAddUint64(pairs, payloadBytes)
		if !ok || next > uint64(len(code)) {
			return instruction{}, 0, fmt.Errorf("truncated lookupswitch pairs at bytecode offset %d", offset)
		}
		if count > uint64(maxInt()-1) {
			return instruction{}, 0, fmt.Errorf("lookupswitch pair count too large at bytecode offset %d", offset)
		}
		targets = make([]uint32, 1, int(count)+1)
		targets[0] = defaultTarget
		var previousKey int32
		for i, pos := uint64(0), pairs; i < count; i, pos = i+1, pos+8 {
			key, _ := readInt32(code, pos)
			if i > 0 && key <= previousKey {
				return instruction{}, 0, fmt.Errorf("lookupswitch keys are not strictly increasing at pair %d", i)
			}
			previousKey = key
			delta, _ := readInt32(code, pos+4)
			target, targetErr := resolveAbsoluteTarget(offset, int64(delta))
			if targetErr != nil {
				return instruction{}, 0, fmt.Errorf("lookupswitch target %d at bytecode offset %d: %w", i, offset, targetErr)
			}
			targets = append(targets, target)
		}
	default:
		return instruction{}, 0, fmt.Errorf("invalid switch opcode 0x%02x", opcode)
	}

	return instruction{
		Offset:      uint32(offset),
		Opcode:      opcode,
		Operands:    cloneByteRange(code, offset+1, next),
		Targets:     targets,
		Fallthrough: false,
	}, next, nil
}

func validateFixedOperands(opcode byte, operands []byte) error {
	switch opcode {
	case 0xb9:
		if operands[2] == 0 {
			return fmt.Errorf("invokeinterface count must be nonzero")
		}
		if operands[3] != 0 {
			return fmt.Errorf("invokeinterface reserved byte must be zero")
		}
	case 0xba:
		if operands[2] != 0 || operands[3] != 0 {
			return fmt.Errorf("invokedynamic reserved bytes must be zero")
		}
	case 0xbc:
		if operands[0] < 4 || operands[0] > 11 {
			return fmt.Errorf("invalid newarray type code %d", operands[0])
		}
	case 0xc5:
		if operands[2] == 0 {
			return fmt.Errorf("multianewarray dimensions must be nonzero")
		}
	}
	return nil
}

func isBranch16(opcode byte) bool {
	return opcode >= 0x99 && opcode <= 0xa8 || opcode == 0xc6 || opcode == 0xc7
}

func isBranch32(opcode byte) bool {
	return opcode == 0xc8 || opcode == 0xc9
}

func opcodeFallsThrough(opcode byte) bool {
	if opcode == 0xa7 || opcode == 0xa8 || opcode == 0xa9 || opcode == 0xaa || opcode == 0xab ||
		opcode == 0xbf || opcode == 0xc8 || opcode == 0xc9 {
		return false
	}
	return opcode < 0xac || opcode > 0xb1
}

func isLegalWideIndexOpcode(opcode byte) bool {
	return opcode >= 0x15 && opcode <= 0x19 || opcode >= 0x36 && opcode <= 0x3a || opcode == 0xa9
}

func resolveAbsoluteTarget(base uint64, delta int64) (uint32, error) {
	if base > math.MaxUint32 {
		return 0, fmt.Errorf("branch base %d exceeds uint32", base)
	}
	if delta < 0 {
		magnitude := uint64(-(delta + 1)) + 1
		if magnitude > base {
			return 0, fmt.Errorf("branch target underflows zero")
		}
		return uint32(base - magnitude), nil
	}
	positive := uint64(delta)
	if positive > math.MaxUint32-base {
		return 0, fmt.Errorf("branch target overflows uint32")
	}
	return uint32(base + positive), nil
}

func readInt32(data []byte, offset uint64) (int32, error) {
	end, ok := checkedAddUint64(offset, 4)
	if !ok || end > uint64(len(data)) {
		return 0, fmt.Errorf("truncated int32")
	}
	return int32(binary.BigEndian.Uint32(data[int(offset):int(end)])), nil
}

func cloneByteRange(data []byte, start, end uint64) []byte {
	if start == end {
		return nil
	}
	return append([]byte(nil), data[int(start):int(end)]...)
}

func checkedAddUint64(a, b uint64) (uint64, bool) {
	if b > math.MaxUint64-a {
		return 0, false
	}
	return a + b, true
}

func checkedMulUint64(a, b uint64) (uint64, bool) {
	if a != 0 && b > math.MaxUint64/a {
		return 0, false
	}
	return a * b, true
}

func maxInt() int {
	return int(^uint(0) >> 1)
}
