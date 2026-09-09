package javadisk

import (
	"bytes"
	"fmt"
	"math"
	"slices"
	"sort"
)

const maxCFGWork uint64 = 1_000_000

type basicBlock struct {
	Start        uint32
	Instructions []instruction
	Successors   []uint32
}

type controlFlowGraph struct {
	Entry  uint32
	Blocks map[uint32]*basicBlock
	Order  []uint32
}

func buildCFG(code *codeModel, instructions []instruction) (*controlFlowGraph, error) {
	if code == nil {
		return nil, fmt.Errorf("nil code model")
	}
	codeLength := uint64(len(code.Bytes))
	if codeLength > math.MaxUint32 {
		return nil, fmt.Errorf("bytecode length %d exceeds uint32 offsets", codeLength)
	}
	if err := validateInstructionStream(code.Bytes, instructions); err != nil {
		return nil, err
	}

	cfg := &controlFlowGraph{
		Entry:  0,
		Blocks: make(map[uint32]*basicBlock),
	}
	if len(instructions) == 0 {
		if len(code.Handlers) != 0 {
			return nil, fmt.Errorf("exception handlers require nonempty bytecode")
		}
		return cfg, nil
	}
	final := instructions[len(instructions)-1]
	if final.Fallthrough {
		end, ok := instructionEnd(final)
		if !ok {
			return nil, fmt.Errorf("instruction length overflow at bytecode offset %d", final.Offset)
		}
		if uint64(end) == codeLength {
			return nil, fmt.Errorf("instruction at bytecode offset %d falls off the end of bytecode", final.Offset)
		}
	}

	boundaries := make(map[uint32]int, len(instructions))
	for index, ins := range instructions {
		boundaries[ins.Offset] = index
	}
	for _, ins := range instructions {
		for _, target := range ins.Targets {
			if _, ok := boundaries[target]; !ok {
				return nil, fmt.Errorf("opcode 0x%02x at bytecode offset %d targets non-instruction boundary %d", ins.Opcode, ins.Offset, target)
			}
		}
	}
	jsrContinuationSet := make(map[uint32]struct{})
	for _, ins := range instructions {
		if !isJSRInstruction(ins) {
			continue
		}
		continuation, ok := instructionEnd(ins)
		if !ok {
			return nil, fmt.Errorf("jsr instruction length overflow at bytecode offset %d", ins.Offset)
		}
		if _, ok := boundaries[continuation]; !ok {
			return nil, fmt.Errorf("jsr at bytecode offset %d has invalid continuation %d", ins.Offset, continuation)
		}
		jsrContinuationSet[continuation] = struct{}{}
	}
	jsrContinuations := sortedOffsets(jsrContinuationSet)
	if err := validateExceptionHandlers(code.Handlers, boundaries, uint32(codeLength)); err != nil {
		return nil, err
	}

	leaders := map[uint32]struct{}{instructions[0].Offset: {}}
	for index, ins := range instructions {
		for _, target := range ins.Targets {
			leaders[target] = struct{}{}
		}
		if (len(ins.Targets) != 0 || !ins.Fallthrough) && index+1 < len(instructions) {
			leaders[instructions[index+1].Offset] = struct{}{}
		}
	}
	for _, handler := range code.Handlers {
		leaders[handler.Start] = struct{}{}
		if uint64(handler.End) < codeLength {
			leaders[handler.End] = struct{}{}
		}
		leaders[handler.Handler] = struct{}{}
	}
	for _, continuation := range jsrContinuations {
		leaders[continuation] = struct{}{}
	}

	cfg.Order = make([]uint32, 0, len(leaders))
	for leader := range leaders {
		cfg.Order = append(cfg.Order, leader)
	}
	sort.Slice(cfg.Order, func(i, j int) bool { return cfg.Order[i] < cfg.Order[j] })
	if err := preflightCFGWork(instructions, len(cfg.Order), len(code.Handlers), len(jsrContinuations)); err != nil {
		return nil, err
	}

	for index, start := range cfg.Order {
		first := boundaries[start]
		last := len(instructions)
		if index+1 < len(cfg.Order) {
			last = boundaries[cfg.Order[index+1]]
		}
		if first >= last {
			return nil, fmt.Errorf("empty basic block at bytecode offset %d", start)
		}
		cfg.Blocks[start] = &basicBlock{
			Start:        start,
			Instructions: append([]instruction(nil), instructions[first:last]...),
		}
	}

	for index, start := range cfg.Order {
		block := cfg.Blocks[start]
		last := block.Instructions[len(block.Instructions)-1]
		successors := make(map[uint32]struct{}, len(last.Targets)+1)
		for _, target := range last.Targets {
			successors[target] = struct{}{}
		}
		if isRetInstruction(last) {
			if len(jsrContinuations) == 0 {
				return nil, fmt.Errorf("ret at bytecode offset %d has no jsr continuation", last.Offset)
			}
			for _, continuation := range jsrContinuations {
				successors[continuation] = struct{}{}
			}
		}
		if last.Fallthrough && index+1 < len(cfg.Order) {
			next := cfg.Order[index+1]
			end, ok := instructionEnd(last)
			if !ok {
				return nil, fmt.Errorf("instruction length overflow at bytecode offset %d", last.Offset)
			}
			if end == next {
				successors[next] = struct{}{}
			} else if uint64(end) < codeLength {
				return nil, fmt.Errorf("missing fallthrough block at bytecode offset %d", end)
			}
		}

		blockEnd := uint32(codeLength)
		if index+1 < len(cfg.Order) {
			blockEnd = cfg.Order[index+1]
		}
		for _, handler := range code.Handlers {
			if start < handler.End && blockEnd > handler.Start {
				successors[handler.Handler] = struct{}{}
			}
		}
		block.Successors = sortedOffsets(successors)
	}

	return cfg, nil
}

func preflightCFGWork(instructions []instruction, blockCount, handlerCount, continuationCount int) error {
	var (
		directSuccessors uint64
		retCount         uint64
	)
	for _, ins := range instructions {
		var ok bool
		directSuccessors, ok = checkedAddUint64(directSuccessors, uint64(len(ins.Targets)))
		if !ok {
			return fmt.Errorf("CFG resource budget exceeded: direct successor count overflow")
		}
		if ins.Fallthrough {
			directSuccessors, ok = checkedAddUint64(directSuccessors, 1)
			if !ok {
				return fmt.Errorf("CFG resource budget exceeded: direct successor count overflow")
			}
		}
		if isRetInstruction(ins) {
			retCount++
		}
	}

	exceptionChecks, ok := checkedMulUint64(uint64(blockCount), uint64(handlerCount))
	if !ok {
		return fmt.Errorf("CFG resource budget exceeded: exception-handler work overflow")
	}
	retContinuations, ok := checkedMulUint64(retCount, uint64(continuationCount))
	if !ok {
		return fmt.Errorf("CFG resource budget exceeded: ret-continuation work overflow")
	}

	used := uint64(0)
	reserve := func(component string, amount uint64) error {
		if amount > maxCFGWork-used {
			return fmt.Errorf(
				"CFG resource budget exceeded: %s needs %d work units with %d already reserved (limit %d)",
				component, amount, used, maxCFGWork,
			)
		}
		used += amount
		return nil
	}
	if err := reserve("direct successors", directSuccessors); err != nil {
		return err
	}
	if err := reserve("exception-handler checks", exceptionChecks); err != nil {
		return err
	}
	if err := reserve("ret continuations", retContinuations); err != nil {
		return err
	}
	return nil
}

func validateInstructionStream(code []byte, instructions []instruction) error {
	codeLength := uint64(len(code))
	if codeLength == 0 {
		if len(instructions) != 0 {
			return fmt.Errorf("instructions supplied for empty bytecode")
		}
		return nil
	}
	if len(instructions) == 0 {
		return fmt.Errorf("nonempty bytecode has no instructions")
	}

	expected := uint64(0)
	for index, ins := range instructions {
		if uint64(ins.Offset) != expected {
			return fmt.Errorf("instruction %d starts at %d, want %d", index, ins.Offset, expected)
		}
		if expected >= codeLength || code[int(expected)] != ins.Opcode {
			return fmt.Errorf("instruction %d opcode does not match bytecode at offset %d", index, expected)
		}
		end, ok := checkedAddUint64(expected, 1)
		if !ok {
			return fmt.Errorf("instruction %d offset overflow", index)
		}
		end, ok = checkedAddUint64(end, uint64(len(ins.Operands)))
		if !ok || end > codeLength {
			return fmt.Errorf("instruction %d operands exceed bytecode", index)
		}
		if !bytes.Equal(ins.Operands, code[int(expected+1):int(end)]) {
			return fmt.Errorf("instruction %d operands do not match bytecode", index)
		}
		expected = end
	}
	if expected != codeLength {
		return fmt.Errorf("instruction stream ends at %d, bytecode length is %d", expected, codeLength)
	}

	decoded, err := decodeInstructions(code, len(instructions))
	if err != nil {
		return fmt.Errorf("instruction stream does not match bytecode: %w", err)
	}
	if len(decoded) != len(instructions) {
		return fmt.Errorf("instruction stream has %d instructions, bytecode decodes to %d", len(instructions), len(decoded))
	}
	for index := range instructions {
		got, want := instructions[index], decoded[index]
		if got.Offset != want.Offset || got.Opcode != want.Opcode ||
			!bytes.Equal(got.Operands, want.Operands) || !slices.Equal(got.Targets, want.Targets) ||
			got.Fallthrough != want.Fallthrough {
			return fmt.Errorf("instruction %d control-flow metadata does not match bytecode", index)
		}
	}
	return nil
}

func validateExceptionHandlers(handlers []exceptionHandler, boundaries map[uint32]int, codeLength uint32) error {
	for index, handler := range handlers {
		if handler.Start >= handler.End {
			return fmt.Errorf("exception handler %d has invalid range [%d,%d)", index, handler.Start, handler.End)
		}
		if handler.End > codeLength {
			return fmt.Errorf("exception handler %d end %d exceeds bytecode length %d", index, handler.End, codeLength)
		}
		if _, ok := boundaries[handler.Start]; !ok {
			return fmt.Errorf("exception handler %d start %d is not an instruction boundary", index, handler.Start)
		}
		if handler.End != codeLength {
			if _, ok := boundaries[handler.End]; !ok {
				return fmt.Errorf("exception handler %d end %d is not an instruction boundary", index, handler.End)
			}
		}
		if _, ok := boundaries[handler.Handler]; !ok {
			return fmt.Errorf("exception handler %d target %d is not an instruction boundary", index, handler.Handler)
		}
	}
	return nil
}

func instructionEnd(ins instruction) (uint32, bool) {
	end, ok := checkedAddUint64(uint64(ins.Offset), 1)
	if !ok {
		return 0, false
	}
	end, ok = checkedAddUint64(end, uint64(len(ins.Operands)))
	if !ok || end > math.MaxUint32 {
		return 0, false
	}
	return uint32(end), true
}

func isJSRInstruction(ins instruction) bool {
	return ins.Opcode == 0xa8 || ins.Opcode == 0xc9
}

func isRetInstruction(ins instruction) bool {
	return ins.Opcode == 0xa9 ||
		ins.Opcode == 0xc4 && len(ins.Operands) != 0 && ins.Operands[0] == 0xa9
}

func sortedOffsets(offsets map[uint32]struct{}) []uint32 {
	if len(offsets) == 0 {
		return nil
	}
	result := make([]uint32, 0, len(offsets))
	for offset := range offsets {
		result = append(result, offset)
	}
	sort.Slice(result, func(i, j int) bool { return result[i] < result[j] })
	return result
}
