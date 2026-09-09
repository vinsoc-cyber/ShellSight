package javadisk

import (
	"slices"
	"strings"
	"testing"
)

func TestBuildCFGSplitsControlFlowAndSortsSuccessors(t *testing.T) {
	code := []byte{
		0x03,
		0x99, 0x00, 0x07,
		0xa7, 0x00, 0x06,
		0x04,
		0x05,
		0xac,
		0x06,
		0xac,
	}
	ins, err := decodeInstructions(code, 100)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := buildCFG(&codeModel{Bytes: code}, ins)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Entry != 0 {
		t.Fatalf("entry=%d", cfg.Entry)
	}
	if !slices.Equal(cfg.Order, []uint32{0, 4, 7, 8, 10}) {
		t.Fatalf("order=%v", cfg.Order)
	}
	wantSuccessors := map[uint32][]uint32{
		0:  {4, 8},
		4:  {10},
		7:  {8},
		8:  nil,
		10: nil,
	}
	for start, want := range wantSuccessors {
		block := cfg.Blocks[start]
		if block == nil {
			t.Fatalf("missing block %d", start)
		}
		if !slices.Equal(block.Successors, want) {
			t.Errorf("block %d successors=%v, want %v", start, block.Successors, want)
		}
	}
	if got := cfg.Blocks[0].Instructions; len(got) != 2 || got[0].Offset != 0 || got[1].Offset != 1 {
		t.Fatalf("entry instructions=%v", got)
	}
}

func TestBuildCFGValidatesEveryBranchAndSwitchTargetBoundary(t *testing.T) {
	tests := []struct {
		name string
		code []byte
	}{
		{"branch into operand", []byte{0x99, 0, 1, 0xb1}},
		{"branch at code end", []byte{0xa7, 0, 4, 0xb1}},
		{"switch into table", tableSwitch(0, 1, 0, 0, []int32{20})},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ins, err := decodeInstructions(tt.code, 100)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := buildCFG(&codeModel{Bytes: tt.code}, ins); err == nil {
				t.Fatal("accepted non-instruction target")
			}
		})
	}
}

func TestBuildCFGSplitsTerminalInstructionFromFollowingCode(t *testing.T) {
	code := []byte{0xb1, 0x03, 0xac}
	ins, err := decodeInstructions(code, 10)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := buildCFG(&codeModel{Bytes: code}, ins)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(cfg.Order, []uint32{0, 1}) {
		t.Fatalf("order=%v", cfg.Order)
	}
	if len(cfg.Blocks[0].Successors) != 0 || len(cfg.Blocks[1].Successors) != 0 {
		t.Fatalf("successors: block 0=%v block 1=%v", cfg.Blocks[0].Successors, cfg.Blocks[1].Successors)
	}
}

func TestBuildCFGRejectsFinalFallthrough(t *testing.T) {
	tests := []struct {
		name string
		code []byte
	}{
		{"nop", []byte{0x00}},
		{"bipush", []byte{0x10, 0x01}},
		{"wide iinc", []byte{0xc4, 0x84, 0, 1, 0, 1}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ins, err := decodeInstructions(tt.code, 10)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := buildCFG(&codeModel{Bytes: tt.code}, ins); err == nil {
				t.Fatal("accepted final fallthrough instruction")
			}
		})
	}
}

func TestBuildCFGAcceptsTerminalControlTransfers(t *testing.T) {
	tests := []struct {
		name string
		code []byte
	}{
		{"return", []byte{0xb1}},
		{"throw", []byte{0xbf}},
		{"goto", []byte{0xa7, 0, 0}},
		{"tableswitch", tableSwitch(0, 0, 0, 0, []int32{0})},
		{"lookupswitch", lookupSwitch(0, 0, nil)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ins, err := decodeInstructions(tt.code, 10)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := buildCFG(&codeModel{Bytes: tt.code}, ins); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestBuildCFGAddsJSRReturnContinuations(t *testing.T) {
	tests := []struct {
		name           string
		code           []byte
		retBlock       uint32
		wantSuccessors []uint32
	}{
		{"jsr ret", []byte{0xa8, 0, 4, 0xb1, 0xa9, 0}, 4, []uint32{3}},
		{"jsr_w wide ret", []byte{0xc9, 0, 0, 0, 6, 0xb1, 0xc4, 0xa9, 0, 0}, 6, []uint32{5}},
		{"multiple jsr sites", []byte{0xa8, 0, 7, 0xa8, 0, 4, 0xb1, 0xa9, 0}, 7, []uint32{3, 6}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ins, err := decodeInstructions(tt.code, 20)
			if err != nil {
				t.Fatal(err)
			}
			for iteration := 0; iteration < 10; iteration++ {
				cfg, err := buildCFG(&codeModel{Bytes: tt.code}, ins)
				if err != nil {
					t.Fatal(err)
				}
				if got := cfg.Blocks[tt.retBlock].Successors; !slices.Equal(got, tt.wantSuccessors) {
					t.Fatalf("iteration %d successors=%v, want %v", iteration, got, tt.wantSuccessors)
				}
			}
		})
	}
}

func TestBuildCFGRejectsRetWithoutJSRContinuation(t *testing.T) {
	tests := []struct {
		name string
		code []byte
	}{
		{"ret", []byte{0xa9, 0}},
		{"wide ret", []byte{0xc4, 0xa9, 0, 0}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ins, err := decodeInstructions(tt.code, 10)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := buildCFG(&codeModel{Bytes: tt.code}, ins); err == nil {
				t.Fatal("accepted ret without a jsr continuation")
			}
		})
	}
}

func TestBuildCFGEnforcesExceptionHandlerWorkBudget(t *testing.T) {
	tests := []struct {
		name         string
		blockCount   int
		handlerCount int
		wantReject   bool
	}{
		{"at budget with duplicate target", 1_000, 1_000, false},
		{"over budget with duplicate target", 1_001, 1_000, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			code := make([]byte, tt.blockCount)
			for index := range code {
				code[index] = 0xb1
			}
			ins, err := decodeInstructions(code, len(code))
			if err != nil {
				t.Fatal(err)
			}
			handlers := make([]exceptionHandler, tt.handlerCount)
			for index := range handlers {
				handlers[index] = exceptionHandler{Start: 0, End: 1, Handler: 0}
			}
			model := &codeModel{Bytes: code, Handlers: handlers}

			var firstError string
			for attempt := 0; attempt < 2; attempt++ {
				_, err := buildCFG(model, ins)
				if !tt.wantReject {
					if err != nil {
						t.Fatal(err)
					}
					continue
				}
				if err == nil {
					t.Fatal("accepted exception-handler work over CFG budget")
				}
				if !strings.Contains(err.Error(), "CFG resource budget exceeded") {
					t.Fatalf("error=%q, want CFG resource budget error", err)
				}
				if attempt == 0 {
					firstError = err.Error()
				} else if err.Error() != firstError {
					t.Fatalf("non-deterministic errors: first=%q second=%q", firstError, err)
				}
			}
		})
	}
}

func TestBuildCFGEnforcesRetContinuationWorkBudget(t *testing.T) {
	tests := []struct {
		name       string
		jsrCount   int
		retCount   int
		wantReject bool
	}{
		{"small ret continuation fanout", 4, 3, false},
		{"over ret continuation budget", 1_001, 1_000, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			code := legacySubroutineFanout(tt.jsrCount, tt.retCount)
			ins, err := decodeInstructions(code, len(code))
			if err != nil {
				t.Fatal(err)
			}
			model := &codeModel{Bytes: code}

			var firstError string
			for attempt := 0; attempt < 2; attempt++ {
				_, err := buildCFG(model, ins)
				if !tt.wantReject {
					if err != nil {
						t.Fatal(err)
					}
					continue
				}
				if err == nil {
					t.Fatal("accepted ret-continuation work over CFG budget")
				}
				if !strings.Contains(err.Error(), "CFG resource budget exceeded") {
					t.Fatalf("error=%q, want CFG resource budget error", err)
				}
				if attempt == 0 {
					firstError = err.Error()
				} else if err.Error() != firstError {
					t.Fatalf("non-deterministic errors: first=%q second=%q", firstError, err)
				}
			}
		})
	}
}

func TestPreflightCFGWorkEnforcesRetContinuationBoundary(t *testing.T) {
	if err := preflightCFGWork(retContinuationBoundaryInstructions(1_000, 999), 1_999, 0, 1_000); err != nil {
		t.Fatalf("exact ret-continuation budget rejected: %v", err)
	}
	err := preflightCFGWork(retContinuationBoundaryInstructions(1_000, 1_000), 2_000, 0, 1_000)
	if err == nil {
		t.Fatal("accepted ret-continuation work over CFG budget")
	}
	if !strings.Contains(err.Error(), "CFG resource budget exceeded") {
		t.Fatalf("error=%q, want CFG resource budget error", err)
	}
}

func TestBuildCFGValidatesHandlerBoundaries(t *testing.T) {
	code := []byte{0x10, 0x01, 0xb1}
	ins, err := decodeInstructions(code, 10)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name    string
		handler exceptionHandler
	}{
		{"empty range", exceptionHandler{Start: 0, End: 0, Handler: 2}},
		{"reversed range", exceptionHandler{Start: 2, End: 0, Handler: 2}},
		{"start in operand", exceptionHandler{Start: 1, End: 2, Handler: 2}},
		{"end in operand", exceptionHandler{Start: 0, End: 1, Handler: 2}},
		{"end beyond code", exceptionHandler{Start: 0, End: 4, Handler: 2}},
		{"target in operand", exceptionHandler{Start: 0, End: 2, Handler: 1}},
		{"target at code end", exceptionHandler{Start: 0, End: 2, Handler: 3}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			model := &codeModel{Bytes: code, Handlers: []exceptionHandler{tt.handler}}
			if _, err := buildCFG(model, ins); err == nil {
				t.Fatalf("accepted handler %+v", tt.handler)
			}
		})
	}
}

func TestBuildCFGAddsConservativeExceptionEdges(t *testing.T) {
	code := []byte{0x03, 0x04, 0x60, 0xac, 0x4c, 0xb1}
	ins, err := decodeInstructions(code, 10)
	if err != nil {
		t.Fatal(err)
	}
	model := &codeModel{
		Bytes: code,
		Handlers: []exceptionHandler{
			{Start: 1, End: 4, Handler: 4, CatchType: "java/lang/Exception"},
			{Start: 0, End: 3, Handler: 4},
		},
	}
	cfg, err := buildCFG(model, ins)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(cfg.Order, []uint32{0, 1, 3, 4}) {
		t.Fatalf("order=%v", cfg.Order)
	}
	want := map[uint32][]uint32{
		0: {1, 4},
		1: {3, 4},
		3: {4},
		4: nil,
	}
	for start, successors := range want {
		if got := cfg.Blocks[start].Successors; !slices.Equal(got, successors) {
			t.Errorf("block %d successors=%v, want %v", start, got, successors)
		}
	}
}

func TestBuildCFGRejectsInconsistentInstructionStream(t *testing.T) {
	code := []byte{0x00, 0xb1}
	valid, err := decodeInstructions(code, 10)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name string
		ins  []instruction
	}{
		{"nil for code", nil},
		{"wrong first offset", []instruction{{Offset: 1, Opcode: 0xb1}}},
		{"gap", []instruction{{Offset: 0, Opcode: 0x00}, {Offset: 2, Opcode: 0xb1}}},
		{"wrong opcode", []instruction{{Offset: 0, Opcode: 0x03}, valid[1]}},
		{"wrong operand length", []instruction{{Offset: 0, Opcode: 0x00, Operands: []byte{0}}, valid[1]}},
		{"merged instructions", []instruction{{Offset: 0, Opcode: 0x00, Operands: []byte{0xb1}}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := buildCFG(&codeModel{Bytes: code}, tt.ins); err == nil {
				t.Fatalf("accepted instruction stream %#v", tt.ins)
			}
		})
	}
	if _, err := buildCFG(nil, nil); err == nil {
		t.Fatal("accepted nil code model")
	}
}

func TestBuildCFGRejectsAlteredDecodedControlFlow(t *testing.T) {
	code := []byte{0x99, 0, 4, 0x00, 0xb1}
	valid, err := decodeInstructions(code, 10)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name   string
		mutate func([]instruction)
	}{
		{"target", func(ins []instruction) { ins[0].Targets = []uint32{3} }},
		{"fallthrough", func(ins []instruction) { ins[0].Fallthrough = false }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ins := append([]instruction(nil), valid...)
			tt.mutate(ins)
			if _, err := buildCFG(&codeModel{Bytes: code}, ins); err == nil {
				t.Fatalf("accepted altered instruction stream %#v", ins)
			}
		})
	}
}

func TestBuildCFGAllowsEmptyCodeWithoutHandlers(t *testing.T) {
	cfg, err := buildCFG(&codeModel{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Entry != 0 || len(cfg.Blocks) != 0 || len(cfg.Order) != 0 {
		t.Fatalf("cfg=%#v", cfg)
	}
	if _, err := buildCFG(&codeModel{Handlers: []exceptionHandler{{}}}, nil); err == nil {
		t.Fatal("accepted handler on empty code")
	}
}

func FuzzBuildCFGNeverPanics(f *testing.F) {
	seeds := [][]byte{
		{0xb1},
		{0x00},
		{0x03, 0x99, 0, 4, 0xb1},
		{0x03, 0x04, 0x60, 0xac, 0x4c, 0xb1},
		append(tableSwitch(0, 24, 0, 1, []int32{24, 24}), 0xb1),
		append(lookupSwitch(0, 20, [][2]int32{{0, 20}}), 0xb1),
		{0xc4, 0x84, 0, 1, 0, 1, 0xb1},
		{0xa8, 0, 4, 0xb1, 0xa9, 0},
		{0xc9, 0, 0, 0, 6, 0xb1, 0xc4, 0xa9, 0, 0},
	}
	for _, seed := range seeds {
		f.Add(seed, uint16(0), uint16(0), uint16(0))
	}
	f.Fuzz(func(t *testing.T, data []byte, start, end, target uint16) {
		ins, err := decodeInstructions(data, 10_000)
		if err != nil {
			return
		}
		model := &codeModel{Bytes: data}
		if start != 0 || end != 0 || target != 0 {
			model.Handlers = []exceptionHandler{{
				Start: uint32(start), End: uint32(end), Handler: uint32(target),
			}}
		}
		cfg, err := buildCFG(model, ins)
		if err != nil {
			return
		}
		assertCFGInvariants(t, cfg, ins)
	})
}

func assertCFGInvariants(t *testing.T, cfg *controlFlowGraph, instructions []instruction) {
	t.Helper()
	assertSortedUniqueOffsets(t, "block order", cfg.Order)
	if len(cfg.Blocks) != len(cfg.Order) {
		t.Fatalf("blocks=%d, order=%d", len(cfg.Blocks), len(cfg.Order))
	}
	if len(instructions) != 0 && instructions[len(instructions)-1].Fallthrough {
		t.Fatal("successful CFG has final fallthrough")
	}

	instructionIndex := 0
	for _, start := range cfg.Order {
		block := cfg.Blocks[start]
		if block == nil {
			t.Fatalf("order names missing block %d", start)
		}
		if block.Start != start || len(block.Instructions) == 0 || block.Instructions[0].Offset != start {
			t.Fatalf("invalid block %d: %#v", start, block)
		}
		for _, got := range block.Instructions {
			if instructionIndex >= len(instructions) || !equalInstruction(got, instructions[instructionIndex]) {
				t.Fatalf("block instruction %d=%#v does not match canonical stream", instructionIndex, got)
			}
			instructionIndex++
		}
		assertSortedUniqueOffsets(t, "successors", block.Successors)
		for _, successor := range block.Successors {
			if cfg.Blocks[successor] == nil {
				t.Fatalf("block %d successor %d does not name a block", start, successor)
			}
		}
	}
	if instructionIndex != len(instructions) {
		t.Fatalf("blocks cover %d of %d instructions", instructionIndex, len(instructions))
	}
}

func assertSortedUniqueOffsets(t *testing.T, name string, offsets []uint32) {
	t.Helper()
	for index := 1; index < len(offsets); index++ {
		if offsets[index-1] >= offsets[index] {
			t.Fatalf("%s is not sorted and unique: %v", name, offsets)
		}
	}
}

func legacySubroutineFanout(jsrCount, retCount int) []byte {
	code := make([]byte, jsrCount*3, jsrCount*3+1+retCount*2)
	code = append(code, 0xb1)
	retStart := len(code)
	for index := 0; index < retCount; index++ {
		code = append(code, 0xa9, 0)
	}
	for index := 0; index < jsrCount; index++ {
		offset := index * 3
		delta := retStart - offset
		code[offset] = 0xa8
		code[offset+1] = byte(delta >> 8)
		code[offset+2] = byte(delta)
	}
	return code
}

func retContinuationBoundaryInstructions(jsrCount, retCount int) []instruction {
	instructions := make([]instruction, 0, jsrCount+retCount)
	for index := 0; index < jsrCount; index++ {
		instructions = append(instructions, instruction{
			Opcode:  0xa8,
			Targets: []uint32{uint32(index)},
		})
	}
	for index := 0; index < retCount; index++ {
		instructions = append(instructions, instruction{Opcode: 0xa9})
	}
	return instructions
}
