package javadisk

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"slices"
	"testing"
)

func TestOpcodeOperandWidthsCoverAllValues(t *testing.T) {
	want := [256]int8{}
	for opcode := range want {
		want[opcode] = invalidOperandWidth
	}
	setRange := func(first, last byte, width int8) {
		for opcode := int(first); opcode <= int(last); opcode++ {
			want[opcode] = width
		}
	}

	setRange(0x00, 0x0f, 0)
	want[0x10], want[0x11], want[0x12] = 1, 2, 1
	setRange(0x13, 0x14, 2)
	setRange(0x15, 0x19, 1)
	setRange(0x1a, 0x35, 0)
	setRange(0x36, 0x3a, 1)
	setRange(0x3b, 0x83, 0)
	want[0x84] = 2
	setRange(0x85, 0x98, 0)
	setRange(0x99, 0xa8, 2)
	want[0xa9] = 1
	want[0xaa], want[0xab] = variableOperandWidth, variableOperandWidth
	setRange(0xac, 0xb1, 0)
	setRange(0xb2, 0xb8, 2)
	want[0xb9], want[0xba] = 4, 4
	want[0xbb], want[0xbc], want[0xbd] = 2, 1, 2
	setRange(0xbe, 0xbf, 0)
	setRange(0xc0, 0xc1, 2)
	setRange(0xc2, 0xc3, 0)
	want[0xc4] = variableOperandWidth
	want[0xc5], want[0xc6], want[0xc7] = 3, 2, 2
	want[0xc8], want[0xc9] = 4, 4

	for opcode, width := range want {
		if got := opcodeOperandWidths[opcode]; got != width {
			t.Errorf("opcode 0x%02x width=%d, want %d", opcode, got, width)
		}
	}
}

func TestDecodeFixedWidthOperandsAndOffsets(t *testing.T) {
	code := []byte{0x10, 0x80, 0x11, 0x12, 0x34, 0x12, 0x7f, 0x84, 0x02, 0xfe, 0xb1}
	got, err := decodeInstructions(code, 10)
	if err != nil {
		t.Fatal(err)
	}
	want := []instruction{
		{Offset: 0, Opcode: 0x10, Operands: []byte{0x80}, Fallthrough: true},
		{Offset: 2, Opcode: 0x11, Operands: []byte{0x12, 0x34}, Fallthrough: true},
		{Offset: 5, Opcode: 0x12, Operands: []byte{0x7f}, Fallthrough: true},
		{Offset: 7, Opcode: 0x84, Operands: []byte{0x02, 0xfe}, Fallthrough: true},
		{Offset: 10, Opcode: 0xb1, Fallthrough: false},
	}
	if !slices.EqualFunc(got, want, equalInstruction) {
		t.Fatalf("instructions=%#v, want %#v", got, want)
	}
}

func TestDecodeRejectsEveryReservedOpcode(t *testing.T) {
	for opcode := 0xca; opcode <= 0xff; opcode++ {
		t.Run(string(rune(opcode)), func(t *testing.T) {
			if _, err := decodeInstructions([]byte{byte(opcode)}, 1); err == nil {
				t.Fatalf("opcode 0x%02x accepted", opcode)
			}
		})
	}
}

func TestDecodeRejectsTruncatedFixedWidthOperands(t *testing.T) {
	for opcode, width := range opcodeOperandWidths {
		if width <= 0 {
			continue
		}
		code := make([]byte, int(width))
		code[0] = byte(opcode)
		if _, err := decodeInstructions(code, 1); err == nil {
			t.Errorf("opcode 0x%02x accepted %d of %d operand bytes", opcode, width-1, width)
		}
	}
}

func TestDecodeSignedBranchTargetsAndFallthrough(t *testing.T) {
	code := []byte{
		0x03,
		0x99, 0x00, 0x09,
		0xa7, 0xff, 0xfc,
		0xc8, 0x00, 0x00, 0x00, 0x05,
		0xb1,
	}
	got, err := decodeInstructions(code, 10)
	if err != nil {
		t.Fatal(err)
	}
	assertTargets(t, got[1], []uint32{10}, true)
	assertTargets(t, got[2], []uint32{0}, false)
	assertTargets(t, got[3], []uint32{12}, false)
	if got[4].Fallthrough {
		t.Fatal("return marked as fallthrough")
	}
}

func TestDecodeJSRRetAndThrowDoNotFallThrough(t *testing.T) {
	tests := []struct {
		name string
		code []byte
	}{
		{"jsr", []byte{0xa8, 0, 0}},
		{"ret", []byte{0xa9, 0}},
		{"athrow", []byte{0xbf}},
		{"jsr_w", []byte{0xc9, 0, 0, 0, 0}},
		{"wide_ret", []byte{0xc4, 0xa9, 0, 0}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := decodeInstructions(tt.code, 1)
			if err != nil {
				t.Fatal(err)
			}
			if got[0].Fallthrough {
				t.Fatalf("opcode 0x%02x marked as fallthrough", got[0].Opcode)
			}
		})
	}
}

func TestDecodeRejectsBranchTargetArithmeticUnderflow(t *testing.T) {
	code := []byte{0x00, 0x99, 0x80, 0x00}
	if _, err := decodeInstructions(code, 10); err == nil {
		t.Fatal("accepted negative absolute branch target")
	}
}

func TestDecodeTableSwitchTargets(t *testing.T) {
	code := []byte{0x03, 0xaa, 0, 0, 0, 0, 0, 19, 0, 0, 0, 1,
		0, 0, 0, 2, 0, 0, 0, 23, 0, 0, 0, 27}
	ins, err := decodeInstructions(code, 100)
	if err != nil {
		t.Fatal(err)
	}
	if got := ins[1].Targets; !slices.Equal(got, []uint32{20, 24, 28}) {
		t.Fatalf("targets=%v", got)
	}
	if ins[1].Fallthrough {
		t.Fatal("tableswitch marked as fallthrough")
	}
	if !slices.Equal(ins[1].Operands, code[2:]) {
		t.Fatalf("raw operands=%v, want %v", ins[1].Operands, code[2:])
	}
}

func TestDecodeRejectsNonzeroSwitchPadding(t *testing.T) {
	switches := []struct {
		name  string
		build func(int) []byte
	}{
		{"tableswitch", func(offset int) []byte { return tableSwitch(offset, 0, 0, 0, []int32{0}) }},
		{"lookupswitch", func(offset int) []byte { return lookupSwitch(offset, 0, nil) }},
	}
	for _, sw := range switches {
		for padding := 1; padding <= 3; padding++ {
			t.Run(fmt.Sprintf("%s/%d", sw.name, padding), func(t *testing.T) {
				offset := 3 - padding
				code := sw.build(offset)
				code[offset+padding] = 1
				if _, err := decodeInstructions(code, 10); err == nil {
					t.Fatalf("accepted %s with %d-byte nonzero padding", sw.name, padding)
				}
			})
		}
	}
}

func TestDecodeSwitchAlignmentWithZeroPadding(t *testing.T) {
	switches := []struct {
		name  string
		build func(int) []byte
	}{
		{"tableswitch", func(offset int) []byte { return tableSwitch(offset, 0, 0, 0, []int32{0}) }},
		{"lookupswitch", func(offset int) []byte { return lookupSwitch(offset, 0, nil) }},
	}
	for _, sw := range switches {
		for padding := 0; padding <= 3; padding++ {
			t.Run(fmt.Sprintf("%s/%d", sw.name, padding), func(t *testing.T) {
				offset := 3 - padding
				code := sw.build(offset)
				ins, err := decodeInstructions(code, 10)
				if err != nil {
					t.Fatal(err)
				}
				got := ins[offset]
				if got.Offset != uint32(offset) {
					t.Fatalf("offset=%d, want %d", got.Offset, offset)
				}
				if !slices.Equal(got.Operands[:padding], make([]byte, padding)) {
					t.Fatalf("padding=%v, want %d zero bytes", got.Operands[:padding], padding)
				}
			})
		}
	}
}

func TestDecodeLookupSwitchTargetsAndKeyOrdering(t *testing.T) {
	code := lookupSwitch(0, 28, [][2]int32{{-7, 32}, {5, 36}})
	ins, err := decodeInstructions(code, 10)
	if err != nil {
		t.Fatal(err)
	}
	assertTargets(t, ins[0], []uint32{28, 32, 36}, false)

	for _, pairs := range [][][2]int32{
		{{5, 0}, {5, 0}},
		{{5, 0}, {-7, 0}},
	} {
		if _, err := decodeInstructions(lookupSwitch(0, 0, pairs), 10); err == nil {
			t.Fatalf("accepted unordered lookup keys %v", pairs)
		}
	}
}

func TestDecodeRejectsMalformedSwitches(t *testing.T) {
	validTable := tableSwitch(0, 0, 1, 2, []int32{0, 0})
	validLookup := lookupSwitch(0, 0, [][2]int32{{1, 0}})
	tests := []struct {
		name string
		code []byte
	}{
		{"truncated table header", validTable[:11]},
		{"negative table range", tableSwitch(0, 0, 2, 1, nil)},
		{"overflowed table range", tableSwitch(0, 0, math.MinInt32, math.MaxInt32, nil)},
		{"truncated table entries", validTable[:len(validTable)-1]},
		{"truncated lookup header", validLookup[:7]},
		{"negative lookup count", switchHeader(0xab, 0, -1)},
		{"overflowed lookup count", switchHeader(0xab, 0, math.MaxInt32)},
		{"truncated lookup pairs", validLookup[:len(validLookup)-1]},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := decodeInstructions(tt.code, 10); err == nil {
				t.Fatalf("accepted malformed switch: %v", tt.code)
			}
		})
	}
}

func TestDecodeWideLegalForms(t *testing.T) {
	tests := []struct {
		name         string
		code         []byte
		fallsThrough bool
	}{
		{"iload", []byte{0xc4, 0x15, 0x12, 0x34}, true},
		{"astore", []byte{0xc4, 0x3a, 0x12, 0x34}, true},
		{"ret", []byte{0xc4, 0xa9, 0x12, 0x34}, false},
		{"iinc", []byte{0xc4, 0x84, 0x12, 0x34, 0xff, 0xfe}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := decodeInstructions(tt.code, 1)
			if err != nil {
				t.Fatal(err)
			}
			if len(got) != 1 || !slices.Equal(got[0].Operands, tt.code[1:]) {
				t.Fatalf("instruction=%#v", got)
			}
			if got[0].Fallthrough != tt.fallsThrough {
				t.Fatalf("fallthrough=%v, want %v", got[0].Fallthrough, tt.fallsThrough)
			}
		})
	}
}

func TestDecodeRejectsIllegalOrTruncatedWideForms(t *testing.T) {
	tests := [][]byte{
		{0xc4},
		{0xc4, 0x00, 0, 0},
		{0xc4, 0x84, 0, 0, 0},
		{0xc4, 0x15, 0},
		{0xc4, 0xac, 0, 0},
	}
	for _, code := range tests {
		if _, err := decodeInstructions(code, 1); err == nil {
			t.Errorf("accepted wide form %v", code)
		}
	}
}

func TestDecodeOpcodeSpecificValidation(t *testing.T) {
	valid := [][]byte{
		{0xb9, 0, 1, 1, 0},
		{0xba, 0, 1, 0, 0},
		{0xbc, 4}, {0xbc, 11},
		{0xc5, 0, 1, 1},
	}
	for _, code := range valid {
		if _, err := decodeInstructions(code, 1); err != nil {
			t.Errorf("valid instruction %v: %v", code, err)
		}
	}

	invalid := [][]byte{
		{0xb9, 0, 1, 0, 0},
		{0xb9, 0, 1, 1, 1},
		{0xba, 0, 1, 1, 0},
		{0xba, 0, 1, 0, 1},
		{0xbc, 3}, {0xbc, 12},
		{0xc5, 0, 1, 0},
	}
	for _, code := range invalid {
		if _, err := decodeInstructions(code, 1); err == nil {
			t.Errorf("accepted invalid instruction %v", code)
		}
	}
}

func TestDecodeEnforcesInstructionLimitBeforeAppend(t *testing.T) {
	if _, err := decodeInstructions([]byte{0x00}, 0); err == nil {
		t.Fatal("accepted an instruction with zero budget")
	}
	if _, err := decodeInstructions([]byte{0x00, 0x00}, 1); err == nil {
		t.Fatal("accepted two instructions with budget one")
	}
	got, err := decodeInstructions(nil, 0)
	if err != nil || len(got) != 0 {
		t.Fatalf("empty decode=(%v, %v)", got, err)
	}
}

func TestDecodeInstructionLimitErrorIsTyped(t *testing.T) {
	_, err := decodeInstructions([]byte{0x00, 0xb1}, 1)
	var limitError *instructionLimitError
	if !errors.As(err, &limitError) {
		t.Fatalf("error=%T %v, want *instructionLimitError", err, err)
	}
	if limitError.Limit != 1 || limitError.Offset != 1 ||
		err.Error() != "instruction limit 1 exceeded at bytecode offset 1" {
		t.Fatalf("limit error=%+v text=%q", limitError, err)
	}
}

func FuzzDecodeInstructionsNeverPanics(f *testing.F) {
	seeds := [][]byte{
		{0xb1},
		{0x03, 0x99, 0, 4, 0xb1},
		tableSwitch(0, 20, 1, 2, []int32{20, 20}),
		lookupSwitch(0, 20, [][2]int32{{-1, 20}, {2, 20}}),
		{0xc4, 0x84, 0, 1, 0xff, 0xff, 0xb1},
		{0xb9, 0, 1, 1, 0, 0xba, 0, 1, 0, 0, 0xb1},
		{0xaa, 0, 0},
	}
	for _, seed := range seeds {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		ins, err := decodeInstructions(data, 10_000)
		if err != nil {
			return
		}
		assertCanonicalDecode(t, data, ins)
	})
}

func assertCanonicalDecode(t *testing.T, data []byte, instructions []instruction) {
	t.Helper()
	expected := uint64(0)
	for index, ins := range instructions {
		if uint64(ins.Offset) != expected {
			t.Fatalf("instruction %d offset=%d, want %d", index, ins.Offset, expected)
		}
		end := expected + 1 + uint64(len(ins.Operands))
		if end > uint64(len(data)) {
			t.Fatalf("instruction %d ends at %d beyond input length %d", index, end, len(data))
		}
		if ins.Opcode != data[int(expected)] {
			t.Fatalf("instruction %d opcode=0x%02x, input=0x%02x", index, ins.Opcode, data[int(expected)])
		}
		if !slices.Equal(ins.Operands, data[int(expected+1):int(end)]) {
			t.Fatalf("instruction %d operands=%v, input=%v", index, ins.Operands, data[int(expected+1):int(end)])
		}
		expected = end
	}
	if expected != uint64(len(data)) {
		t.Fatalf("decoded coverage ends at %d, input length is %d", expected, len(data))
	}

	canonical, err := decodeInstructions(data, 10_000)
	if err != nil {
		t.Fatalf("canonical re-decode failed: %v", err)
	}
	if !slices.EqualFunc(instructions, canonical, equalInstruction) {
		t.Fatalf("non-deterministic decode: first=%#v second=%#v", instructions, canonical)
	}
}

func equalInstruction(a, b instruction) bool {
	return a.Offset == b.Offset && a.Opcode == b.Opcode &&
		slices.Equal(a.Operands, b.Operands) && slices.Equal(a.Targets, b.Targets) &&
		a.Fallthrough == b.Fallthrough
}

func assertTargets(t *testing.T, ins instruction, want []uint32, fallsThrough bool) {
	t.Helper()
	if !slices.Equal(ins.Targets, want) {
		t.Fatalf("targets=%v, want %v", ins.Targets, want)
	}
	if ins.Fallthrough != fallsThrough {
		t.Fatalf("fallthrough=%v, want %v", ins.Fallthrough, fallsThrough)
	}
}

func tableSwitch(offset int, defaultOffset, low, high int32, targets []int32) []byte {
	code := make([]byte, offset+1)
	code[offset] = 0xaa
	for len(code)%4 != 0 {
		code = append(code, 0)
	}
	code = appendInt32(code, defaultOffset)
	code = appendInt32(code, low)
	code = appendInt32(code, high)
	for _, target := range targets {
		code = appendInt32(code, target)
	}
	return code
}

func lookupSwitch(offset int, defaultOffset int32, pairs [][2]int32) []byte {
	code := make([]byte, offset+1)
	code[offset] = 0xab
	for len(code)%4 != 0 {
		code = append(code, 0)
	}
	code = appendInt32(code, defaultOffset)
	code = appendInt32(code, int32(len(pairs)))
	for _, pair := range pairs {
		code = appendInt32(code, pair[0])
		code = appendInt32(code, pair[1])
	}
	return code
}

func switchHeader(opcode byte, defaultOffset, count int32) []byte {
	code := []byte{opcode, 0, 0, 0}
	code = appendInt32(code, defaultOffset)
	return appendInt32(code, count)
}

func appendInt32(dst []byte, value int32) []byte {
	var buf [4]byte
	binary.BigEndian.PutUint32(buf[:], uint32(value))
	return append(dst, buf[:]...)
}
