package javadisk

import (
	"strings"
	"testing"
)

func TestDescriptorParsesFieldTypesAndWidths(t *testing.T) {
	tests := []struct {
		descriptor string
		width      uint8
		object     string
		array      bool
	}{
		{"I", 1, "", false},
		{"J", 2, "", false},
		{"D", 2, "", false},
		{"Ljava/lang/String;", 1, "java/lang/String", false},
		{"[[J", 1, "", true},
		{"[Ljava/lang/String;", 1, "java/lang/String", true},
	}
	for _, tt := range tests {
		t.Run(tt.descriptor, func(t *testing.T) {
			got, err := parseFieldDescriptor(tt.descriptor)
			if err != nil {
				t.Fatal(err)
			}
			if got.Width != tt.width || got.Object != tt.object || got.Array != tt.array || got.Void {
				t.Fatalf("parseFieldDescriptor(%q)=%+v", tt.descriptor, got)
			}
		})
	}
}

func TestDescriptorParsesMethodsAndInvokeEffects(t *testing.T) {
	parsed, err := parseMethodDescriptor("(ID[JLjava/lang/String;)D")
	if err != nil {
		t.Fatal(err)
	}
	if len(parsed.Parameters) != 4 || parsed.ParameterSlots != 5 || parsed.Return.Width != 2 || parsed.Return.Void {
		t.Fatalf("parsed=%+v", parsed)
	}

	for _, tt := range []struct {
		name     string
		static   bool
		wantPop  int
		wantPush int
	}{
		{"static", true, 5, 2},
		{"receiver", false, 6, 2},
	} {
		t.Run(tt.name, func(t *testing.T) {
			pop, push, err := invokeStackEffect("(ID[JLjava/lang/String;)D", tt.static)
			if err != nil {
				t.Fatal(err)
			}
			if pop != tt.wantPop || push != tt.wantPush {
				t.Fatalf("pop=%d push=%d", pop, push)
			}
		})
	}
}

func TestDescriptorRejectsMalformedAndIllegalVoid(t *testing.T) {
	for _, descriptor := range []string{
		"", "V", "II", "L;", "Ljava/lang/String", "[", "[V", "(V)V", "(I", "I)V", "()", "()VI",
		"(Ljava/lang/String;)Vtrailing", "(I)[V",
	} {
		t.Run(strings.ReplaceAll(descriptor, "/", "_"), func(t *testing.T) {
			var err error
			if strings.HasPrefix(descriptor, "(") || strings.Contains(descriptor, ")") {
				_, err = parseMethodDescriptor(descriptor)
			} else {
				_, err = parseFieldDescriptor(descriptor)
			}
			if err == nil {
				t.Fatalf("accepted %q", descriptor)
			}
		})
	}
}

func TestDescriptorEnforcesJVMParameterSlotLimit(t *testing.T) {
	valid := "(" + strings.Repeat("J", 127) + "I)V"
	if parsed, err := parseMethodDescriptor(valid); err != nil || parsed.ParameterSlots != 255 {
		t.Fatalf("valid descriptor: parsed=%+v err=%v", parsed, err)
	}
	if _, err := parseMethodDescriptor("(" + strings.Repeat("J", 128) + ")V"); err == nil {
		t.Fatal("accepted 256 parameter slots")
	}
	if _, _, err := invokeStackEffect(valid, false); err == nil {
		t.Fatal("accepted receiver plus 255 explicit parameter slots")
	}
}

func TestDescriptorObjectNamesUseJVMSUnqualifiedNameExclusions(t *testing.T) {
	for _, descriptor := range []string{
		"Lpkg/Name(with)parens;",
		"Lpkg/Name\x00WithNul;",
		"[Lpkg/(Generated);",
	} {
		if _, err := parseFieldDescriptor(descriptor); err != nil {
			t.Fatalf("rejected legal descriptor %q: %v", descriptor, err)
		}
	}
	for _, descriptor := range []string{
		"Lpkg/Bad.Name;", "Lpkg//Name;", "L/pkg/Name/;", "L/pkg/[Name;",
	} {
		if _, err := parseFieldDescriptor(descriptor); err == nil {
			t.Fatalf("accepted illegal descriptor %q", descriptor)
		}
	}
}
