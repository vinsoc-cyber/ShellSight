package jvmprov

import (
	"encoding/binary"
	"sort"
	"strings"
)

// Family is a family attribution for one captured class.
type Family struct {
	Name       string // "behinder", "godzilla", "" when unattributed
	Evidence   string
	Confidence float64
}

// marker is one attribution rule.
//
// Every marker must SURVIVE COMPILATION. A Java constant pool holds method references and string
// literals, not source expressions — so a marker like "getClass().getClassLoader()" can never
// appear and would be a rule that silently never fires. Both markers here are derived key literals
// verified present in the constant pool of real generated shells.
//
// These are DEFAULT keys: change the tool's password and the derived key changes, at which point
// attribution correctly reports nothing rather than guessing.
type marker struct {
	family, needle, evidence string
	confidence               float64
}

// Deliberately small. An attribution that fires on a generic string is worse than none: it is a
// confident wrong answer in an incident report.
var markers = []marker{
	{"behinder", "e45e329feb5d925b", `default Behinder AES key literal (MD5("rebeyond")[:16])`, 0.9},
	{"godzilla", "3c6e0b8a9c15224a", `default Godzilla key literal (MD5("key")[:16])`, 0.9},
	// Suo5 sets X-Accel-Buffering: no so nginx will not buffer its chunked tunnel stream. Public
	// defender guidance calls the header "almost never sent by legitimate components ... a
	// near-zero false-positive detection indicator", and it is absent from all 4,016 classes in a
	// stock Tomcat 9. It is a HEADER NAME, not a derived key, so it survives a password change --
	// unlike the two above, which correctly stop attributing when the operator changes the key.
	// Confidence is 0.85 rather than 0.9: this identifies the tool by its transport behaviour, one
	// step weaker than a key literal unique to a build.
	// Checked against Neo-reGeorg, the other tunnel family in the corpus: its classes carry neither
	// this header nor java/net/Socket, so this does not misattribute one tunnel family as another.
	// Evidence: docs/measurements/2026-08-30-memshell-detection-landscape/02-tunnel-capability.md
	{"suo5", "X-Accel-Buffering", "Suo5 anti-buffering header literal (X-Accel-Buffering)", 0.85},
}

// capabilityNeedles are constant-pool references that say what a class can DO. Internal (slash)
// form, which is how type references appear in the pool.
var capabilityNeedles = map[string][]string{
	"exec":    {"java/lang/Runtime", "java/lang/ProcessBuilder", "cmd.exe", "/bin/sh", "/bin/bash"},
	// Tunnelling is a capability in its own right, and the reason Suo5 scored below every command
	// shell: it relays TCP over HTTP and never executes anything, so an exec-only vocabulary had no
	// term for what it does.
	//
	// Deliberately ONE needle. The obvious additions -- java/net/Socket, SocketChannel,
	// InetSocketAddress -- are what Suo5 actually uses, but 45 of 4,016 stock Tomcat classes
	// reference java/net/Socket: it is a web server. Counting relay APIs as capability would
	// re-import precisely the weakness the exec gate was added to remove. They corroborate in
	// analysis; they do not score.
	"tunnel":  {"X-Accel-Buffering"},
	"crypto":  {"javax/crypto/Cipher", "javax/crypto/spec/SecretKeySpec"},
	"loader":  {"java/lang/ClassLoader"},
	"reflect": {"java/lang/reflect/Method"},
	"script":  {"javax/script/ScriptEngine"},
	"jndi":    {"javax/naming/InitialContext"},
}

// Attribute names the family of a captured class, and reports what it can do.
//
// ADDITIVE ONLY. It never gates a verdict and never suppresses one: an unattributed class is
// exactly as malicious as the rest of the evidence says. It is only worth having if it stays honest
// about what it does not know -- which applies to the claim around it as much as to the output.
//
// THE CLAIM, as measurement supports it (2026-09-01): no surveyed Java memshell tool attributes
// family at all, and no tool of any kind attributes from OUTSIDE the target process. It is NOT
// unclaimed everywhere -- yzddmr6/ASP.NET-Memshell-Scanner reflects Godzilla's live password and key
// straight out of a resident .NET VirtualPathProvider. That is attribution, and for its one
// mechanism it recovers the operator's real key where the markers below match only a DEFAULT key.
// The advantage we actually hold is that a constant-pool literal is not attacker-renameable, where
// its GetField("password") is. See
// docs/measurements/2026-08-30-memshell-detection-landscape/05-dotnet-oss-incumbent-and-sample-supply.md
func Attribute(classBytes []byte) (Family, []string) {
	if len(classBytes) == 0 {
		return Family{}, nil
	}
	strs := constantPoolStrings(classBytes)
	raw := string(classBytes)

	var fam Family
	for _, m := range markers {
		if strs[m.needle] {
			fam = Family{Name: m.family, Evidence: m.evidence, Confidence: m.confidence}
			break
		}
	}

	var caps []string
	for cap, needles := range capabilityNeedles {
		for _, n := range needles {
			// String literals come from the pool (precise); type references appear as Utf8
			// entries, so a raw scan covers those. Both are constrained to this class's bytes.
			if strs[n] || strings.Contains(raw, n) {
				caps = append(caps, cap)
				break
			}
		}
	}
	sort.Strings(caps) // stable output: findings feed a SIEM, where an unstable list breaks dedup
	return fam, caps
}

// constantPoolStrings returns the set of genuine string LITERALS in a class file — the Utf8 entries
// referenced by a CONSTANT_String.
//
// Reading the pool directly, rather than relying on where a bytecode visitor surfaces a literal,
// is what makes this work at all. The equivalent Java code matched strings only through
// visitLdcInsn and silently missed both family keys across 92 real memshells, even though both
// were present as CONSTANT_String entries.
//
// Only CONSTANT_String entries count, never every Utf8 — otherwise class names, field names and
// method descriptors would produce hits.
func constantPoolStrings(b []byte) map[string]bool {
	out := map[string]bool{}
	defer func() { _ = recover() }() // malformed input is a best-effort miss, never a crash
	if len(b) < 10 {
		return out
	}
	count := int(binary.BigEndian.Uint16(b[8:10]))
	utf8 := make(map[int]string, count)
	var stringRefs []int

	i := 10
	for idx := 1; idx < count && i < len(b); idx++ {
		switch b[i] {
		case 1: // CONSTANT_Utf8
			if i+3 > len(b) {
				return out
			}
			n := int(binary.BigEndian.Uint16(b[i+1 : i+3]))
			if i+3+n > len(b) {
				return out
			}
			utf8[idx] = string(b[i+3 : i+3+n])
			i += 3 + n
		case 8: // CONSTANT_String -> index of its Utf8
			if i+3 > len(b) {
				return out
			}
			stringRefs = append(stringRefs, int(binary.BigEndian.Uint16(b[i+1:i+3])))
			i += 3
		case 7, 16, 19, 20: // Class / MethodType / Module / Package
			i += 3
		case 15: // MethodHandle
			i += 4
		case 5, 6: // Long / Double take two constant-pool slots
			i += 9
			idx++
		default: // Fieldref / Methodref / NameAndType / ...
			i += 5
		}
	}
	for _, ref := range stringRefs {
		if s, ok := utf8[ref]; ok {
			out[s] = true
		}
	}
	return out
}
