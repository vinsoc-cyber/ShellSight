package deobfuscate

import (
	"strings"
	"testing"
)

// Regressions for the two defects that made the generated Python matrix score 0 on 21 of its 63
// cells while the folding itself was working perfectly. Both are gate/decoder failures, not
// analysis failures, and neither was visible from a unit test of Fold alone -- Fold produced the
// right bytes and Run threw them away.

func foldedLayer(t *testing.T, src string) string {
	t.Helper()
	for _, l := range Run([]byte(src)).Layers {
		if l.Method == "folded" {
			return string(l.Data)
		}
	}
	return ""
}

// DEFECT 1: revealsFoldedSink asked only "did a sink NAME appear that was not there before?".
// `subprocess` is already present inside `__import__('subprocess')`, so nothing looked newly
// revealed and the layer was dropped. The technique hides the METHOD name, not the module.
func TestGetattrImportDispatchSurvivesTheRevealGate(t *testing.T) {
	for name, src := range map[string]string{
		"concat":  "cmd = request.args.get(\"c\")\nfn = 'ca' + 'll'\ngetattr(__import__('subprocess'), fn)(cmd, shell=True)\n",
		"chr":     "cmd = request.args.get(\"c\")\nfn = chr(99)+chr(97)+chr(108)+chr(108)\ngetattr(__import__('subprocess'), fn)(cmd, shell=True)\n",
		"reverse": "cmd = request.args.get(\"c\")\nfn = 'llac'[::-1]\ngetattr(__import__('subprocess'), fn)(cmd, shell=True)\n",
	} {
		got := foldedLayer(t, src)
		if got == "" {
			t.Fatalf("%s: no folded layer -- the reveal gate dropped it", name)
		}
		if !strings.Contains(got, "subprocess.call(") {
			t.Fatalf("%s: sink not resolved: %q", name, got)
		}
	}
}

// DEFECT 2: Fold had no decoders, so a name spelled through base64 or hex never folded at all --
// zero across EVERY dispatch in both languages, while concat and chr passed.
func TestDecoderSpellingsFold(t *testing.T) {
	cases := []struct{ name, src, want string }{
		{"py base64", "fn = __import__('base64').b64decode('Y2FsbA==').decode()\ngetattr(__import__('subprocess'), fn)(cmd)\n", "subprocess.call("},
		{"py hex", "fn = bytes.fromhex('63616c6c').decode()\ngetattr(__import__('subprocess'), fn)(cmd)\n", "subprocess.call("},
		{"perl base64", "my $fn = decode_base64(\"c3lzdGVt\");\n$fn($CMD);\n", "system"},
		{"perl pack-hex", "my $fn = pack(\"H*\", \"73797374656d\");\n$fn($CMD);\n", "system"},
	}
	for _, c := range cases {
		out := string(Fold([]byte(c.src)))
		if !strings.Contains(out, c.want) {
			t.Errorf("%s: want %q in folded output, got %q", c.name, c.want, out)
		}
	}
}

// Perl's spellings populate the SECOND capture group of each decoder regex, because each pattern is
// an alternation of the Python and Perl forms. Reading p[1] unconditionally dropped every Perl fold
// while the Python ones passed -- a half-working pass looks exactly like a working one.
func TestPerlDecoderUsesItsOwnCaptureGroup(t *testing.T) {
	for _, src := range []string{
		"my $x = decode_base64(\"c3lzdGVt\");",
		"my $x = pack(\"H*\", \"73797374656d\");",
	} {
		out := string(foldDecoders([]byte(src)))
		if !strings.Contains(out, "'system'") {
			t.Errorf("perl decoder did not fold: %q -> %q", src, out)
		}
	}
}

// The gate must stay tight. Benign code concatenates constantly; without this every minified asset
// would gain a layer and double the mirror-scan surface for no detection gain.
func TestBenignConcatenationGainsNoFoldedLayer(t *testing.T) {
	src := "greeting = 'hel' + 'lo'\nname = 'wor' + 'ld'\nprint(greeting, name)\n"
	if got := foldedLayer(t, src); got != "" {
		t.Fatalf("benign concatenation gained a folded layer: %q", got)
	}
}

// A decoder call on a VARIABLE must be left alone -- folding across one fabricates a string that
// need not exist at runtime, which is the safety property the whole file rests on.
func TestDecoderOnAVariableIsNotFolded(t *testing.T) {
	src := "fn = bytes.fromhex(user_supplied).decode()\n"
	if out := string(foldDecoders([]byte(src))); out != src {
		t.Fatalf("folded a non-literal argument: %q", out)
	}
}

// A decode whose result is not printable is not a sink name; quoting it would inject control bytes
// into the view the scanner reads.
func TestNonPrintableDecodeIsRejected(t *testing.T) {
	src := "x = bytes.fromhex('0001020304').decode()\n"
	if out := string(foldDecoders([]byte(src))); out != src {
		t.Fatalf("folded a non-printable decode: %q", out)
	}
}
