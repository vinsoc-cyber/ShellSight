package deobfuscate

import (
	"bytes"
	"strings"
	"testing"
)

// Constant folding — the highest-value gap measured in 2026-08-18-perl-python-detection-litreview.
//
// ShellSight's entire Perl/Python capability is one literal source->sink YARA rule per language, so
// any transform that breaks the literal sink string defeats it outright. Measured on the 1,008-sample
// generated matrices, `concat` and `reverse` score 0.000 in BOTH languages, and Python's `chr` scores
// 0.000 while Perl's scores 1.000 -- because the existing chr fold only accepts '.' as a separator
// and Python concatenates with '+'.
//
// Prior art: SAFE-Deobs (Herrera, IEEE SCAM 2020) -- constant folding and propagation as a static
// pre-pass before matching. The inputs below are verbatim from the generator, not invented.

// --- concat ------------------------------------------------------------------------------------

// Perl: my $fn = 'ex' . 'ec';  -> the sink name only exists once the literals are folded.
func TestFoldJoinsDotConcatenatedStringLiterals(t *testing.T) {
	got := Fold([]byte(`my $fn = 'ex' . 'ec';`))
	if !bytes.Contains(got, []byte("exec")) {
		t.Fatalf("dot-concatenated literals not folded; got %q", got)
	}
}

// Python: fn = 'po' + 'pen'
func TestFoldJoinsPlusConcatenatedStringLiterals(t *testing.T) {
	got := Fold([]byte(`fn = 'po' + 'pen'`))
	if !bytes.Contains(got, []byte("popen")) {
		t.Fatalf("plus-concatenated literals not folded; got %q", got)
	}
}

func TestFoldJoinsMoreThanTwoConcatenatedLiterals(t *testing.T) {
	got := Fold([]byte(`$x = 'sy' . 's' . 'tem';`))
	if !bytes.Contains(got, []byte("system")) {
		t.Fatalf("three-part concatenation not folded; got %q", got)
	}
}

func TestFoldJoinsDoubleQuotedLiterals(t *testing.T) {
	got := Fold([]byte(`fn = "po" + "pen"`))
	if !bytes.Contains(got, []byte("popen")) {
		t.Fatalf("double-quoted concatenation not folded; got %q", got)
	}
}

// Mixed quoting is ordinary in real samples and must not stop the fold.
func TestFoldJoinsMixedQuoteStyles(t *testing.T) {
	got := Fold([]byte(`$x = 'sys' . "tem";`))
	if !bytes.Contains(got, []byte("system")) {
		t.Fatalf("mixed-quote concatenation not folded; got %q", got)
	}
}

// A '+' between a literal and a NON-literal is arithmetic or variable concatenation, not a constant.
// Folding across it would fabricate a string that never exists at runtime.
func TestFoldLeavesConcatenationWithAVariableAlone(t *testing.T) {
	src := []byte(`$x = 'sys' . $tem;`)
	if got := Fold(src); bytes.Contains(got, []byte("system")) {
		t.Fatalf("folded across a variable, fabricating a literal; got %q", got)
	}
}

// --- reverse -----------------------------------------------------------------------------------

// Perl: my $fn = scalar reverse('cexe');
func TestFoldResolvesPerlScalarReverse(t *testing.T) {
	got := Fold([]byte(`my $fn = scalar reverse('cexe');`))
	if !bytes.Contains(got, []byte("exec")) {
		t.Fatalf("scalar reverse not folded; got %q", got)
	}
}

func TestFoldResolvesBarePerlReverse(t *testing.T) {
	got := Fold([]byte(`my $fn = reverse("metsys");`))
	if !bytes.Contains(got, []byte("system")) {
		t.Fatalf("bare reverse not folded; got %q", got)
	}
}

// Python: fn = 'nepop'[::-1]
func TestFoldResolvesPythonSliceReverse(t *testing.T) {
	got := Fold([]byte(`fn = 'nepop'[::-1]`))
	if !bytes.Contains(got, []byte("popen")) {
		t.Fatalf("python slice reverse not folded; got %q", got)
	}
}

func TestFoldReverseHandlesDoubleQuotes(t *testing.T) {
	got := Fold([]byte(`fn = "nepop"[::-1]`))
	if !bytes.Contains(got, []byte("popen")) {
		t.Fatalf("double-quoted slice reverse not folded; got %q", got)
	}
}

// A reverse of a VARIABLE is not a constant and must be left as-is.
func TestFoldLeavesReverseOfAVariableAlone(t *testing.T) {
	src := []byte(`my $fn = reverse($x);`)
	got := Fold(src)
	if !bytes.Equal(got, src) {
		t.Fatalf("rewrote a non-constant reverse; got %q", got)
	}
}

// --- chr with a '+' separator (the Python gap) -------------------------------------------------

// Python: fn = chr(112)+chr(111)+chr(112)+chr(101)+chr(110)
// Perl's '.'-separated form already folds; the '+' form measured 0.000.
func TestFoldJoinsPlusSeparatedChrRun(t *testing.T) {
	got := Fold([]byte(`fn = chr(112)+chr(111)+chr(112)+chr(101)+chr(110)`))
	if !bytes.Contains(got, []byte("popen")) {
		t.Fatalf("plus-separated chr run not folded; got %q", got)
	}
}

// --- composition and safety --------------------------------------------------------------------

// Folding must compose: chr run -> literal, then concatenated with a neighbouring literal.
func TestFoldComposesChrRunWithAdjacentLiteral(t *testing.T) {
	got := Fold([]byte(`$x = chr(115).chr(121).chr(115) . 'tem';`))
	if !bytes.Contains(got, []byte("system")) {
		t.Fatalf("chr run did not compose with an adjacent literal; got %q", got)
	}
}

// Reverse of a folded concatenation — two passes are required, so the folder must iterate.
func TestFoldIteratesUntilStable(t *testing.T) {
	got := Fold([]byte(`$fn = reverse('me' . 'tsys');`))
	if !bytes.Contains(got, []byte("system")) {
		t.Fatalf("did not iterate concat-then-reverse; got %q", got)
	}
}

// The overwhelming majority of concatenation in real code is benign. Folding is a REWRITE, so it
// must be byte-identical on input that contains nothing to fold, or every benign file changes and
// the false-positive surface moves for reasons unrelated to detection.
func TestFoldIsIdentityWhenThereIsNothingToFold(t *testing.T) {
	src := []byte("use strict;\nmy $x = $a . $b;\nprint \"hello\\n\";\n")
	if got := Fold(src); !bytes.Equal(got, src) {
		t.Fatalf("folder rewrote input with nothing to fold:\n in: %q\nout: %q", src, got)
	}
}

// Pathological input must terminate rather than loop or blow up.
func TestFoldTerminatesOnDeeplyChainedConcatenation(t *testing.T) {
	src := []byte("$x = " + strings.Repeat("'a' . ", 5000) + "'b';")
	got := Fold(src)
	if len(got) == 0 {
		t.Fatalf("folder returned nothing on a long chain")
	}
}

func TestFoldHandlesEmptyInput(t *testing.T) {
	if got := Fold(nil); len(got) != 0 {
		t.Fatalf("expected empty output for empty input, got %q", got)
	}
}

// --- wiring into Run ---------------------------------------------------------------------------

// The fold has to reach the rule engine, which only sees what Run emits. Gated like the other
// layers: emit only when folding actually reveals something worth scanning.
func TestRunEmitsAFoldedLayerWhenFoldingRevealsASink(t *testing.T) {
	src := []byte("#!/usr/bin/perl\nmy $CMD = $ENV{'QUERY_STRING'};\n" +
		"my $fn = 'ex' . 'ec';\neval \"$fn($CMD)\";\n")
	var got []byte
	for _, l := range Run(src).Layers {
		if l.Method == "folded" {
			got = l.Data
		}
	}
	if got == nil {
		t.Fatalf("no folded layer produced")
	}
	if !bytes.Contains(got, []byte("exec")) {
		t.Fatalf("folded layer does not contain the revealed sink; got %q", got)
	}
}

// Benign concatenation reveals no sink, so no layer -- otherwise every benign file gains a layer
// and the mirror scan's false-positive surface doubles for nothing.
func TestRunEmitsNoFoldedLayerForBenignConcatenation(t *testing.T) {
	src := []byte("my $greeting = 'hel' . 'lo';\nprint $greeting;\n")
	for _, l := range Run(src).Layers {
		if l.Method == "folded" {
			t.Fatalf("emitted a folded layer for benign concatenation: %q", l.Data)
		}
	}
}

// --- constant propagation ----------------------------------------------------------------------
//
// Folding alone is inert end-to-end, which the first measurement showed: it turns `'ex' . 'ec'`
// into `'exec'`, but every sink rule is anchored on a CALL (`system\s*\(`, `os.popen\s*\(`), and a
// bare literal is not a call. The technique these samples use is to build the name and then
// dispatch on it, so the constant has to reach its use site. This mirrors what
// phptaint.ResolvedLayers already does for PHP: rewrite the dynamic call site to the literal sink
// name so existing literal-anchored rules fire.

func TestFoldPropagatesAPerlConstantIntoCallPosition(t *testing.T) {
	got := Fold([]byte("my $fn = 'system';\n$fn($CMD);\n"))
	if !bytes.Contains(got, []byte("system(")) {
		t.Fatalf("constant not propagated to the call site; got %q", got)
	}
}

// The generator's Perl dispatches through an interpolated string: eval "$fn($CMD)".
func TestFoldPropagatesAPerlConstantInsideAnInterpolatedString(t *testing.T) {
	got := Fold([]byte("my $fn = 'system';\neval \"$fn($CMD)\";\n"))
	if !bytes.Contains(got, []byte("system(")) {
		t.Fatalf("constant not propagated inside interpolation; got %q", got)
	}
}

func TestFoldPropagatesAPythonConstantIntoCallPosition(t *testing.T) {
	got := Fold([]byte("fn = 'popen'\nfn(cmd)\n"))
	if !bytes.Contains(got, []byte("popen(")) {
		t.Fatalf("python constant not propagated; got %q", got)
	}
}

// A variable REASSIGNED later is not a constant. Propagating the first value would describe code
// that never runs, so the whole variable is abandoned rather than guessed at.
func TestFoldDoesNotPropagateAReassignedVariable(t *testing.T) {
	src := []byte("my $fn = 'system';\n$fn = $user_input;\n$fn($CMD);\n")
	if got := Fold(src); bytes.Contains(got, []byte("system(")) {
		t.Fatalf("propagated a reassigned variable; got %q", got)
	}
}

// --- getattr dynamic dispatch (the Python idiom in the matrix) ---------------------------------

func TestFoldResolvesGetattrOnImportedModule(t *testing.T) {
	got := Fold([]byte("getattr(__import__('os'), 'popen')(cmd)"))
	if !bytes.Contains(got, []byte("os.popen(")) {
		t.Fatalf("getattr(__import__(..)) not resolved; got %q", got)
	}
}

func TestFoldResolvesGetattrOnAPlainModuleName(t *testing.T) {
	got := Fold([]byte("getattr(os, 'system')(cmd)"))
	if !bytes.Contains(got, []byte("os.system(")) {
		t.Fatalf("getattr(mod, 'name') not resolved; got %q", got)
	}
}

// The whole chain the generator emits, end to end.
func TestFoldResolvesTheGeneratorsPythonDispatchChain(t *testing.T) {
	src := []byte("import cgi\ncmd = cgi.FieldStorage().getvalue(\"c\")\n" +
		"fn = 'po' + 'pen'\ngetattr(__import__('os'), fn)(cmd)\n")
	got := Fold(src)
	if !bytes.Contains(got, []byte("os.popen(")) {
		t.Fatalf("full python chain not resolved; got %q", got)
	}
}

// And the Perl equivalent.
func TestFoldResolvesTheGeneratorsPerlDispatchChain(t *testing.T) {
	src := []byte("#!/usr/bin/perl\nmy $CMD = $ENV{'QUERY_STRING'};\n" +
		"my $fn = 'sys' . 'tem';\neval \"$fn($CMD)\";\n")
	got := Fold(src)
	if !bytes.Contains(got, []byte("system(")) {
		t.Fatalf("full perl chain not resolved; got %q", got)
	}
}

// A getattr whose attribute is a VARIABLE that is not a known constant must be left alone.
func TestFoldLeavesGetattrWithAnUnknownAttributeAlone(t *testing.T) {
	src := []byte("getattr(os, user_supplied)(cmd)")
	if got := Fold(src); !bytes.Equal(got, src) {
		t.Fatalf("rewrote a getattr with a non-constant attribute; got %q", got)
	}
}
