package deobfuscate

import (
	"bytes"
	"compress/flate"
	"encoding/base64"
	"testing"
)

// hasLayerContaining reports whether any decoded layer contains want.
func hasLayerContaining(r Result, want string) bool {
	for _, l := range r.Layers {
		if bytes.Contains(l.Data, []byte(want)) {
			return true
		}
	}
	return false
}

// hasLayerMethod reports whether any decoded layer was produced by the named method.
func hasLayerMethod(r Result, method string) bool {
	for _, l := range r.Layers {
		if l.Method == method {
			return true
		}
	}
	return false
}

// gzdeflate raw-DEFLATEs b and base64-encodes it, mirroring PHP base64_encode(gzdeflate(...)).
func gzdeflate(b []byte) string {
	var buf bytes.Buffer
	w, _ := flate.NewWriter(&buf, flate.BestCompression)
	w.Write(b)
	w.Close()
	return base64.StdEncoding.EncodeToString(buf.Bytes())
}

func TestBase64Layer(t *testing.T) {
	payload := `system($_GET["c"]);`
	src := `<?php eval(base64_decode("` + base64.StdEncoding.EncodeToString([]byte(payload)) + `")); ?>`
	if !hasLayerContaining(Run([]byte(src)), payload) {
		t.Fatalf("expected a decoded layer containing %q", payload)
	}
}

func TestGzinflateNest(t *testing.T) {
	payload := `passthru($_REQUEST["x"]);`
	src := `<?php eval(gzinflate(base64_decode("` + gzdeflate([]byte(payload)) + `"))); ?>`
	if !hasLayerContaining(Run([]byte(src)), payload) {
		t.Fatalf("expected gzinflate(base64(...)) to decode to %q", payload)
	}
}

func TestHexDecode(t *testing.T) {
	// \x73\x79\x73\x74\x65\x6d = "system" (6 escapes; reHex requires >=6).
	src := []byte(`<?php $f="\x73\x79\x73\x74\x65\x6d"; ?>`)
	if !hasLayerContaining(Run(src), "system") {
		t.Fatal("expected hex \\xNN run to decode to 'system'")
	}
}

func TestEvalArgExtraction(t *testing.T) {
	// The sink is hidden inside an eval'd string literal (not base64-encoded).
	src := []byte(`<?php @eval("system($_GET['c']);"); ?>`)
	if !hasLayerContaining(Run(src), "system(") {
		t.Fatal("expected eval-arg extraction to surface system(")
	}
}

func TestBombBounded(t *testing.T) {
	// 2 MiB of 'A' (all valid base64 chars) must terminate and stay within bounds, not hang.
	res := Run(bytes.Repeat([]byte("A"), 2<<20))
	if len(res.Layers) > maxLayers {
		t.Fatalf("exceeded maxLayers: %d", len(res.Layers))
	}
}

func TestNoLayersOnPlainText(t *testing.T) {
	// A benign file with no encoders should yield no decoded layers (keeps the mirror small).
	res := Run([]byte(`<?php echo "hello world"; phpinfo(); ?>`))
	if len(res.Layers) != 0 {
		t.Fatalf("plain PHP should produce 0 layers, got %d", len(res.Layers))
	}
}

// --- universal in-place escape normalizer (closes a measured inline-escape gap) ---

// A SINGLE \xNN inside a sink name (reHex requires a >=6 run, so it misses this).
func TestNormalizeSingleHexEscape(t *testing.T) {
	src := []byte(`<?php ev\x61l($_REQUEST["c"]); ?>`) // ev\x61l = eval
	r := Run(src)
	if !hasLayerMethod(r, "normalized") || !hasLayerContaining(r, "eval(") {
		t.Fatalf("expected a 'normalized' layer surfacing eval(, got %+v", r.Layers)
	}
}

func TestNormalizeUnicode4Escape(t *testing.T) {
	// s (4-hex unicode) = 's'. Built from explicit bytes so neither Go nor the
	// editing pipeline collapses the \u escape before the normalizer sees it.
	u0073 := []byte{0x5c, 0x75, 0x30, 0x30, 0x37, 0x33} // bytes: \ u 0 0 7 3
	src := []byte(`<?php sy`)
	src = append(src, u0073...)
	src = append(src, []byte(`tem($_GET["c"]); ?>`)...)
	if !hasLayerContaining(Run(src), "system(") {
		t.Fatal("expected \\uNNNN to surface system(")
	}
}

func TestNormalizeUnicodeBraceEscape(t *testing.T) {
	src := []byte(`<?php sy\u{73}tem($_GET["c"]); ?>`) // \u{73} = s
	if !hasLayerContaining(Run(src), "system(") {
		t.Fatal("expected \\u{NN} to surface system(")
	}
}

func TestNormalizeOctalEscape(t *testing.T) {
	src := []byte(`<?php sy\163tem($_GET["c"]); ?>`) // \163 (octal) = s
	if !hasLayerContaining(Run(src), "system(") {
		t.Fatal("expected octal \\NNN to surface system(")
	}
}

func TestNormalizeUrlEncoding(t *testing.T) {
	src := []byte(`<?php %65val($_REQUEST["c"]); ?>`) // %65 = e
	if !hasLayerContaining(Run(src), "eval(") {
		t.Fatal("expected %NN URL-decoding to surface eval(")
	}
}

func TestNormalizeHtmlEntities(t *testing.T) {
	dec := []byte(`<?php &#101;val($_REQUEST["c"]); ?>`)   // &#101; = e
	hexEnt := []byte(`<?php &#x65;val($_REQUEST["c"]); ?>`) // &#x65; = e
	if !hasLayerContaining(Run(dec), "eval(") {
		t.Fatal("expected &#NN; to surface eval(")
	}
	if !hasLayerContaining(Run(hexEnt), "eval(") {
		t.Fatal("expected &#xNN; to surface eval(")
	}
}

// FP gate: escapes that decode to benign text (no sink token revealed) must NOT
// emit a normalized layer — otherwise every benign file with a \x string or %NN URL
// grows the decoded mirror and risks an incidental rule hit.
func TestNormalizeGateSkipsBenignEscapes(t *testing.T) {
	src := []byte(`<?php $greeting = "\x68\x69"; $url = "page%2Ephp"; ?>`) // "hi", "page.php"
	if hasLayerMethod(Run(src), "normalized") {
		t.Fatal("benign escapes (no sink token) must not emit a normalized layer")
	}
}

// The gate keys on a NEWLY revealed sink, not merely "original had no sink":
// a file with a literal eval plus an escaped system must still surface system.
func TestNormalizeRevealsNewSinkBesideLiteral(t *testing.T) {
	src := []byte(`<?php eval("noop"); sy\x73tem($_GET["c"]); ?>`)
	if !hasLayerContaining(Run(src), "system(") {
		t.Fatal("expected the escaped system( to be revealed even though eval is literal")
	}
}
