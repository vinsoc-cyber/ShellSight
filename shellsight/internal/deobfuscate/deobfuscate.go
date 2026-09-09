// Package deobfuscate statically (NEVER executing) unwraps the common webshell encoder nests —
// base64 / gzinflate(raw DEFLATE) / gzuncompress(zlib) / gzdecode(gzip) / str_rot13 / hex \xNN, plus
// eval/assert string-argument extraction — into decoded "layers" so the YARA rule engine can scan
// the cleartext hidden underneath. The decoders are byte-level and language-agnostic. It is pure
// (bytes -> layers, no I/O) and bounded (depth/layers/output) to stay safe against decompression
// bombs and pathological nesting.
package deobfuscate

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"encoding/base64"
	"encoding/hex"
	"io"
	"regexp"
	"strconv"
)

const (
	maxDepth   = 6       // max nesting of encoders we unwrap
	maxLayers  = 64      // max decoded layers emitted per file
	maxOutput  = 8 << 20 // total decoded bytes emitted per file
	maxInflate = 4 << 20 // cap a single inflate's output (bomb guard)
)

// Layer is one decoded representation produced from the input.
type Layer struct {
	Method string
	Data   []byte
}

// Result is the decoded layers plus whether a bound forced truncation.
type Result struct {
	Layers    []Layer
	Truncated bool
}

var (
	// base64 run (>=24 chars to skip short tokens), optional padding.
	reB64 = regexp.MustCompile(`[A-Za-z0-9+/]{24,}={0,2}`)
	// >=6 consecutive \xNN hex escapes (e.g. PHP "\x73\x79\x73\x74\x65\x6d" = "system").
	reHex = regexp.MustCompile(`(?:\\x[0-9A-Fa-f]{2}){6,}`)
	// the string literal handed to eval/assert/create_function/preg_replace — the cleartext payload.
	reEvalArg = regexp.MustCompile(`(?i)(?:eval|assert|create_function|preg_replace)\s*\(\s*["']([^"']{4,1000})["']`)
	// cheap pre-filter: a file only has something to unwrap if it actually CALLS a decoder/eval.
	reEncMarker = regexp.MustCompile(`(?i)base64_decode|gz(inflate|uncompress|decode)|str_rot13|eval\s*\(|assert\s*\(|create_function|preg_replace|convert_uudecode`)
	// reChrRun matches a run of >=4 chr(N) calls (decimal or 0xNN hex, case-insensitive), optionally
	// '.'-concatenated: cHr(97).ChR(115)...  /  cHr(0x40).ChR(0x69)...  (AntSword chr & chr16 encoders,
	// and the general eval(chr(..)..) obfuscation class). The run gate keeps single benign chr() quiet.
	reChrRun = regexp.MustCompile(`(?i)(?:chr\s*\(\s*(?:0x[0-9a-f]{1,2}|\d{1,3})\s*\)\s*(?:\.\s*)?){4,}`)
	// reChrCall extracts one chr(N) value from within a run.
	reChrCall = regexp.MustCompile(`(?i)chr\s*\(\s*(0x[0-9a-f]{1,2}|\d{1,3})\s*\)`)

	// --- universal in-place escape normalizer (the "normalized" layer) ---
	// Closes the inline/short-escape gap that the reHex{6,} *run* layer misses: a single
	// \x61 in ev\x61l( or sy\x73tem( is invisible to a 6-escape run but trivially deobfuscated
	// by decoding every escape in place. Each form is decoded independently (distinct prefixes).
	reEscX   = regexp.MustCompile(`\\x([0-9A-Fa-f]{2})`)           // \xNN          -> byte
	reEscUB  = regexp.MustCompile(`\\u\{([0-9A-Fa-f]{1,6})\}`)     // \u{1-6 hex}   -> rune
	reEscU   = regexp.MustCompile(`\\u([0-9A-Fa-f]{4})`)          // \uNNNN        -> rune
	reEscOct = regexp.MustCompile(`\\([0-7]{1,3})`)              // \NNN (octal)  -> byte
	reEscPct = regexp.MustCompile(`%([0-9A-Fa-f]{2})`)           // %NN (URL)     -> byte
	reEntHex = regexp.MustCompile(`&#[xX]([0-9A-Fa-f]{1,6});`)   // &#xNN; (HTML) -> rune
	reEntDec = regexp.MustCompile(`&#([0-9]{1,7});`)             // &#NN; (HTML)  -> rune
	// cheap presence check: run the normalizer only when an escape actually appears.
	reEscMarker = regexp.MustCompile(`(?i)\\x[0-9a-f]{2}|\\u[0-9a-f]{4}|\\u\{[0-9a-f]{1,6}\}|\\[0-7]{2,3}|%[0-9a-f]{2}|&#x?[0-9a-f]+;`)

	// FP gate: emit the normalized layer ONLY if decoding reveals one of these sink/decoder
	// tokens that was not literally present in the original. Benign \x strings / %NN URLs
	// decode to non-sink text and are dropped, so the mirror stays small and FP-clean.
	sinkTokens = [][]byte{
		[]byte("eval("), []byte("assert("), []byte("system("), []byte("exec("),
		[]byte("passthru("), []byte("shell_exec("), []byte("popen("), []byte("proc_open("),
		[]byte("pcntl_exec("), []byte("preg_replace("), []byte("create_function("),
		[]byte("call_user_func"), []byte("base64_decode("), []byte("gzinflate("),
		[]byte("gzuncompress("), []byte("gzdecode("), []byte("str_rot13("),
	}
)

// normalizeEscapes decodes every textual escape (\xNN, \uNNNN, \u{..}, \NNN octal, %NN,
// &#NN;, &#xNN;) in place, single-pass per form. The result is a scannable cleartext view;
// further encoder nesting in it is handled by walk(). It never executes anything.
func normalizeEscapes(src []byte) []byte {
	out := src
	out = replaceByte(reEscX, out, 16)   // \xNN
	out = replaceRune(reEscUB, out, 16)  // \u{..}
	out = replaceRune(reEscU, out, 16)   // \uNNNN
	out = replaceByte(reEscOct, out, 8)  // \NNN octal
	out = replaceByte(reEscPct, out, 16) // %NN
	out = replaceRune(reEntHex, out, 16) // &#xNN;
	out = replaceRune(reEntDec, out, 10) // &#NN;
	return out
}

// replaceByte rewrites each match of re (capture group 1 a number in the given base) to its
// single byte value; leaves malformed matches untouched.
func replaceByte(re *regexp.Regexp, src []byte, base int) []byte {
	return re.ReplaceAllFunc(src, func(m []byte) []byte {
		g := re.FindSubmatch(m)
		n, err := strconv.ParseInt(string(g[1]), base, 32)
		if err != nil {
			return m
		}
		return []byte{byte(n)}
	})
}

// replaceRune rewrites each match of re (capture group 1 a codepoint in the given base) to its
// UTF-8 encoding; leaves malformed/out-of-range matches untouched.
func replaceRune(re *regexp.Regexp, src []byte, base int) []byte {
	return re.ReplaceAllFunc(src, func(m []byte) []byte {
		g := re.FindSubmatch(m)
		n, err := strconv.ParseInt(string(g[1]), base, 32)
		if err != nil || n < 0 || n > 0x10FFFF {
			return m
		}
		return []byte(string(rune(n)))
	})
}

// revealsSink reports whether norm contains a sink/decoder token (case-insensitive) that the
// original did not — i.e. decoding actually unmasked something worth scanning.
func revealsSink(orig, norm []byte) bool {
	lo, ln := bytes.ToLower(orig), bytes.ToLower(norm)
	for _, kw := range sinkTokens {
		if bytes.Contains(ln, kw) && !bytes.Contains(lo, kw) {
			return true
		}
	}
	return false
}

// Run unwraps src and returns the decoded layers (deduped by content).
func Run(src []byte) Result {
	st := &state{seen: map[string]bool{}}

	// (A) Universal in-place escape normalization. Catches the short/interleaved escapes the
	// run-based reHex layer misses (ev\x61l(, sy\x73tem(, %65val(, &#101;val(). Gated on a NEWLY
	// revealed sink token so benign files with \x strings / %NN URLs neither bloat the mirror nor
	// risk an incidental hit. The normalized view is itself walked so a revealed encoder nest
	// (e.g. eval(base64_decode("..."))) is still unwrapped.
	if reEscMarker.Match(src) {
		if norm := normalizeEscapes(src); !bytes.Equal(norm, src) && revealsSink(src, norm) {
			if st.add("normalized", norm) {
				st.walk(norm, 0)
			}
		}
	}

	// (B) Encoder-nest unwrap (base64 / gz* / hex run / eval-arg). Pre-filtered: a file only has
	// something here if it actually calls a decoder/eval or carries a hex-escape run. This avoids
	// the expensive base64-blob scan on the vast majority of benign files (large minified JS etc.).
	if reEncMarker.Match(src) || reHex.Match(src) || reChrRun.Match(src) {
		st.walk(src, 0)
	}

	// (C) Constant folding. Collapses constant string expressions -- `'ex' . 'ec'`, `'po' + 'pen'`,
	// `scalar reverse('cexe')`, `'nepop'[::-1]`, `chr(112)+chr(111)+...` -- to the literal they
	// evaluate to, so a literal-matching rule sees a sink name the author split up. Measured need:
	// the concat and reverse cells of both Perl and Python matrices score 0.000 without it.
	//
	// Gated on a NEWLY revealed sink NAME rather than call syntax, because building the name and
	// dispatching on it (`eval "$fn(...)"`, `getattr(os, fn)(...)`) is the technique. Benign code
	// concatenates constantly, so without the gate every such file would gain a layer and double
	// the mirror-scan surface for no detection gain.
	//
	// Runs LAST on purpose. state.add dedupes by CONTENT and the first writer keeps the method
	// name, so folding earlier let the "folded" layer claim bytes the "chr" layer was meant to
	// produce -- silently renaming an existing layer and breaking TestRunFoldsHexChrConcat.
	// Ordering it after (B) keeps this pass purely additive.
	if folded := Fold(src); !bytes.Equal(folded, src) && revealsFoldedSink(src, folded) {
		if st.add("folded", folded) {
			st.walk(folded, 0)
		}
	}

	return Result{Layers: st.layers, Truncated: st.truncated}
}

type state struct {
	layers    []Layer
	seen      map[string]bool
	total     int
	truncated bool
}

// add records a decoded layer, enforcing the layer/output bounds and content dedup.
func (s *state) add(method string, data []byte) bool {
	if len(data) == 0 {
		return false
	}
	if len(s.layers) >= maxLayers || s.total+len(data) > maxOutput {
		s.truncated = true
		return false
	}
	k := string(data)
	if s.seen[k] {
		return false
	}
	s.seen[k] = true
	s.total += len(data)
	s.layers = append(s.layers, Layer{Method: method, Data: data})
	return true
}

func (s *state) walk(data []byte, depth int) {
	if depth > maxDepth {
		s.truncated = true
		return
	}
	// 1) eval/assert/preg string-literal argument — the cleartext inside eval("...").
	for _, m := range reEvalArg.FindAllSubmatch(data, -1) {
		if len(m) == 2 && s.add("eval-arg", m[1]) {
			s.walk(m[1], depth+1)
		}
	}
	// 2) hex \xNN runs -> bytes.
	for _, m := range reHex.FindAll(data, -1) {
		if d := decodeHexEscapes(m); s.add("hex", d) {
			s.walk(d, depth+1)
		}
	}
	// 3) base64 blobs -> decoded; then try the binary inflaters + rot13 on each decoded blob and recurse.
	for _, m := range reB64.FindAll(data, -1) {
		dec, err := base64.StdEncoding.DecodeString(string(m))
		if err != nil || len(dec) == 0 {
			continue
		}
		if s.add("base64", dec) {
			for _, l := range tryInflaters(dec) {
				if s.add(l.Method, l.Data) {
					s.walk(l.Data, depth+1)
				}
			}
			if r := rot13(dec); s.add("str_rot13", r) {
				s.walk(r, depth+1)
			}
			s.walk(dec, depth+1)
		}
	}
	// 4) chr(N) concatenation runs -> bytes (AntSword chr/chr16 encoders; eval(chr(..)..) folds to cleartext).
	for _, m := range reChrRun.FindAll(data, -1) {
		if d := decodeChrRun(m); s.add("chr", d) {
			s.walk(d, depth+1)
		}
	}
}

// tryInflaters attempts the three PHP gz* decompressors: raw DEFLATE (gzinflate),
// zlib (gzuncompress), and gzip (gzdecode). Each output is capped against bombs.
func tryInflaters(data []byte) []Layer {
	var out []Layer
	emit := func(method string, r io.Reader) {
		if r == nil {
			return
		}
		b, _ := io.ReadAll(io.LimitReader(r, maxInflate))
		if len(b) > 0 {
			out = append(out, Layer{Method: method, Data: b})
		}
	}
	emit("gzinflate", flate.NewReader(bytes.NewReader(data)))
	if zr, err := zlib.NewReader(bytes.NewReader(data)); err == nil {
		emit("gzuncompress", zr)
	}
	if gr, err := gzip.NewReader(bytes.NewReader(data)); err == nil {
		emit("gzdecode", gr)
	}
	return out
}

func rot13(b []byte) []byte {
	out := make([]byte, len(b))
	for i, c := range b {
		switch {
		case c >= 'a' && c <= 'z':
			out[i] = 'a' + (c-'a'+13)%26
		case c >= 'A' && c <= 'Z':
			out[i] = 'A' + (c-'A'+13)%26
		default:
			out[i] = c
		}
	}
	return out
}

// decodeChrRun turns a run of chr(N) calls (decimal or 0xNN hex) into the bytes they spell.
// Returns nil if any value is out of byte range, so a malformed run is dropped, not mis-decoded.
func decodeChrRun(m []byte) []byte {
	calls := reChrCall.FindAllSubmatch(m, -1)
	out := make([]byte, 0, len(calls))
	for _, c := range calls {
		s := string(c[1])
		base := 10
		if len(s) > 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X') {
			base, s = 16, s[2:]
		}
		n, err := strconv.ParseInt(s, base, 32)
		if err != nil || n < 0 || n > 255 {
			return nil
		}
		out = append(out, byte(n))
	}
	return out
}

// decodeHexEscapes turns a run of \xNN escapes into the raw bytes (nil on malformed input).
func decodeHexEscapes(m []byte) []byte {
	s := bytes.ReplaceAll(m, []byte(`\x`), nil)
	out := make([]byte, len(s)/2)
	if _, err := hex.Decode(out, s); err != nil {
		return nil
	}
	return out
}
