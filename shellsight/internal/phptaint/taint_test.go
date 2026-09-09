package phptaint

import "testing"

func hasRule(fs []Finding, rule string) bool {
	for _, f := range fs {
		if f.Rule == rule {
			return true
		}
	}
	return false
}

func TestAnalyzeResolvedDynamicDispatch(t *testing.T) {
	fs := Analyze([]byte(`<?php $f="system"; $f($_GET['c']);`))
	if !hasRule(fs, "phptaint:sink-on-request") {
		t.Fatalf("want sink-on-request for $f=\"system\";$f($_GET), got %v", fs)
	}
}

func TestAnalyzeChrBuiltName(t *testing.T) {
	// chr(115)=s chr(121)=y + "stem" = "system".
	fs := Analyze([]byte(`<?php $f=chr(115).chr(121)."stem"; $f($_GET['c']);`))
	if !hasRule(fs, "phptaint:sink-on-request") {
		t.Fatalf("want resolved 'system' via chr+concat, got %v", fs)
	}
}

func TestAnalyzeArrayKeyDispatch(t *testing.T) {
	fs := Analyze([]byte(`<?php $item['k']='assert'; $item['k']($_POST['d']);`))
	if len(fs) == 0 {
		t.Fatalf("want a finding for $item['k']($_POST) array-key dispatch, got none")
	}
}

func TestAnalyzeTaintIndirection(t *testing.T) {
	fs := Analyze([]byte(`<?php $q=$_GET['x']; system($q);`))
	if !hasRule(fs, "phptaint:sink-on-request") {
		t.Fatalf("want sink-on-request for system(tainted $q), got %v", fs)
	}
}

func TestAnalyzeSourceAnchoredDynamic(t *testing.T) {
	// Name unresolved (built by an unknown function), but a tainted arg reaches a dynamic call.
	fs := Analyze([]byte(`<?php $f=some_func(); $f($_GET['c']);`))
	if !hasRule(fs, "phptaint:dynamic-dispatch-on-request") {
		t.Fatalf("want source-anchored dynamic-dispatch, got %v", fs)
	}
}

// --- P2: structural detection of obfuscated-callee + request-tainted invocation ---

func TestAnalyzeForwarderObfuscatedCallee(t *testing.T) {
	// Mirrors 7a0641fa: a call-forwarding HOF (forward_static_call_array) whose callable is built
	// from a substring of a request header + concat, invoked with request input. The callee never
	// resolves to a literal, but the structure — forwarder + obfuscation-built callable + request
	// taint — is the tell.
	fs := Analyze([]byte(`<?php $wx = substr($_SERVER['HTTP_REFERER'], -7, -4); forward_static_call_array($wx . 'ert', array($_REQUEST['p']));`))
	if len(fs) == 0 {
		t.Fatalf("want a finding for forward_static_call_array with obfuscated callee + request input, got none")
	}
}

func TestAnalyzeVarVarTaintPropagation(t *testing.T) {
	// Mirrors bb411749: request input assigned through variable-variable syntax ${"c"} must still
	// taint $c, so a sink reading $c is flagged.
	fs := Analyze([]byte(`<?php ${"c"} = $_POST['x']; system($c);`))
	if !hasRule(fs, "phptaint:sink-on-request") {
		t.Fatalf("want sink-on-request: ${\"c\"}=$_POST must taint $c for system($c), got %v", fs)
	}
}

func TestAnalyzeNoFPForwarderLiteralSafeCallback(t *testing.T) {
	// FP guard: a forwarder with a LITERAL, non-sink callback (not obfuscation-built) must not fire,
	// even with request data in the args.
	fs := Analyze([]byte(`<?php call_user_func_array('array_sum', array($_GET['nums']));`))
	if hasRule(fs, "phptaint:forwarder-obfuscated-callee") {
		t.Fatalf("literal safe callback through a forwarder must NOT fire the obfuscated-callee rule, got %v", fs)
	}
}

// --- P2 slice 2: obfuscation provenance through a variable, into a last-arg-callback HOF ---

func TestAnalyzeObfVarCalleeViaLastArgHOF(t *testing.T) {
	// Mirrors 2577a44: $f is a bitwise-XOR/pack-built (unresolvable) callable passed as the
	// comparator (LAST arg) of array_intersect_uassoc, with request input in the data arg. The
	// callee is a plain variable at the call site, so its obfuscation provenance must be tracked
	// from the assignment.
	fs := Analyze([]byte(`<?php $k = substr(__FILE__, -5, -4); $f = pack("H*", "6173736572") ^ $k; array_intersect_uassoc(array($_REQUEST['p'] => ""), array(1), $f);`))
	if len(fs) == 0 {
		t.Fatalf("want a finding for an obf-built var callable via array_intersect_uassoc with request input, got none")
	}
}

// --- Godzilla-family: a hand-rolled hex-nibble byte assembler ---
// The packed loader decodes a punctuation-alphabet payload with its own nibble assembler:
// chr((hi << 4) + lo) inside a loop. PHP ships hex2bin() and pack('H*') for this, so an application
// has no reason to hand-roll it; a packer does, because the payload must carry no recognisable token.
// It needs no request source and no dispatch, which is exactly why every taint-gated rule stayed
// silent on this family.

func TestAnalyzeNibbleAssemblerLoop(t *testing.T) {
	// Structure of the real samples, with an inert payload.
	php := `<?php
for ($o = 0, $e = 'ABC', $d = ''; @ord($e[$o]); $o++) {
    if ($o < 16) { $h[$e[$o]] = $o; }
    else { $d .= @chr(($h[$e[$o]] << 4) + $h[$e[++$o]]); }
}`
	if !hasRule(Analyze([]byte(php)), "phptaint:nibble-assembler-loop") {
		t.Fatalf("want nibble-assembler-loop for a hand-rolled hex decoder, got %v", Analyze([]byte(php)))
	}
}

func TestAnalyzeNibbleAssemblerVariants(t *testing.T) {
	// The family varies the combining operator and the loop form; the assembler is the invariant.
	cases := []struct{ name, php string }{
		{"bitwise-or combine", `<?php while (@ord($e[$o])) { $d .= chr(($h[$e[$o]] << 4) | $h[$e[++$o]]); }`},
		{"while loop", `<?php $i=0; while ($i < 99) { $out .= chr(($a[$i] << 4) + $b[$i]); $i++; }`},
		{"foreach loop", `<?php foreach ($pairs as $p) { $out .= chr(($p[0] << 4) + $p[1]); }`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if !hasRule(Analyze([]byte(c.php)), "phptaint:nibble-assembler-loop") {
				t.Fatalf("%s: want nibble-assembler-loop, got %v", c.name, Analyze([]byte(c.php)))
			}
		})
	}
}

func TestAnalyzeNoFPNibbleAssembler(t *testing.T) {
	// Each of these has one of the ingredients and must NOT fire: the signature is chr() fed by a
	// 4-bit shift INSIDE a loop, not any of its parts alone.
	cases := []struct{ name, php string }{
		{"chr in loop, no shift", `<?php for ($i=0;$i<256;$i++) { $charset .= chr($i); }`},
		{"shift by 4, no chr", `<?php for ($i=0;$i<10;$i++) { $packed[] = ($hi[$i] << 4) + $lo[$i]; }`},
		{"chr with shift, not in a loop", `<?php $b = chr(($hi << 4) + $lo);`},
		{"shift by other amounts in loop", `<?php for ($i=0;$i<10;$i++) { $out .= chr($v[$i] << 1); }`},
		{"ord loop without assembly", `<?php for ($i=0; $i<strlen($s); $i++) { $sum += ord($s[$i]); }`},
		{"legitimate hex decode via hex2bin", `<?php foreach ($rows as $r) { $out .= hex2bin($r); }`},
		// The real false positive this rule produced: FPDF's UTF-8 -> UTF-16 conversion. It shifts a
		// MASKED bit-field out of a byte ($c1 & 0x0F), which is bit-field extraction, not a nibble-map
		// lookup. FPDF/TCPDF ship inside countless CMS installs, so this one FP would be everywhere.
		{"FPDF utf8 bit-field extraction", `<?php
while ($i < $nb) {
    $c1 = ord($s[$i++]); $c2 = ord($s[$i++]); $c3 = ord($s[$i++]);
    $res .= chr((($c1 & 0x0F)<<4) + (($c2 & 0x3C)>>2));
    $res .= chr((($c2 & 0x03)<<6) + ($c3 & 0x3F));
}`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if hasRule(Analyze([]byte(c.php)), "phptaint:nibble-assembler-loop") {
				t.Fatalf("%s must NOT fire: %v", c.name, Analyze([]byte(c.php)))
			}
		})
	}
}

// --- P2 slice 5: request sources that are not superglobals ---
// HTTP headers reach PHP through getenv()/getallheaders() as well as $_SERVER, and the raw body
// through php://input. A shell using those routes contains no $_GET/$_POST token at all, so every
// taint-gated detection stayed silent regardless of how well the callee resolved.

func TestAnalyzeNonSuperglobalRequestSources(t *testing.T) {
	cases := []struct{ name, php, want string }{
		{"getenv HTTP_ header", `<?php $c = getenv("HTTP_CMD"); system($c);`, "phptaint:sink-on-request"},
		{"getallheaders", `<?php $h = getallheaders(); eval($h['x']);`, "phptaint:sink-on-request"},
		{"apache_request_headers", `<?php $h = apache_request_headers(); system($h['c']);`, "phptaint:sink-on-request"},
		{"php://input body", `<?php eval(file_get_contents("php://input"));`, "phptaint:sink-on-request"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if fs := Analyze([]byte(c.php)); !hasRule(fs, c.want) {
				t.Fatalf("%s: want %s, got %v", c.name, c.want, fs)
			}
		})
	}
}

func TestAnalyzeNoFPNonRequestEnv(t *testing.T) {
	// Only the HTTP_* slice of the environment is attacker-controlled. getenv("PATH") is ordinary
	// configuration and must not taint, or every deployment script becomes a finding.
	cases := []string{
		`<?php system(getenv("PATH"));`,
		`<?php $home = getenv("HOME"); echo $home;`,
		`<?php $f = file_get_contents("config.json"); eval($f);`,
	}
	for _, php := range cases {
		if fs := Analyze([]byte(php)); hasRule(fs, "phptaint:sink-on-request") {
			t.Fatalf("non-request env/file must NOT taint: %s -> %v", php, fs)
		}
	}
}

func TestAnalyzeFoldedForwarderWithHeaderSource(t *testing.T) {
	// The real 146e7cf7 shape, reduced: the callee folds to call_user_func_array, the forwarded name
	// folds to a function, and the payload arrives via an XOR-built HTTP_ header name through getenv.
	php := `<?php $g = ("#"^"|")."all_user_func_array"; $n = "syst"."em"; $h = "HTTP_"."CMD"; $g($n, array(getenv($h)));`
	if fs := Analyze([]byte(php)); len(fs) == 0 {
		t.Fatalf("want a finding for a folded forwarder fed by a header source, got none")
	}
}

// --- P2 slice 4: constant-fold PHP bitwise string operators ---
// PHP's ^ | & ~ on strings are bytewise. Webshells use them to spell "_POST"/"assert" out of
// punctuation so no literal token exists. Both operands are literals, so this is constant folding
// (like the existing chr() fold), not emulation.

func TestAnalyzeBitwiseFoldedSuperglobalDispatch(t *testing.T) {
	// The real 792c0465 sample: ("#"^"|") = 0x23^0x7C = "_", … spelling "_POST"; the shell then calls
	// $_POST[0]($_POST[1]) through a variable-variable.
	fs := Analyze([]byte(`<?php @$_++;$__=("#"^"|").("."^"~").("/"^"` + "`" + `").("|"^"/").("{"^"/");@${$__}[!$_](${$__}[$_]);`))
	if len(fs) == 0 {
		t.Fatalf("want a finding once the XOR-built superglobal name folds to _POST, got none")
	}
}

func TestAnalyzeBitwiseFoldedSinkName(t *testing.T) {
	// "assert" spelled by XOR: 0x21^0x40='a', 0x33^0x40='s', 0x25^0x40='e', 0x32^0x40='r', 0x34^0x40='t'.
	php := `<?php $f = ("!"^"@").("3"^"@").("3"^"@").("%"^"@").("2"^"@").("4"^"@"); $f($_POST['x']);`
	fs := Analyze([]byte(php))
	if !hasRule(fs, "phptaint:sink-on-request") {
		t.Fatalf("want sink-on-request once the XOR-built callee folds to assert, got %v", fs)
	}
}

func TestAnalyzeBitwiseFoldBarewordAndNot(t *testing.T) {
	// Barewords: PHP treats an undefined constant as its own name, which these shells rely on.
	// x|x == x, and ~~x == x, so both fold back to the sink name.
	cases := []struct{ name, php string }{
		{"bareword OR", `<?php $f = (assert|assert); $f($_POST['x']);`},
		{"bareword double NOT", `<?php $f = ~~assert; $f($_POST['x']);`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if fs := Analyze([]byte(c.php)); !hasRule(fs, "phptaint:sink-on-request") {
				t.Fatalf("%s: want sink-on-request, got %v", c.name, fs)
			}
		})
	}
}

// --- P2 slice 3: a callback variable that is never BOUND anywhere in the file ---

func TestAnalyzeUnboundCallbackVar(t *testing.T) {
	// Mirrors 11aaa7e2: request input reaches array_udiff's data arg and its comparator is $e, which
	// is never assigned, declared, or bound as a parameter anywhere in the file. Real PHP would error
	// on that, so in a shipped file it means the callable arrives out-of-band.
	fs := Analyze([]byte(`<?php $arr = array($_POST['pass']); $arr2 = array(1); array_udiff($arr, $arr2, $e);`))
	if !hasRule(fs, "phptaint:unbound-callback-dispatch") {
		t.Fatalf("want unbound-callback-dispatch for a never-bound comparator, got %v", fs)
	}
}

// The FP guards below are the whole reason this detection needs binding-form coverage: each one is a
// legitimate way to bind a callback variable, and treating any of them as "unbound" would fire on
// ordinary application code.
func TestAnalyzeNoFPBoundCallbackVars(t *testing.T) {
	cases := []struct{ name, php string }{
		{"closure assigned", `<?php $cb = function($a,$b){ return strcmp($a,$b); }; array_udiff($_POST['a'], array(1), $cb);`},
		{"arrow fn assigned", `<?php $cb = fn($a,$b) => strcmp($a,$b); array_udiff($_POST['a'], array(1), $cb);`},
		{"function parameter", `<?php function s($cb){ return array_map($cb, $_POST['x']); }`},
		{"closure use clause", `<?php $cb = 'strlen'; $f = function() use ($cb) { return array_map($cb, $_POST['x']); };`},
		{"foreach bound", `<?php foreach ($cbs as $cb) { array_map($cb, $_POST['x']); }`},
		{"global declared", `<?php function g(){ global $cb; return array_map($cb, $_POST['x']); }`},
		{"static declared", `<?php function g(){ static $cb = 'trim'; return array_map($cb, $_POST['x']); }`},
		{"list destructuring", `<?php list($a, $cb) = $pair; array_map($cb, $_POST['x']);`},
		{"by-ref assignment", `<?php $cb =& $other; array_map($cb, $_POST['x']);`},
		{"extract makes binding dynamic", `<?php extract($cfg); array_map($cb, $_POST['x']);`},
		{"catch bound", `<?php try { x(); } catch (Exception $cb) { array_map($cb, $_POST['x']); }`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if fs := Analyze([]byte(c.php)); hasRule(fs, "phptaint:unbound-callback-dispatch") {
				t.Fatalf("%s must NOT fire unbound-callback-dispatch, got %v", c.name, fs)
			}
		})
	}
}

func TestAnalyzeLastArgHOFLiteralSinkComparator(t *testing.T) {
	// Mirrors 75156e3b: array_udiff_assoc's comparator is the LITERAL sink name "assert" with request
	// input in the data array. The literal-sink callback branch only knew fixed-index HOFs, so the
	// array_u*/uassoc family (comparator = last positional arg) slipped through.
	fs := Analyze([]byte(`<?php $password = "LandGrey"; array_udiff_assoc(array($_REQUEST[$password]), array(1), "assert");`))
	if !hasRule(fs, "phptaint:callback-on-request") {
		t.Fatalf("want callback-on-request for a literal sink comparator via array_udiff_assoc, got %v", fs)
	}
}

func TestAnalyzeNoFPLastArgHOFLiteralComparator(t *testing.T) {
	// FP guard: a last-arg-callback HOF with a LITERAL comparator (not obfuscation-built) must not
	// fire, even with request data in the arrays.
	fs := Analyze([]byte(`<?php array_intersect_uassoc($_GET['a'], array(1), 'strcasecmp');`))
	if hasRule(fs, "phptaint:forwarder-obfuscated-callee") {
		t.Fatalf("literal comparator through a last-arg HOF must NOT fire, got %v", fs)
	}
}

func TestAnalyzeFileDropCopySuperglobalDest(t *testing.T) {
	// Real uploader miss (02f8f648…php): @copy($_FILES['file']['tmp_name'], $_FILES['file']['name']) —
	// the destination filename is fully request-controlled.
	fs := Analyze([]byte(`<?php @copy($_FILES['file']['tmp_name'], $_FILES['file']['name']);`))
	if !hasRule(fs, "phptaint:file-drop-on-request") {
		t.Fatalf("copy with request-controlled destination should fire file-drop, got %v", fs)
	}
}

func TestAnalyzeFileDropWriteExecutablePath(t *testing.T) {
	// file_put_contents of request content to a .php path — classic dropper.
	fs := Analyze([]byte(`<?php file_put_contents("shell.php", $_POST['code']);`))
	if !hasRule(fs, "phptaint:file-drop-on-request") {
		t.Fatalf("writing request content to an executable path should fire file-drop, got %v", fs)
	}
}

func TestAnalyzeNoFPOnLegitUploadToUploadDir(t *testing.T) {
	// Benign upload: literal upload-dir prefix + basename() — destination is neither a raw
	// request-controlled path nor an executable extension. Must NOT fire.
	fs := Analyze([]byte(`<?php move_uploaded_file($_FILES['f']['tmp_name'], "uploads/".basename($_FILES['f']['name']));`))
	if hasRule(fs, "phptaint:file-drop-on-request") {
		t.Fatalf("legit upload to a non-executable prefixed path must not fire, got %v", fs)
	}
}

func TestAnalyzeUnserializeOfRequest(t *testing.T) {
	// PHP Object Injection (0c54b443…php gadget): unserialize($_GET[...]) is the source-anchored
	// sink — gadgets reach eval()/system() at runtime, but the request input enters via unserialize.
	fs := Analyze([]byte(`<?php unserialize($_GET['saved_code']);`))
	if !hasRule(fs, "phptaint:sink-on-request") {
		t.Fatalf("unserialize of request input should fire sink-on-request, got %v", fs)
	}
}

func TestAnalyzeCaseInsensitiveResolvedSink(t *testing.T) {
	// PHP function names are case-insensitive; webshells use mixed case to evade case-sensitive
	// detectors. $f holds "SyStem" -> must match the "system" sink.
	fs := Analyze([]byte(`<?php $f="SyStem"; $f($_GET['c']);`))
	if !hasRule(fs, "phptaint:sink-on-request") {
		t.Fatalf("mixed-case resolved sink should fire, got %v", fs)
	}
}

func TestAnalyzeCaseInsensitiveLiteralSinkCall(t *testing.T) {
	fs := Analyze([]byte(`<?php System($_GET['c']);`))
	if !hasRule(fs, "phptaint:sink-on-request") {
		t.Fatalf("mixed-case literal System() should fire, got %v", fs)
	}
}

func TestAnalyzeCallbackHOF(t *testing.T) {
	fs := Analyze([]byte(`<?php array_filter($_GET['x'], 'system');`))
	if !hasRule(fs, "phptaint:callback-on-request") {
		t.Fatalf("want callback-on-request for array_filter($_GET,'system'), got %v", fs)
	}
}

func TestAnalyzeNoFPOnBenignSanitizer(t *testing.T) {
	// Reading $_GET then passing it to a non-sink builtin (htmlspecialchars) must NOT flag.
	fs := Analyze([]byte(`<?php $q=$_GET['x']; echo htmlspecialchars($q);`))
	if len(fs) != 0 {
		t.Fatalf("benign sanitizer must not flag, got %v", fs)
	}
}

func TestAnalyzeNoFPOnReassignedAwayTaint(t *testing.T) {
	// $q reads request, then is reassigned to a clean value before reaching a sink -> no flag.
	fs := Analyze([]byte(`<?php $q=$_GET['x']; $q='safe'; system($q);`))
	if len(fs) != 0 {
		t.Fatalf("reassigned-away taint must not flag, got %v", fs)
	}
}

func TestAnalyzeSplitSuperglobal(t *testing.T) {
	// ${"_P"."O"."S"."T"} is a split-superglobal (the name built from pieces); eval() of its
	// content must be flagged (a literal-sink YARA rule cannot see this).
	fs := Analyze([]byte(`<?php eval(${"_P"."O"."S"."T"}['c']);`))
	if !hasRule(fs, "phptaint:sink-on-request") {
		t.Fatalf("want sink-on-request on eval(split-superglobal $_POST), got %v", fs)
	}
}

func TestAnalyzeDecodeLoopDispatch(t *testing.T) {
	// A user function with a chr/hexdec decode loop; its return is invoked as a function. The arg
	// is itself a decode call (no superglobal) -- invisible to Tier 2's source-anchored rule (c).
	// This is the custom-cipher (P3) class that needs either emulation or this structural detector.
	src := []byte(`<?php function dec($s){ $o=""; for($i=0;$i<strlen($s);$i+=2){ $o.=chr(hexdec(substr($s,$i,2))); } return $o; } $f=dec('73797374656d'); $f(dec('68656c6c6f'));`)
	if !hasRule(fs(t, src), "phptaint:decode-loop-dispatch") {
		t.Fatal("want decode-loop-dispatch for dec()->$f->$f(dec(...))")
	}
}

func TestAnalyzeDecodeLoopNoFP(t *testing.T) {
	// Benign: a loop+chr helper whose return is echoed (not invoked as a function).
	src := []byte(`<?php function shift($s){ $o=""; for($i=0;$i<strlen($s);$i++){ $o.=chr(ord($s[$i])+1); } return $o; } echo shift("abc");`)
	if hasRule(fs(t, src), "phptaint:decode-loop-dispatch") {
		t.Fatal("benign loop+chr not invoked as a function must not flag")
	}
}

func TestAnalyzeDecodeLoopEval(t *testing.T) {
	src := []byte(`<?php function dec($s){ $o=""; for($i=0;$i<strlen($s);$i+=2){ $o.=chr(hexdec(substr($s,$i,2))); } return $o; } eval(dec('73797374656d'));`)
	if !hasRule(fs(t, src), "phptaint:decode-loop-dispatch") {
		t.Fatal("want decode-loop-dispatch for eval(dec(...))")
	}
}

func TestAnalyzeDecodeLoopInclude(t *testing.T) {
	src := []byte(`<?php function dec($s){ $o=""; for($i=0;$i<strlen($s);$i+=2){ $o.=chr(hexdec(substr($s,$i,2))); } return $o; } include(dec('2f657463'));`)
	if !hasRule(fs(t, src), "phptaint:decode-loop-dispatch") {
		t.Fatal("want decode-loop-dispatch for include(dec(...))")
	}
}

func TestAnalyzeDecodeLoopDirectInvoke(t *testing.T) {
	// dec(...)() -- the decode return invoked directly, no intermediate variable.
	src := []byte(`<?php function dec($s){ $o=""; for($i=0;$i<strlen($s);$i+=2){ $o.=chr(hexdec(substr($s,$i,2))); } return $o; } dec('73797374656d')($_GET['c']);`)
	if !hasRule(fs(t, src), "phptaint:decode-loop-dispatch") {
		t.Fatal("want decode-loop-dispatch for dec(...)()")
	}
}

// fs is a tiny helper: run Analyze and fail the test loudly on a parse panic.
func fs(t *testing.T, src []byte) []Finding {
	t.Helper()
	return Analyze(src)
}


// --- direct-invoke of a runtime-BUILT callable (evasion class: reconstructed sink name in call
// position, not a HOF arg). Mechanism tests — minimal synthetic shapes, NOT corpus samples. ---

func TestEvasionDirectInvokeSubstrConcat(t *testing.T) {
	// (substr($m,..).substr($m,..))($_GET) -- the sink name is spliced at runtime and the built
	// callable is invoked directly with request input. Must be flagged on the mechanism, not a literal.
	src := []byte(`<?php $m='xsystemy'; (substr($m,1,3).substr($m,4,3))($_GET['c']);`)
	if len(fs(t, src)) == 0 {
		t.Fatalf("want a finding for direct-invoke of a substr-built callable with request input, got none")
	}
}

func TestEvasionDirectInvokeInsideClosure(t *testing.T) {
	// Same mechanism nested in a closure body (the anony_func shape). $_GET is directly tainted here.
	src := []byte(`<?php $g=function(){ $m='asysb'; (substr($m,1,3).substr($m,4))($_GET['a']); }; $g();`)
	if len(fs(t, src)) == 0 {
		t.Fatalf("want a finding for a built-callable direct-invoke inside a closure, got none")
	}
}

func TestEvasionDirectInvokeBrackets(t *testing.T) {
	// A non-resolvable built callee (substr, which resolveValue cannot fold), double-parenthesised and
	// invoked directly. Brackets must be transparent so the built-callable is still seen.
	src := []byte(`<?php $m='asystemb'; ((substr($m,1,6)))($_POST['c']);`)
	if len(fs(t, src)) == 0 {
		t.Fatalf("want a finding for a bracket-wrapped substr-built callable direct-invoke, got none")
	}
}

func TestBenignDirectInvokeNoTaint_MustNotFire(t *testing.T) {
	// A built callable invoked with a CONSTANT (no request input) must NOT fire — the taint gate holds.
	src := []byte(`<?php $m='strtoupper'; (substr($m,0,4).substr($m,4))("hello");`)
	if len(fs(t, src)) != 0 {
		t.Fatalf("built callable with a constant arg must not fire, got %v", fs(t, src))
	}
}

// --- improvement #2: a request-controlled callback NAME passed to a callable-invoking HOF.
// The engine caught $_GET['f']($x) (direct) but not call_user_func($_GET['f'], $x) (via HOF).
// Mechanism tests -- minimal synthetic shapes, not corpus samples. ---

func TestEvasionReqTaintedCallbackHOF(t *testing.T) {
	// The callback NAME comes from request input, passed to call_user_func_array.
	src := []byte(`<?php call_user_func_array($_GET['f'], array($_POST['x']));`)
	if len(fs(t, src)) == 0 {
		t.Fatalf("want a finding for a request-controlled callback name via a HOF, got none")
	}
}

func TestEvasionReqTaintedCallbackTernary(t *testing.T) {
	// The callback resolves to request data through a ternary -- same mechanism, wrapped.
	src := []byte(`<?php $a=$_GET['a']; $b=$_POST['b']; call_user_func_array($a==$a?$a:$a, array($b));`)
	if len(fs(t, src)) == 0 {
		t.Fatalf("want a finding for a request-derived callback via a ternary, got none")
	}
}

func TestBenignLiteralCallbackTaintedData_MustNotFire(t *testing.T) {
	// FP guard: a LITERAL, safe callback with tainted DATA must not fire -- only a request-controlled
	// callback NAME is the tell.
	src := []byte(`<?php array_map('trim', $_GET['arr']); call_user_func_array('array_sum', array($_GET['n']));`)
	if hasRule(fs(t, src), "phptaint:request-tainted-callback") {
		t.Fatalf("literal safe callback with tainted data must NOT fire, got %v", fs(t, src))
	}
}

// --- registry-lookup discriminator: a request value used as an array KEY selects one of the
// application's PRE-REGISTERED callables (WordPress widget/hook dispatch). The attacker chooses
// WHICH registered function runs, not WHAT runs, so it must not fire. Distinct from the shapes where
// the attacker supplies the callable itself, which must keep firing. ---

func TestBenignRegistryLookupCallback_MustNotFire(t *testing.T) {
	// The WordPress wp_dashboard_trigger_widget_control shape: $registry[$tainted].
	src := []byte(`<?php call_user_func($wp_callbacks[$_GET['id']], '');`)
	if hasRule(fs(t, src), "phptaint:request-tainted-callback") {
		t.Fatalf("registry lookup keyed by request input must NOT fire, got %v", fs(t, src))
	}
}

func TestEvasionTaintedCalleeStillFires(t *testing.T) {
	// Regression guard for #2: the request value IS the callee (base is the superglobal).
	src := []byte(`<?php call_user_func($_GET['f'], 'x');`)
	if !hasRule(fs(t, src), "phptaint:request-tainted-callback") {
		t.Fatalf("request value AS the callee must still fire, got %v", fs(t, src))
	}
}

func TestEvasionTaintedArrayBaseStillFires(t *testing.T) {
	// The whole ARRAY is request data, so the callable came from the attacker.
	src := []byte(`<?php $a = $_POST; call_user_func($a['f'], 'x');`)
	if !hasRule(fs(t, src), "phptaint:request-tainted-callback") {
		t.Fatalf("callable from a request-controlled array must still fire, got %v", fs(t, src))
	}
}

func TestEvasionTaintedVarCalleeStillFires(t *testing.T) {
	// A tainted variable used directly as the callable.
	src := []byte(`<?php $f = $_GET['f']; call_user_func($f, 'x');`)
	if !hasRule(fs(t, src), "phptaint:request-tainted-callback") {
		t.Fatalf("tainted variable as callable must still fire, got %v", fs(t, src))
	}
}

// --- Deferred / implicit dispatch (landscape axis-1 mode 4) -------------------------------------
// register_shutdown_function, register_tick_function, set_error_handler, set_exception_handler,
// spl_autoload_register and ob_start take a callable and invoke it LATER, from the engine. There is
// no call at the injection point, so a source->sink walk sees nothing. Measured: 34 corpus samples
// carry this mode and recall was 0.235 — the worst-performing dispatch mode we hold.

func TestDeferredDispatchRegisterTickRequestControlledCallable(t *testing.T) {
	// Verbatim shape of corpus sample ac1b3a85…/4d9f30ac… — the callable itself is request data.
	src := []byte(`<?php $e = $_REQUEST['e']; declare(ticks=1); register_tick_function($e, $_REQUEST['pass']);`)
	if !hasRule(fs(t, src), "phptaint:request-tainted-callback") {
		t.Fatalf("register_tick_function with a request-controlled callable must fire, got %v", fs(t, src))
	}
}

func TestDeferredDispatchShutdownFunctionResolvedSink(t *testing.T) {
	src := []byte(`<?php register_shutdown_function('system', $_GET['c']);`)
	if !hasRule(fs(t, src), "phptaint:callback-on-request") {
		t.Fatalf("register_shutdown_function('system', tainted) must fire, got %v", fs(t, src))
	}
}

func TestDeferredDispatchAutoloadRequestControlledCallable(t *testing.T) {
	src := []byte(`<?php spl_autoload_register($_GET['f']);`)
	if !hasRule(fs(t, src), "phptaint:request-tainted-callback") {
		t.Fatalf("spl_autoload_register with a request-controlled callable must fire, got %v", fs(t, src))
	}
}

func TestDeferredDispatchErrorHandlerSplicedSinkName(t *testing.T) {
	// substr('xsys',1).'tem' folds to "system", so this is reported as the resolved sink it is
	// (score 85) rather than the weaker "a callable was built here" heuristic (80).
	src := []byte(`<?php set_error_handler(substr('xsys',1).'tem', $_POST['a']);`)
	if !hasRule(fs(t, src), "phptaint:callback-on-request") {
		t.Fatalf("set_error_handler with a spliced sink name must fire, got %v", fs(t, src))
	}
}

func TestDeferredDispatchUnresolvableBuiltCallee(t *testing.T) {
	// A callable whose name cannot be folded (pack over a runtime value) must still be caught by the
	// obfuscated-callee path — the branch that folding must never quietly bypass.
	src := []byte(`<?php $k = $_GET['k']; $f = pack('H*', $k); register_shutdown_function($f, $_POST['a']);`)
	got := fs(t, src)
	if !hasRule(got, "phptaint:forwarder-obfuscated-callee") && !hasRule(got, "phptaint:request-tainted-callback") {
		t.Fatalf("an unresolvable built callable must still fire, got %v", got)
	}
}

// The benign idioms these functions exist for. WordPress + phpMyAdmin use ob_start 216 times,
// set_error_handler 25, spl_autoload_register 7, register_shutdown_function 6 — so a name-only gate
// here would be a false-positive flood. Each must stay silent.

func TestDeferredDispatchBenignFixedCallbackSilent(t *testing.T) {
	for _, src := range []string{
		`<?php ob_start('ob_gzhandler');`,
		`<?php ob_start();`,
		`<?php spl_autoload_register(array($loader, 'loadClass'), true, true);`,
		`<?php register_shutdown_function('my_shutdown_handler');`,
		`<?php set_error_handler(array($this, 'handleError'));`,
		`<?php set_exception_handler('PMA_mysqlDie');`,
	} {
		if got := fs(t, []byte(src)); len(got) != 0 {
			t.Errorf("benign deferred-dispatch idiom must be silent: %s -> %v", src, got)
		}
	}
}

func TestDeferredDispatchBoundClosureWithTaintSilent(t *testing.T) {
	// A closure defined in-file is bound and not obfuscated; request input reaching an unrelated
	// argument must not turn a legitimate handler registration into a finding.
	src := []byte(`<?php $h = function($m) { echo htmlspecialchars($m); }; ob_start($h, $_GET['n']);`)
	if got := fs(t, src); len(got) != 0 {
		t.Errorf("in-file closure callback must stay silent, got %v", got)
	}
}

// --- Method-call sinks (landscape axis-1 modes 11 and, for COM, 1) ------------------------------
// The taint pass handled ExprFunctionCall only, so every `$obj->method($tainted)` was invisible.
// That is why SQL-mediated dispatch measured recall 0.0000 on the 12 samples we hold and COM 0.765:
// not a missing name in a table, a missing AST node type.

func TestMethodSinkSqliteCreateFunctionRequestCallable(t *testing.T) {
	// Verbatim corpus shape (ac1b3a85…, 8406adf8…, m_f71ffc8a…): the callable handed to the SQL
	// engine is request data, and the engine invokes it per row.
	src := []byte(`<?php $e = $_REQUEST['e']; $db = new SQLite3('x.db3'); $db->createFunction('myfunc', $e);`)
	if !hasRule(fs(t, src), "phptaint:sql-registered-callable") {
		t.Fatalf("SQLite3::createFunction with a request-controlled callable must fire, got %v", fs(t, src))
	}
}

func TestMethodSinkSqliteCreateFunctionFixedCallableSilent(t *testing.T) {
	src := []byte(`<?php $db = new SQLite3('x.db3'); $db->createFunction('lower', 'strtolower');`)
	if got := fs(t, src); len(got) != 0 {
		t.Errorf("a fixed, application-supplied SQL callable must stay silent, got %v", got)
	}
}

func TestMethodSinkComShellExec(t *testing.T) {
	// m_17358a5e…, m_1fe4c60e…: new COM('WScript.Shell') then ->exec / ->Run with request input.
	for _, src := range []string{
		`<?php $ws = new COM('WScript.Shell'); $ws->exec("cmd.exe /c " . $_GET['c']);`,
		`<?php $w = new COM("WScript.Shell"); $w->Run('cmd /c '.$_POST['cfe']);`,
	} {
		if !hasRule(fs(t, []byte(src)), "phptaint:com-exec-on-request") {
			t.Errorf("COM shell exec on request input must fire: %s -> %v", src, fs(t, []byte(src)))
		}
	}
}

// ->exec and ->run are among the commonest method names in any codebase. Without object provenance
// a name-only gate would fire on every database query and every command-pattern class, so these
// must stay silent even with request input present.
func TestMethodSinkNonComExecSilent(t *testing.T) {
	for _, src := range []string{
		`<?php $db = new PDO('sqlite:x'); $db->exec($_GET['q']);`,
		`<?php $this->run($_GET['x']);`,
		`<?php $cmd = new MyCommand(); $cmd->Run($_POST['a']);`,
		`<?php $mysqli->query($_GET['id']);`,
	} {
		if got := fs(t, []byte(src)); len(got) != 0 {
			t.Errorf("non-COM method call must stay silent: %s -> %v", src, got)
		}
	}
}

// --- Backtick operator (landscape axis-1 mode 1 / cell 13) --------------------------------------
// `cmd` is shell_exec with no function name to match, so neither a signature nor a name-keyed sink
// table sees it. `<?=`$_GET[1]`;` is a complete 14-byte shell and was the smallest miss in the corpus.

func TestBacktickShellExecOnRequest(t *testing.T) {
	for _, src := range []string{
		"<?=`$_GET[1]`;",
		"<?php echo `ls -la {$_POST['d']}`;",
		"<?php $c = $_REQUEST['c']; $out = `$c`;",
	} {
		if !hasRule(fs(t, []byte(src)), "phptaint:sink-on-request") {
			t.Errorf("backtick exec of request input must fire: %s -> %v", src, fs(t, []byte(src)))
		}
	}
}

func TestBacktickWithoutRequestInputSilent(t *testing.T) {
	src := []byte("<?php $v = `git rev-parse HEAD`;")
	if got := fs(t, src); len(got) != 0 {
		t.Errorf("a fixed backtick command is not request-driven, got %v", got)
	}
}

// --- Reflection construction (the ->invoke shape) -----------------------------------------------
// ReflectionFunction/ReflectionMethod are in `sinks`, but `new X(...)` is ExprNew, not a call, so
// handleCall never saw them. Corpus: (new ReflectionFunction($p['a']))->invoke($p['b']) with $p
// from json_decode($_GET['p']).

func TestReflectionConstructedFromRequest(t *testing.T) {
	src := []byte(`<?php $p = json_decode($_GET['p'], true); $r = new ReflectionFunction($p['a']); $r->invoke($p['b']);`)
	if !hasRule(fs(t, src), "phptaint:sink-on-request") {
		t.Fatalf("new ReflectionFunction(request) must fire, got %v", fs(t, src))
	}
}

func TestReflectionOnFixedNameSilent(t *testing.T) {
	src := []byte(`<?php $r = new ReflectionClass('MyService'); $r->getMethods();`)
	if got := fs(t, src); len(got) != 0 {
		t.Errorf("reflection over a fixed class name must stay silent, got %v", got)
	}
}

// --- Runtime-reconstructed sink names (bypass-corpus mechanism) ---------------------------------
// The dangerous name never appears as a literal: it is spliced with substr, rot13-decoded, or
// trimmed out of a non-printable-prefixed string. 26 of 67 bypass samples used this, all scoring 0.

func TestReconstructedSinkNameSubstrSplice(t *testing.T) {
	// "sysatem" -> "sys" + "tem" = system
	src := []byte(`<?php $method='sysatem'; (substr($method,0,3).substr($method,4))($_GET['arg']);`)
	if len(fs(t, src)) == 0 {
		t.Fatalf("substr-spliced sink name must fire, got none")
	}
}

func TestReconstructedSinkNameRot13(t *testing.T) {
	src := []byte(`<?php $c = str_rot13('nffreg'); $c($_REQUEST['x']);`)
	if !hasRule(fs(t, src), "phptaint:sink-on-request") {
		t.Fatalf("str_rot13('nffreg') -> assert must resolve and fire, got %v", fs(t, src))
	}
}

func TestReconstructedSinkNameNonPrintableTrim(t *testing.T) {
	src := []byte("<?php $a=\"\x0Bassert\"; call_user_func_array(trim($a), array($_POST['a']));")
	if len(fs(t, src)) == 0 {
		t.Fatalf("trim of a non-printable-prefixed sink name must fire, got none")
	}
}

func TestReconstructedSinkNameStrrev(t *testing.T) {
	src := []byte(`<?php $f = strrev('metsys'); $f($_GET['c']);`)
	if !hasRule(fs(t, src), "phptaint:sink-on-request") {
		t.Fatalf("strrev('metsys') -> system must resolve and fire, got %v", fs(t, src))
	}
}

func TestFoldedNonSinkNameStaysSilent(t *testing.T) {
	// Folding must not turn every resolvable string operation into a finding.
	src := []byte(`<?php $label = strtoupper(substr('hello world',0,5)); echo htmlspecialchars($label . $_GET['n']);`)
	if got := fs(t, src); len(got) != 0 {
		t.Errorf("folding a harmless string must not create a finding, got %v", got)
	}
}

// --- Arbitrary file write (file-manager shells) -------------------------------------------------
// The file-drop detector gates on an executable destination extension, so a fully request-controlled
// path it cannot resolve is suppressed. A request-controlled path AND request-controlled content
// written through the same handle is arbitrary file write, which needs no extension to be a shell.

func TestArbitraryFileWriteViaHandle(t *testing.T) {
	src := []byte(`<?php $p = $_POST['filepath']; $c = $_POST['savedfile']; $h = fopen($p, 'w'); fwrite($h, $c); fclose($h);`)
	if !hasRule(fs(t, src), "phptaint:arbitrary-file-write") {
		t.Fatalf("request-controlled path AND content must fire, got %v", fs(t, src))
	}
}

func TestFileWriteFixedPathSilent(t *testing.T) {
	for _, src := range []string{
		// Content from the request but a path the application chose: an ordinary save/upload handler.
		`<?php $h = fopen('/var/log/app.log', 'a'); fwrite($h, $_POST['msg']);`,
		// Path from the request but content the application chose.
		`<?php $h = fopen($_POST['name'], 'w'); fwrite($h, "fixed");`,
		// Read-mode handle.
		`<?php $h = fopen($_POST['p'], 'r'); $d = fread($h, 100);`,
	} {
		if hasRule(fs(t, []byte(src)), "phptaint:arbitrary-file-write") {
			t.Errorf("must not fire arbitrary-file-write: %s -> %v", src, fs(t, []byte(src)))
		}
	}
}
