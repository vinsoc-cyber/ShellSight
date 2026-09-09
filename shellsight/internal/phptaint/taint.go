package phptaint

import (
	"reflect"
	"strconv"
	"strings"

	"github.com/VKCOM/php-parser/pkg/ast"
)

// Finding is one taint/dynamic-dispatch finding produced by the AST pass. Converted to a
// finding.Finding by the diskprobe wiring (M2.5).
type Finding struct {
	Score    int
	Family   string
	Rule     string // knowledge-ref suffix, e.g. "phptaint:dynamic-dispatch"
	Evidence string
}

var superglobals = map[string]bool{
	"_GET": true, "_POST": true, "_REQUEST": true, "_COOKIE": true,
	"_FILES": true, "_SERVER": true, "_ENV": true,
	// The raw request body under always_populate_raw_post_data; deprecated in PHP 7 but still the
	// carrier in older shells, and it is request data by definition.
	"HTTP_RAW_POST_DATA": true,
}

// sinks is the WTA + Argus + leavesongs catalog of DIRECT code-exec sinks: a call to one of these
// with a tainted argument (or a resolved-name variable holding one of these called with a tainted
// arg) is flagged. HOFs whose DANGER is only via a callback argument (preg_replace, call_user_func,
// preg_replace_callback, array_*, filter_var) are NOT here -- they go in hofCallbacks (callback
// resolves to a sink name) or are covered by the YARA /e and FILTER_CALLBACK rules. Measured FP on
// wordpress/phpMyAdmin: preg_replace alone was 55/63 FPs (apps sanitize request input with it).
var sinks = map[string]bool{
	"eval": true, "assert": true, "system": true, "exec": true, "passthru": true,
	"shell_exec": true, "proc_open": true, "popen": true, "pcntl_exec": true,
	"create_function": true,
	"ReflectionFunction": true, "ReflectionMethod": true,
	// unserialize of request input is a PHP Object Injection vector: an attacker-controlled
	// serialized payload drives __wakeup/__destruct gadgets that reach eval()/system() at runtime.
	// The request input enters here, so this is source-anchored like the exec sinks above.
	"unserialize": true,
	"include": true, "require": true, "include_once": true, "require_once": true,
}

// hofCallbacks maps a higher-order function to the 0-based index of its callable argument, so a
// built-in sink NAME passed as that callback (with a tainted arg elsewhere) is flagged.
var hofCallbacks = map[string]int{
	"call_user_func": 0, "call_user_func_array": 0,
	"array_map": 0, "array_filter": 1, "array_walk": 1, "array_walk_recursive": 1,
	"array_intersect_ukey": 2, "array_udiff": 2, "usort": 1, "uasort": 1, "uksort": 1,
	"preg_replace_callback": 1,

	// Deferred / implicit dispatch: the engine invokes the callable LATER, so there is no call at
	// the injection point for a source→sink walk to find. Measured on the corpus: 34 samples use
	// this mode and recall was 0.235 — the worst dispatch mode we hold, and structurally invisible
	// rather than merely under-tuned. All six take their callable at argument 0.
	//
	// These are also ordinary framework idioms (WordPress + phpMyAdmin: ob_start 216 uses,
	// set_error_handler 25, spl_autoload_register 7, register_shutdown_function 6), so registering
	// the NAME here is deliberately not enough to fire. The callable position still has to resolve
	// to a sink, be obfuscation-built, be unbound in this file, or be request-controlled — and the
	// call still has to carry request taint. A fixed handler registration stays silent.
	"register_shutdown_function": 0, "register_tick_function": 0,
	"set_error_handler": 0, "set_exception_handler": 0,
	"spl_autoload_register": 0, "ob_start": 0,
}

// sqlCallableMethods maps a METHOD that hands a user callable to the SQL engine to the 0-based index
// of that callable. SQLite3::createFunction / createAggregate and the PDO sqlite* equivalents let the
// database invoke the callable per row — dispatch that never appears as a call in the file. Measured
// recall on the 12 corpus samples that use it was 0.0000, because the taint pass had no method-call
// path at all. The names are distinctive enough to key on without object provenance.
var sqlCallableMethods = map[string]int{
	"createfunction": 1, "createaggregate": 1,
	"sqlitecreatefunction": 1, "sqlitecreateaggregate": 1,
}

// comExecMethods are the WScript.Shell execution methods. Gated on the receiver's PROVENANCE (a
// variable assigned `new COM(...)`), never on the method name alone: `->exec`, `->run` and
// `->query` are among the commonest method names in any codebase, so a name-only rule would fire on
// every database call. Corpus shape: `$ws = new COM('WScript.Shell'); $ws->exec("cmd /c ".$_GET[c])`.
var comExecMethods = map[string]bool{
	"exec": true, "run": true, "shellexecute": true, "execute": true,
}

// fileWriteDestIdx maps a filesystem-write builtin to the 0-based index of its DESTINATION-path
// argument. Used by the file-drop (dropper/uploader) detector. fwrite is excluded: its path is the
// fopen() handle (arg 0), not visible at the fwrite call, so the path cannot be assessed here.
var fileWriteDestIdx = map[string]int{
	"copy": 1, "move_uploaded_file": 1, "rename": 1,
	"file_put_contents": 0, "fopen": 0,
}

// forwarders maps a call-forwarding builtin to the 0-based index of its CALLABLE argument. Unlike
// hofCallbacks (whose callable often resolves to a literal sink), these are the ones webshells use
// to invoke a callable whose NAME is built at runtime and cannot be resolved — so the tell is the
// structure (forwarder + obfuscation-built callable + request input), not the resolved name.
var forwarders = map[string]int{
	"forward_static_call_array": 0, "forward_static_call": 0, "call_user_func_array": 0,
}

// lastArgCallbackHOFs are HOFs whose comparator/callback is the LAST positional argument (the
// data-array count is variadic, so the callable's index is not fixed). Webshells hide a runtime-
// built callable there while smuggling request input through the data arrays (2577a44 uses
// array_intersect_uassoc). Resolved positionally as len(Args)-1, not via a fixed index like
// hofCallbacks/forwarders.
var lastArgCallbackHOFs = map[string]bool{
	"array_intersect_uassoc": true, "array_diff_uassoc": true,
	"array_uintersect": true, "array_uintersect_assoc": true, "array_uintersect_uassoc": true,
	"array_udiff": true, "array_udiff_assoc": true, "array_udiff_uassoc": true,
}

// isObfuscatedCallee reports whether a callable expression is BUILT at runtime (a concat, or a
// string-mangling call like substr/strrev/str_replace/pack) rather than a plain literal. A callable
// that resolves to a literal is NOT obfuscated — it is handled by the literal-sink / HOF-callback
// branches. This is the "cannot resolve, but constructed" signal that separates a webshell forwarder
// from a benign one passing a fixed callback.
func (a *analyzer) isObfuscatedCallee(v ast.Vertex) bool {
	// A direct call to a string-mangling builtin in a callable position is a runtime-built callable
	// whether or not the fold succeeds. Checked BEFORE the resolve gate below because foldStringCall
	// now resolves several of these: a folded value that turns out to be a sink name is caught by the
	// stronger literal-sink branch, and one that is not must still read as "built here", exactly as
	// it did before folding existed. Without this ordering, folding would silently remove detections.
	if n, ok := v.(*ast.ExprFunctionCall); ok {
		if nm, ok := nameOfCall(n.Function); ok {
			switch nm {
			case "substr", "strrev", "str_replace", "pack":
				return true
			}
		}
	}
	if _, ok := a.resolveValue(v); ok {
		return false
	}
	switch n := v.(type) {
	case *ast.ExprBrackets:
		// Parentheses are their own node; a parenthesised built callable — (substr(..).substr(..)) —
		// must be seen through, exactly as resolveValue already does.
		return a.isObfuscatedCallee(n.Expr)
	case *ast.ExprBinaryConcat:
		return true
	case *ast.ExprBinaryBitwiseXor, *ast.ExprBinaryBitwiseOr:
		// A value assembled by XOR/OR keying is a custom-cipher construction, not a plain name.
		return true
	case *ast.ExprVariable:
		// Provenance: a plain variable that was assigned an obfuscation-built value upstream
		// ($f = pack(...) ^ $k; ... HOF(.., $f)). Its name never resolves, so obf carries the tell.
		if nm, ok := varNameOf(n); ok {
			return a.obf[nm]
		}
	case *ast.ExprFunctionCall:
		if nm, ok := nameOfCall(n.Function); ok {
			switch nm {
			case "substr", "strrev", "str_replace", "pack":
				return true
			}
		}
	}
	return false
}

// isRegistryLookup reports whether v selects an entry OUT OF a non-request-controlled array using a
// request-controlled KEY — `$registry[$_GET['id']]`. Frameworks dispatch this way (WordPress's widget
// and hook registries): the callables are registered by the application, so a request can only choose
// WHICH pre-registered callable runs, never WHAT runs. That is not attacker code execution.
//
// The two shapes where the attacker DOES supply the callable are excluded by requiring the base to be
// clean: `$_GET['f']` has a superglobal base, and `$a['f']` after `$a = $_POST` has a tainted base —
// in both the array itself is request data, so they keep firing.
func (a *analyzer) isRegistryLookup(v ast.Vertex) bool {
	switch n := v.(type) {
	case *ast.ExprBrackets:
		return a.isRegistryLookup(n.Expr)
	case *ast.ExprArrayDimFetch:
		if n.Dim == nil {
			return false
		}
		// Request taint must be in the KEY, and the array being indexed must itself be clean.
		return a.readsTaint(n.Dim) && !a.readsTaint(n.Var)
	}
	return false
}

// dynamicBindingFns create or read variables by name at runtime, so a variable can be bound without
// any syntactic binding form being visible. Their presence disables the unbound-callback rule for the
// whole file: better to miss than to assert "never bound" when binding is unobservable.
var dynamicBindingFns = map[string]bool{
	"extract": true, "compact": true, "import_request_variables": true,
	"get_defined_vars": true, "eval": true,
}

// bindings is the whole-file variable census the unbound-callback rule needs. `bound` holds every
// name reachable by a syntactic binding form (assignment of any flavour, parameter, `global`,
// `static`, foreach key/value, catch, closure `use`, and list/array destructuring). `uses` counts
// every plain-variable occurrence. `dynamic` means binding cannot be observed statically anywhere in
// this file.
type bindings struct {
	bound   map[string]bool
	uses    map[string]int
	dynamic bool
}

// collectBindings walks the whole file once to build the census. It is deliberately generous about
// what counts as bound — every miss here would become a false positive.
func collectBindings(root ast.Vertex) bindings {
	b := bindings{bound: map[string]bool{}, uses: map[string]int{}}
	// addBound marks every plain-variable inside v as bound, so destructuring targets
	// (list($a,$cb) / [$a,$cb]) and reference params bind their nested variables too.
	var addBound func(ast.Vertex)
	addBound = func(v ast.Vertex) {
		if v == nil {
			return
		}
		if ev, ok := v.(*ast.ExprVariable); ok {
			if nm, ok := varNameOf(ev); ok {
				b.bound[nm] = true
			}
		}
		forEachChild(v, addBound)
	}
	var visit func(ast.Vertex)
	visit = func(v ast.Vertex) {
		if v == nil {
			return
		}
		switch n := v.(type) {
		case *ast.ExprVariable:
			if nm, ok := varNameOf(n); ok {
				b.uses[nm]++
			} else if n.Name != nil {
				// $$x / ${expr} with a non-literal name: the variable touched is chosen at runtime.
				b.dynamic = true
			}
		case *ast.Parameter:
			addBound(n.Var)
		case *ast.StmtGlobal:
			for _, x := range n.Vars {
				addBound(x)
			}
		case *ast.StmtStaticVar:
			addBound(n.Var)
		case *ast.StmtForeach:
			addBound(n.Key)
			addBound(n.Var)
		case *ast.StmtCatch:
			addBound(n.Var)
		case *ast.ExprClosure:
			for _, u := range n.Uses {
				addBound(u)
			}
		case *ast.ExprFunctionCall:
			if nm, ok := nameOfCall(n.Function); ok && dynamicBindingFns[strings.ToLower(nm)] {
				b.dynamic = true
			}
		}
		// Any assignment flavour (ExprAssign, ExprAssignReference, ExprAssignConcat, ExprAssignPlus, …)
		// binds its Var. Matched structurally so a new operator in the parser cannot silently
		// reintroduce a false positive.
		if t := reflect.TypeOf(v); t != nil && strings.Contains(t.String(), ".ExprAssign") {
			if rv := reflect.ValueOf(v); rv.Kind() == reflect.Ptr && !rv.IsNil() {
				if f := rv.Elem().FieldByName("Var"); f.IsValid() && f.CanInterface() {
					if node, ok := f.Interface().(ast.Vertex); ok && node != nil {
						addBound(node)
						// $GLOBALS['cb'] = … binds $cb in every scope, invisibly to a name census.
						if mentionsGlobals(node) {
							b.dynamic = true
						}
					}
				}
			}
		}
		forEachChild(v, visit)
	}
	visit(root)
	return b
}

// mentionsGlobals reports whether v reads or writes the $GLOBALS array.
func mentionsGlobals(v ast.Vertex) bool {
	if v == nil {
		return false
	}
	if ev, ok := v.(*ast.ExprVariable); ok {
		if nm, ok := varNameOf(ev); ok && nm == "GLOBALS" {
			return true
		}
	}
	hit := false
	forEachChild(v, func(c ast.Vertex) {
		if !hit && mentionsGlobals(c) {
			hit = true
		}
	})
	return hit
}

// isUnboundCallbackVar reports whether v is a bare variable that this file never binds and never
// mentions anywhere else — i.e. a callable that arrives out-of-band. PHP itself would fail on such a
// call, so in a shipped file it signals the name is supplied by something the file does not show.
// Conservative on three axes: the file must have no dynamic-binding construct, the name must match no
// binding form, and it must occur exactly once (this call site) so a by-reference population
// elsewhere cannot be mistaken for absence.
func (a *analyzer) isUnboundCallbackVar(v ast.Vertex) bool {
	if a.binds.dynamic {
		return false
	}
	ev, ok := v.(*ast.ExprVariable)
	if !ok {
		return false
	}
	nm, ok := varNameOf(ev)
	if !ok || superglobals[nm] {
		return false
	}
	if a.binds.bound[nm] || a.binds.uses[nm] != 1 {
		return false
	}
	// A name this analyzer already resolved to a value is bound by definition.
	_, resolved := a.values[nm]
	return !resolved
}

// executableExts marks path suffixes that make a written file server-executable (a write of request
// data to one of these is a dropper signature).
var executableExts = []string{
	".php", ".phtml", ".phar", ".pht", ".php5", ".php7",
	".asp", ".aspx", ".ashx", ".asmx", ".cer",
	".jsp", ".jspx", ".jspf",
}

func hasExecutableExt(s string) bool {
	low := strings.ToLower(s)
	for _, e := range executableExts {
		if strings.Contains(low, e) {
			return true
		}
	}
	return false
}

// isDirectSuperglobalAccess reports whether v is a bare read of a superglobal, optionally dimmed
// (e.g. $_FILES, $_FILES['x'], $_POST['k']['y']) — i.e. the value's ROOT is a request superglobal,
// not wrapped in a concat/builtin that would sanitize or prefix it.
func isDirectSuperglobalAccess(v ast.Vertex) bool {
	switch n := v.(type) {
	case *ast.ExprVariable:
		if nm, ok := varNameOf(n); ok {
			return superglobals[nm]
		}
	case *ast.ExprArrayDimFetch:
		return isDirectSuperglobalAccess(n.Var)
	}
	return false
}

// Analyze parses PHP src and returns dynamic-dispatch / superglobal-taint findings that the
// byte-level YARA rules cannot express (split superglobals, define/sprintf/bitwise name-building,
// array-key dispatch, source-anchored dynamic calls). Pure + bounded; parsePHP provides the
// recover guard. Returns nil for unparseable input (caller falls back to byte-level rules).
func Analyze(src []byte) []Finding {
	root, ok := parsePHP(src)
	if !ok {
		return nil
	}
	a := &analyzer{
		values:    map[string]string{}, // key: bare var name ("x") or composite ("arr['k']")
		tainted:   map[string]bool{},   // key: bare var name that reads a superglobal
		decoded:   map[string]bool{},   // key: bare var name holding a custom-cipher function's return
		obf:       map[string]bool{},   // key: bare var name assigned an obfuscation-built (unresolvable) value
		com:       map[string]bool{},   // key: bare var name assigned `new COM(...)`
		wrHandle:  map[string]bool{},   // key: bare var name holding a request-pathed write handle
		decodeFns: collectDecodeFns(root),
		binds:     collectBindings(root),
	}
	a.walk(root)
	// Whole-file structural signature, independent of the taint walk: a hand-rolled nibble assembler
	// is a packer tell on its own, and this family carries no request source for the walk to anchor on.
	if hasNibbleAssemblerLoop(root) {
		a.findings = append(a.findings, Finding{
			Score: 70, Family: "PackedLoader", Rule: "phptaint:nibble-assembler-loop",
			Evidence: "AST: loop assembles bytes from 4-bit halves (chr(hi<<4|lo)) — a hand-rolled hex decoder",
		})
	}
	return a.findings
}

type analyzer struct {
	values    map[string]string
	tainted   map[string]bool
	decoded   map[string]bool   // var assigned a custom-cipher decode-loop function's return
	obf       map[string]bool   // var assigned an obfuscation-built (bitwise/pack/concat, unresolvable) value
	com       map[string]bool   // var assigned `new COM(...)` — receiver provenance for ->exec/->Run
	wrHandle  map[string]bool   // var assigned fopen(<request-controlled path>, <write mode>)
	foldDepth int               // resolveValue recursion guard (see maxFoldDepth)
	decodeFns map[string]bool   // user-defined functions whose body is a decode loop
	binds     bindings          // whole-file variable binding census (unbound-callback rule)
	findings  []Finding
}

// forEachChild invokes fn on every direct Vertex child of v (across Ptr/Interface/Slice fields),
// via reflect. Shared by walk/readsTaint/collectDecodeFns so all three descend identically.
func forEachChild(v ast.Vertex, fn func(ast.Vertex)) {
	rv := reflect.ValueOf(v)
	if rv.Kind() == reflect.Ptr {
		rv = rv.Elem()
	}
	if rv.Kind() != reflect.Struct {
		return
	}
	for i := 0; i < rv.NumField(); i++ {
		f := rv.Field(i)
		if !f.CanInterface() {
			continue
		}
		switch f.Kind() {
		case reflect.Ptr, reflect.Interface:
			if node, ok := f.Interface().(ast.Vertex); ok && node != nil {
				fn(node)
			}
		case reflect.Slice:
			for j := 0; j < f.Len(); j++ {
				if node, ok := f.Index(j).Interface().(ast.Vertex); ok {
					fn(node)
				}
			}
		}
	}
}

// walk pre-order traverses the AST and processes Assign / Call / Eval / Include nodes.
func (a *analyzer) walk(v ast.Vertex) {
	if v == nil {
		return
	}
	a.process(v)
	forEachChild(v, a.walk)
}

func (a *analyzer) process(v ast.Vertex) {
	switch n := v.(type) {
	case *ast.ExprAssign:
		a.handleAssign(n.Var, n.Expr, false)
	case *ast.ExprAssignConcat:
		a.handleAssign(n.Var, n.Expr, true) // .=  append
	case *ast.ExprFunctionCall:
		a.handleCall(n)
	case *ast.ExprMethodCall:
		a.handleMethodCall(n)
	case *ast.ExprShellExec:
		// `cmd` is shell_exec with no function name for a signature or a name-keyed sink table to
		// match. `<?=`$_GET[1]`;` is a complete 14-byte shell and was the smallest miss in the corpus.
		for _, part := range n.Parts {
			if a.readsTaint(part) {
				a.findings = append(a.findings, Finding{
					Score: 85, Family: "GenericEval", Rule: "phptaint:sink-on-request",
					Evidence: "AST taint: backtick shell execution of request input",
				})
				break
			}
		}
	case *ast.ExprNew:
		// ReflectionFunction/ReflectionMethod are in `sinks`, but `new X(...)` is not a call, so
		// handleCall never sees it: (new ReflectionFunction($p['a']))->invoke($p['b']) was invisible.
		if nm, ok := nameOfCall(n.Class); ok && sinks[strings.TrimPrefix(nm, "\\")] {
			for _, arg := range n.Args {
				if ae, ok := arg.(*ast.Argument); ok && a.readsTaint(ae.Expr) {
					a.findings = append(a.findings, Finding{
						Score: 85, Family: "DynamicDispatch", Rule: "phptaint:sink-on-request",
						Evidence: "AST taint: new " + nm + "(...) constructed from request input",
					})
					break
				}
			}
		}
	case *ast.ExprEval:
		// eval is a language construct (not a function call): it is always a sink.
		if n.Expr != nil && a.readsTaint(n.Expr) {
			a.findings = append(a.findings, Finding{
				Score: 90, Family: "GenericEval", Rule: "phptaint:sink-on-request",
				Evidence: "AST taint: eval(...) of request input",
			})
		} else if n.Expr != nil && a.involvesDecoded(n.Expr) {
			a.findings = append(a.findings, decodeDispatch("decode-loop result eval'd"))
		}
	case *ast.ExprInclude:
		// include/require(_once) is a language construct: of request input it is an LFI sink.
		if n.Expr != nil && a.readsTaint(n.Expr) {
			a.findings = append(a.findings, Finding{
				Score: 80, Family: "GenericEval", Rule: "phptaint:sink-on-request",
				Evidence: "AST taint: include/require(...) of request input (LFI)",
			})
		} else if n.Expr != nil && a.involvesDecoded(n.Expr) {
			a.findings = append(a.findings, decodeDispatch("decode-loop result include'd/require'd"))
		}
	}
}

// handleAssign updates the value and taint maps for an assignment. Last-write-wins: a later
// clean (non-tainted) assignment clears taint; a later unresolvable value clears the resolved name.
func (a *analyzer) handleAssign(lhs, rhs ast.Vertex, append bool) {
	key, isPlainVar := assignTarget(lhs)
	if key == "" {
		return
	}
	rt := a.readsTaint(rhs)
	// Receiver provenance for the COM branch of handleMethodCall. Last-write-wins like the maps
	// below, so reassigning the variable to something else clears it.
	if isPlainVar {
		if nw, ok := rhs.(*ast.ExprNew); ok && isCOMConstruction(nw) {
			a.com[key] = true
		} else if !append {
			delete(a.com, key)
		}
		// Handle provenance for the arbitrary-file-write detector: $h = fopen(<tainted>, 'w').
		if a.isRequestPathedWriteOpen(rhs) {
			a.wrHandle[key] = true
		} else if !append {
			delete(a.wrHandle, key)
		}
	}
	if val, ok := a.resolveValue(rhs); ok {
		if append {
			a.values[key] += val
		} else {
			a.values[key] = val
		}
	} else if !append {
		delete(a.values, key)
	}
	if isPlainVar {
		if rt {
			a.tainted[key] = true
		} else if !append {
			delete(a.tainted, key)
		}
		// Custom-cipher: $x = decodeFn(...) -> $x holds a runtime-decoded value (last-write-wins).
		if dn, ok := calledLiteralName(rhs); ok && a.decodeFns[dn] {
			a.decoded[key] = true
		} else if !append {
			delete(a.decoded, key)
		}
		// Obfuscation provenance: $x = <bitwise ^/| | pack/substr/strrev/str_replace | non-literal
		// concat | a var already so flagged>. A var carrying this flag, later passed as a callable to
		// a forwarder / last-arg-callback HOF, is a runtime-built dispatch even though its name never
		// resolves (2577a44: $f = pack(...) ^ $k; array_intersect_uassoc(.., $_REQUEST[..], .., $f)).
		if a.isObfuscatedCallee(rhs) {
			a.obf[key] = true
		} else if !append {
			delete(a.obf, key)
		}
	}
}

// isRequestPathedWriteOpen reports whether an expression is `fopen(<request-controlled>, <write mode>)`.
// The mode must be resolvable and must not be read-only: a handle opened 'r' cannot be written through,
// so including it would only add noise.
func (a *analyzer) isRequestPathedWriteOpen(v ast.Vertex) bool {
	call, ok := v.(*ast.ExprFunctionCall)
	if !ok {
		return false
	}
	if nm, ok := nameOfCall(call.Function); !ok || nm != "fopen" || len(call.Args) < 2 {
		return false
	}
	path, ok := call.Args[0].(*ast.Argument)
	if !ok || !a.readsTaint(path.Expr) {
		return false
	}
	mode, ok := call.Args[1].(*ast.Argument)
	if !ok {
		return false
	}
	m, ok := a.resolveValue(mode.Expr)
	if !ok {
		return false
	}
	return strings.ContainsAny(strings.ToLower(m), "wax+")
}

// handleArbitraryFileWrite fires when request-controlled CONTENT is written through a handle opened
// on a request-controlled PATH. handleFileDrop already covers the dropper case, but it gates on an
// executable destination extension, so a fully request-supplied path it cannot resolve is suppressed
// — which is why the file-manager shells in the corpus (read/write any path) scored 0.
//
// Requiring both halves is what keeps this off ordinary save and upload handlers: those write
// request content to a path the application chose, or a request-named file into a fixed directory.
// Both halves attacker-controlled is arbitrary file write, and needs no extension to be a webshell.
func (a *analyzer) handleArbitraryFileWrite(call *ast.ExprFunctionCall) bool {
	nm, ok := nameOfCall(call.Function)
	if !ok || (nm != "fwrite" && nm != "fputs") || len(call.Args) < 2 {
		return false
	}
	h, ok := call.Args[0].(*ast.Argument)
	if !ok {
		return false
	}
	hv, ok := h.Expr.(*ast.ExprVariable)
	if !ok {
		return false
	}
	hn, ok := varNameOf(hv)
	if !ok || !a.wrHandle[hn] {
		return false
	}
	data, ok := call.Args[1].(*ast.Argument)
	if !ok || !a.readsTaint(data.Expr) {
		return false
	}
	a.findings = append(a.findings, Finding{
		Score: 85, Family: "FileDrop", Rule: "phptaint:arbitrary-file-write",
		Evidence: "AST taint: request-controlled content written to a request-controlled path",
	})
	return true
}

// handleMethodCall is the sink detector for `$obj->method(...)`. PHP method dispatch is untyped, so
// there is no receiver type to consult; each branch below therefore establishes what the receiver IS
// before treating the method as dangerous — either because the method name is distinctive enough to
// stand alone (the SQL callable registrars) or from tracked `new COM(...)` provenance.
func (a *analyzer) handleMethodCall(call *ast.ExprMethodCall) {
	name := ""
	if id, ok := call.Method.(*ast.Identifier); ok {
		name = strings.ToLower(string(id.Value))
	}
	if name == "" {
		return
	}

	// (a) A callable registered with the SQL engine. Fires when the callable is request-controlled,
	// obfuscation-built, or resolves to a code-exec sink — not when it is a fixed application name.
	if idx, ok := sqlCallableMethods[name]; ok && idx < len(call.Args) {
		if ae, ok := call.Args[idx].(*ast.Argument); ok {
			cb, resolved := a.resolveValue(ae.Expr)
			switch {
			case resolved && sinks[strings.ToLower(cb)]:
				a.findings = append(a.findings, Finding{
					Score: 85, Family: "SQLDispatch", Rule: "phptaint:sql-registered-callable",
					Evidence: "AST taint: ->" + name + "(..., " + cb + ") registers a code-exec sink with the SQL engine",
				})
			case a.readsTaint(ae.Expr) && !a.isRegistryLookup(ae.Expr):
				a.findings = append(a.findings, Finding{
					Score: 85, Family: "SQLDispatch", Rule: "phptaint:sql-registered-callable",
					Evidence: "AST taint: ->" + name + "(...) registers a request-controlled callable with the SQL engine",
				})
			case a.isObfuscatedCallee(ae.Expr):
				a.findings = append(a.findings, Finding{
					Score: 80, Family: "SQLDispatch", Rule: "phptaint:sql-registered-callable",
					Evidence: "AST taint: ->" + name + "(...) registers a runtime-built callable with the SQL engine",
				})
			}
			return
		}
	}

	// (b) COM shell execution on a receiver known to be a COM object, with request input.
	if comExecMethods[name] && a.receiverIsCOM(call.Var) {
		for _, arg := range call.Args {
			if ae, ok := arg.(*ast.Argument); ok && a.readsTaint(ae.Expr) {
				a.findings = append(a.findings, Finding{
					Score: 90, Family: "ComExec", Rule: "phptaint:com-exec-on-request",
					Evidence: "AST taint: COM object ->" + name + "(...) called with request input",
				})
				return
			}
		}
	}
}

// receiverIsCOM reports whether an expression is a variable this file assigned from `new COM(...)`.
func (a *analyzer) receiverIsCOM(v ast.Vertex) bool {
	switch n := v.(type) {
	case *ast.ExprBrackets:
		return a.receiverIsCOM(n.Expr)
	case *ast.ExprVariable:
		if nm, ok := varNameOf(n); ok {
			return a.com[nm]
		}
	case *ast.ExprNew:
		// Chained straight off the constructor: (new COM('WScript.Shell'))->exec(...).
		return isCOMConstruction(n)
	}
	return false
}

// isCOMConstruction reports whether a `new` expression instantiates the COM class.
func isCOMConstruction(n *ast.ExprNew) bool {
	if n == nil || n.Class == nil {
		return false
	}
	nm, ok := nameOfCall(n.Class)
	return ok && strings.EqualFold(strings.TrimPrefix(nm, "\\"), "COM")
}

// handleCall is the sink detector.
func (a *analyzer) handleCall(call *ast.ExprFunctionCall) {
	// (d) Custom-cipher dispatch: a decode-loop function's RETURN is invoked as a function, passed
	// as a call argument, eval'd, or include'd. The sink name / payload is the runtime return of a
	// decoder no static analysis can recover; the structure alone is a packed-webshell signature,
	// so this fires WITHOUT requiring a visible superglobal.
	if a.involvesDecoded(call.Function) {
		a.findings = append(a.findings, decodeDispatch("decode-loop return invoked as a function"))
		return
	}
	// A decoded payload passed as an argument is only flagged when the receiving call is itself a
	// sink/HOF (create_function, call_user_func, array_u*, ...): a decoded string into an arbitrary
	// benign function is too weak a signal (FP-prone).
	if rn, _ := a.calledName(call.Function); rn != "" && (sinks[rn] || isHOF(rn)) {
		for _, arg := range call.Args {
			if ae, ok := arg.(*ast.Argument); ok && a.involvesDecoded(ae.Expr) {
				a.findings = append(a.findings, decodeDispatch("decode-loop result passed to "+rn+"(...)"))
				return
			}
		}
	}
	// (e) File-drop: a request-controlled filesystem write (dropper/uploader). Independent of the
	// taint-arg gate below because the destination path itself can be the request-controlled part.
	if a.handleFileDrop(call) {
		return
	}
	// (e2) Arbitrary file write through a handle opened on a request-controlled path. Also outside
	// the taint-arg gate: the path taint was established at fopen time, not at this call.
	if a.handleArbitraryFileWrite(call) {
		return
	}
	anyTainted := false
	for _, arg := range call.Args {
		if ae, ok := arg.(*ast.Argument); ok && a.readsTaint(ae.Expr) {
			anyTainted = true
			break
		}
	}
	if !anyTainted {
		return
	}
	resolvedName, isDynamic := a.calledName(call.Function)

	// assert() is a sink for its FIRST argument only, and only when that argument can be a string
	// (lit-review.md, php/dispatch/eval-request, amendment 2026-08-26; spec 007 US4). PHP 8 removed
	// string evaluation from assert(), and a comparison, an instanceof, a negation or a cast was never
	// code on any version -- phpMyAdmin's `assert($statement instanceof SelectStatement)` scored 85 on
	// the curated benign tree, the tier the runbook maps to "isolate host". The sink stays for every
	// string-capable argument, which is what every assertion-based shell in the corpus passes.
	if resolvedName == "assert" && !a.assertArgumentIsCode(call.Args) {
		return
	}

	// (a) resolved/literal sink called with a tainted argument.
	if resolvedName != "" && sinks[resolvedName] {
		a.findings = append(a.findings, Finding{
			Score: 85, Family: "DynamicDispatch", Rule: "phptaint:sink-on-request",
			Evidence: "AST taint: " + resolvedName + "(...) called with request input",
		})
		return
	}
	// (b) HOF whose callback argument either resolves to a sink NAME or is a runtime-BUILT callable.
	// The index comes from callbackIdx so the fixed-index HOFs and the array_u*/uassoc family (whose
	// comparator is the last positional arg) share one resolution.
	if cbIdx, ok := callbackIdx(resolvedName, len(call.Args)); ok && cbIdx < len(call.Args) {
		if ae, ok := call.Args[cbIdx].(*ast.Argument); ok {
			if cb, ok := a.resolveValue(ae.Expr); ok && sinks[strings.ToLower(cb)] {
				a.findings = append(a.findings, Finding{
					Score: 85, Family: "CallbackSink", Rule: "phptaint:callback-on-request",
					Evidence: "AST taint: " + resolvedName + "(..., " + cb + ") callback on request input",
				})
				return
			}
			// The callable's name cannot be resolved but is obfuscation-BUILT (bitwise/pack/concat, or a
			// variable carrying that provenance): a runtime-assembled dispatch, not a fixed callback.
			if a.isObfuscatedCallee(ae.Expr) {
				a.findings = append(a.findings, Finding{
					Score: 80, Family: "DynamicDispatch", Rule: "phptaint:forwarder-obfuscated-callee",
					Evidence: "AST taint: " + resolvedName + "(...) callback is a runtime-built callable with request input",
				})
				return
			}
			// The callable is a variable this file never binds and never mentions elsewhere: the name
			// arrives out-of-band, so the dispatch target is not in the file being scanned.
			if a.isUnboundCallbackVar(ae.Expr) {
				a.findings = append(a.findings, Finding{
					Score: 75, Family: "DynamicDispatch", Rule: "phptaint:unbound-callback-dispatch",
					Evidence: "AST taint: " + resolvedName + "(...) callback is a variable never bound in this file, with request input",
				})
				return
			}
			// The callback NAME is request-controlled: a superglobal reaches the callback position
			// (directly, or through a resolved-tainted var / ternary) — call_user_func($_GET['f'], …).
			// A request-chosen callable is arbitrary-function-call: the same dynamic-dispatch tell the
			// direct form ($_GET['f']($x)) already flags, here routed through a HOF.
			//
			// Excluded: a REGISTRY lookup — $registry[$_GET['id']] — where the request only picks which
			// application-registered callable runs. Frameworks (WordPress widget/hook dispatch) do this
			// legitimately, and it is not attacker-supplied code.
			if a.readsTaint(ae.Expr) && !a.isRegistryLookup(ae.Expr) {
				a.findings = append(a.findings, Finding{
					Score: 78, Family: "DynamicDispatch", Rule: "phptaint:request-tainted-callback",
					Evidence: "AST taint: " + resolvedName + "(...) callback name is request-controlled",
				})
				return
			}
		}
	}
	// (b2) call-forwarder (forward_static_call_array / call_user_func_array / ...) whose callable is
	// built at runtime (concat/substr/strrev/pack) so its name cannot be resolved, invoked with
	// request input. The forwarder callee is a literal name (so branch (c) below does not fire), but
	// the obfuscation-built callable + request taint is the webshell tell.
	if fwIdx, ok := forwarders[resolvedName]; ok && fwIdx < len(call.Args) {
		if ae, ok := call.Args[fwIdx].(*ast.Argument); ok && a.isObfuscatedCallee(ae.Expr) {
			a.findings = append(a.findings, Finding{
				Score: 80, Family: "DynamicDispatch", Rule: "phptaint:forwarder-obfuscated-callee",
				Evidence: "AST taint: " + resolvedName + "(...) forwards to a runtime-built callable with request input",
			})
			return
		}
	}
	// (b3) direct-invoke of a runtime-BUILT callable in call position: (substr(...).substr(...))($tainted),
	// (("s"^..).("y"^..))($tainted). This is not a HOF/forwarder argument (so branches b/b2 never see it)
	// and its name never resolves to a variable/array-key (so branches a/c do not fire), yet a callable
	// assembled at runtime and invoked directly with request input is the reconstructed-sink-name webshell
	// tell. Keyed on the STRUCTURE (built callable + request taint), general to the mechanism.
	if a.isObfuscatedCallee(call.Function) {
		a.findings = append(a.findings, Finding{
			Score: 78, Family: "DynamicDispatch", Rule: "phptaint:direct-invoke-built-callable",
			Evidence: "AST taint: a runtime-built callable invoked directly with request input",
		})
		return
	}
	// (c) source-anchored dynamic dispatch: a VARIABLE/array-key is invoked with a tainted arg,
	// regardless of whether its name resolved (WTA INIT_DYNAMIC_CALL equivalent).
	if isDynamic {
		a.findings = append(a.findings, Finding{
			Score: 75, Family: "DynamicDispatch", Rule: "phptaint:dynamic-dispatch-on-request",
			Evidence: "AST taint: variable/array-key invoked with request input (sink name held as data)",
		})
	}
}

// assertArgumentIsCode reports whether an assert(...) call's first argument is request-tainted and of
// a kind that can evaluate to a string. The description argument (index 1) was never evaluated on any
// PHP version, so taint there is not code execution.
func (a *analyzer) assertArgumentIsCode(args []ast.Vertex) bool {
	if len(args) == 0 {
		return false
	}
	ae, ok := args[0].(*ast.Argument)
	if !ok || cannotBeString(ae.Expr) {
		return false
	}
	return a.readsTaint(ae.Expr)
}

// cannotBeString reports whether an expression's kind rules out a string value: the grammar-defined
// boolean and numeric forms. Deliberately no function-name list -- a call's return type is not knowable
// here, and a curated list would be a second finite list to maintain (research R5).
func cannotBeString(v ast.Vertex) bool {
	for {
		b, ok := v.(*ast.ExprBrackets)
		if !ok {
			break
		}
		v = b.Expr
	}
	switch v.(type) {
	case *ast.ExprInstanceOf, *ast.ExprBooleanNot, *ast.ExprIsset, *ast.ExprEmpty,
		*ast.ExprCastBool, *ast.ExprCastInt, *ast.ExprCastDouble, *ast.ExprCastArray,
		*ast.ExprBinaryEqual, *ast.ExprBinaryIdentical, *ast.ExprBinaryNotEqual, *ast.ExprBinaryNotIdentical,
		*ast.ExprBinarySmaller, *ast.ExprBinarySmallerOrEqual, *ast.ExprBinaryGreater, *ast.ExprBinaryGreaterOrEqual,
		*ast.ExprBinarySpaceship, *ast.ExprBinaryBooleanAnd, *ast.ExprBinaryBooleanOr,
		*ast.ExprBinaryLogicalAnd, *ast.ExprBinaryLogicalOr, *ast.ExprBinaryLogicalXor:
		return true
	}
	return false
}

// handleFileDrop flags a dropper/uploader: a filesystem-write builtin whose destination PATH is
// either a bare request-superglobal access (attacker-controlled filename) or resolves to a
// server-executable extension while request input flows in. Returns true if it emitted a finding.
// Conservative by design (executable-content / bare-superglobal gate) to avoid flagging legit app
// uploads to prefixed, non-executable destination dirs.
func (a *analyzer) handleFileDrop(call *ast.ExprFunctionCall) bool {
	name, _ := a.calledName(call.Function)
	destIdx, ok := fileWriteDestIdx[name]
	if !ok || destIdx >= len(call.Args) {
		return false
	}
	destArg, ok := call.Args[destIdx].(*ast.Argument)
	if !ok || destArg.Expr == nil {
		return false
	}
	dest := destArg.Expr
	if isDirectSuperglobalAccess(dest) {
		a.findings = append(a.findings, Finding{
			Score: 70, Family: "FileDrop", Rule: "phptaint:file-drop-on-request",
			Evidence: "AST taint: " + name + "(...) writes to a request-controlled destination path",
		})
		return true
	}
	if pv, ok := a.resolveValue(dest); ok && hasExecutableExt(pv) {
		// Executable destination: require request input somewhere in the call (the payload),
		// so a config generator writing a literal .php from non-request data is not flagged.
		for _, arg := range call.Args {
			if ae, ok := arg.(*ast.Argument); ok && a.readsTaint(ae.Expr) {
				a.findings = append(a.findings, Finding{
					Score: 70, Family: "FileDrop", Rule: "phptaint:file-drop-on-request",
					Evidence: "AST taint: " + name + "(...) writes request input to executable path " + truncate(pv),
				})
				return true
			}
		}
	}
	return false
}

func truncate(s string) string {
	if len(s) > 48 {
		return s[:48] + "…"
	}
	return s
}

// calledName resolves the callee to a function name string and reports whether it is a DYNAMIC
// call (variable/array-key, not a literal Name). The name is lowercased because PHP function
// names are case-insensitive — webshells use mixed case (Create_Function, SyStem) to evade
// case-sensitive detectors, so all sink/HOF/decode lookups must compare case-insensitively.
func (a *analyzer) calledName(fn ast.Vertex) (name string, dynamic bool) {
	switch n := fn.(type) {
	case *ast.Name:
		return strings.ToLower(nameString(n)), false
	case *ast.ExprVariable:
		if nm, ok := varNameOf(n); ok {
			if v, ok := a.values[nm]; ok {
				return strings.ToLower(v), true
			}
		}
		return "", true
	case *ast.ExprArrayDimFetch:
		if key, ok := arrayKeyOf(n); ok {
			if v, ok := a.values[key]; ok {
				return strings.ToLower(v), true
			}
		}
		return "", true
	case *ast.ExprBrackets, *ast.ExprBinaryConcat:
		// A callee assembled inline and invoked directly: (substr($m,0,3).substr($m,4))($_GET[a]).
		// Since foldStringCall resolves the pieces, the whole callee can now resolve to a real sink
		// name — so report it as one rather than leaving it to the weaker "built here" heuristic.
		if v, ok := a.resolveValue(fn); ok {
			return strings.ToLower(v), true
		}
		return "", true
	}
	return "", false
}

// maxFoldDepth bounds resolveValue's recursion. Folding descends into call arguments, and this runs
// over attacker-controlled files: a deeply nested chr(ord(substr(...))) chain — which real packers
// emit — would otherwise cost unbounded time and stack. Depth 64 is far past any genuine sink-name
// reconstruction seen in the corpus (the deepest is single digits), so the bound costs no recall.
const maxFoldDepth = 64

// resolveValue folds an expression to a concrete string: string literal, number, concat, chr(N),
// the pure string builtins in foldStringCall, or a previously-resolved variable. Used to recover
// sink names built at runtime.
func (a *analyzer) resolveValue(v ast.Vertex) (string, bool) {
	if a.foldDepth >= maxFoldDepth {
		return "", false
	}
	a.foldDepth++
	defer func() { a.foldDepth-- }()
	switch n := v.(type) {
	case *ast.ExprBrackets:
		// Parentheses are their own node here; these shells parenthesise every folded pair
		// (("#"^"|").("."^"~")…), so resolution must see through them.
		return a.resolveValue(n.Expr)
	case *ast.ScalarString:
		return unquotePHP(n.Value), true
	case *ast.ScalarLnumber:
		return string(n.Value), true
	case *ast.ScalarDnumber:
		return string(n.Value), true
	case *ast.ExprBinaryConcat:
		l, ok1 := a.resolveValue(n.Left)
		r, ok2 := a.resolveValue(n.Right)
		if ok1 && ok2 {
			return l + r, true
		}
		return "", false
	case *ast.ExprVariable:
		if nm, ok := varNameOf(n); ok {
			if val, ok := a.values[nm]; ok {
				return val, true
			}
		}
		return "", false
	case *ast.ExprConstFetch:
		// A bareword that is not a defined constant evaluates to its own name in PHP < 8, which is how
		// these shells smuggle text past a string-literal scan ('yBR9vVE' & ~ix5NBYV).
		if nm, ok := n.Const.(*ast.Name); ok {
			return nameString(nm), true
		}
		return "", false
	case *ast.ExprBinaryBitwiseXor:
		return a.foldBitwise(n.Left, n.Right, '^')
	case *ast.ExprBinaryBitwiseOr:
		return a.foldBitwise(n.Left, n.Right, '|')
	case *ast.ExprBinaryBitwiseAnd:
		return a.foldBitwise(n.Left, n.Right, '&')
	case *ast.ExprBitwiseNot:
		v, ok := a.resolveValue(n.Expr)
		if !ok {
			return "", false
		}
		b := []byte(v)
		for i := range b {
			b[i] = ^b[i]
		}
		return string(b), true
	case *ast.ExprFunctionCall:
		return a.foldStringCall(n)
	}
	return "", false
}

// phpTrimSet is PHP's default trim charlist. The vertical tab matters: a corpus shell stores
// "\x0Bassert" so the sink name is never a clean literal, then trims it back at call time.
const phpTrimSet = " \t\n\r\x00\x0B"

// foldStringCall constant-folds the pure string builtins webshells use to reconstruct a sink name at
// runtime, so `strrev('metsys')` and `str_rot13('nffreg')` resolve to `system` and `assert` and reach
// the literal-sink branch instead of the weaker "something was built here" heuristics.
//
// Every argument must itself resolve, so this only ever folds attacker-static data — it cannot fold
// request input, and a call it cannot fold returns not-resolved exactly as before.
func (a *analyzer) foldStringCall(n *ast.ExprFunctionCall) (string, bool) {
	nm, ok := nameOfCall(n.Function)
	if !ok {
		return "", false
	}
	args := make([]string, 0, len(n.Args))
	for _, arg := range n.Args {
		ae, ok := arg.(*ast.Argument)
		if !ok {
			return "", false
		}
		v, ok := a.resolveValue(ae.Expr)
		if !ok {
			return "", false
		}
		args = append(args, v)
	}
	switch strings.ToLower(nm) {
	case "chr":
		if len(args) == 1 {
			if b, err := strconv.Atoi(strings.TrimSpace(args[0])); err == nil && b >= 0 && b <= 255 {
				return string([]byte{byte(b)}), true
			}
		}
	case "strrev":
		if len(args) == 1 {
			b := []byte(args[0])
			for i, j := 0, len(b)-1; i < j; i, j = i+1, j-1 {
				b[i], b[j] = b[j], b[i]
			}
			return string(b), true
		}
	case "str_rot13":
		if len(args) == 1 {
			b := []byte(args[0])
			for i, c := range b {
				switch {
				case c >= 'a' && c <= 'z':
					b[i] = 'a' + (c-'a'+13)%26
				case c >= 'A' && c <= 'Z':
					b[i] = 'A' + (c-'A'+13)%26
				}
			}
			return string(b), true
		}
	case "trim":
		if len(args) == 1 {
			return strings.Trim(args[0], phpTrimSet), true
		}
	case "ltrim":
		if len(args) == 1 {
			return strings.TrimLeft(args[0], phpTrimSet), true
		}
	case "rtrim":
		if len(args) == 1 {
			return strings.TrimRight(args[0], phpTrimSet), true
		}
	case "strtolower":
		if len(args) == 1 {
			return strings.ToLower(args[0]), true
		}
	case "strtoupper":
		if len(args) == 1 {
			return strings.ToUpper(args[0]), true
		}
	case "substr":
		// PHP substr($s, $start[, $len]) with negative-index semantics.
		if len(args) == 2 || len(args) == 3 {
			s := args[0]
			start, err := strconv.Atoi(strings.TrimSpace(args[1]))
			if err != nil {
				return "", false
			}
			if start < 0 {
				start += len(s)
				if start < 0 {
					start = 0
				}
			}
			if start > len(s) {
				return "", true // PHP >= 8 yields ""
			}
			out := s[start:]
			if len(args) == 3 {
				ln, err := strconv.Atoi(strings.TrimSpace(args[2]))
				if err != nil {
					return "", false
				}
				if ln < 0 {
					if ln = len(out) + ln; ln < 0 {
						ln = 0
					}
				}
				if ln < len(out) {
					out = out[:ln]
				}
			}
			return out, true
		}
	case "str_replace":
		// Only the all-scalar form; the array form is not what these shells use.
		if len(args) == 3 {
			return strings.ReplaceAll(args[2], args[0], args[1]), true
		}
	}
	return "", false
}

// foldBitwise constant-folds a PHP bitwise operator over two operands that both resolve to values.
// This is folding, not emulation: both operands are literals (or already-folded literals), so the
// result is decidable statically. Webshells use it to spell "_POST"/"assert" out of punctuation, which
// leaves no literal token for a byte-level rule to match.
//
// PHP semantics are bytewise and the length rule differs per operator: & and ^ truncate to the SHORTER
// operand, | extends to the LONGER one with the shorter zero-padded. Two integer operands are integer
// arithmetic instead — folded separately so a numeric expression is not mangled into bytes.
//
// A wrong fold cannot create a false positive: every consumer requires the result to EQUAL a known
// superglobal or sink name, so a bad value simply fails to match.
func (a *analyzer) foldBitwise(left, right ast.Vertex, op byte) (string, bool) {
	l, ok1 := a.resolveValue(left)
	r, ok2 := a.resolveValue(right)
	if !ok1 || !ok2 {
		return "", false
	}
	if isIntLiteral(left) && isIntLiteral(right) {
		li, e1 := strconv.Atoi(l)
		ri, e2 := strconv.Atoi(r)
		if e1 != nil || e2 != nil {
			return "", false
		}
		switch op {
		case '^':
			return strconv.Itoa(li ^ ri), true
		case '|':
			return strconv.Itoa(li | ri), true
		case '&':
			return strconv.Itoa(li & ri), true
		}
		return "", false
	}
	switch op {
	case '|':
		n := len(l)
		if len(r) > n {
			n = len(r)
		}
		out := make([]byte, n)
		for i := 0; i < n; i++ {
			var lb, rb byte
			if i < len(l) {
				lb = l[i]
			}
			if i < len(r) {
				rb = r[i]
			}
			out[i] = lb | rb
		}
		return string(out), true
	case '^', '&':
		n := len(l)
		if len(r) < n {
			n = len(r)
		}
		out := make([]byte, n)
		for i := 0; i < n; i++ {
			if op == '^' {
				out[i] = l[i] ^ r[i]
			} else {
				out[i] = l[i] & r[i]
			}
		}
		return string(out), true
	}
	return "", false
}

// isIntLiteral reports whether v is syntactically an integer literal, so bitwise folding uses integer
// rather than bytewise-string semantics.
func isIntLiteral(v ast.Vertex) bool {
	_, ok := v.(*ast.ScalarLnumber)
	return ok
}

// requestSourceCall reports whether a call reads attacker-controlled request data by a route that is
// NOT a superglobal: HTTP request headers via getenv/apache_request_headers/getallheaders, or the raw
// request body via php://input. Shells use these precisely so that no $_GET/$_POST token appears in the
// file at all — the source, not just the sink, is hidden.
//
// getenv is gated on an HTTP_ prefix because only that slice of the environment is request-controlled:
// getenv("PATH")/getenv("HOME") are ordinary configuration and tainting them would flag deployment
// scripts. A getenv whose name cannot be resolved is likewise NOT treated as a source — falling open is
// preferable to a rule that fires on every environment read.
func (a *analyzer) requestSourceCall(c *ast.ExprFunctionCall) bool {
	// calledName, not nameOfCall: in these shells the SOURCE function is itself held in a variable
	// ($ae3 = "getenv"), so a literal-name-only lookup never matches the real sample.
	nm, _ := a.calledName(c.Function)
	if nm == "" {
		return false
	}
	switch nm {
	case "apache_request_headers", "getallheaders":
		return true
	case "getenv":
		if len(c.Args) == 1 {
			if ae, ok := c.Args[0].(*ast.Argument); ok {
				if v, ok := a.resolveValue(ae.Expr); ok && strings.HasPrefix(strings.ToUpper(v), "HTTP_") {
					return true
				}
			}
		}
	case "file_get_contents", "fopen", "readfile", "stream_get_contents":
		if len(c.Args) >= 1 {
			if ae, ok := c.Args[0].(*ast.Argument); ok {
				if v, ok := a.resolveValue(ae.Expr); ok && strings.EqualFold(strings.TrimSpace(v), "php://input") {
					return true
				}
			}
		}
	}
	return false
}

// readsTaint reports whether v reads a superglobal or a tainted variable anywhere in it.
func (a *analyzer) readsTaint(v ast.Vertex) bool {
	if v == nil {
		return false
	}
	if c, ok := v.(*ast.ExprFunctionCall); ok && a.requestSourceCall(c) {
		return true
	}
	if ev, ok := v.(*ast.ExprVariable); ok {
		if nm, ok := varNameOf(ev); ok {
			return superglobals[nm] || a.tainted[nm]
		}
		// ${expr} / $$var form: Name is not a plain Identifier. Resolve it (e.g. ${"_P"."O"."S"."T"}
		// -> "_POST") and treat as a superglobal if it resolves to one.
		if ev.Name != nil {
			if resolved, ok := a.resolveValue(ev.Name); ok {
				if superglobals[strings.TrimPrefix(resolved, "$")] {
					return true
				}
			}
		}
		return false
	}
	rv := reflect.ValueOf(v)
	if rv.Kind() == reflect.Ptr {
		rv = rv.Elem()
	}
	if rv.Kind() != reflect.Struct {
		return false
	}
	hit := false
	forEachChild(v, func(c ast.Vertex) {
		if !hit && a.readsTaint(c) {
			hit = true
		}
	})
	return hit
}

// ---- small node helpers ----

// assignTarget returns the value-map key for an assignment LHS and whether it is a plain variable
// (vs an array element). Plain var -> bare name "x"; array element -> composite "arr['k']".
func assignTarget(lhs ast.Vertex) (key string, isPlainVar bool) {
	switch n := lhs.(type) {
	case *ast.ExprVariable:
		if nm, ok := varNameOf(n); ok {
			return nm, true
		}
	case *ast.ExprArrayDimFetch:
		if key, ok := arrayKeyOf(n); ok {
			return key, false
		}
	}
	return "", false
}

func varNameOf(v *ast.ExprVariable) (string, bool) {
	switch nm := v.Name.(type) {
	case *ast.Identifier:
		return strings.TrimPrefix(string(nm.Value), "$"), true // VKCOM includes the $ in Identifier.Value
	case *ast.ScalarString:
		// ${"c"} variable-variable with a literal name refers to the same variable as $c, so track it
		// under the same key (webshells assign request input via ${"..."} to dodge $-name matching).
		return unquotePHP(nm.Value), true
	}
	return "", false
}

// arrayKeyOf returns the composite key "arr['k']" for an ExprArrayDimFetch whose base is a plain
// variable and whose dim is a string literal.
func arrayKeyOf(n *ast.ExprArrayDimFetch) (string, bool) {
	base, ok := n.Var.(*ast.ExprVariable)
	if !ok {
		return "", false
	}
	nm, ok := varNameOf(base)
	if !ok || n.Dim == nil {
		return "", false
	}
	if ss, ok := n.Dim.(*ast.ScalarString); ok {
		return nm + "['" + unquotePHP(ss.Value) + "']", true
	}
	return "", false
}

func nameOfCall(fn ast.Vertex) (string, bool) {
	if nm, ok := fn.(*ast.Name); ok {
		return nameString(nm), true
	}
	return "", false
}

func nameString(n *ast.Name) string {
	var b strings.Builder
	for i, p := range n.Parts {
		if pp, ok := p.(*ast.NamePart); ok {
			if i > 0 {
				b.WriteByte('\\')
			}
			b.Write(pp.Value)
		}
	}
	return b.String()
}

// unquotePHP strips surrounding quotes from a PHP string token and resolves the common escapes.
func unquotePHP(v []byte) string {
	if len(v) < 2 {
		return string(v)
	}
	q := v[0]
	if (q == '"' || q == '\'') && v[len(v)-1] == q {
		inner := v[1 : len(v)-1]
		if q == '\'' {
			return strings.ReplaceAll(string(inner), "\\'", "'")
		}
		// double-quoted: resolve \n \r \t \" \\ and leave the rest.
		r := strings.NewReplacer("\\n", "\n", "\\r", "\r", "\\t", "\t", "\\\"", "\"", "\\\\", "\\")
		return r.Replace(string(inner))
	}
	return string(v)
}

// decodePrimitives: built-in calls whose presence inside a loop body indicates a string-decode loop
// (the custom-cipher fingerprint).
var decodePrimitives = map[string]bool{
	"chr": true, "ord": true, "hexdec": true, "hex2bin": true,
	"base64_decode": true, "gzinflate": true, "gzuncompress": true, "gzdecode": true,
	"strrev": true, "pack": true, "convert_uudecode": true,
}

// hasNibbleAssemblerLoop reports whether the file contains a loop that assembles bytes from 4-bit
// halves — `chr((hi << 4) + lo)` or the `|` form — i.e. a hand-rolled hex decoder.
//
// This is a PACKER signature and it deliberately requires neither a request source nor a dispatch,
// which is what makes it reach a family every taint-gated rule misses: the payload is a punctuation
// alphabet (no token for a byte rule to match), the decode loop sits at top level (so the
// decode-loop-dispatch rule, which only inspects declared function bodies, never runs), and the
// second stage is eval'd from a literal (so nothing is tainted).
//
// The narrowness is the point: PHP ships hex2bin() and pack('H*'), so application code has no reason
// to hand-roll nibble assembly, whereas a packer must, precisely to avoid a recognisable decoder name.
// Each ingredient alone (chr in a loop, a 4-bit shift, an ord-guarded loop) is ordinary; only the
// combination is not.
func hasNibbleAssemblerLoop(root ast.Vertex) bool {
	found := false
	var inLoop func(ast.Vertex)
	// chrOfNibbleShift: a chr() call whose argument subtree contains a "<< 4".
	var chrOfNibbleShift func(ast.Vertex) bool
	chrOfNibbleShift = func(v ast.Vertex) bool {
		if v == nil {
			return false
		}
		if c, ok := v.(*ast.ExprFunctionCall); ok {
			if nm, ok := nameOfCall(c.Function); ok && strings.EqualFold(nm, "chr") {
				for _, a := range c.Args {
					if ae, ok := a.(*ast.Argument); ok && containsShiftByFour(ae.Expr) {
						return true
					}
				}
			}
		}
		hit := false
		forEachChild(v, func(ch ast.Vertex) {
			if !hit && chrOfNibbleShift(ch) {
				hit = true
			}
		})
		return hit
	}
	inLoop = func(v ast.Vertex) {
		if v == nil || found {
			return
		}
		switch v.(type) {
		case *ast.StmtFor, *ast.StmtWhile, *ast.StmtForeach, *ast.StmtDo:
			if chrOfNibbleShift(v) {
				found = true
				return
			}
		}
		forEachChild(v, inLoop)
	}
	inLoop(root)
	return found
}

// containsShiftByFour reports whether v contains a nibble shift: a left-shift by the literal 4 whose
// shifted operand is a value read DIRECTLY — a variable or an array element.
//
// That last condition is what separates a nibble-map decoder from bit-field extraction. FPDF's UTF-8
// conversion shifts a masked field out of a byte, `($c1 & 0x0F) << 4`, and FPDF/TCPDF ship inside
// countless CMS installs — so without this the rule would fire across ordinary sites. A packer looks
// up a half-byte and shifts it into place: `$h[$e[$o]] << 4`.
func containsShiftByFour(v ast.Vertex) bool {
	if v == nil {
		return false
	}
	if sh, ok := v.(*ast.ExprBinaryShiftLeft); ok {
		if n, ok := sh.Right.(*ast.ScalarLnumber); ok && string(n.Value) == "4" && isDirectRead(sh.Left) {
			return true
		}
	}
	hit := false
	forEachChild(v, func(c ast.Vertex) {
		if !hit && containsShiftByFour(c) {
			hit = true
		}
	})
	return hit
}

// isDirectRead reports whether v reads a value directly (a variable or an array element, possibly
// parenthesised) rather than computing one — a mask, arithmetic or a call is not a direct read.
func isDirectRead(v ast.Vertex) bool {
	switch n := v.(type) {
	case *ast.ExprBrackets:
		return isDirectRead(n.Expr)
	case *ast.ExprVariable, *ast.ExprArrayDimFetch:
		return true
	}
	return false
}

// collectDecodeFns returns the set of user-defined functions whose body is a decode loop. A decode
// loop = a loop (for/while/foreach/do) AND a decode primitive call or bitwise-xor/ord-arithmetic.
// The return value of such a function is a runtime-computed string no static analysis can recover;
// when it is later invoked as a function (handleCall case d) that is a packed-webshell signature.
func collectDecodeFns(root ast.Vertex) map[string]bool {
	out := map[string]bool{}
	var visit func(ast.Vertex)
	visit = func(v ast.Vertex) {
		if v == nil {
			return
		}
		if fn, ok := v.(*ast.StmtFunction); ok {
			if name, ok := funcDeclName(fn.Name); ok && hasDecodeSignature(fn.Stmts) {
				out[name] = true
			}
		}
		forEachChild(v, visit)
	}
	visit(root)
	return out
}


func funcDeclName(name ast.Vertex) (string, bool) {
	if id, ok := name.(*ast.Identifier); ok {
		return strings.TrimPrefix(string(id.Value), "$"), true
	}
	return "", false
}

func hasDecodeSignature(stmts []ast.Vertex) bool {
	hasLoop, hasDecode := false, false
	var check func(ast.Vertex)
	check = func(v ast.Vertex) {
		if v == nil || (hasLoop && hasDecode) {
			return
		}
		switch v.(type) {
		case *ast.StmtFor, *ast.StmtWhile, *ast.StmtForeach, *ast.StmtDo:
			hasLoop = true
		case *ast.ExprBinaryBitwiseXor, *ast.ExprBinaryMinus:
			hasDecode = true // XOR-keyed or ord-subtraction decode arithmetic
		case *ast.ExprFunctionCall:
			if nm, ok := nameOfCall(v.(*ast.ExprFunctionCall).Function); ok && decodePrimitives[nm] {
				hasDecode = true
			}
		}
		forEachChild(v, check)
	}
	for _, s := range stmts {
		check(s)
	}
	return hasLoop && hasDecode
}

// calledLiteralName returns the function name if v is a call to a literal-named function (Name, not
// a variable/array-key). Used to detect $x = decodeFn(...).
func calledLiteralName(v ast.Vertex) (string, bool) {
	if c, ok := v.(*ast.ExprFunctionCall); ok {
		return nameOfCall(c.Function)
	}
	return "", false
}

// involvesDecoded reports whether v references a decoded var (one holding a decode-loop function's
// return) or contains a call to a decode-loop function. Used to flag eval/include/invocation/arg
// flow of a custom-cipher's decoded output.
func (a *analyzer) involvesDecoded(v ast.Vertex) bool {
	if v == nil {
		return false
	}
	if ev, ok := v.(*ast.ExprVariable); ok {
		if nm, ok := varNameOf(ev); ok {
			return a.decoded[nm]
		}
		return false
	}
	if c, ok := v.(*ast.ExprFunctionCall); ok {
		if nm, ok := nameOfCall(c.Function); ok && a.decodeFns[nm] {
			return true
		}
	}
	hit := false
	forEachChild(v, func(ch ast.Vertex) {
		if !hit && a.involvesDecoded(ch) {
			hit = true
		}
	})
	return hit
}

// decodeDispatch builds the standard custom-cipher finding.
func decodeDispatch(detail string) Finding {
	return Finding{
		Score: 80, Family: "DynamicDispatch", Rule: "phptaint:decode-loop-dispatch",
		Evidence: "AST: custom-cipher " + detail,
	}
}

func isHOF(name string) bool {
	if _, ok := hofCallbacks[name]; ok {
		return true
	}
	return lastArgCallbackHOFs[name]
}

// callbackIdx returns the 0-based index of a HOF's callable argument. Fixed-index HOFs come from
// hofCallbacks; the array_u*/uassoc family takes its comparator as the LAST positional argument
// (the data-array count is variadic, so the index is not fixed).
func callbackIdx(name string, nargs int) (int, bool) {
	if i, ok := hofCallbacks[name]; ok {
		return i, true
	}
	if lastArgCallbackHOFs[name] && nargs >= 2 {
		return nargs - 1, true
	}
	return 0, false
}
