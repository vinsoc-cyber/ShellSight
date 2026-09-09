package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"shellsight/internal/asptaint"
	"shellsight/internal/deobfuscate"
	"shellsight/internal/finding"
	"shellsight/internal/javadisk"
	"shellsight/internal/perlpytaint"
	"shellsight/internal/phptaint"
	"shellsight/internal/ssitaint"
	"shellsight/internal/weblang"
)

const maxDecodedSourceBytes = 32 << 20

type javaDiagnosticSummary struct {
	Code  string
	Count int
}

// webshellLikeExt limits deobfuscation to plausible web-source files (cheap pre-filter). The
// decoders are byte-level/language-agnostic, so we run on every language the rule gate scopes rules
// to — PHP/JSP/ASPX/ASP/Perl/Python/CGI/SSI. PHP gains the most (encoder-nest source decodes to PHP
// text our rules match; JSP/.NET more often encode bytecode).
func webshellLikeExt(p string) bool {
	return weblang.IsWebSource(weblang.Classify(p))
}

// webshellLikeContent extends webshellLikeExt to a file whose NAME claims nothing but whose content
// is plausibly a web source language. The decoders are byte-level and language-agnostic, so the only
// question is whether the file is worth decoding at all.
func webshellLikeContent(p string, signs *signCache) bool {
	if webshellLikeExt(p) {
		return true
	}
	if signs == nil || inferFileContext(p) != ctxUnknown {
		return false
	}
	for _, l := range []weblang.Lang{
		weblang.PHP, weblang.JSP, weblang.ASP, weblang.ASPX,
		weblang.Perl, weblang.Python, weblang.CGI, weblang.Shtml,
	} {
		if signs.admits(p, l) {
			return true
		}
	}
	return false
}

// buildDecodedMirror statically unwraps each web-source file in paths and writes each decoded layer
// as a file under mirrorDir. Returns cleaned-mirror-path -> origin-path and the number of layer
// files written. The caller scans the mirror with the same rules and rewrites hits to origin.
//
// Takes an already-vetted path list rather than walking the roots itself: enumerateScannable has
// applied the file-kind allowlist, so no entry here can be a FIFO whose os.Open never returns.
func buildDecodedMirror(paths []string, mirrorDir string, signs *signCache) (map[string]string, int, error) {
	originOf := map[string]string{}
	n := 0
	for _, p := range paths {
		err := func() error {
			// FR-003: the SAME admission rule as every other gate. A name that claims nothing is
			// decided by content, or the literal-anchored rules never see the decoded payload of a
			// renamed obfuscated shell -- measured 2026-08-26 on the 14 real samples in
			// curated/disk/php/obfuscated staged as `.php` and `.txt`: nine rule firings lost on the
			// renamed copy, two samples dropped 75 -> 70, including two UNSCOPED third-party rules
			// that fire on any name and were lost only for want of a layer to fire on.
			if !webshellLikeContent(p, signs) {
				return nil
			}
			data, rerr := readBoundedFile(p, maxScanFileBytes)
			if rerr != nil || len(data) == 0 {
				return nil
			}
			res := deobfuscate.Run(data)
			for i, layer := range res.Layers {
				sum := sha256.Sum256([]byte(p))
				sub := filepath.Join(mirrorDir, hex.EncodeToString(sum[:6]))
				if err := os.MkdirAll(sub, 0o755); err != nil {
					return err
				}
				// Keep the ORIGIN's extension: the mirror is scanned as its own tree, and the language
				// rule-gate runs on the path yr reports (this one) BEFORE the finding is rewritten back
				// to the origin. A hardcoded .php here makes every jsp/asp/aspx-gated rule ineligible on
				// the decoded body of a JSP or ASPX shell.
				mp := filepath.Join(sub, fmt.Sprintf("layer_%d_%s%s", i, layer.Method, mirrorExtFor(p, signs)))
				if err := os.WriteFile(mp, layer.Data, 0o644); err != nil {
					return err
				}
				originOf[filepath.Clean(mp)] = p
				n++
			}
			// phptaint resolved layers (PHP only): rewrite resolved $X(<sink>) call sites to the
			// literal sink name so existing literal-anchored rules fire. Same mirror path/mechanism
			// as the deobfuscate layers above.
			// PHP-family only, from the shared table. `.inc` and `.phar` are PHP there but were
			// absent from this hand-kept list, so resolved layers were never mirrored for them.
			//
			// FR-003 again: `passAdmits`, not `phpExt`. This is the same gate as the taint passes and
			// must answer the same way -- a name that claims nothing is decided by content. Measured
			// 2026-08-26, this was the last of nine rule firings still lost on a renamed obfuscated
			// sample after the mirror gate above was widened: `php_eval_concat_request_webshell` on
			// curated/disk/php/obfuscated/o_a4e2cc8adc33e216 fired on the `.php` copy and not on the
			// byte-identical `.txt` copy, because resolved layers were never written for it.
			if passAdmits(p, ctxPHP, weblang.PHP, signs) {
				for i, layer := range phptaint.ResolvedLayers(data) {
					sum := sha256.Sum256([]byte(p))
					sub := filepath.Join(mirrorDir, hex.EncodeToString(sum[:6])+"-r")
					if err := os.MkdirAll(sub, 0o755); err != nil {
						return err
					}
					// Sanitize ":" out of the method (invalid in Windows filenames).
					method := strings.ReplaceAll(layer.Method, ":", "_")
					mp := filepath.Join(sub, fmt.Sprintf("res_%d_%s.php", i, method))
					if err := os.WriteFile(mp, layer.Data, 0o644); err != nil {
						return err
					}
					originOf[filepath.Clean(mp)] = p
					n++
				}
			}
			return nil
		}()
		if err != nil {
			return originOf, n, err
		}
	}
	return originOf, n, nil
}

func readBoundedFile(path string, limit int64) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	reader := &io.LimitedReader{R: file, N: limit + 1}
	data, err := io.ReadAll(reader)
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("file exceeds %d-byte limit", limit)
	}
	return data, nil
}

// diskScanResult is one full disk pass: the findings, the REAL roots' coverage counters, and the
// Java analysis pass with its diagnostics still unsummarized (the per-artifact coverage channel
// needs the individual Diagnostic values, which summarizing throws away).
type diskScanResult struct {
	Findings    []finding.Finding
	ScannedOK   int
	FailedRoots []string
	Java        javaArtifactScan
	Skips       scanSkips
}

// scanWithDeobf scans the real roots normally, then scans a temp mirror of statically-decoded
// layers; decoded-layer hits are rewritten to point at the origin file (with the decoder noted in
// evidence). Findings are deduped per (origin path, rule), keeping the highest score. The mirror is
// removed before returning. Coverage (scannedOK, failedRoots) is that of the REAL roots' raw scan —
// the mirror is derived data, not a target — so the caller's coverage-honesty logic is preserved.
// On any deobfuscation failure it degrades to the raw scan + its coverage.
func scanWithDeobf(ctx context.Context, yr, rules string, compiled bool, roots []string, host string, javaOpts javadisk.Options) ([]finding.Finding, int, []string, []javaDiagnosticSummary) {
	result := scanWithDeobfDetailed(ctx, yr, rules, compiled, roots, host, javaOpts, false)
	return result.Findings, result.ScannedOK, result.FailedRoots, summarizeJavaDiagnostics(result.Java.Diagnostics)
}

// scanWithDeobfDetailed is scanWithDeobf retaining the raw Java diagnostics, and — only when
// collectArtifacts is set — the enumerated Java artifacts. Detection is identical either way:
// collectArtifacts adds observation, never a rule, score, source, sink or transform.
func scanWithDeobfDetailed(ctx context.Context, yr, rules string, compiled bool, roots []string, host string, javaOpts javadisk.Options, collectArtifacts bool) diskScanResult {
	// One walk per root, before anything reads. Everything downstream consumes this list, so the
	// file-kind allowlist is applied in exactly one place and a skip is counted once rather than
	// once per pass. Previously each of the four passes walked the tree itself and the engine
	// walked it a fifth time, with no pass agreeing on what it was willing to open.
	enumerated, skips := enumerateScannable(roots)
	paths := allPaths(enumerated)

	// ONE cache for every gate in this scan. Each pass would otherwise re-read the same
	// unknown-extension file to ask its own question; the cache reads it once and remembers which
	// languages its content is plausibly written in.
	signs := newSignCache()

	// Coverage honesty (FR-007, Constitution IV): a file whose NAME claims no language and whose
	// CONTENT matches no language sign was examined by no language-specific detector. It was still
	// scanned by the unscoped rule layer, so "no finding" is a weaker statement for it than for the
	// rest of the tree, and the report must say so rather than presenting it as examined and clean.
	for _, p := range paths {
		if inferFileContext(p) != ctxUnknown {
			continue
		}
		if !webshellLikeContent(p, signs) {
			skips.markNoLangDetector(p)
		}
	}

	raw, scannedOK, failedRoots := scanWebroots(ctx, yr, rules, compiled, enumerated, host)

	// AST superglobal-taint pass (PHP only), independent of the deobf mirror: catches variable-
	// function dispatch / split superglobals / constructed-callback sinks the byte-level YARA rules
	// cannot express. Computed once and merged into every return path (the n==0 mirror short-circuit
	// below must not skip it).
	phpFinds := phptaintFindings(paths, host, signs)
	// Same pass for Perl/Python, as a CONFIRMED-band escalator rather than a replacement: the
	// YARA rules there fire on (any sink AND any source) anywhere in the file, which is 14 of the
	// 20 benign false positives, while a proven request->sink flow is what earns >=85.
	plFinds := perlpytaintFindings(paths, host, signs)
	phpFinds = append(phpFinds, plFinds...)
	// Same pass again for Classic ASP, and for the same reason: measured in the phase 5 language
	// session, `<%Execute(Request("c"))%>` scores 75 and `<%a=request("x")%><%execute(a)%>` scores
	// 0, because the rules need the accessor INSIDE the call. One assignment defeats them, and 33
	// of that language's 349 malicious samples take the indirect form.
	phpFinds = append(phpFinds, asptaintFindings(paths, host, signs)...)
	// And again for Server Side Includes, where the motivation is inverted: recall is already 1.0
	// on both real samples, but `#exec` presence scores 80 whether the command comes from the
	// query string or is the literal `openssl dgst -md5`. This pass is what makes >=85 mean "the
	// request reaches the shell" for this language rather than "the page uses a documented Apache
	// feature". Prior art: langkit/shtml/ssi-taint-lit-review.md.
	phpFinds = append(phpFinds, ssitaintFindings(paths, host, signs)...)
	java := javadiskScan(ctx, roots, host, javaOpts, collectArtifacts, signs)
	result := diskScanResult{ScannedOK: scannedOK, FailedRoots: failedRoots, Java: java, Skips: skips}

	mirror, err := tempDir("ss-deobf-")
	if err != nil {
		result.Findings = append(dedupByOriginRule(append(raw, phpFinds...)), java.Findings...)
		return result
	}
	defer os.RemoveAll(mirror)

	originOf, n, err := buildDecodedMirror(paths, mirror, signs)
	if err != nil || n == 0 {
		result.Findings = append(dedupByOriginRule(append(raw, phpFinds...)), java.Findings...)
		return result
	}
	// The mirror holds only files this process wrote, so its enumeration cannot turn up a device
	// or a FIFO -- but it goes through the same gate rather than a second, trusted path, so there
	// is exactly one way for a file to reach the engine.
	mirrorPaths, _ := enumerateScannable([]string{mirror})
	decoded, _, _ := scanWebroots(ctx, yr, rules, compiled, mirrorPaths, host)
	for i := range decoded {
		f := &decoded[i]
		if f.Target.File == nil {
			continue
		}
		if origin, ok := originOf[filepath.Clean(f.Target.File.Path)]; ok {
			f.Detection.Evidence += " (matched in a DECODED layer of the file)"
			f.Target.File.Path = origin
			f.Artifact.Location = origin
			f.Artifact.Identity = filepath.Base(origin)
		}
	}
	// yr's emission order is nondeterministic, and the dedup below breaks score ties by keeping the
	// first it sees -- so the decoded slice has to be ordered or the surviving LAYER varies per run.
	sortDecodedForDedup(decoded)
	all := append(raw, decoded...)
	all = append(all, phpFinds...)
	all = dedupByOriginRule(all)
	result.Findings = append(all, java.Findings...)
	return result
}

// mirrorExtFor returns the extension to give a decoded-layer mirror file so that inferFileContext
// resolves it to the SAME language context as its origin. Unknown/extension-less origins fall back to
// .php, which is what the mirror used unconditionally before and keeps the permissive default.
func mirrorExtFor(origin string, signs *signCache) string {
	if ctx := inferFileContext(origin); ctx != ctxUnknown {
		// THE RESOLVED LANGUAGE, NOT THE TRAILING SUFFIX. `shell.jsp.bak` resolves to JSP under
		// FR-005, and returning its literal `.bak` here named no language at all -- so the mirror
		// layer of a compound-named shell was scoped to nothing and every language-declaring rule
		// was refused on it. Whenever the trailing suffix IS the resolved language this returns
		// exactly what `filepath.Ext` used to.
		if e := canonicalExtForContext(ctx); e != "" {
			return e
		}
		return strings.ToLower(filepath.Ext(origin))
	}
	// The name claims nothing, so there is no origin extension to carry. The pre-008 fallback was a
	// hardcoded `.php`, which was harmless only because unknown-named files never reached the mirror
	// at all. Now that they do, it is load-bearing: it would leave every jsp/asp/aspx-scoped rule
	// ineligible on the decoded body of a renamed JSP or ASP.NET shell, so the widening would buy
	// back PHP and nothing else.
	//
	// The sign already read this file and knows which languages its content is plausibly written in.
	// Preference order is the same one signsFor uses; `.php` remains the tail default, so a file the
	// sign cannot place behaves exactly as before.
	for _, l := range []weblang.Lang{
		weblang.PHP, weblang.JSP, weblang.ASP, weblang.ASPX,
		weblang.Perl, weblang.Python, weblang.CGI, weblang.Shtml,
	} {
		if signs != nil && signs.admits(origin, l) {
			if exts := weblang.ExtensionsFor(l); len(exts) > 0 {
				return canonicalMirrorExt(l, exts)
			}
		}
	}
	return ".php"
}

// canonicalExtForContext is the extension that makes `inferFileContext` answer `ctx` again.
//
// It exists because a file's NAME and its resolved CONTEXT can differ once compound suffixes are
// walked, and anything that re-derives the language from a synthesised name -- the deobfuscation
// mirror, the Java analyser's synthetic path -- must synthesise the context, not the spelling.
func canonicalExtForContext(ctx fileContext) string {
	switch ctx {
	case ctxPHP:
		return ".php"
	case ctxJSP:
		return ".jsp"
	case ctxASP:
		return ".asp"
	case ctxASPX:
		return ".aspx"
	case ctxPerl:
		return ".pl"
	case ctxPython:
		return ".py"
	case ctxCGI:
		return ".cgi"
	case ctxShtml:
		return ".shtml"
	}
	return ""
}

// canonicalMirrorExt picks the extension a mirror layer should wear for lang. ExtensionsFor returns
// the set sorted, and the alphabetically-first entry is not always the canonical one (.asa before
// .asp, .jhtml before .jsp), so the canonical name is stated rather than derived.
func canonicalMirrorExt(lang weblang.Lang, sorted []string) string {
	canonical := map[weblang.Lang]string{
		weblang.PHP: ".php", weblang.JSP: ".jsp", weblang.ASP: ".asp", weblang.ASPX: ".aspx",
		weblang.Perl: ".pl", weblang.Python: ".py", weblang.CGI: ".cgi", weblang.Shtml: ".shtml",
	}
	if e, ok := canonical[lang]; ok {
		return e
	}
	return sorted[0]
}

// phpExt reports whether p is a PHP-family file (the AST taint pass is PHP-only).
//
// The list is internal/weblang's, not a second copy. This function held its own until 2026-08-26,
// which is why a WSO shell renamed `.txt` produced zero taint findings: the rule metadata was never
// what stopped the taint engine, a different extension list was.
func phpExt(p string) bool {
	return inferFileContext(p) == ctxPHP
}

// javaDiskExt reports whether p is JVM-relevant: JSP source OR a compiled/archived artifact. The two
// are separate languages in the shared table on purpose -- folding .jar into JSP would fire JSP and
// ASP.NET SOURCE rules on archives -- and this scanner is the one consumer that wants both.
func javaDiskExt(p string) bool {
	switch inferFileContext(p) {
	case ctxJSP, ctxJVM:
		return true
	}
	return false
}

// javaArtifact is one physically enumerated Java artifact: a loose class/source file or an archive.
// It is the unit the optional per-artifact coverage channel describes.
type javaArtifact struct {
	Path   string
	SHA    string
	Bytes  int64
	ReadOK bool // false when the artifact could not be sized or hashed
}

// javaArtifactScan is the Java analysis pass with its diagnostics retained UNSUMMARIZED (so each
// one can be attributed to a physical artifact) plus, when requested, the enumerated artifacts.
type javaArtifactScan struct {
	Findings    []finding.Finding
	Diagnostics []javadisk.Diagnostic
	Artifacts   []javaArtifact
}

func javadiskFindings(ctx context.Context, roots []string, host string, baseOpts javadisk.Options) ([]finding.Finding, []javaDiagnosticSummary) {
	scan := javadiskScan(ctx, roots, host, baseOpts, false, newSignCache())
	return scan.Findings, summarizeJavaDiagnostics(scan.Diagnostics)
}

// javadiskScan runs the Java disk analysis over roots. Java artifacts are enumerated exactly once;
// when collectArtifacts is set each is also sized and hashed at enumeration time, seeding the same
// digest cache the finding path uses so a coverage digest can never disagree with a finding digest.
// collectArtifacts adds observation only — the findings and diagnostics are identical either way.
func javadiskScan(ctx context.Context, roots []string, host string, baseOpts javadisk.Options, collectArtifacts bool, signs *signCache) javaArtifactScan {
	var out []finding.Finding
	var diagnostics []javadisk.Diagnostic
	var artifacts []javaArtifact
	hashes := make(map[string]string)
	for _, root := range roots {
		var loosePaths, archivePaths, signedPaths []string
		walkErr := filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
			if ctx.Err() != nil {
				return filepath.SkipAll
			}
			if err != nil {
				diagnostics = append(diagnostics, integrationJavaDiagnostic(p, javadisk.DiagCodeArtifactRead, "walk Java artifact"))
				return nil
			}
			if d.IsDir() {
				return nil
			}
			// A compound-named JSP is JSP to us and NOT to `internal/javadisk`, which keys on the
			// literal path suffix (`isJSPPath`). `shell.jsp.bak` therefore reached the analyser and
			// was analysed as plain Java -- no scriptlet stripping, no JSP analyzer state, two
			// finding rules gated off. Measured 2026-08-28 over all 246 real java/malicious samples
			// (T042): the compound scheme dropped the confirmed band from 85/246 to 3/246, making a
			// compound name WORSE than no name at all, which inverts FR-005.
			//
			// Routed through the same synthetic-name path the unknown case already uses.
			if inferFileContext(p) == ctxJSP && !javadiskSeesJSP(p) {
				signedPaths = append(signedPaths, p)
				return nil
			}
			if !javaDiskExt(p) {
				// FR-003: the bytecode pass is one of the seven gates and answers the same question
				// as the others -- a name that claims nothing is decided by content. Measured
				// 2026-08-26 over all 246 real samples in curated/disk/java/malicious staged as
				// `.txt`: 114 javadisk findings present under the native name were absent on the
				// byte-identical renamed copy, 82 of them `request-exec`.
				if inferFileContext(p) == ctxUnknown && signs != nil && signs.admits(p, weblang.JSP) {
					signedPaths = append(signedPaths, p)
				}
				return nil
			}
			switch strings.ToLower(filepath.Ext(p)) {
			case ".jar", ".war":
				archivePaths = append(archivePaths, p)
			default:
				loosePaths = append(loosePaths, p)
			}
			if collectArtifacts {
				artifacts = append(artifacts, enumerateJavaArtifact(p, d, hashes))
			}
			return nil
		})
		if walkErr != nil {
			diagnostics = append(diagnostics, integrationJavaDiagnostic(root, javadisk.DiagCodeArtifactRead, "walk Java root"))
		}
		if ctx.Err() != nil {
			diagnostics = append(diagnostics, integrationJavaDiagnostic(root, javadisk.DiagCodeCancelled, "analysis cancelled"))
			break
		}

		opts := baseOpts
		opts.Webroots = []string{root}
		if len(loosePaths) > 0 {
			findings, resultDiagnostics := javaResultFindings(javadisk.AnalyzePaths(ctx, loosePaths, opts), host, hashes)
			out = append(out, findings...)
			diagnostics = append(diagnostics, resultDiagnostics...)
		}
		for _, p := range signedPaths {
			findings, resultDiagnostics := javaResultFindings(analyzeAsJSPSource(ctx, p, opts), host, hashes)
			out = append(out, findings...)
			diagnostics = append(diagnostics, resultDiagnostics...)
		}
		sort.Strings(archivePaths)
		for _, archivePath := range archivePaths {
			findings, resultDiagnostics := javaResultFindings(javadisk.AnalyzePath(ctx, archivePath, opts), host, hashes)
			out = append(out, findings...)
			diagnostics = append(diagnostics, resultDiagnostics...)
			if ctx.Err() != nil {
				break
			}
		}
	}
	return javaArtifactScan{Findings: out, Diagnostics: diagnostics, Artifacts: artifacts}
}

// javadiskSeesJSP reports whether `internal/javadisk` will recognise this path as JSP SOURCE.
//
// It duplicates that package's `isJSPPath` on purpose rather than exporting it: the point is that
// the two can disagree, and the caller is the side that has to notice. A name whose resolved context
// is JSP but whose literal suffix is not is exactly the disagreement.
func javadiskSeesJSP(p string) bool {
	ext := strings.ToLower(filepath.Ext(p))
	for _, e := range weblang.ExtensionsFor(weblang.JSP) {
		if ext == e {
			return true
		}
	}
	return false
}

// analyzeAsJSPSource runs the Java analysis over a file whose NAME claims no language but whose
// CONTENT the JSP sign admits.
//
// WHY A SYNTHETIC NAME. `internal/javadisk` decides Java-versus-JSP from the path suffix in six
// places -- `isJSPPath` gates comment stripping, scriptlet-delimiter removal, the analyzer's JSP
// state and two finding rules. Rewiring all six to take an explicit kind would change the reasoning
// of this project's most mature detector to serve one caller. Instead the caller states what it has
// established by presenting a `.jsp` name, and `AnalyzeArtifactContext` is given the REAL bytes --
// nothing is read from the synthetic path, which never touches the filesystem.
//
// This is the same idiom the deobfuscation mirror already uses and tests: analyse under a
// language-bearing name, then rewrite the artifact path back to the origin so every downstream
// consumer -- hashing, dedup, the report -- sees the real file. `javaResultFindings` hashes
// `ArtifactPath`, so the rewrite must happen before it is called, and it does.
func analyzeAsJSPSource(ctx context.Context, path string, opts javadisk.Options) javadisk.Result {
	data, err := readBoundedFile(path, maxScanFileBytes)
	if err != nil || len(data) == 0 {
		// Past the read bound or unreadable. Disclosed through the existing skip accounting, not
		// invented as a finding.
		return javadisk.Result{}
	}
	synthetic := path + ".jsp"
	res := javadisk.AnalyzeArtifactContext(ctx, synthetic, data, opts)
	for i := range res.Findings {
		if res.Findings[i].ArtifactPath == synthetic || res.Findings[i].ArtifactPath == "" {
			res.Findings[i].ArtifactPath = path
		}
	}
	for i := range res.Diagnostics {
		if res.Diagnostics[i].Artifact == synthetic {
			res.Diagnostics[i].Artifact = path
		}
	}
	return res
}

// enumerateJavaArtifact records one artifact's physical identity — on-disk size and digest — and
// seeds the shared digest cache so the analysis pass never hashes the same file twice. A FAILED hash
// is never cached: a transient read error at enumeration must not make the finding path skip a
// finding it would otherwise have kept (see javaResultFindings).
func enumerateJavaArtifact(path string, entry os.DirEntry, hashes map[string]string) javaArtifact {
	artifact := javaArtifact{Path: path}
	info, infoErr := entry.Info()
	if infoErr == nil {
		artifact.Bytes = info.Size()
	}
	artifact.SHA = cachedSHA256File(path, hashes)
	artifact.ReadOK = infoErr == nil && artifact.SHA != ""
	return artifact
}

// cachedSHA256File hashes path at most once per scan. Only a successful digest is memoized, so a
// transient failure is retried rather than remembered as "this artifact has no digest".
func cachedSHA256File(path string, hashes map[string]string) string {
	key := filepath.Clean(path)
	if sha, cached := hashes[key]; cached {
		return sha
	}
	sha := sha256File(path)
	if sha != "" {
		hashes[key] = sha
	}
	return sha
}

// javaDiagnosticSeverity maps each diagnostic code in javadisk's canonical vocabulary to the artifact
// status it implies. It is BUILT from javadisk.StableDiagnosticCodes() rather than re-declared, so a
// code added to the analyzer cannot silently drift out of this table (a test pins the two together).
// The map is only a severity lookup, never a gate: a code outside it still degrades the artifact
// (impliedArtifactStatus) — it just cannot be named in the emitted channel.
var javaDiagnosticSeverity = buildJavaDiagnosticSeverity()

func buildJavaDiagnosticSeverity() map[string]string {
	codes := javadisk.StableDiagnosticCodes()
	severity := make(map[string]string, len(codes))
	for _, code := range codes {
		// Only a read/hash failure means the artifact was never analyzed at all; every other
		// diagnostic means it was analyzed under a parser/unsupported/budget limitation.
		if code == javadisk.DiagCodeArtifactRead {
			severity[code] = finding.ArtifactCovFailed
			continue
		}
		severity[code] = finding.ArtifactCovDegraded
	}
	return severity
}

// impliedArtifactStatus fails CLOSED: a diagnostic code this build does not recognize — a code a
// newer javadisk emits, say — still degrades the artifact it applied to. "Unknown" must never be
// read as "covered". The code text itself is only emitted when it is in the stable vocabulary, so an
// unrecognized (potentially attacker-influenced) string never rides the channel.
func impliedArtifactStatus(code string) (status string, emitCode bool) {
	if known, ok := javaDiagnosticSeverity[code]; ok {
		return known, true
	}
	return finding.ArtifactCovDegraded, false
}

// physicalArtifactPath maps a javadisk diagnostic's artifact reference to the file on disk. Archive
// members are reported logically as "<archive>!/<member>" (nested ones repeat the separator), so
// everything before the FIRST "!/" is the physical outer archive.
func physicalArtifactPath(artifact string) string {
	if i := strings.Index(artifact, "!/"); i >= 0 {
		return artifact[:i]
	}
	return artifact
}

func artifactStatusRank(status string) int {
	switch status {
	case finding.ArtifactCovFailed:
		return 2
	case finding.ArtifactCovDegraded:
		return 1
	default:
		return 0
	}
}

// javaArtifactAccumulator folds every diagnostic that reached one enumerated artifact into a single
// coverage entry.
type javaArtifactAccumulator struct {
	artifact javaArtifact
	status   string
	codes    map[string]struct{}
}

// javaDiagnosticScope resolves which enumerated artifacts one aggregated diagnostic can describe, and
// which single artifact (if any) it provably names.
//
// javadisk aggregates diagnostics BY CODE per analysis Result: the Diagnostic that survives carries
// ONE example artifact (the lexicographically smallest) plus the TOTAL occurrence count, and
// group-phase diagnostics are named after the logical analysis root — a WEB-INF/classes directory, a
// bare binary class name, or "" — none of which is a physical artifact. A diagnostic therefore pins
// to exactly one artifact only when it names an enumerated artifact AND either represents a single
// occurrence or belongs to an archive (whose Result covers nothing else). Otherwise the unlocated
// occurrences sit somewhere in the enclosing scope, so coverage honesty requires degrading all of
// that scope rather than dropping the diagnostic and calling the siblings complete.
func javaDiagnosticScope(index map[string]*javaArtifactAccumulator, order []string, diagnostic javadisk.Diagnostic) (scope []string, named string) {
	physical := physicalArtifactPath(diagnostic.Artifact)
	if strings.TrimSpace(physical) == "" {
		return order, "" // an unnamed root: the whole enumerated set is in scope
	}
	key := filepath.Clean(physical)
	count := max(1, diagnostic.Count)
	if index[key] != nil && (count == 1 || physical != diagnostic.Artifact || javaArchiveArtifact(key)) {
		// Exactly attributable: a single occurrence, a "<archive>!/<member>" diagnostic, or any
		// diagnostic naming an archive — each archive is analyzed as its own javadisk Result, so
		// however many occurrences were aggregated they all happened inside that one artifact.
		return []string{key}, key
	}
	if index[key] == nil && count == 1 {
		// A single occurrence named after a logical root. If that root is a directory containing
		// enumerated artifacts (the canonical WEB-INF/classes group), the occurrence happened inside
		// that group and nowhere else.
		if members := javaArtifactsUnder(order, key); len(members) > 0 {
			return members, ""
		}
	}
	return order, key
}

// javaArchiveArtifact reports whether an enumerated artifact is an archive. javadiskScan analyses each
// archive with its own javadisk.AnalyzePath call — hence its own aggregation scope — while all loose
// classes and sources of a root share one AnalyzePaths call.
func javaArchiveArtifact(path string) bool {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".jar", ".war":
		return true
	}
	return false
}

// javaArtifactsUnder returns the enumerated artifacts inside directory dir (both already cleaned).
func javaArtifactsUnder(order []string, dir string) []string {
	prefix := dir + string(filepath.Separator)
	members := make([]string, 0, len(order))
	for _, key := range order {
		if strings.HasPrefix(key, prefix) {
			members = append(members, key)
		}
	}
	return members
}

// softenedArtifactStatus is the status a diagnostic implies for an artifact it did NOT name. Analysis
// of the scope was provably incomplete, so degraded is earned — but "failed" claims the artifact
// itself could not be read, which is only known for the artifact the diagnostic actually named.
func softenedArtifactStatus(status string) string {
	if status == finding.ArtifactCovFailed {
		return finding.ArtifactCovDegraded
	}
	return status
}

// javaArtifactCoverage builds the optional per-artifact coverage channel: one entry per enumerated
// Java artifact, with the diagnostics whose scope reached it folded in. An artifact we could not read
// or hash is failed; one a parser/unsupported/budget diagnostic scope covered is degraded.
//
// "complete" therefore guarantees exactly this: no diagnostic — attributable to this artifact or to
// any analysis scope containing it — applied. It does NOT guarantee that only this artifact's own
// bytes were fully analyzed, because javadisk reports one example artifact per code per Result; when
// a diagnostic cannot be pinned down, every artifact in its scope is degraded and carries the code
// (see javaDiagnosticScope). Entries are sorted by path and diagnostic codes are sorted and
// deduplicated, so the channel is byte-stable across runs.
func javaArtifactCoverage(scan javaArtifactScan) []finding.ArtifactCoverage {
	if len(scan.Artifacts) == 0 {
		return nil
	}
	index := make(map[string]*javaArtifactAccumulator, len(scan.Artifacts))
	order := make([]string, 0, len(scan.Artifacts))
	for _, artifact := range scan.Artifacts {
		key := filepath.Clean(artifact.Path)
		if _, seen := index[key]; seen {
			continue // enumerated once: a repeat is the same physical artifact
		}
		status := finding.ArtifactCovComplete
		if !artifact.ReadOK {
			status = finding.ArtifactCovFailed
		}
		index[key] = &javaArtifactAccumulator{artifact: artifact, status: status, codes: map[string]struct{}{}}
		order = append(order, key)
	}
	for _, diagnostic := range scan.Diagnostics {
		implied, stableCode := impliedArtifactStatus(diagnostic.Code)
		scope, named := javaDiagnosticScope(index, order, diagnostic)
		for _, key := range scope {
			entry := index[key]
			if entry == nil {
				continue
			}
			status := implied
			if key != named {
				status = softenedArtifactStatus(implied)
			}
			if stableCode {
				entry.codes[diagnostic.Code] = struct{}{}
			}
			if artifactStatusRank(status) > artifactStatusRank(entry.status) {
				entry.status = status
			}
		}
	}
	coverage := make([]finding.ArtifactCoverage, 0, len(order))
	for _, key := range order {
		entry := index[key]
		var codes []string
		if len(entry.codes) > 0 {
			codes = make([]string, 0, len(entry.codes))
			for code := range entry.codes {
				codes = append(codes, code)
			}
			sort.Strings(codes)
		}
		coverage = append(coverage, finding.ArtifactCoverage{
			Path:            entry.artifact.Path,
			SHA256:          entry.artifact.SHA,
			Status:          entry.status,
			Bytes:           entry.artifact.Bytes,
			DiagnosticCodes: codes,
		})
	}
	sort.Slice(coverage, func(i, j int) bool { return coverage[i].Path < coverage[j].Path })
	return coverage
}

func javaResultFindings(result javadisk.Result, host string, hashes map[string]string) ([]finding.Finding, []javadisk.Diagnostic) {
	out := make([]finding.Finding, 0, len(result.Findings))
	diagnostics := append([]javadisk.Diagnostic(nil), result.Diagnostics...)
	for _, javaFinding := range result.Findings {
		if javaFinding.ArtifactPath == "" {
			diagnostics = append(diagnostics, integrationJavaDiagnostic("", javadisk.DiagCodeClassMalformed, "Java finding lacks physical artifact path"))
			continue
		}
		sha := cachedSHA256File(javaFinding.ArtifactPath, hashes)
		if sha == "" {
			diagnostics = append(diagnostics, integrationJavaDiagnostic(javaFinding.ArtifactPath, javadisk.DiagCodeArtifactRead, "hash Java artifact"))
			continue
		}
		out = append(out, javadiskToFinding(javaFinding.ArtifactPath, sha, javaFinding, host))
	}
	return out, diagnostics
}

func integrationJavaDiagnostic(artifact, code, detail string) javadisk.Diagnostic {
	return javadisk.Diagnostic{Artifact: artifact, Code: code, Detail: detail, Count: 1}
}

func summarizeJavaDiagnostics(diagnostics []javadisk.Diagnostic) []javaDiagnosticSummary {
	type diagnosticKey struct {
		artifact string
		code     string
		detail   string
	}
	deduped := make(map[diagnosticKey]int)
	for _, diagnostic := range diagnostics {
		count := diagnostic.Count
		if count < 1 {
			count = 1
		}
		key := diagnosticKey{artifact: diagnostic.Artifact, code: diagnostic.Code, detail: diagnostic.Detail}
		if count > deduped[key] {
			deduped[key] = count
		}
	}
	byCode := make(map[string]int)
	for key, count := range deduped {
		if byCode[key.code] > math.MaxInt-count {
			byCode[key.code] = math.MaxInt
		} else {
			byCode[key.code] += count
		}
	}
	codes := make([]string, 0, len(byCode))
	for code := range byCode {
		codes = append(codes, code)
	}
	sort.Strings(codes)
	summaries := make([]javaDiagnosticSummary, 0, len(codes))
	for _, code := range codes {
		summaries = append(summaries, javaDiagnosticSummary{Code: code, Count: byCode[code]})
	}
	return summaries
}

func applyJavaDiagnostics(coverage *finding.ProbeCoverage, summaries []javaDiagnosticSummary) {
	if coverage == nil || len(summaries) == 0 {
		return
	}
	ordered := append([]javaDiagnosticSummary(nil), summaries...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].Code < ordered[j].Code })
	var reason strings.Builder
	for _, summary := range ordered {
		pair := summary.Code + "=" + strconv.Itoa(max(1, summary.Count))
		if reason.Len() > 0 {
			pair = "; " + pair
		}
		remaining := 512 - reason.Len()
		if remaining <= 0 {
			break
		}
		if len(pair) > remaining {
			pair = pair[:remaining]
		}
		reason.WriteString(pair)
	}
	if reason.Len() == 0 {
		return
	}
	coverage.Status = finding.CovDegraded
	if coverage.Reason != "" {
		coverage.Reason += "; "
	}
	coverage.Reason += reason.String()
}

func javadiskToFinding(path, sha string, f javadisk.Finding, host string) finding.Finding {
	fam := f.Family
	return finding.Finding{
		SchemaVersion:  finding.SchemaVersion,
		ID:             shortID(sha, f.Rule),
		Host:           host,
		View:           "disk",
		Target:         finding.Target{Kind: "file", File: &finding.File{Path: path, SHA256: sha}},
		Artifact:       finding.Artifact{Kind: "file-webshell", Identity: filepath.Base(path), Location: path},
		Detection:      finding.Detection{Basis: "heuristic", KnowledgeRef: f.Rule, Evidence: f.Evidence},
		Score:          f.Score,
		Tier:           scoreToTier(f.Score),
		Classification: finding.Classification{Family: &fam},
	}
}

// phptaintFindings runs the AST superglobal-taint pass over each PHP file in paths and converts the
// findings. This is the Tier 2 path; it complements the YARA + deobf-engine findings.
//
// The read is bounded (FR-016). It used to be os.ReadFile, which is unbounded in both directions
// that matter: it blocks forever opening a FIFO, and it grows without limit on an endless device.
// The kind allowlist already keeps both out of `paths`; the bound is the second line, for an
// ordinary file that is merely enormous.
// passAdmits decides whether a language-specific pass may examine a file.
//
// FR-003: the policy governs EVERY gate uniformly. Widening the YARA rule layer while leaving these
// passes narrow would report a file as examined by a detector that never read it -- which is the
// dishonesty the coverage counters exist to prevent, arriving through the front door.
//
// A recognised language is decided by the name, exactly as before. A name that claims NOTHING is
// decided by the file's content (the sign gate), which is what makes a renamed webshell reachable by
// the taint passes and not only by the unscoped third-party rules. Measured 2026-08-26: a WSO shell
// renamed `.txt` produced zero taint findings, because these lists -- not the rule metadata -- were
// what stopped them.
func passAdmits(path string, want fileContext, lang weblang.Lang, signs *signCache) bool {
	switch ctx := inferFileContext(path); ctx {
	case want:
		return true
	case ctxUnknown:
		return signs != nil && signs.admits(path, lang)
	default:
		return false
	}
}

func phptaintFindings(paths []string, host string, signs *signCache) []finding.Finding {
	var out []finding.Finding
	for _, p := range paths {
		if !passAdmits(p, ctxPHP, weblang.PHP, signs) {
			continue
		}
		data, rerr := readBoundedFile(p, maxScanFileBytes)
		if rerr != nil || len(data) == 0 {
			continue
		}
		sha := sha256File(p)
		for _, f := range phptaint.Analyze(data) {
			out = append(out, phptaintToFinding(p, sha, f, host))
		}
	}
	return out
}

// perlpytaintFindings runs the Perl/Python source-to-sink taint pass. Unlike the PHP pass this one
// is an ESCALATOR: the YARA rules keep the recall at `likely`, and a demonstrated flow from request
// state to an execution sink is what earns the `confirmed` band -- which on these languages is
// otherwise empty (2 of 24 real samples reach >=85 today).
//
// This is the site that produced the measured 466 MB RSS on a symlink to /dev/zero: os.ReadFile
// with no bound, on a path the walk had not checked the kind of. Both halves are fixed -- the
// allowlist keeps the device out of `paths`, and the read is bounded.
func perlpytaintFindings(paths []string, host string, signs *signCache) []finding.Finding {
	var out []finding.Finding
	for _, p := range paths {
		lang := perlPyLang(p)
		if lang == "" {
			// ASK ctxUnknown FIRST. `perlPyLang` returns "" for two unrelated reasons: the name
			// claims NOTHING, or the name claims a recognised language that simply is not Perl or
			// Python. Consulting the sign on both was wrong twice over.
			//
			// Correctness: it offered a .php, .js or .jsp file to the Perl/Python taint grammar
			// whenever its content matched the CGI sign -- exactly the cross-language matching FR-008
			// refuses and SC-005 asserts does not happen. A Perl CGI shell named `shell.php`
			// produced Perl findings.
			//
			// Cost: `signs.admits` READS THE FILE. Every recognised file in a tree was read and
			// swept -- 3,650 files / 89.8 MB on the WordPress recognised half, about 30 s of a 65 s
			// run, on a tree with no unknown-extension file in it at all. This was the whole of the
			// SC-009 overrun that survived R10.
			//
			// The other two taint passes route through `passAdmits`, which has always asked this
			// question in this order. This one did not, because it was written around
			// `perlPyLang`'s return value instead.
			if inferFileContext(p) != ctxUnknown {
				continue
			}
			// The name claims nothing. Perl and Python share the CGI sign, so a file whose content
			// is plausibly either is offered to the grammar its shebang names, defaulting to perl --
			// the same tie-break the .cgi extension already uses, for the same measured reason.
			if signs == nil || !signs.admits(p, weblang.CGI) {
				continue
			}
			if lang = shebangLang(p); lang == "" {
				lang = "perl"
			}
		}
		data, rerr := readBoundedFile(p, maxScanFileBytes)
		if rerr != nil || len(data) == 0 {
			continue
		}
		sha := sha256File(p)
		for _, f := range perlpytaint.Analyze(data, lang) {
			out = append(out, perlpytaintToFinding(p, sha, f, host))
		}
	}
	return out
}

// asptaintFindings runs the Classic ASP / VBScript source-to-sink taint pass. An ESCALATOR, exactly
// like the Perl/Python one: the rules keep the recall at `likely` and a demonstrated flow from a
// request accessor to a code-execution sink is what earns `confirmed`.
//
// The file gate is `inferFileContext` rather a second extension list, so this pass and the rule layer
// can never disagree about what a Classic ASP file is.
//
// ctxASPX WAS deliberately excluded, on the reasoning that "VBScript statement forms do not describe
// ASP.NET". Measured 2026-08-24 against the ASPX kit's phase-5 gap list, that reasoning was wrong for
// the shape that actually dominates it. Four of the eight gap items are JScript pages whose flow is
// `keng = Request.Item["zhe"]; ... eval(keng,"unsafe")`, and an untyped JScript assignment is
// *character-for-character* the VBScript form this pass already parses -- the engine scored all four
// at 85 with no change to its statement model, and this gate was the only thing between them and a
// confirmed verdict. Their published score was 0, from every one of 5,872 rules.
//
// What the exclusion got right is C#: `string command = ...` is a typed declaration that `assignRe`
// does not match, so C# pages are analysed and found clean rather than mis-analysed. That is the
// conservative direction for an escalator, and it is why widening the gate does not require a C#
// statement model first.
func asptaintFindings(paths []string, host string, signs *signCache) []finding.Finding {
	var out []finding.Finding
	for _, p := range paths {
		if !passAdmits(p, ctxASP, weblang.ASP, signs) && !passAdmits(p, ctxASPX, weblang.ASPX, signs) {
			continue
		}
		data, rerr := readBoundedFile(p, maxScanFileBytes)
		if rerr != nil || len(data) == 0 {
			continue
		}
		sha := sha256File(p)
		for _, f := range asptaint.Analyze(data) {
			out = append(out, asptaintToFinding(p, sha, f, host))
		}
	}
	return out
}

// asptaintToFinding mirrors perlpytaintToFinding. Basis is "taint": the finding asserts a specific
// dataflow, and an operator triaging it should be able to tell that from a pattern that merely
// looked suspicious.
func asptaintToFinding(path, sha string, f asptaint.Finding, host string) finding.Finding {
	fam := f.Family
	return finding.Finding{
		SchemaVersion:  finding.SchemaVersion,
		ID:             shortID(sha, f.Rule),
		Host:           host,
		View:           "disk",
		Target:         finding.Target{Kind: "file", File: &finding.File{Path: path, SHA256: sha}},
		Artifact:       finding.Artifact{Kind: "file-webshell", Identity: filepath.Base(path), Location: path},
		Detection:      finding.Detection{Basis: "taint", KnowledgeRef: f.Rule, Evidence: f.Evidence},
		Score:          f.Score,
		Tier:           scoreToTier(f.Score),
		Classification: finding.Classification{Family: &fam},
	}
}

// ssitaintFindings runs the Server Side Includes source-to-sink taint pass. The same ESCALATOR
// contract as the other three, but it exists for the opposite reason -- not to add recall, which
// is already 1.0 on both real samples, but to make the confirmed band MEAN something for this
// language.
//
// `ssi_exec_webshell` scores the presence of `#exec` 80, and measured 2026-09-07 that cannot rank:
// Digi's embedded-SDK sample page, the netCDF Operators documentation site and the Dublin Core
// Metadata Initiative's 1998 website all score 80, identically to a webshell taking its command
// from the query string. Over the 59 real files available -- 4 malicious, 55 legitimate -- this
// pass separates them completely: 4 of 4 flagged, 0 of 55 flagged. The rule scores all 59 the same.
//
// It also relabelled three files the harvest's repository-name filter had let through as benign:
// two bengkulucyberteam pages carrying the beched SSI-shell pattern verbatim, and one legitimate
// project (JoshData/thunderbird-spf) with a genuine command injection,
// `#exec cmd="dig +short -x $QUERY_STRING_UNESCAPED"` -- the CVE-2025-58098 shape.
func ssitaintFindings(paths []string, host string, signs *signCache) []finding.Finding {
	var out []finding.Finding
	for _, p := range paths {
		if !passAdmits(p, ctxShtml, weblang.Shtml, signs) {
			continue
		}
		data, rerr := readBoundedFile(p, maxScanFileBytes)
		if rerr != nil || len(data) == 0 {
			continue
		}
		sha := sha256File(p)
		for _, f := range ssitaint.Analyze(data) {
			out = append(out, ssitaintToFinding(p, sha, f, host))
		}
	}
	return out
}

// ssitaintToFinding mirrors asptaintToFinding exactly, including Basis "taint": the finding
// asserts a specific dataflow, and that is what distinguishes it from the rule that merely saw the
// directive.
func ssitaintToFinding(path, sha string, f ssitaint.Finding, host string) finding.Finding {
	fam := f.Family
	return finding.Finding{
		SchemaVersion:  finding.SchemaVersion,
		ID:             shortID(sha, f.Rule),
		Host:           host,
		View:           "disk",
		Target:         finding.Target{Kind: "file", File: &finding.File{Path: path, SHA256: sha}},
		Artifact:       finding.Artifact{Kind: "file-webshell", Identity: filepath.Base(path), Location: path},
		Detection:      finding.Detection{Basis: "taint", KnowledgeRef: f.Rule, Evidence: f.Evidence},
		Score:          f.Score,
		Tier:           scoreToTier(f.Score),
		Classification: finding.Classification{Family: &fam},
	}
}

// perlPyLang returns the taint dialect for a path, or "" if the pass does not apply.
// .cgi is Perl here: CGI is an interface rather than a language, but every .cgi sample in the
// corpus is Perl, and the Perl sink set is the superset that matters for it.
// perlPyLang decides which sink inventory a file is analysed with.
//
// THE EXTENSION DECIDES ONLY WHERE IT CAN. `.pl` is Perl and `.py` is Python; `.cgi` and `.fcgi`
// are neither. RFC 3875 section 1.4 makes a CGI script an executable the server invokes and fixes
// no language, so the suffix is a server configuration choice rather than a property of the code --
// and the incumbent's own database says the same thing by having no `cgi` token and letting
// `perl.exts` and `python.exts` both claim the extension.
//
// This used to return "perl" for `.cgi` unconditionally. MEASURED over the five real Python
// samples held, by running both sink tables: THREE OF FIVE lose every sink when the file is named
// `.cgi`. `os.popen(` -- in four of the five, and the commonest Python webshell sink in that
// corpus -- matches no Perl sink at all. The two that survived did so for the wrong reason: Perl's
// `\bsystem\s*\(` matches `os.system(` by accident, because `.` is a non-word character. See
// docs/measurements/2026-08-23-lang-cgi/.
//
// Extensionless files were worse than mis-routed: they returned "" and were never analysed, which
// is the conventional `cgi-bin/` layout. A file never opened does not appear in any recall figure,
// because it is outside the denominator.
//
// The shebang is the only in-file evidence of the interpreter, and it is what the kernel itself
// uses. It is consulted ONLY where the extension is ambiguous or absent, so a shebang can never
// override an unambiguous suffix -- a `.py` file is Python whatever its first line claims.
func perlPyLang(p string) string {
	switch inferFileContext(p) {
	case ctxPerl:
		return "perl"
	case ctxPython:
		return "python"
	case ctxCGI:
		// Ambiguous by construction. Fall back to perl when there is no shebang: that is the
		// previous behaviour for this extension, and it is the right default -- of the four real
		// CGI samples held, all four carry `#!/usr/bin/perl`.
		if lang := shebangLang(p); lang != "" {
			return lang
		}
		return "perl"
	case ctxUnknown:
		// PRESERVED SEMANTICS, deliberately narrower than the case label. This branch used to be
		// `case ""`, matching an EMPTY extension only; `ctxUnknown` is wider -- it also covers a
		// name we do not recognise, such as `.txt`. Admitting those is the point of spec 008, but it
		// belongs to the widening task with its sign gate and its false-positive measurement, not to
		// this refactor. Until then an unrecognised extension is refused exactly as before, so this
		// change is a pure lift of the extension lists into the shared table.
		if filepath.Ext(p) != "" {
			return ""
		}
		// A cgi-bin/ script. No extension, so the shebang is the only evidence of the interpreter --
		// but a shebang alone is NOT evidence that the file is web-served, and that distinction cost
		// three false positives before it was made.
		//
		// MEASURED. The first cut accepted any extensionless file with a perl or python shebang.
		// Over seven cloned benign applications that is 44 files, and one of them --
		// `webmin/bin/language-manager`, a 2,282-line maintainer utility -- produced three
		// CONFIRMED-band findings at score 85. Its "request source" was `chomp(my $a = <STDIN>);`
		// at lines 1743 and 1767: an interactive y/n prompt. `<STDIN>` is a POST body in a CGI
		// script and a console prompt in a command-line tool, and nothing in the file distinguishes
		// them.
		//
		// So the extensionless case additionally requires the file to BE a CGI program, and RFC
		// 3875 section 4.1 says what that means: a CGI program obtains the request through the
		// meta-variables. A program that never reads one is not a CGI program, whatever its
		// shebang. This is the specification's own definition of the interface, not a list of
		// directory names that an attacker chooses.
		lang := shebangLang(p)
		if lang == "" || !readsCGIMetaVariable(p) {
			return ""
		}
		return lang
	}
	return ""
}

// cgiMetaVariable matches the RFC 3875 section 4.1 meta-variable names, as read by either language.
// The list is the specification's, closed and complete; `HTTP_` covers the protocol variables.
// Deliberately NOT a general `%ENV` or `os.environ` match: reading PATH or HOME is ubiquitous in
// benign code and produced 98 stdlib false positives the last time this project matched the broad
// form.
var cgiMetaVariable = regexp.MustCompile(
	`(?:\$ENV\s*\{\s*['"]?|environ\s*[\[(]\s*['"])` +
		`(?:QUERY_STRING|REQUEST_METHOD|CONTENT_LENGTH|CONTENT_TYPE|PATH_INFO|PATH_TRANSLATED` +
		`|REMOTE_ADDR|REMOTE_HOST|REMOTE_IDENT|REMOTE_USER|AUTH_TYPE|SCRIPT_NAME|GATEWAY_INTERFACE` +
		`|HTTP_[A-Z0-9_]+)`)

// readsCGIMetaVariable reports whether the file obtains the request the way RFC 3875 specifies.
// Bounded like every other read on this path: this runs over extensionless files in a scan root.
func readsCGIMetaVariable(p string) bool {
	data, err := readBoundedFile(p, maxScanFileBytes)
	if err != nil {
		return false
	}
	return cgiMetaVariable.Match(data)
}

// shebangLang reads the interpreter from a `#!` line, or "" when there is none.
//
// Bounded to the first line and to 256 bytes: this runs over every extensionless file in a scan
// root, and attacker-controlled input should not choose its cost.
func shebangLang(p string) string {
	fh, err := os.Open(p)
	if err != nil {
		return ""
	}
	defer fh.Close()
	var head [256]byte
	n, _ := fh.Read(head[:])
	line := head[:n]
	if i := bytes.IndexAny(line, "\r\n"); i >= 0 {
		line = line[:i]
	}
	if !bytes.HasPrefix(line, []byte("#!")) {
		return ""
	}
	lower := strings.ToLower(string(line))
	// `python` before `perl`: `#!/usr/bin/env python3` contains neither substring in the other, but
	// checking the more specific interpreter first keeps the order from mattering if that changes.
	if strings.Contains(lower, "python") {
		return "python"
	}
	if strings.Contains(lower, "perl") {
		return "perl"
	}
	return ""
}

// perlpytaintToFinding mirrors phptaintToFinding. Basis is "taint" rather than "heuristic": the
// finding asserts a specific dataflow, and the fusion layer and any operator triaging it should be
// able to tell that apart from a pattern that merely looked suspicious.
func perlpytaintToFinding(path, sha string, f perlpytaint.Finding, host string) finding.Finding {
	fam := f.Family
	return finding.Finding{
		SchemaVersion:  finding.SchemaVersion,
		ID:             shortID(sha, f.Rule),
		Host:           host,
		View:           "disk",
		Target:         finding.Target{Kind: "file", File: &finding.File{Path: path, SHA256: sha}},
		Artifact:       finding.Artifact{Kind: "file-webshell", Identity: filepath.Base(path), Location: path},
		Detection:      finding.Detection{Basis: "taint", KnowledgeRef: f.Rule, Evidence: f.Evidence},
		Score:          f.Score,
		Tier:           scoreToTier(f.Score),
		Classification: finding.Classification{Family: &fam},
	}
}

// phptaintToFinding maps a phptaint.Finding to a disk finding.Finding (mirrors findingFromRule).
// f.Rule is already the full knowledge-ref (e.g. "phptaint:sink-on-request").
func phptaintToFinding(path, sha string, f phptaint.Finding, host string) finding.Finding {
	fam := f.Family
	return finding.Finding{
		SchemaVersion:  finding.SchemaVersion,
		ID:             shortID(sha, f.Rule),
		Host:           host,
		View:           "disk",
		Target:         finding.Target{Kind: "file", File: &finding.File{Path: path, SHA256: sha}},
		Artifact:       finding.Artifact{Kind: "file-webshell", Identity: filepath.Base(path), Location: path},
		Detection:      finding.Detection{Basis: "heuristic", KnowledgeRef: f.Rule, Evidence: f.Evidence},
		Score:          f.Score,
		Tier:           scoreToTier(f.Score),
		Classification: finding.Classification{Family: &fam},
	}
}

// sortDecodedForDedup orders decoded-layer findings deterministically before they are merged with
// the raw ones and deduped.
//
// `yr` emits matches in parallel COMPLETION order, not scan-list order. Measured 2026-09-04: four
// runs over an identical 400-file scan list produced FOUR different orderings and one identical
// result set. dedupByOriginRule keeps the first finding it sees for a (path, rule) and replaces it
// only on a STRICTLY higher score, so when two decoded layers of one file matched the same rule at
// the same score, the survivor was whichever layer yr happened to finish first.
//
// That is not cosmetic. The survivor's Target.File.SHA256 is the hash of the LAYER, and that value
// is the content key the console groups triage by and part of the fingerprint. Two scans of one
// host could produce different content keys for the same artifact, so a decision an analyst
// recorded against one scan would not match the next.
//
// Only the DECODED slice is sorted. Raw findings are appended ahead of it and keep winning ties,
// which is the behaviour worth preserving: a raw finding's evidence points at bytes on disk, a
// decoded layer's at a reconstruction.
func sortDecodedForDedup(fs []finding.Finding) {
	key := func(f finding.Finding) (string, string, string) {
		if f.Target.File == nil {
			return "", f.Detection.KnowledgeRef, ""
		}
		return filepath.Clean(f.Target.File.Path), f.Detection.KnowledgeRef, f.Target.File.SHA256
	}
	sort.SliceStable(fs, func(i, j int) bool {
		pi, ri, si := key(fs[i])
		pj, rj, sj := key(fs[j])
		if pi != pj {
			return pi < pj
		}
		if ri != rj {
			return ri < rj
		}
		return si < sj
	})
}

// dedupByOriginRule keeps one finding per (file path, knowledge_ref), highest score — so a shell
// flagged both raw and via a decoded layer collapses to a single finding.
func dedupByOriginRule(in []finding.Finding) []finding.Finding {
	best := map[string]int{}
	out := []finding.Finding{}
	for _, f := range in {
		path := ""
		if f.Target.File != nil {
			path = filepath.Clean(f.Target.File.Path)
		}
		k := path + "\x00" + f.Detection.KnowledgeRef
		if idx, seen := best[k]; seen {
			if f.Score > out[idx].Score {
				out[idx] = f
			}
			continue
		}
		best[k] = len(out)
		out = append(out, f)
	}
	return out
}
