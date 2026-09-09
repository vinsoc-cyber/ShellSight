package main

import (
	"bytes"
	"regexp"
	"sync"

	"shellsight/internal/weblang"
)

// Language signs: the content test that decides whether a file whose NAME claims nothing is
// plausibly a given language.
//
// A SIGN IS NOT A DETECTOR. It admits a file to a pass; it never contributes to a score, never
// produces a finding, and never appears in `detection.basis`. That boundary is what keeps it outside
// Constitution principle I's detector bar while its METHOD still carries citations.
//
// A SIGN MAY NOT SIMPLY BE PERMISSIVE. This header used to reason that "being wrong costs a wasted
// parse, not a false positive", and both halves of that were measured false on 2026-08-26: admitting
// 286 fonts and images on one benign webroot cost 101 s of a 128.6 s run and three false positives on
// real .NET assemblies. Permissiveness within TEXT is still deliberate -- a wasted parse of a text
// file is cheap and a missed shell is not -- but binary content is refused outright before any
// language is considered. See `looksBinary` below and research.md R10.
//
// PRIOR ART (retrieved 2026-08-26, recorded in specs/008-rule-scope-policy/research.md R2):
//
//   - ClamAV determines file type by *File Type Magic* -- byte signatures at file offsets -- with no
//     extension-based path in its type-recognition documentation.
//     https://docs.clamav.net/manual/Signatures/FileTypeMagic.html
//   - The INCUMBENT already ships this exact two-stage design, and it is reverse-engineered and
//     measured in-tree: an extension route plus a content `sign` gate asking whether the file is the
//     language at all. Its PHP sign is `(?im)(\<\?php|\<\?)(?:\=|\s{1,}|\s|\@|\w|\$)` and "if it
//     does not match, PhpScan is never called" (prior-art record, held privately); its Java sign is
//     `(?ims)(java\.|public\ class|javax\.|\<jsp.*?\>|<%.*request.*%>)` (same record).
//     Measured selectivity: 461 of 912 benign Java files admitted, roughly half.
//   - Our own bundled php-malware-finder pack decides a file is PHP from content rather than
//     filename, which is why it was among the five rules that still caught the renamed WSO shell on
//     2026-08-26 while every one of our own PHP rules went silent.
//
// THE MEASURED WEAKNESS WE BEAT. The incumbent's Java sign contains `<%.*request.*%>`, which is a
// Classic ASP shape, so "the `java` sign therefore admits ASP pages" and the overlap runs in both
// directions. Its consequence there is a mis-attributed token. Ours would be worse -- a file assigned
// to one language would be denied the other's detectors -- so signs here are NOT exclusive: a file
// admitted by two signs is offered to BOTH languages. `signsFor` returns every match, never a winner.
var langSigns = map[weblang.Lang]*regexp.Regexp{
	// PHP open tag, per the incumbent's shape. `<?` alone is deliberate: short_open_tag files are
	// real, and a wasted parse is cheaper than a missed shell.
	weblang.PHP: regexp.MustCompile(`(?i)<\?(php|=|\s|$)|<\?\w`),

	// JSP: scriptlet/expression/declaration, a JSP tag or directive, or a Java import a page would
	// carry. Deliberately does NOT include the incumbent's `<%.*request.*%>`, which is the ASP shape
	// its own kit records as the source of cross-language admission -- `<%` alone is enough here and
	// the ASP sign claims the same bytes independently.
	weblang.JSP: regexp.MustCompile(`(?is)<%[=!@]?|<jsp:|javax\.servlet|java\.lang\.|page\s+import\s*=`),

	// ASP family, both flavours: a page/handler/control directive, a server-side script block, or a
	// Request accessor in either the Classic (`Request("x")`) or .NET (`Request.Item[...]`) spelling.
	weblang.ASP: regexp.MustCompile(`(?is)<%@|<script[^>]*runat\s*=|\brequest\s*[.(\[]|server\.createobject`),

	// Perl: the interpreter shebang, a pragma, or a sigil-heavy declaration. `use strict` and
	// `my $x` are the forms that separate Perl from a shell script with a perl shebang.
	weblang.Perl: regexp.MustCompile(`(?m)^#!.*\bperl\b|\buse\s+(strict|warnings|CGI)\b|\bmy\s+[\$@%]\w`),

	// Python: the interpreter shebang, an import, or a def/class at line start.
	weblang.Python: regexp.MustCompile(`(?m)^#!.*\bpython[0-9.]*\b|^\s*(import|from)\s+\w|^\s*def\s+\w+\s*\(`),

	// SSI directives -- the whole of the language.
	weblang.Shtml: regexp.MustCompile(`(?i)<!--\s*#\s*(exec|include|echo|config|printenv)`),
}

// aspFamilySigns is the ASP sign shared by both ASP-family contexts: one pattern, two languages. The
// Classic and .NET spellings overlap enough that separating them would be a distinction the pattern
// cannot actually draw, and pretending otherwise is what produced the incumbent's asymmetry.
func init() {
	langSigns[weblang.ASPX] = langSigns[weblang.ASP]
	// .cgi/.fcgi are Perl-or-Python by construction, so an unnamed CGI file is admitted by either.
	langSigns[weblang.CGI] = regexp.MustCompile(
		langSigns[weblang.Perl].String() + `|` + langSigns[weblang.Python].String())
}

// signMatches reports whether data is plausibly lang.
//
// THE WHOLE (BOUNDED) FILE IS SEARCHED, NOT A PREFIX. An earlier design read only a leading window,
// on the reasoning that the cost should be bounded before any parse decision. That is wrong for this
// threat: appending a shell to the tail of a legitimate file is a standard infection pattern, and a
// prefix-only sign is blind to exactly that. The bound that matters is already in place -- callers
// pass content they read through readBoundedFile -- and a regex sweep over those bytes is orders of
// magnitude cheaper than the AST parse it is protecting.
// It does NOT apply the binary refusal -- `signsFor` is the single production choke point that does,
// and this stays a pure regex test so the sign patterns can be unit-tested on their own terms. It has
// exactly one production caller, `signsFor`, and must keep having exactly one: reaching a sign around
// that function is how binary content would get back in.
func signMatches(lang weblang.Lang, data []byte) bool {
	re, ok := langSigns[lang]
	if !ok {
		return false
	}
	return re.Match(data)
}

// firstFewBytes is the window the binary test inspects, taken from git's own constant so the two
// answer alike on the same file.
const firstFewBytes = 8000

// looksBinary reports whether data is binary content -- a NUL byte within the first 8,000 bytes.
//
// WHY A SIGN MUST ASK THIS FIRST (spec 008 R10). The JSP sign's first alternative is the bare
// two-byte string `<%`, and PHP's is `<?` plus one word character. In COMPRESSED data those pairs
// occur by chance: for a 100 KB compressed file the probability that `<%` appears somewhere is about
// 78%. Measured 2026-08-26 on the WordPress benign webroot, that admitted 123 of 315 .woff2, 54 of 85
// .jpg, 35 of 56 .webp and 25 of 161 .png -- 286 binaries put through PHP AST parsing, Classic-ASP
// taint, the deobfuscation mirror and the Java analyser, costing 101 s of a 128.6 s run, and
// producing 3 false positives on real .NET assemblies. Uncompressed text in the same tree (.json,
// .scss, .gif, .md) admitted 0, which is the control that isolates the mechanism.
//
// The header above claims a permissive sign "costs a wasted parse, not a false positive". On real
// webroot assets it measurably cost both, which is why this test exists.
//
// PRIOR ART (retrieved 2026-08-27, recorded in research.md R10):
//
//   - git is the canonical implementation. `xdiff-interface.c`: `#define FIRST_FEW_BYTES 8000`, and
//     `buffer_is_binary` is, in full, `if (FIRST_FEW_BYTES < size) size = FIRST_FEW_BYTES;
//     return !!memchr(ptr, 0, size);`
//     https://github.com/git/git/blob/master/xdiff-interface.c
//   - GNU grep -- the closest analogue to what a sign does, applying text patterns to a file --
//     refuses binary BY DEFAULT: it "suppresses output after null input binary data is discovered",
//     and `--binary-files=without-match` (`-I`) makes the refusal explicit.
//     https://www.gnu.org/software/grep/manual/grep.html
//   - ClamAV establishes the file TYPE from File Type Magic -- byte signatures at an offset, its
//     "primary mechanism for determining file types" -- before applying type-specific logic. That
//     ordering is the step this gate was missing.
//     https://docs.clamav.net/manual/Signatures/FileTypeMagic.html
//
// THE KNOWN WEAKNESS DOES NOT TRANSFER. git and grep both document that UTF-16 and UTF-32 text
// legitimately contains NUL bytes and is misclassified by this test. Our signs are byte-oriented
// ASCII regexes, so UTF-16 source never matched them anyway -- `<%` in UTF-16LE is `3C 00 25 00`,
// which the pattern `<%` does not match. Nothing that was detectable becomes undetectable.
//
// The 8,000-byte bound is load-bearing, not decoration: this runs on every unknown-named file in a
// webroot, so it must be O(1) per file rather than O(size).
func looksBinary(data []byte) bool {
	if len(data) > firstFewBytes {
		data = data[:firstFewBytes]
	}
	return bytes.IndexByte(data, 0) >= 0
}

// strongLangMarker is an unambiguous opener for a server-parsed language: long enough that chance
// occurrence in binary data is not a concern.
//
// WHY IT EXISTS. A flat binary refusal contradicts addendum A3 of this same spec, which established
// that the sign must sweep the WHOLE bounded file because "appending a shell to the tail of a
// legitimate file is a standard infection pattern". The most common form of that is a webshell
// appended to a JPEG, GIF or PNG -- the image header carries NULs, so a flat NUL test throws the file
// away without ever reaching the shell.
//
// Measured 2026-08-27 over 41,797 corpus files: **88 real malicious samples** are binary in their
// first 8 KB and carry one of these markers -- 33 JPEG, 13 GIF, 6 PNG, 6 ZIP, 30 other containers.
//
// WHY IT IS SAFE. Length is the whole argument. `<%` is two bytes and appears by chance in roughly
// 78% of 100 KB compressed files; `<?php` is five, which is about one chance occurrence per 10^12
// bytes. Measured: of the 7,504 binary files in the T046 benign population, **0** carry a marker
// here, and of the 1,533 unknown-extension files in the WordPress webroot, **0** do. The exception
// costs nothing measurable and recovers a real technique.
var strongLangMarker = regexp.MustCompile(`(?i)<\?php` +
	`|<%@\s*(page|control|webhandler|master|servicehost|import)` +
	`|<jsp:|javax\.servlet` +
	`|#!\s*/\S*(perl|python)` +
	`|<script[^>]{0,60}runat\s*=` +
	`|server\.createobject|executeglobal` +
	`|<!--\s*#\s*exec`)

// signsFor returns every language whose sign matches, in no particular order. A file admitted by two
// signs is offered to both -- see the note on exclusivity above.
//
// Binary content is admitted to NOTHING before any language is considered (R10) -- UNLESS it carries
// an unambiguous long marker, which is how an image polyglot keeps reaching the passes. Once a file
// is past that door the ordinary sign set decides, non-exclusively, exactly as for text.
func signsFor(data []byte) []weblang.Lang {
	if looksBinary(data) && !strongLangMarker.Match(data) {
		return nil
	}
	var out []weblang.Lang
	for _, lang := range []weblang.Lang{
		weblang.PHP, weblang.JSP, weblang.ASP, weblang.ASPX,
		weblang.Perl, weblang.Python, weblang.CGI, weblang.Shtml,
	} {
		if signMatches(lang, data) {
			out = append(out, lang)
		}
	}
	return out
}

// signCache memoises the per-path sign result for one scan. The rule layer consults a sign only for a
// file that already produced a match from a language-declaring rule, which is rare, but several rules
// can match the same file and each would otherwise re-read it.
type signCache struct {
	mu sync.Mutex
	m  map[string]map[weblang.Lang]bool
}

func newSignCache() *signCache {
	return &signCache{m: map[string]map[weblang.Lang]bool{}}
}

// admits reports whether the file at path is plausibly lang, reading it at most once per scan.
//
// An unreadable file admits NOTHING. That is the fail-closed direction here, and it is the right one:
// the alternative admits every language's rules to a file whose content nobody has seen, which is a
// false-positive engine rather than a detector. A file we could not read is disclosed through the
// existing skip accounting instead.
func (c *signCache) admits(path string, lang weblang.Lang) bool {
	c.mu.Lock()
	entry, ok := c.m[path]
	c.mu.Unlock()
	if !ok {
		entry = map[weblang.Lang]bool{}
		if data, err := readBoundedFile(path, maxScanFileBytes); err == nil && len(data) > 0 {
			for _, l := range signsFor(data) {
				entry[l] = true
			}
		}
		c.mu.Lock()
		c.m[path] = entry
		c.mu.Unlock()
	}
	return entry[lang]
}
