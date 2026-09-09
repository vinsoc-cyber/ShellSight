# What ShellSight looks for

A reference for the question that comes up during triage: *would this tool have seen that?* It
describes coverage, not detection rates — for why no rates are published here, see
`docs/PERFORMANCE.md`.

## Languages and file types

A file's language comes from its **extension**, and the extension set is deliberately wider than the
obvious one, because a web server will happily execute more than the canonical suffix.

| language | extensions |
|---|---|
| PHP | `.php` `.php3` `.php4` `.php5` `.php7` `.phtml` `.pht` `.inc` `.phar` |
| JSP | `.jsp` `.jspx` `.jspf` `.jsw` `.jsv` `.jhtml` |
| Classic ASP | `.asp` `.asa` `.cer` `.cdx` |
| ASP.NET | `.aspx` `.ascx` `.ashx` `.asmx` `.asax` `.cshtml` `.vbhtml` `.master` `.svc` |
| Perl | `.pl` `.pm` `.plx` `.pl6` |
| Python | `.py` `.pyw` `.py3` `.pyi` `.pyp` `.pyx` |
| CGI | `.cgi` `.fcgi` |
| SSI | `.shtml` `.shtm` `.stm` |

Also examined: `.config` (handler registration), `.html`/`.htm`/`.js`/`.css` (static files that
should not contain server-side code), and `.java`/`.class`/`.jar`/`.war` (JVM artifacts).

**Detection follows content, not the filename.** A `.cer` or `.cdx` file is parsed as Classic ASP
because IIS will serve it as one. Some of the wider rows — `.master`, `.svc`, `.vbhtml`, `.jsw`,
`.jsv`, `.jhtml`, `.cdx` — are structural coverage derived from how the server parses them, and are
recorded internally as unmeasured rather than as measured wins.

## Two kinds of evidence

Every finding carries a `basis` saying what kind of thing found it. This matters more than the score
when you are deciding whether to believe a verdict.

### Signatures — `basis: signature`

YARA rules over file content. Four packs ship:

| pack | rules | source |
|---|---:|---|
| `signature-base-thor-webshells.yar` | 624 | Neo23x0/signature-base |
| `shellsight-heuristics.yar` | 57 | ours |
| `php-malware-finder.yar` | 10 | nbs-system, ported to YARA-X |
| `nsa-webshells-core.yar` | 6 | nsacyber, low-FP core set |

Plus the YARA-Forge core package, fetched at build time rather than vendored. Licences and
attribution: `shellsight/kb/rules/foundation/SOURCES.md`.

A signature match tells you a file **looks like** something known. It is strong when the rule is
specific and weak when the pattern is generic, which is why the probe assigns each rule its own
calibrated score rather than one flat band.

### Dataflow — `basis: taint` and `basis: heuristic`

The stronger evidence, and what most `confirmed` verdicts rest on. These passes ask a different
question: **does an attacker-controlled value reach an execution sink in this file?** A request
parameter reaching `system()`, `eval()`, a file write to an executable path, a shell invocation.

| pass | languages | basis |
|---|---|---|
| `phptaint` | PHP | `heuristic` |
| `javadisk` | JSP | `heuristic` |
| `asptaint` | Classic ASP, ASP.NET | `taint` |
| `perlpytaint` | Perl, Python, CGI | `taint` |
| `ssitaint` | SSI | `taint` |

A dataflow finding names the source and the sink in its evidence string — *"request-derived content
written to `Request.Form("pathname")` via `f.write Request.Form("FILEDATA")"`* — so it can be judged
on the path it found rather than on a pattern that matched. This is why these reach the `confirmed`
band: a proven source-to-sink path is the strongest thing a static scanner can say about a web file.

These passes exist specifically for the languages whose signature coverage cannot *rank*. On SSI, for
example, the presence of `#exec` scores the same on a webshell and on legitimate documentation that
mentions the directive; only the dataflow pass separates them.

### Obfuscation

Before either kind of evidence is gathered, encoded and layered content is decoded and re-scanned —
base64, hex, `chr()` concatenation, string reversal, variable indirection, and constant folding
through intermediate assignments. A shell that hides its sink behind three layers of encoding is
scanned as what it decodes to.

### Family attribution

Where a shell carries a recognisable fingerprint, the finding names the family — Behinder, Godzilla,
AntSword, China Chopper, IceScorpion. Attribution is for triage and reporting, and only an
*attributed* family escalates a verdict; the many generic rule categories do not.

## Memory views

The disk view is the common case, but a memory-resident shell leaves no file to scan.

| view | platform | what it examines |
|---|---|---|
| `java-mem` | Linux, Windows | classes resident in a live JVM's heap that implement request-pipeline contracts but have no code source on disk |
| `dotnet-mem` | Windows | `w3wp` worker memory — wired filters, routes, modules and path-less CLR loads |
| `native-mem` | Windows | unbacked executable memory, RWX regions, PE images with no backing file |
| `behavioral` | Windows | process-creation telemetry for a web worker spawning a shell |

Each needs a target process, and says so when there isn't one. `behavioral` needs Sysmon or
`Audit Process Creation`, and reports itself **blind** without them rather than reporting nothing
found.

## Reading a verdict

| tier | score | meaning |
|---|---|---|
| `confirmed` | ≥ 85 | a proven dataflow or an attributed family — act on it |
| `likely` | ≥ 60 | a strong signature or heuristic match |
| `suspicious` | ≥ 40 | a weaker signal worth a look |
| `clean` | < 40 | nothing reportable |

An incomplete scan is never reported as clean: `verdict=unknown [INCOMPLETE]` means a view did not
run, and the coverage block names which and why. `docs/RUNBOOK.md` maps tiers to actions.

## Known limits

Worth stating plainly, because a tool that hides these is harder to trust:

- **Static analysis has a ceiling.** A shell that assembles its sink entirely at runtime from
  material the file does not contain — fetched over the network, read from a database — has no
  dataflow for a file scanner to find.
- **The `suspicious` band is thinly populated.** Most findings land at `likely` or above; if you are
  tuning triage thresholds, expect the 40–59 range to be sparse.
- **JSP ranks less sharply than the others.** It has no dedicated dataflow pass of its own, so its
  strong findings come from signatures and `javadisk` rather than a source-to-sink proof.
- **`.NET` memory coverage does not include ViewState or per-request transient shells.** Resident,
  wired components are covered; a shell that exists only for the duration of one request is not.
- **Extension-based classification can be defeated by server configuration.** A handler mapping that
  executes an unusual extension as script is examined only if that extension is in the table above.
