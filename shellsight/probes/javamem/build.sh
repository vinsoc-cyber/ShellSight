#!/usr/bin/env bash
# Bash build for the javamem probe — mirrors build.ps1 exactly.
# Use this on this VM: PowerShell ExecutionPolicy blocks running build.ps1 directly, and the
# -ExecutionPolicy Bypass flag is denied by the harness. This script needs no policy change.
# Native Windows JDK tools require Windows-form paths for -cp / -d / jar file+dir args (Git Bash does
# NOT auto-convert semicolon-joined classpaths), so those are passed through cygpath -w. Source-file
# args from `find` are auto-converted by MSYS and left as-is.
set -euo pipefail
# Portable: derive the JDK home from the javac on PATH (override with a JDK= env var), and the
# probe dir from this script's own location — no hardcoded per-machine paths.
JDK="${JDK:-$(cd "$(dirname "$(command -v javac)")/.." && pwd)}"
P="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
lib="$P/lib"; out="$P/out"
cp=$(for j in "$lib"/*.jar; do cygpath -w "$j"; done | paste -sd';' -)
servlet=$(cygpath -w "$lib/javax.servlet-api-4.0.1.jar")
websocket=$(cygpath -w "$lib/javax.websocket-api-1.1.jar")

rm -rf "$out"; mkdir -p "$out/probe" "$out/agent"

# agent jar (pure JDK + ASM; manifest enables retransform)
# --release 11: shipped jars target Java 11 — the lowest floor the attach code allows (jdk.attach is
# Java 9+) — so they run on every Java 11+ host (forward-compatible). The build JDK can be newer (e.g. 17).
# ASM is bundled into the agent jar because normalize() uses ClassReader/ClassWriter at agent runtime
# (the agent jar is the only artifact on the classpath in the target JVM during attach).
"$JDK/bin/javac.exe" --release 11 --add-modules jdk.attach -cp "$(cygpath -w "$lib/asm-9.7.jar");$(cygpath -w "$lib/asm-tree-9.7.jar")" -d "$(cygpath -w "$out/agent")" $(find "$P/agent" -name '*.java')
( cd "$out/agent" && "$JDK/bin/jar.exe" --extract --file "$(cygpath -w "$lib/asm-9.7.jar")" )
( cd "$out/agent" && "$JDK/bin/jar.exe" --extract --file "$(cygpath -w "$lib/asm-tree-9.7.jar")" )
rm -f "$out/agent/module-info.class"
find "$out/agent/META-INF" -type f \( -name '*.SF' -o -name '*.RSA' -o -name '*.DSA' \) -delete 2>/dev/null || true
"$JDK/bin/jar.exe" --create --file "$(cygpath -w "$P/javamem-agent.jar")" --manifest "$(cygpath -w "$P/agent/MANIFEST-agent.mf")" -C "$(cygpath -w "$out/agent")" .

# probe jar (gson + cfr on cp; servlet-api only needed by lab/tests)
"$JDK/bin/javac.exe" --release 11 --add-modules jdk.attach -cp "$cp" -d "$(cygpath -w "$out/probe")" $(find "$P/src" -name '*.java')
# Fat jar: unpack the runtime deps into the probe classes dir, strip their signatures
# and manifests, then jar everything under one Main-Class manifest (no Class-Path / no bin/lib).
for dep in gson-2.11.0 cfr-0.152 asm-9.7 asm-tree-9.7; do
  ( cd "$out/probe" && "$JDK/bin/jar.exe" --extract --file "$(cygpath -w "$lib/$dep.jar")" )
done
rm -rf "$out/probe/META-INF/MANIFEST.MF" "$out/probe/module-info.class"
find "$out/probe/META-INF" -type f \( -name '*.SF' -o -name '*.RSA' -o -name '*.DSA' \) -delete 2>/dev/null || true
printf 'Main-Class: com.shellsight.javamem.Probe\r\n' > "$P/MANIFEST-probe.mf"
"$JDK/bin/jar.exe" --create --file "$(cygpath -w "$P/javamem.jar")" --manifest "$(cygpath -w "$P/MANIFEST-probe.mf")" -C "$(cygpath -w "$out/probe")" .

# lab split (servlet-api on cp): victim -> lab/out (victim runtime cp), fixtures -> lab/shells (OFF cp;
# forces the defineClass(byte[]) fileless residency path the agent recovers).
rm -rf "$P/lab/out" "$P/lab/shells"; mkdir -p "$P/lab/out" "$P/lab/shells"
"$JDK/bin/javac.exe" -cp "$servlet" -d "$(cygpath -w "$P/lab/out")"    $(find "$P/lab/victim"   -name '*.java')

# --- Corpus fixtures (CE-6 + CE-7 extended coverage) ---
# Stubs must be compiled FIRST so CE-6/CE-7 fixtures that reference them (e.g. HttpJspBase,
# GroovyObject, ValveBase) can be compiled in the next step.
# Sources live in shellsight-corpus/curated/mem/java/ (repo-root corpus, gitignored); .class -> lab/shells/.
#
# RESIDENCY SPLIT (so the corpus measures genuine memory-residency, not just contract-recognition):
#   stubs    -> lab/shells/corpus-stubs/  (ON the Victim cp: lets the JVM verify a fileless
#                                          fixture's supertypes when it is defined)
#   fixtures -> lab/shells/corpus/        (OFF the Victim cp: measure.sh reads the bytes and
#                                          injects them via defineClass(byte[]) -> disk-absent)
CORPUS="$P/../../../shellsight-corpus/curated/mem/java"
CORPUS_SHELLS="$P/lab/shells/corpus"
CORPUS_STUBS="$P/lab/shells/corpus-stubs"
if [ -d "$CORPUS" ]; then
  mkdir -p "$CORPUS_SHELLS" "$CORPUS_STUBS"
  CORPUS_SHELLS_W=$(cygpath -w "$CORPUS_SHELLS")
  CORPUS_STUBS_W=$(cygpath -w "$CORPUS_STUBS")
  STUBS="$CORPUS/stubs"
  # Compile stubs (ValveBase, Adapter, HandlerInterceptor, jakarta.servlet.*,
  # ApplicationFilterChain, HttpJspBase, GroovyObject) -> corpus-stubs (ON the Victim cp).
  # shellcheck disable=SC2046
  "$JDK/bin/javac.exe" --release 11 -d "$CORPUS_STUBS_W" $(find "$STUBS" -name '*.java')
  echo "[build] corpus stubs compiled -> lab/shells/corpus-stubs/ (on Victim cp)"
  # Compile CE-6 corpus fixtures (malicious): stubs + servlet-api + asm on the COMPILE cp.
  # Output goes to CORPUS_SHELLS (OFF the Victim cp) so the Victim defines each one fileless
  # (defineClass(byte[]) -> disk-absent): the genuine memshell residency path, not pipeline-only.
  ASM_W=$(cygpath -w "$lib/asm-9.7.jar")
  CP_CORPUS="$CORPUS_STUBS_W;$servlet;$websocket;$ASM_W"
  # shellcheck disable=SC2046
  "$JDK/bin/javac.exe" --release 11 -cp "$CP_CORPUS" -d "$CORPUS_SHELLS_W" \
    $(find "$CORPUS" -maxdepth 4 -name '*.java' ! -path '*/stubs/*')
  echo "[build] CE-6 corpus fixtures compiled -> lab/shells/corpus/ (OFF cp, fileless)"
else
  echo "[build] corpus/java-mem/ not found — skipping corpus fixtures"
fi

# Compile standard fixtures (excluding the APM-patched helper — it needs special handling).
# CE-7 fixtures (BenignJsp, BenignGroovy, BenignApmFilter, ReflHookEncrypted) were moved
# 2026-07-27 into the gitignored corpus root at shellsight-corpus/curated/mem/java-lab/ and
# reference corpus stubs (HttpJspBase, GroovyObject) via CORPUS_SHELLS. They compile to
# lab/shells/ (NOT corpus/), so they are NOT on the Victim classpath → the Victim defines them
# with null CodeSource (truly fileless) via the custom classloader. Skipped if absent (clone).
FIXTURES="$P/../../../shellsight-corpus/curated/mem/java-lab"
if [ -d "$FIXTURES" ]; then
CORPUS_STUBS_W=$(cygpath -w "$P/lab/shells/corpus-stubs")
CP_FIXTURES="$servlet;$websocket;$CORPUS_STUBS_W"
"$JDK/bin/javac.exe" --release 11 -cp "$CP_FIXTURES" -d "$(cygpath -w "$P/lab/shells")" \
  $(find "$FIXTURES" -name '*.java' ! -name 'BenignApmRetransformPatched.java')

# --- APM retransform fixture setup ---
# apm.jar: a real jar containing the CLEAN BenignApmRetransform class, used as the
# "authoritative source" that the agent reads via readFromCodeSource.  The victim's
# --apm mode points its ProtectionDomain's CodeSource at this jar.
APM_SHELLS=$(cygpath -w "$P/lab/shells")
"$JDK/bin/jar.exe" --create --file "$APM_SHELLS/apm.jar" \
  -C "$APM_SHELLS" com/shellsight/lab/BenignApmRetransform.class
echo "[build] apm.jar created (clean BenignApmRetransform for CodeSource diff)"

# BenignApmRetransformPatched: compiled under the binary name com.shellsight.lab.BenignApmRetransform
# (same internal class name) but with an extra static constant (APM_INSTRUMENTED_AT).  When the
# victim defines this class with CodeSource=apm.jar, the agent sees MISMATCH vs the jar copy.
APM_TMP=$(mktemp -d)
cp "$FIXTURES/BenignApmRetransformPatched.java" "$APM_TMP/BenignApmRetransform.java"
"$JDK/bin/javac.exe" --release 11 -d "$(cygpath -w "$APM_TMP")" "$(cygpath -w "$APM_TMP/BenignApmRetransform.java")"
# Place the compiled patched class where measure.sh expects it (path used as --apm arg).
mkdir -p "$P/lab/shells/com/shellsight/lab/patched"
cp "$APM_TMP/com/shellsight/lab/BenignApmRetransform.class" \
   "$P/lab/shells/com/shellsight/lab/patched/BenignApmRetransform.class"
rm -rf "$APM_TMP"
echo "[build] BenignApmRetransform-patched.class created (APM-instrumented, differs from apm.jar)"
else
  echo "[build] lab fixtures not found ($FIXTURES) — skipping CE-7 fixtures + APM setup"
fi

echo "BUILT: javamem.jar + javamem-agent.jar + lab (out/victim, shells/fixtures)"

# Copy probe jars to core binary's asset dir (binary-relative packaging path).
BIN_DIR="$P/../../bin"
mkdir -p "$BIN_DIR"
cp "$P/javamem.jar"       "$BIN_DIR/javamem.jar"
cp "$P/javamem-agent.jar" "$BIN_DIR/javamem-agent.jar"
echo "COPIED: javamem.jar + javamem-agent.jar -> $BIN_DIR/"

# The Linux native probe EMBEDS the agent (//go:embed in internal/jvmattach/embed.go), so this copy
# is what a `go build` of jvmprobe picks up. It used to be a manual step that nothing performed and
# nothing checked: on 2026-09-01 the embedded jar was found a day stale, which would have shipped a
# jvmprobe whose in-JVM agent predated the change being measured. Mechanical now, and
# TestEmbeddedAgentMatchesBuiltAgent fails if the two ever diverge again.
EMBED_DIR="$P/../../internal/jvmattach/agent"
if [ -d "$EMBED_DIR" ]; then
  cp "$P/javamem-agent.jar" "$EMBED_DIR/javamem-agent.jar"
  echo "COPIED: javamem-agent.jar -> internal/jvmattach/agent/ (embedded into jvmprobe)"
fi
