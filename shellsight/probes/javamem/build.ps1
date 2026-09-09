$ErrorActionPreference='Stop'
# Portable, matching build.sh: derive the JDK from the javac on PATH (override with a JDK env var)
# and the probe directory from this script's own location. Both used to be hardcoded to an absolute
# path on a build VM that no longer exists, so this script could not run for anybody -- including on
# the workstation it was committed from.
if ($env:JDK) { $JDK = $env:JDK }
else {
  $javac = (Get-Command javac -ErrorAction SilentlyContinue).Source
  if (-not $javac) { throw "no javac on PATH; set the JDK environment variable to a JDK home" }
  $JDK = Split-Path -Parent (Split-Path -Parent $javac)
}
$P = $PSScriptRoot
$lib = "$P\lib"; $out = "$P\out"
$cp  = (Get-ChildItem "$lib\*.jar" | ForEach-Object FullName) -join ';'
Remove-Item -Recurse -Force $out -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force "$out\probe","$out\agent" | Out-Null

# agent jar (pure JDK + ASM; manifest enables retransform)
# ASM is bundled into the agent jar because normalize() uses ClassReader/ClassWriter at agent runtime.
& "$JDK\bin\javac.exe" --add-modules jdk.attach -cp "$lib\asm-9.7.jar" -d "$out\agent" (Get-ChildItem "$P\agent" -Recurse -Filter *.java | ForEach-Object FullName)
if ($LASTEXITCODE) { throw "agent compile failed" }
Push-Location "$out\agent"
& "$JDK\bin\jar.exe" --extract --file "$lib\asm-9.7.jar"
Pop-Location
Remove-Item -Force "$out\agent\module-info.class" -ErrorAction SilentlyContinue
Get-ChildItem "$out\agent\META-INF" -Recurse -Include "*.SF","*.RSA","*.DSA" -ErrorAction SilentlyContinue | Remove-Item -Force
& "$JDK\bin\jar.exe" --create --file "$P\javamem-agent.jar" --manifest "$P\agent\MANIFEST-agent.mf" -C "$out\agent" .

# probe jar (gson + cfr on cp; servlet-api only needed by lab/tests)
& "$JDK\bin\javac.exe" --add-modules jdk.attach -cp $cp -d "$out\probe" (Get-ChildItem "$P\src" -Recurse -Filter *.java | ForEach-Object FullName)
if ($LASTEXITCODE) { throw "probe compile failed" }
"Main-Class: com.shellsight.javamem.Probe`r`nClass-Path: lib/gson-2.11.0.jar lib/cfr-0.152.jar`r`n" | Set-Content -Encoding ascii "$P\MANIFEST-probe.mf"
& "$JDK\bin\jar.exe" --create --file "$P\javamem.jar" --manifest "$P\MANIFEST-probe.mf" -C "$out\probe" .

# lab (servlet-api on cp). SPLIT layout, on purpose:
#   victim   -> lab\out    (the victim's runtime classpath dir)
#   fixtures -> lab\shells (injection copy-source for the harness; kept OFF the victim classpath)
# The shell fixtures must NOT be on the victim classpath: the victim's custom loader delegates
# parent-first, so if the shell package were reachable on the classpath it would be loaded from
# disk (real codesource) and would NOT be fileless. Off-classpath forces the defineClass(byte[])
# residency path the agent is meant to recover.
$servlet   = "$lib\javax.servlet-api-4.0.1.jar"
$websocket = "$lib\javax.websocket-api-1.1.jar"
Remove-Item -Recurse -Force "$P\lab\out","$P\lab\shells" -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force "$P\lab\out","$P\lab\shells" | Out-Null
& "$JDK\bin\javac.exe" -cp $servlet -d "$P\lab\out" (Get-ChildItem "$P\lab\victim" -Recurse -Filter *.java | ForEach-Object FullName)
if ($LASTEXITCODE) { throw "lab victim compile failed" }

# Compile standard fixtures (excluding BenignApmRetransformPatched.java - needs special handling)
$standardFixtures = Get-ChildItem "$P\lab\fixtures" -Recurse -Filter *.java |
    Where-Object { $_.Name -ne 'BenignApmRetransformPatched.java' } |
    ForEach-Object FullName
& "$JDK\bin\javac.exe" -cp "$servlet;$websocket" -d "$P\lab\shells" $standardFixtures
if ($LASTEXITCODE) { throw "lab fixtures compile failed" }

# --- APM retransform fixture setup ---
# apm.jar: real jar with CLEAN BenignApmRetransform for CodeSource-diff baseline.
& "$JDK\bin\jar.exe" --create --file "$P\lab\shells\apm.jar" -C "$P\lab\shells" "com/shellsight/lab/BenignApmRetransform.class"
if ($LASTEXITCODE) { throw "apm.jar creation failed" }
Write-Output "[build] apm.jar created (clean BenignApmRetransform for CodeSource diff)"

# BenignApmRetransformPatched: compiled under the binary name com.shellsight.lab.BenignApmRetransform
# with an extra static constant (APM_INSTRUMENTED_AT). Agent sees MISMATCH vs jar copy.
$apmTmp = New-TemporaryFile | ForEach-Object { Remove-Item $_; New-Item -ItemType Directory -Path $_.FullName }
Copy-Item "$P\lab\fixtures\BenignApmRetransformPatched.java" "$apmTmp\BenignApmRetransform.java"
& "$JDK\bin\javac.exe" --release 11 -d $apmTmp "$apmTmp\BenignApmRetransform.java"
if ($LASTEXITCODE) { throw "BenignApmRetransform patched compile failed" }
New-Item -ItemType Directory -Force "$P\lab\shells\com\shellsight\lab\patched" | Out-Null
Copy-Item "$apmTmp\com\shellsight\lab\BenignApmRetransform.class" "$P\lab\shells\com\shellsight\lab\patched\BenignApmRetransform.class"
Remove-Item -Recurse -Force $apmTmp
Write-Output "[build] BenignApmRetransform-patched.class created (APM-instrumented, differs from apm.jar)"

Write-Output "BUILT: javamem.jar + javamem-agent.jar + lab (out/victim, shells/fixtures)"
