# Bundled Java probe dependencies — sources & attribution

The Java memory probe (`probes/javamem`) ships these JARs. Every licence below was read from the
JAR's own `META-INF/MANIFEST.MF` or its embedded licence file on 2026-09-08 — not from memory, and
not from a package index.

| File | Source | License | Notes |
|---|---|---|---|
| `asm-9.7.jar` | https://asm.ow2.io | BSD-3-Clause | Declares `Bundle-License: BSD-3-Clause;link=https://asm.ow2.io/LICENSE.txt`. Bytecode reading for the class-shape matcher. |
| `asm-tree-9.7.jar` | https://asm.ow2.io | BSD-3-Clause | Same declaration. ASM's tree API, used where a whole method body is needed rather than a visitor pass. |
| `cfr-0.152.jar` | https://github.com/leibnitz27/cfr | **undeclared in the artifact — see below** | Decompiles memory-resident classes so a finding can carry readable evidence. `Implementation-Vendor-Id: org.benf`. |
| `gson-2.11.0.jar` | https://github.com/google/gson | Apache-2.0 | Declares `Bundle-License: "Apache-2.0"`. The probe's wire format to the orchestrator. |
| `javax.servlet-api-4.0.1.jar` | https://projects.eclipse.org/projects/ee4j.servlet | CDDL-1.1 / GPL-2.0-with-classpath-exception | Declares `Bundle-License: https://oss.oracle.com/licenses/CDDL+GPL-1.1` and carries `META-INF/LICENSE.txt`. API only — the interfaces the pipeline-contract matcher resolves a resident class against. |
| `javax.websocket-api-1.1.jar` | https://projects.eclipse.org/projects/ee4j.websocket | CDDL-1.1 / GPL-2.0-with-classpath-exception | Declares `Bundle-License: https://glassfish.java.net/public/CDDL+GPL_1_1.html`. API only, same role for websocket endpoints. |

## CFR's licence is not established by what we ship

`cfr-0.152.jar` contains **no licence file and no licence declaration**: its manifest carries only
`Specification-Title`, `Implementation-Version`, `Implementation-Vendor-Id: org.benf` and
`Main-Class`, and the archive holds no `META-INF/LICENSE`, `NOTICE` or `COPYING` entry.

That is recorded as unverified rather than filled in from recollection. Before this JAR is
redistributed outside the team, confirm the licence at the upstream project
(https://github.com/leibnitz27/cfr) for the **0.152 tag specifically**, and replace the cell above
with what that states.

The two `javax.*` JARs are API definitions carrying a GPL-2.0 option with the classpath exception.
The exception is the operative part for us — it permits linking without the linked work becoming
subject to the GPL — and the probe links against these interfaces rather than modifying them.

## Not shipped

`junit-platform-console-standalone-1.11.4.jar` is used only by `probes/javamem/test.sh` and is
excluded from any distribution: it is a 2.7 MB test harness, the agent source never references it,
and `test.sh` itself says "not build.sh, not measure.sh, not any Go test".

## Regenerating this table

```sh
cd probes/javamem/lib
for j in *.jar; do
  echo "=== $j"
  unzip -l "$j" | grep -iE 'LICENSE|NOTICE|COPYING'
  unzip -p "$j" META-INF/MANIFEST.MF | tr -d '\r' | grep -iE 'Bundle-License|Implementation-Vendor'
done
```

A JAR that prints nothing for both is undeclared, and belongs in the section above rather than the
table — read it from upstream and say where the answer came from.
