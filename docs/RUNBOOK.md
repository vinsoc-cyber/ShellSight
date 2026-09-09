# ShellSight v1 — SOC Analyst Runbook

## Quick Start

```bash
# Scan current host (disk + .NET memory + Java memory)
shellsight scan --views disk,dotnet-mem,java-mem --out /tmp/ss-$(hostname)

# Disk-only (safe, no process attach)
shellsight scan --views disk --path /var/www --out /tmp/ss-disk

# .NET IIS memshell scan (safe — PSS snapshot, no suspension)
shellsight scan --views dotnet-mem --out /tmp/ss-dotnet
```

Exit codes: 0=clean, 2=suspicious, 3=likely, 4=confirmed, **5=unknown — a view failed or timed out
and nothing was found. This is NOT an all-clear.** Treat 5 as "rescan", never as clean; the verdict
line reads `verdict=unknown` and `summary.txt` names the view that failed and why.

### Scan time and the timeout

Scan cost tracks **how obfuscated the content is, not how many files there are** — the disk probe
measures ~0.26 s/file on obfuscated webshells against ~0.011 s/file on clean framework code. A
compromised host is therefore *slower* to scan than a clean one, so a too-small budget expires
soonest on the hosts that matter. The default is 1800s (30 min) per probe. For a large webroot,
raise it rather than accepting an incomplete run:

```bash
shellsight scan --views disk --path /var/www --timeout 3600 --out /tmp/ss-disk
```

Reference points: 1,230 clean PHP files ≈ 14s; 989 obfuscated shells ≈ 4m16s; a 5,213-file
WordPress tree ≈ 2m10s.

## Linux

The Linux release runs two views: **`disk`** and **`java-mem`**. `.NET`-in-memory and the
behavioral view are Windows-only and report `n/a` with that reason rather than pretending to run. A
clean Linux scan exits **0**, not 5.

`java-mem` on Linux is the native `jvmprobe`, not the Windows jar: a static ELF that speaks the
HotSpot attach protocol itself with the agent embedded, so **no JRE, JDK, `jcmd` or `jattach` is
needed anywhere on the host**. It finds memory-resident Java shells with no file on disk — mutated
Filter/Servlet/Listener registries, inserted pipeline Valves, and bytecode-retransformed
(Agent-type) components — and attributes a family from constant-pool literals in the recovered
bytecode. Measured **92/92** on real resident shells at 0 false positives on clean Tomcat 9 and 10;
**Tomcat only**, other application servers are untested. The measurement record for this figure
is held privately and is not part of this distribution.

### Unpack and verify

The archive unpacks **flat**, into the current directory — there is no top-level folder, so unpack
into an empty directory or it will scatter files beside whatever is already there.

```bash
mkdir -p /opt/shellsight && cd /opt/shellsight
sha256sum -c shellsight-<version>-linux-amd64.tar.gz.sha256
tar xzf shellsight-<version>-linux-amd64.tar.gz

# Four things to confirm before trusting a scan:
./shellsight version                     # matches the archive name
test -x ./shellsight -a -x ./diskprobe   # the execute bit survived the transfer
file ./diskprobe | grep -q 'statically linked' && echo static
ls kb/rules | head                       # the rule tree came across
```

The execute bit is worth checking explicitly: a copy that passed through a Windows filesystem loses
it, and NTFS cannot carry it at all. A 0644 engine binary takes down the whole scan.

Static linkage is why one archive works across distributions — there is no `PT_INTERP` and no
`GLIBC_2.x` dependency, so a musl host (Alpine) runs the same binary as a glibc one.

### Scan

```bash
# Discover the webroots and scan them. No path needed.
./shellsight scan --out /tmp/ss-$(hostname)

# Name them yourself, which suppresses discovery entirely.
./shellsight scan --path /var/www,/srv/sites --out /tmp/ss-web

# A live production server: yield CPU and disk to the web server (FR-042).
./shellsight scan --low-priority --out /tmp/ss-prod

# A compromised host, where a server binary may have been replaced: refuse the
# mechanisms that would execute one. Config-file parsing is unaffected.
./shellsight scan --discovery-refuse exec --out /tmp/ss-careful

# A MOUNTED IMAGE or snapshot, not this host. Discovery reads the image's own
# configuration and maps the paths it names into the mount.
./shellsight scan --root /mnt/image --out /tmp/ss-image
```

**`--root` is not optional for an image.** Without it, discovery reads *this* machine's
configuration and scans *this* machine's webroots — and returns a clean verdict about an image it
never opened, citing your own config files as provenance. With it, roots are reported in both
namespaces:

```
      root /mnt/image/var/www  via convention, served as /var/www
```

`served as` is what the scanned host was serving; the first path is only where the disk is attached
right now. Mechanisms that can only describe a running machine — the process table, `CATALINA_*`,
`nginx -T`, `apache2ctl -S` — report `unavailable` rather than answering about the wrong host.

`--low-priority` sets `nice 10` and the idle I/O class, and the probes inherit both — it changes when
the work happens, never what it concludes. If the kernel or a container refuses either half, it says
so and the scan proceeds at normal priority; it never claims a throttle it did not get.

### Reading the discovery block

Coverage now states how each scanned directory was found, because a clean verdict means different
things depending on the answer:

```
  disk           ran
      root /srv/sites/a  via nginx-config (/etc/nginx/sites-enabled/a)
      root /var/www  via convention
           covers /var/www/html
      found nothing: apache-config=unavailable (no Apache configuration in the standard
        locations); tomcat-env=unavailable (neither CATALINA_BASE nor CATALINA_HOME is set)
      REFUSED /  (nginx-config: rejected by containment: the filesystem root is not a webroot)
```

- **`via <mechanism> (<file>)`** — read out of live configuration. The strongest provenance; go read
  that file if a finding needs context.
- **`via convention`** — a distro default that happened to exist. A *guess*. If a scan came back clean
  and every root was a guess, the next question is whether the real webroot was ever looked at.
- **`covers <path>`** — a directory inside another discovered root. Scanned once, as part of its
  parent, and listed so it does not look lost.
- **`found nothing:`** — every mechanism that produced no root, and why. `unavailable` means there was
  nothing here to consult; `attempted` means it ran and found nothing. During an IR those are
  different facts: "no nginx on this host" and "nginx is here and named no root" lead different
  places.
- **`REFUSED`** — a path something proposed and validation rejected. On a compromised host this is a
  lead, not noise: an attacker-writable config naming `/` would turn a webroot sweep into a full-disk
  scan.

### Interpreting coverage status

| Status | Meaning | Action |
|---|---|---|
| `ran` | The view examined its targets | Read the findings |
| `degraded` | It ran but could not cover everything (files skipped, some roots failed) | Read the reason; the numbers are in `skipped` |
| `n/a` | The capability cannot apply here, or is deferred in this release | Nothing to do — this does NOT make the scan incomplete |
| `failed` | It could not do the job it was asked to do | **Rescan.** This sets `incomplete` and the verdict becomes `unknown`, exit 5 |

One field cuts across the table: **`truncated: true`** on a coverage record means the view **stopped
early and cannot say what it did not examine** — as opposed to `degraded`, where it lists exactly
what it skipped. Truncation sets `incomplete`, so a truncated view that found nothing reports
`unknown` and exit 5 rather than clean. **Rescan.** Both `java-mem` paths set it (Linux native probe
and the Windows jar); `disk` does not, because its gaps are enumerated. A coverage record with no
`truncated` field came from a probe that predates it and cannot report truncation at all.

`n/a` reasons on Linux:

- *"...is supported on windows only; this host is linux"* — the capability cannot exist here. This
  is what `dotnet-mem`, `dotnet-mem-x86`, `native-mem` and `behavioral` report.
- *"...is deferred on <platform> in this release: ..."* — it CAN exist here and this build does not
  ship it. No capability reports this on Linux any more; `java-mem` used to, and now runs.

`java-mem` reporting `status: ran` with **`targets_scanned: 0`** is not a failure and not a clean
bill of health for a JVM — it means no JVM process was found. If you expected one, check that the
scan can see it: in a container, that means `--root /proc/<pid>/root` or scanning from the node.

**"no webroot could be discovered"** is a `failed` view, not a clean scan. Scanning nothing is not
evidence of absence — supply `--path`.

## Containers (Kubernetes / Docker)

Every figure in this section comes from a privately-held container-IR measurement run; every external claim carries its
source. Nothing here is a resident agent: the Linux release is a one-shot, on-disk scan, run when a
responder decides to run it.

### What the Linux release can do here

The disk view, once, against a container's filesystem. Two ways in: a **debug container** that shares
the pod's process namespace, or **the node**. Nothing is installed in the target, nothing stays behind.

### Getting the bundle to the pod

Minimal images have no shell and no `tar`, so `kubectl cp` and `kubectl exec` fail on exactly the
containers you most want to look at — Kubernetes: *"Since distroless images do not include a shell or
any debugging utilities, it's difficult to troubleshoot distroless images using kubectl exec alone."*
(<https://kubernetes.io/docs/concepts/workloads/pods/ephemeral-containers/>). Bake the unpacked
tarball into a debug image instead — `FROM scratch` is enough, every binary is static — and attach it:

```bash
kubectl debug -it <pod> --image=<registry>/shellsight-debug:<version> --target=<container> -- \
  /opt/shellsight/shellsight scan --views disk --root /proc/1/root --out /tmp/ss
```

*"The --target parameter targets the process namespace of another container."* and *"The --target
parameter must be supported by the Container Runtime. When not supported, the Ephemeral Container may
not be started, or it may be started with an isolated process namespace so that ps does not reveal
processes in other containers."* (<https://kubernetes.io/docs/tasks/debug/debug-application/debug-running-pod/>).
If `ps` shows no target processes, `/proc/<pid>` is not there either and nothing below applies.

### Which path to type

The target's filesystem is reachable through its **process-root view**: *"Container filesystems are
visible to other containers in the pod through the /proc/$pid/root link."*
(<https://kubernetes.io/docs/tasks/configure-pod-container/share-process-namespace/>). Two forms, both
supported:

```bash
# Discovery: configuration is read inside the target, roots are shown in both namespaces.
shellsight scan --views disk --root /proc/<pid>/root --out /tmp/ss
      root /proc/1/root/usr/local/tomcat/webapps  via tomcat-convention (/proc/1/root/usr/local/tomcat/conf/server.xml), served as /usr/local/tomcat/webapps

# Naming it: when you already know the webroot.
shellsight scan --views disk --path /proc/<pid>/root/var/www/html --out /tmp/ss
      root /proc/1/root/var/www/html  via explicit
```

`/proc/<pid>/root` is not an ordinary symlink — *"It provides the same view of the filesystem
(including namespaces and the set of per-process mounts) as the process itself"*
(<https://man7.org/linux/man-pages/man5/proc_pid_root.5.html>) — and reading through it needs
ptrace-level access to the target: root in the debug container, or `SYS_PTRACE`. Both forms are
validated on what the kernel says about the directory, never by resolving the link.

### What the scan must be able to write

`--out` must be writable — the report goes there. The scan also needs a temporary workspace (the
engine's file list and the decoded-layer mirror); when the default temporary location is not writable
(a read-only root filesystem with no `/tmp`), it falls back to the run folder **and says so**:

```
      scratch workspace: /tmp/ss/run_web-7f9c_20260826_101502/scratch (default temporary location not writable)
```

The directory is removed when the run ends. If neither location is writable the disk view fails with
`temporary workspace unavailable: <default>: …; <scratch>: … — set TMPDIR to a writable directory or
pass a writable --out` and the verdict is **unknown (exit 5)**, never clean. On a memory-backed `/tmp`
the decoded mirror counts against the pod's memory: up to 32 MiB per decoded file.

### Memory and time inside the pod's budget

The rule engine compiles the rule tree on every invocation — measured on the release build
(`01-observations.md` §2): **≈285–292 MB resident for the compile alone**, **≈290–365 MB peak per
scan**, **3.5–6.5 s CPU per compile** (paid at least once per scan), then ≈0.011–0.026 s per file.
Ephemeral containers cannot carry their own limits — *"Pod resource allocations are immutable, so
setting resources is disallowed."* (ephemeral-containers doc above) — so the scan draws on the pod's
existing memory limit. A pod near its limit can be OOM-killed *by the scan*: there is then no run
folder at all, `kubectl describe pod` shows `OOMKilled`, and **that is not a clean result** — rerun
from the node (below) or against a pod with headroom. `--low-priority` still applies (`nice 10`, idle
I/O class), but a CPU limit is what actually throttles across containers.

### Reading the coverage block

- `via tomcat-convention (…/conf/server.xml), served as …` — the instance was found at a location its
  vendor or official image documents, confirmed by its own `server.xml`; the `served as` path is the
  container's own name for the directory.
- `found nothing: … tomcat-convention=attempted (checked N conventional location(s): …; none held an
  instance; not checked in this release (no primary citation): /usr/share/tomcat, /var/lib/tomcat,
  /opt/tomcat)` — the locations this release checks, and the ones it deliberately does not (no
  primary source could be retrieved for them). A RHEL-family Tomcat lives at the second group: pass
  `--path`.
- `exists without an instance layout: <location>` — something is there but not in a shape this
  release recognises. A **missed webroot** until you pass `--path`, not an absence.
- `REFUSED <path> (<mechanism>: …)` — a configured path that resolved to `/` or an OS directory
  *inside the container*. On a compromised container that is a lead.
- *"no webroot could be discovered … name one with --path"* — **exit 5, not clean.** The failure line
  now carries each mechanism's own account (`Mechanisms: …`) so the next command writes itself.

### Sweeping the whole container

Never `--path /`: there is no exclude flag and `/proc` would be walked. Everything written since the
image was built lives in the container's **writable layer** or in a **mounted volume** — Docker:
*"The new directory for the container is the upperdir and is writable."*
(<https://docs.docker.com/engine/storage/drivers/overlayfs-driver/>); the kernel: writes trigger
copy-up into the upper filesystem (<https://docs.kernel.org/filesystems/overlayfs.html>). On the node,
read `upperdir=` from the container's overlay mount in `/proc/mounts` and scan that plus the volume
mount points with `--path`; the image itself is scanned once, offline, with `--root <unpacked image>`.
What a webroot-only scan does not cover in a container — configuration-pointed payloads
(`auto_prepend_file`, `.user.ini`), server aliases outside the document root, runtime-loaded jars and
extensions, staging copies in `/tmp` or `/dev/shm` — is exactly what the writable-layer sweep reaches.

### From the node

```bash
kubectl debug node/<node> -it --image=<registry>/shellsight-debug:<version>
```

*"The root filesystem of the Node will be mounted at /host."* (debug-running-pod doc above). A
container's root filesystem and writable layer are plain paths there — find them with `crictl inspect
<container-id>` or from the mount table — and `--root /host/<rootfs>` / `--path /host/<upperdir>` work
without any process-root view.

### Not in this release

Resident, sidecar or scheduled scanning; baseline suppression of known findings; enumerating a node's
containers automatically; Windows containers; memory views on Linux. The exit code is the worst tier
in one run — read `summary.txt`, and suppress in your SIEM on `fingerprint`.

## Verdict Tiers

| Tier | Meaning | Analyst action |
|---|---|---|
| `clean` | No signals found by active rules | Archive; no action |
| `suspicious` | Weak signal (fileless class, no pipeline hook) | Review `findings.ndjson` context; correlate with other indicators |
| `likely-malicious` | Strong signature or structural match | Escalate; pull decompiled artifact from run folder |
| `confirmed` | Multiple corroborating signals or family fingerprint | Incident response; isolate host |

## Findings Output

Run folder (`--out`) contains:
- `findings.ndjson` — one OCSF 2004 Detection Finding per line; pipe to Splunk/Elastic

**Decompiled memshell artifacts are NOT in the run folder.** The memory probes write them beside
the binary, in `<install>/artifacts/`:
- `artifacts/class_N.class` + `class_N.java` — decompiled Java memshell source
- `artifacts/module_N.bin` + `module_N.cs` — decompiled .NET memshell source

`report.json` records the location in `artifacts_dir` when any were produced. Copy that directory
into your evidence store as part of the run — it is not self-cleaning, so a later scan adds to it.

Parse with Splunk: `index=ir sourcetype=ndjson class_uid=2004 | spath severity_id | where severity_id>=4`

## Prod-Safety Notes

| View | Safety | Required opt-in |
|---|---|---|
| `disk` | Read-only file scan | None |
| `dotnet-mem` | PSS snapshot — IIS not suspended | None |
| `java-mem` (Windows) | Attach API — requires JRE in PATH | `--force-live-attach` flag |
| `java-mem` (Linux) | Dynamic attach from a static binary — no JRE needed | None |
| `behavioral` | Read-only event-log query (`wevtutil`) | Admin for Security/Sysmon channels |

On **Windows**, Java attach is disabled by default. Enable for a specific PID:
```bash
SHELLSIGHT_JAVA_PID_ALLOWLIST=1234 shellsight scan --views java-mem
```
The `--force-live-attach` flag is automatically added when `java-mem` is in `--views`.

On **Linux** the view is in the default set and needs no opt-in. What it does to a live server, and
why it is safe to run on one:

- **It attaches, it does not suspend.** Dynamic attach makes the JVM load an agent on its own attach
  thread. Application threads are not stopped. There is no core dump, no `ptrace`, no signal beyond
  the `SIGQUIT` the attach protocol itself uses to wake the attach listener.
- **It is bounded.** The agent captures at most 64 classes and gives up after 5 s, then detaches.
  If it hits either limit — or does not signal completion at all — the view's coverage record becomes
  **`degraded`**, with a reason naming how many classes it got through, e.g. *"in-JVM sweep truncated
  — pid 1: time budget exhausted after 40 class(es) captured"*.

  A truncated sweep also sets **`truncated: true`** on that coverage record, which makes the run
  `incomplete` — so a truncated sweep that found nothing reports **`verdict: unknown`, exit 5**, not
  a clean bill of health. **You can triage `java-mem` on the exit code.** Exit 5 on this view means
  "re-run", not "compromised".

  This is narrower than it sounds, and deliberately so. `degraded` on its own does **not** downgrade
  a verdict, because `degraded` is the ordinary state of a disk scan — any webroot holding a file
  with no language-specific detector reports it. The distinction is whether the gap is **bounded**:
  a disk scan lists exactly what it skipped, so a clean result still means something; a truncated
  in-JVM sweep cannot say what was in the classes it never reached. Only the second flips the
  verdict. Measured frequency of truncation: 1 of 92 corpus cells on a contended host running 92
  scans back to back, 0 of 92 otherwise (measured; the run record is held privately).

  The limits are **not tunable from the CLI** in this release. The agent reads
  `shellsight.maxCapture` / `shellsight.budgetMs` as system properties of the JVM it is loaded into,
  and `jvmprobe` does not pass them through — so the only way to change them would be to restart the
  target web server with different properties, which defeats the purpose. Re-running the scan is the
  remedy. (The per-class list of what the agent declined stays in its handoff directory and is not
  carried into the report.)
- **It retransforms only to read.** Agent-type detection re-transforms watchlisted classes to
  recover their in-memory bytecode; the bytes handed back are the bytes that were there. Nothing is
  rewritten.
- **It leaves nothing behind.** The staged agent jar and handoff directory are removed on exit.
- **One side effect is permanent and worth knowing:** attaching starts HotSpot's attach listener,
  which stays started for the life of that JVM and creates `/tmp/.java_pid<pid>`. That is inherent
  to dynamic attach — `jcmd`, `jstack` and every APM agent do the same — but it means a *later*
  scan can see that *something* attached. ShellSight snapshots that channel before it attaches, so
  it never reports its own footprint; a third-party tool might.

### Behavioral / log view

**Supplementary host-log signals — NOT a memshell catcher.** Its one genuine malicious signal is
**`w3wp.exe` spawning a shell/LOLBin** (Security 4688 / Sysmon 1). ViewState MAC failures (EventID
1316) and IIS module/web.config changes (EventID 29/50) are **informational context only** — they
are high-FP, and 1316 fires on a *failed/keyless* ViewState forge, **not** a successful key-signed
attack (a valid-MAC forged ViewState leaves no 1316; it runs in-memory and is the **`.NET-mem`
view's** job, not this one). Read-only; never clears logs.

**Coverage honesty:** if process-creation telemetry is unavailable (Audit Process Creation OFF and
no Sysmon, or the older Server ≤2012R2 4688 schema), the view reports **`degraded`** with the
reason — never a false clean. Enable "Audit Process Creation" (Server 2016+) or install Sysmon to
get w3wp→child detection.

Offline triage of a collected log:
```bash
behaviorprobe --evtx C:\evidence\Security.evtx < spec.json
```

## Rule Update Cadence

```bash
# Update foundation rules (requires internet)
shellsight rules update

# Air-gapped: transfer bundle from internet machine
shellsight rules export --out rules-2026-06-14.tar.gz   # on internet machine
shellsight rules import rules-2026-06-14.tar.gz          # on air-gapped machine

# Check current rule set
shellsight rules list

# Validate rules against clean corpus (run after any update)
shellsight rules validate
```

## Custom Rule Authoring

Place `.yar` files in `kb/rules/custom/` (beside the binary). Standard YARA syntax.

**Scope your rule with `shellsight_lang`.** Without it a rule fires on *every* file type — the shape
that once produced 23 of 24 .NET false positives from a single over-broad ASP rule. Scoping costs you
nothing in reach: a scoped rule still reaches renamed and extension-less files whose content matches
(see below).

```yara
rule my_custom_shell {
  meta:
    shellsight_lang = "php"                          // scope: see the table below
    family          = "CustomFramework-Shell"
    score           = "75"
    reference       = "internal://INCIDENT-2026-042"
  strings:
    $s = "MyInternalFramework.ExecCmd" ascii
  condition:
    $s
}
```

| `shellsight_lang` | fires on files named |
|---|---|
| `php` | `.php .php3 .php4 .php5 .php7 .phtml .pht .inc .phar` |
| `jsp` / `java` | `.jsp .jspx .jspf .jsw .jsv .jhtml` |
| `asp` | `.asp .asa .cer .cdx` |
| `aspx` / `dotnet` | `.aspx .ascx .ashx .asmx .asax .cshtml .vbhtml .master .svc` |
| `asp-family` | asp + aspx + `.config` |
| `perl` | `.pl .pm .plx .pl6` + `.cgi .fcgi` |
| `python` | `.py .pyw .py3 .pyi .pyp .pyx` + `.cgi .fcgi` |
| `shtml` | `.shtml .shtm .stm` |
| `web-generic` | php + jsp + asp + aspx + `.config` |
| *(omitted)* | **every file, including `.js`/`.html` and unrecognised names** |

**...and, whatever it declares, on a file whose name claims no language at all.** A rule scoped to
`php` also fires on `shell.txt`, `shell.bak` or a file with no extension when the *content* is
plausibly PHP. Compound names resolve to their inner extension, so `shell.php.bak` is PHP outright.
A rule never fires on a file whose name claims a *different* language — `shell.jsp` is not offered to
PHP rules — which is the one shape this deliberately does not cover.

Findings admitted on content rather than name carry `context.rule_scope = "unknown-language"` in
`report.json`. **Treat that as a lead, not a caveat**: the score and tier are exactly what the same
rule gives a normally-named file, and what the marking adds is that the name on disk disagrees with
what the file contains. On a compromised host that disagreement is itself worth looking at.

There is no flag for any of this and nothing to enable.

`score` maps to the tier the analyst triages on: `>=85` confirmed, `>=60` likely, `>=40` suspicious,
below that clean. `family` is a free label; `reference` appears in `report.json` as
`context.rule_reference`.

**YARA rules only run against the `disk` view.** The memory views (`java-mem`, `dotnet-mem`,
`native-mem`) and `behavioral` receive no rules at all — memory detection is driven by
`kb/rules/mem-contracts.json` and by logic compiled into the probes. A custom YARA rule can never
match a memshell. The PHP taint engine (`phptaint:*`) and Java bytecode scanner (`javadisk:*`) are
likewise compiled in and not tunable from rules.

### Custom rules and upgrades

`kb/rules/custom/`, `lab/` and `artifacts/` are carried across by `scripts/package.sh`, and
`shellsight rules update` / `rules import` leave the custom layer alone (`import` merges a bundle's
custom rules over yours, keeping local-only ones). Even so, for anything you cannot recreate:

```bash
shellsight rules export --include-custom --out custom-backup.tar.gz   # before upgrading
```

To keep rules somewhere the installer never touches at all, point the scanner at them:

```bash
shellsight scan --views disk --rules-dir D:\ir\shellsight-rules --path C:\inetpub\wwwroot
```

That directory needs the same shape as `kb/rules` (`foundation/`, `own/`, `custom/`,
`mem-contracts.json`) — copy the shipped tree once and maintain it there.

Validate before deploying: `shellsight rules validate --layer custom`

**Read the exit code — `validate` is three-valued:**

| exit | meaning | what to do |
|---:|---|---|
| 0 | rules compile **and** fire on nothing in the benign corpus | deploy |
| 1 | **FAILED** — they do not compile, or they hit benign files | fix the rule |
| 3 | **INCOMPLETE** — they compile, but the false-positive check could not run | see below |

Exit **3** is what you get in the shipped kit, because no benign corpus is bundled. The rules were
compile-checked (so syntax errors are caught) but **never tested against legitimate code**, which is
the usual way a new rule causes harm. Either supply a corpus at `lab/corpus/disk/benign`, or scan a
known-clean webroot and review every finding:

```bash
shellsight scan --views disk --path /path/to/known-clean-webroot --out /tmp/ss-fpcheck
```

### Triaging a false positive

`summary.txt` gives you, per finding, the full path, the rule that fired, and the pattern that
matched inside it:

```
  [likely-malicious] disk score=70 — C:\inetpub\wwwroot\examples\openid.php
      rule=kb:yara/DodgyPhp  basis=signature  [T1505.003]
      YARA rule DodgyPhp matched: $silenced_include
      matched: $silenced_include@531: @include
```

That is usually enough to call it: `@include` is ordinary PHP. To go further, find the rule with
`grep -rl "^rule DodgyPhp" kb/rules/`, and see `report.json` for the SHA-256, `context.rule_author`
and `context.rule_reference`.

**There is no built-in suppression.** Suppress in your SIEM on the finding's `fingerprint`
(`report.json`), which is stable across re-scans for the same file, rule and evidence. Note that
fingerprints for YARA findings **changed** when matched patterns were added to the evidence — any
suppression written before that release must be re-created.

## Triage Checklist

When verdict is `likely-malicious` or `confirmed`:
- [ ] Note the `correlation_id` — all findings from one scan share the same ID for SIEM correlation
- [ ] Pull the decompiled artifact from the run folder and review for family markers (Behinder key, Godzilla pattern)
- [ ] Check `classification.family` in the NDJSON — if populated, a rule/fingerprint identified the family. **v1 = detection only:** family is a *best-effort default-key IOC hint* (e.g. a factory-default Godzilla/Behinder key literal), NOT a classifier. Any operator who changed the key → no family label. Don't rely on it; real family classification is post-v1.
- [ ] Run the behavioral view: `shellsight scan --views disk,dotnet-mem,java-mem` to cross-correlate
- [ ] Escalate per your IR SOP with the full run folder as evidence

---

## Verification stamp

Every command in this document was re-run against the **shipped archive**, not a development build,
on 2026-08-21. What was confirmed, and what was not:

| claim | how it was checked | result |
|---|---|---|
| `shellsight version` | run | `shellsight 1.0.0` |
| top-level commands | run with no arguments | `usage: shellsight <scan\|rules\|version> [flags]` |
| `shellsight rules <...>` | run with no verb | `usage: shellsight rules <list\|update\|validate\|export\|import>` |
| `--views` / `--path` / `--out` | run with double dashes | accepted; Go's flag package takes one dash or two |
| `shellsight scan` | run on Windows 10 and on Alpine 3.21 musl | completed, exit 0, `report.json` path on stdout with `--json` |
| `shellsight rules list` | run | layer table: foundation / own / custom, with counts, versions and paths |
| `shellsight rules validate` | run | compiles the rules and then reports **INCOMPLETE** — "the rules compile, but they have NOT been checked against" a benign corpus, because none is present beside the archive. That is the honest answer and it is what an operator will see. |
| the SIEM stream is `findings.ndjson` | grep + `internal/output/runbook_test.go` | correct throughout; the historical `report.ndjson` drift is gone and a test now fails if it returns |
| the NDJSON is ingestible | `internal/output/siem_roundtrip_test.go` over a real run | one complete object per line, no BOM, no CR, exactly one trailing newline, unique `finding_info.uid`, finite epoch-millisecond `time`, re-encodes cleanly |

**Unchanged by the 004 language-hardening work.** That feature raised the standard the per-language measurement harness enforces — corpus floors, provenance tiers, the gate predicate, the platform matrix — and touched **no command in this document**. The analyst surface (`scan`, `rules`, `version`, their flags and their outputs) is byte-for-byte the surface this stamp verified. The harness's own commands are development tooling, are not part of this distribution, and an operator never runs them.

**Not re-run, and therefore not confirmed by this stamp**: `rules update`, `rules export` and
`rules import`, which need a rule-distribution endpoint and a second machine; and every
memory-view command, which needs a live IIS or JVM host. Their documented behaviour is unchanged
from the previous release and is not evidence produced by this one.
