# Deployment

How to point ShellSight at the thing you need swept. For what to do with the findings, see
`docs/RUNBOOK.md`.

ShellSight is an **on-demand IR sweep**, not a resident agent. It runs, writes a report, and exits.
There is no service to install, no scheduler and no daemon.

## Webroot discovery

With no `-path`, the disk view discovers webroots from the host's own configuration. The mechanism
that found each root is recorded in the report's coverage block, so a sweep always says *why* it
looked where it looked:

| mechanism | reads |
|---|---|
| `iis-config`, `iis-default` | IIS configuration and the default site path |
| `apache-config`, `nginx-config` | the server's own config files |
| `apache-dump`, `nginx-dump` | **runs the host's `httpd`/`nginx` binary** to dump its resolved config |
| `tomcat-server-xml`, `tomcat-env`, `tomcat-process`, `tomcat-convention` | Tomcat's `server.xml`, environment, running process, and conventional layout |
| `appserver-process`, `appserver-convention` | other application servers |
| `convention` | conventional webroot locations |
| `explicit` | you passed `-path` |

### On a host you believe is compromised, refuse the exec mechanisms

```sh
shellsight scan -views disk -discovery-refuse exec -out ./run
```

`apache-dump` and `nginx-dump` work by **executing a binary on the target host**. On a compromised
host an intruder may have replaced that binary, so asking it to describe the server is asking the
adversary where to look. `-discovery-refuse exec` drops both and falls back to reading config files
directly. The cost is that a webroot defined only in a dynamically-resolved config may be missed —
which the coverage block will show, rather than passing over in silence.

Individual mechanisms can be refused by name for the same reason.

## Scanning something other than this host

### A mounted image, snapshot, or another root filesystem

```sh
shellsight scan -views disk -root /mnt/evidence -out ./run
```

`-root` makes discovery read **that filesystem's** configuration rather than the running host's, so
an offline image is examined on its own terms instead of the analyst workstation's.

### A container, from the node

```sh
shellsight scan -views disk -root /proc/<pid>/root -out ./run
```

Two limitations here are known and measured, and neither is silent:

- An explicit `-path` **through** a `/proc/<pid>/root` magic link does not resolve. Use `-root`
  alone and let discovery work inside it.
- There is no offline Tomcat discovery: a Tomcat whose configuration is only reachable through the
  container's own process context may not be found via `-root`.

For a Kubernetes workload, `kubectl debug` into a node and sweep the container's root, or run
node-side against `/proc/<pid>/root`. There is no in-cluster mode.

## Sweeping a live production server

```sh
shellsight scan -views disk -low-priority -out ./run
```

`-low-priority` drops the scan's CPU and I/O priority to background, and the probes inherit it. Use
it on anything serving real traffic. The scan takes longer and does not compete with the workload.

`-timeout` bounds each probe in seconds (default 1800). A large webroot on slow storage may need
more; a probe that hits its timeout reports `degraded` coverage rather than a clean result.

## Choosing views

```sh
shellsight scan -views disk                    # the common case
shellsight scan -views disk,java-mem           # plus resident Java memshells
```

A generated agent carries only the views it was built for and reports the rest as `n/a`, naming
`agent.json` as the reason. Asking for a view the build does not carry is refused rather than
silently ignored.

**Memory views need a target process.** `java-mem` attaches to a running JVM; `dotnet-mem` looks for
`w3wp`/`dotnet`/`iisexpress`. With no such process the view reports `n/a` with that reason — which is
an answer, not a failure.

## Output

A run folder under `-out` containing:

| file | for |
|---|---|
| `summary.txt` | the human — read this first |
| `report.json` | the full verdict, coverage per view, and every finding |
| `findings.ndjson` | your SIEM — one OCSF Detection Finding per line |

An incomplete scan says so. `verdict=unknown [INCOMPLETE]` means a view did not run, and the
coverage block names which and why — it is never reported as clean.
