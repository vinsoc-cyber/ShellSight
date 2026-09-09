# ShellSight

An on-demand webshell sweep for incident response. Point it at a host, a mounted image, or a
container's filesystem; it examines web-servable files on disk and, on request, memory-resident
implants in running Java and .NET web workers. It writes a scored, evidence-carrying report and
exits.

There is no agent, no service, and nothing resident. It runs when you run it.

Eight web languages on disk — PHP, JSP, Classic ASP, ASP.NET, Perl, Python, CGI, SSI — plus four
memory views. See `docs/COVERAGE.md` for what it actually looks for.

## Get a binary

**This is the supported path.** Download the archive for your platform from the release, verify it,
unpack it, run it. No toolchain required.

```sh
sha256sum -c shellsight-<version>-linux-amd64.tar.gz.sha256
tar -xzf shellsight-<version>-linux-amd64.tar.gz
cd shellsight-<version>-linux-amd64
```

On Windows, unpack the `-win.zip` and check it against the `.sha256` beside it.

Each archive carries its own `RELEASE-FILES.sha256`, an inventory of every file it contains with
that file's hash — so you can verify the archive and then verify what came out of it.

## First scan

```sh
./shellsight scan -views disk -path /var/www -out ./run
```

Three files land in a run folder under `-out`:

| file | for |
|---|---|
| `summary.txt` | read this first |
| `report.json` | the full verdict, per-view coverage, every finding with its evidence |
| `findings.ndjson` | your SIEM — one OCSF Detection Finding per line |

Sweeping a live production server:

```sh
./shellsight scan -views disk -low-priority -out ./run
```

With no `-path`, webroots are discovered from the host's own configuration and the report records
which mechanism found each one. On a host you believe is compromised, add `-discovery-refuse exec` —
see `docs/DEPLOYMENT.md` for why that matters.

## Reading a verdict

| tier | score | meaning |
|---|---|---|
| `confirmed` | ≥ 85 | a proven request-to-sink dataflow, or an attributed family — act on it |
| `likely` | ≥ 60 | a strong signature or heuristic match |
| `suspicious` | ≥ 40 | a weaker signal worth a look |
| `clean` | < 40 | nothing reportable |

Every finding names its `basis` — what *kind* of thing found it — and carries an evidence string, so
a verdict can be judged on what it found rather than on its number.

**An incomplete scan is never reported as clean.** `verdict=unknown [INCOMPLETE]` means a view did
not run, and the coverage block names which and why.

`docs/RUNBOOK.md` maps each tier to an operator action.

## Documentation

| | |
|---|---|
| `docs/RUNBOOK.md` | operations: commands, exit codes, outputs, tier-to-action |
| `docs/COVERAGE.md` | what is detected, per language, and the known limits |
| `docs/DEPLOYMENT.md` | discovery, images, containers, live servers |
| `docs/CONSOLE.md` | the analyst console: rules, reports, generating agents |
| `docs/PERFORMANCE.md` | why no detection rates are published here |

## The console

A web console for curating rule sets, reviewing scan reports across cases, and generating scanner
binaries pre-configured for an engagement — a specific view set, webroot scope and frozen rule set,
assembled from a published release. `docs/CONSOLE.md` has the walkthrough.

## Building from source

Only needed if you are changing the tool. To *use* it, take a release archive.

Requirements:

| for | you need |
|---|---|
| the scanner and console (Go) | Go 1.26.4 |
| the YARA engine | `shellsight/scripts/fetch-yara-x.sh` — it is fetched, not vendored |
| the .NET memory probe | a .NET SDK |
| the Java memory probe | a JDK |

```sh
cd shellsight && go build ./...
cd ../console  && go build ./...
```

To assemble a release archive, `scripts/package.sh` needs `SHELLSIGHT_PREBUILT_DIR` pointing at a
directory of built probe binaries and a `SHA256SUMS` manifest. Without it the script stops and says
so. If the probes are unchanged, `scripts/prebuilt-from-bin.sh` builds that directory from an
existing `bin/`, which is much faster than rebuilding the .NET and Java probes.

## Tests

```sh
cd shellsight && go test ./...
cd ../console  && go test ./...
```

Two things to know so a green result is not read for more than it says:

- **Corpus-dependent tests skip.** Several tests score against a research corpus that is not part of
  this distribution. They skip cleanly when it is absent, and the packages still report `ok`.
- **The bundle-freshness gate is not here.** It checks a built `bin/` against the source tree it was
  built from, which is build tooling rather than product, so `go test ./...` in this repository does
  not include it.

For the console, database-backed tests also skip unless `CONSOLE_TEST_DSN` is set — see
`docs/CONSOLE.md`.

## What is not in this repository

The measurement corpus, the per-language measurement harness and its gate evidence are held
privately. The corpus is licensed research material containing live malware; it is not redistributed,
and no sample of it appears here.

Detection rates are not published here either, and `docs/PERFORMANCE.md` explains that rather than
leaving it as a gap.

## Bundled third-party content

ShellSight ships third-party rule packs and Java libraries, each under its own terms:

- `shellsight/kb/rules/foundation/SOURCES.md` — the YARA packs
- `shellsight/probes/javamem/lib/SOURCES.md` — the Java dependencies

Both record the source, the licence, and where that licence was read from.

## Licence

**Terms of use are not yet settled**, and no licence file is included. This distribution is internal
pending that decision — please do not redistribute it. Ask before using it outside your own
engagements.
