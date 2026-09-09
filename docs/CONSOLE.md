# The analyst console

A web console for managing detection rules, reviewing scan reports, and generating pre-configured
scanner binaries for a specific engagement. It is a separate Go module from the scanner and imports
nothing from it — the scanner is a binary you drop on a host you assume is compromised, and its
dependency surface is kept deliberately small.

## Standing it up

### 1. PostgreSQL

```sh
cd shellsight/deploy
docker compose up -d
```

Or point the console at any PostgreSQL 14+ you already run. **Migrations run automatically on
start** — there is no separate migrate step.

### 2. Start the console

```sh
cd console
go run ./cmd/console \
  -dsn   "postgres://user:pass@127.0.0.1:5432/ssconsole?sslmode=disable" \
  -blobs /var/lib/shellsight/blobs \
  -yr    /path/to/third_party/yara-x/yr \
  -addr  127.0.0.1:8080
```

All four flags are validated before anything connects, and the binary names the missing one:

| flag | why it is required |
|---|---|
| `-dsn` | PostgreSQL connection string |
| `-blobs` | content-addressed store for release files, compiled rule sets and generated agents |
| `-yr` | the YARA engine. The console **compiles every rule before accepting it**, and cannot validate a rule without it |
| `-addr` | listen address; defaults to localhost — put it behind your own auth if you expose it |

The dashboard is embedded in the binary, so `http://127.0.0.1:8080/` serves it with no separate
front-end build. If you change the front end, rebuild it (`cd console/web && npm ci && npm run
build`) and rebuild the binary.

## The workflow

### Publish a release

```sh
go run ./cmd/console publish \
  -dsn "$DSN" -blobs /var/lib/shellsight/blobs \
  -dir  /path/to/unpacked/shellsight-v1.0.1-win \
  -version v1.0.1 -target windows-amd64 -by you@example.com
```

Unpack a release archive and publish the directory. Every file is verified against the release's own
`RELEASE-FILES.sha256` inventory **before anything is stored** — a release that does not verify is
refused whole rather than half-published. Each file's bytes go into the blob store under their own
hash, so generating an agent later is a lookup rather than a rebuild.

### Manage rules

Rules live in three layers, and only two of them are writable:

| layer | writable | notes |
|---|---|---|
| `foundation` | **no** | the bundled third-party packs. Exclude-only |
| `own` | yes | ShellSight's own heuristics |
| `custom` | yes | yours |

```
POST   /api/rules            author a rule            {"layer","text","lang"}
PUT    /api/rules/{id}       edit it
DELETE /api/rules/{id}       delete it
GET    /api/rules/index      every rule, latest revision
```

Two refusals worth knowing, because they are the ones you will meet:

- **A rule that does not compile is refused with HTTP 422**, carrying `yr`'s own diagnostic and line
  number. This is not pedantry: `yr compile` has no partial-success mode, so one malformed rule
  would block *every* agent build for *everyone* until somebody found it.
- **Writing to `foundation` is refused with HTTP 403.** Upstream packs are not edited; a rule you
  disagree with gets excluded from a rule set instead.

Rules are revisioned and every write is attributed to an actor.

### Freeze a rule set

A rule set is a named, versioned selection of rules. Freezing compiles it to a single `.yarc` blob —
that blob, not the rule tree, is what a generated agent carries.

```
POST /api/rulesets                       create
PUT  /api/rulesets/{id}/selection        choose layers and rules
POST /api/rulesets/{id}/exclusions       drop a foundation rule
POST /api/rulesets/{id}/freeze           compile          {"version"}
GET  /api/rulesets/{id}/compare/{other}  diff two sets
```

### Generate an agent

```
POST /api/builds
{ "release_id": 1, "rule_set_id": 1, "views": ["disk"],
  "scan_scope": ["C:\\inetpub\\wwwroot"],
  "output_format": "json", "process_priority": "low" }

GET  /api/builds/{id}/download
```

Assembly, never compilation: every executable byte is copied from a published release. The build id
is derived from the request, so **the same request produces byte-identical output** — two analysts
asking for the same agent get the same artefact.

The download carries `X-Agent-SHA256`, and the build record stores the same hash, so what was handed
out is what was recorded.

Refusals here are deliberate too. A memory-only selection carrying a rule set is refused (the
archive would name a `rules/set.yarc` it does not hold), and a rule set that resolves to zero rules
is refused before assembly rather than producing an agent that scans everything and reports nothing.

**The baked configuration is a default, not a boundary.** A generated agent will not run a view it
was not built for, but the scan scope is a default that `-path` overrides, and the view list is not
tamper-proof against someone with file access on the host. Treat it as a convenience for the
responder, not a guarantee to a third party.

### Review reports

```
POST /api/cases                    open a case
POST /api/cases/{id}/reports       ingest a scan report
GET  /api/scans/{id}/findings      its findings
POST /api/decisions                record a triage decision
```

## Running the tests

```sh
cd console
go test ./...                                   # 214 tests, no database needed
CONSOLE_TEST_DSN="$DSN" go test ./...           # + 60 database-backed, incl. end-to-end
```

Without `CONSOLE_TEST_DSN` the database-backed tests **skip**, and the packages still report `ok`.
If you are trying to verify the persistence layer, set it — otherwise you are reading a green result
that never touched a database.
