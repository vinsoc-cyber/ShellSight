# Cross-module contracts

Files in here are read by **both** Go modules and belong to neither.

`agent.json` is the golden example of a generated agent's configuration. The console writes that
format (`console/internal/agentgen`) and the scanner reads it (`shellsight/internal/agentcfg`), and
the two modules deliberately share no code: `console/go.mod` records why — the scanner is copied
onto hosts assumed to be compromised and keeps a two-dependency surface.

Two modules describing one format is a drift risk, so each side has a test pointed at this file:

| test | asserts |
|---|---|
| `console/internal/agentgen/agentjson_test.go` | the console **writes** exactly these bytes |
| `shellsight/internal/agentcfg/contract_test.go` | the scanner **reads** them, and every field arrives |

Change the format and both tests must be updated together. Change one side alone and one fails,
which is the entire point. **Do not "fix" a failure here by editing only the golden** — that
silences the alarm and leaves the two implementations disagreeing.

Both tests were watched failing before this was committed, on `"build_id"` renamed to `"buildid"`:
the console reported a byte mismatch, the scanner reported `BuildID = ""`. A contract nobody has
seen fail is a contract nobody knows works.

## Notes for whoever changes the format next

- The console's byte comparison normalises line endings. `core.autocrlf` is on for this repo and
  there is no `.gitattributes` entry for `contracts/`, so a Windows checkout materialises this file
  with CRLF while Linux gets LF. Normalising is what keeps one commit from passing on one host and
  failing on the other for a reason that is not the format.
- `output_format` and `process_priority` marshal as a **bare JSON string** when chosen and **`null`**
  when not — never as an object, and never as `""`. The scanner rejects an unrecognised value
  including the empty string; `null` is the spelling that means nothing was chosen and lets the
  scanner's built-in default win.
- The golden deliberately chooses **both** settings, so a renderer that dropped either key would
  fail the byte comparison. The `null` case is covered by a separate console test rather than by a
  second golden.
