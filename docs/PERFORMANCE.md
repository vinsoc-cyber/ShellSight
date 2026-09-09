# Detection performance

**No recall or false-positive figure is published in this repository.** That is deliberate, and this
page exists to say why rather than to leave you wondering.

## Why there is no number here

ShellSight's per-language figures come from a measurement harness that scores the scanner against a
held-out corpus of real webshells and real benign web application code, one corpus per language,
with published corpus floors, sample-provenance tiers and 95% confidence intervals. A language whose
corpus cannot support a rate is reported as *unmeasurable* rather than given a number.

That harness, its corpora and its per-language gate evidence are **not part of this distribution**.
The corpus is licensed research material containing live malware; it is not something to hand out.

At the time of this release the per-language gates are mid-regeneration: the corpus and the
detectors have both moved since the last certified run, so every gate reports either *void* (its
figures describe a population that no longer exists) or *unmeasurable*. Figures do exist from the
interim runs, and they are good — but they are not gate-certified, and a detection rate quoted
onward by an analyst should be one the tool's own release gate signed off. Publishing an uncertified
number here would invite exactly that.

Certified figures will accompany a subsequent release.

## What you can rely on in the meantime

The tiering is a property of the tool you have, not of a measurement, and you can read it directly:

| tier | score | what it asserts |
|---|---|---|
| `confirmed` | ≥ 85 | a specific dataflow or an attributed family fingerprint — act on it |
| `likely` | ≥ 60 | a strong signature or heuristic match |
| `suspicious` | ≥ 40 | a weaker signal worth a look |
| `clean` | < 40 | nothing reportable |

`docs/RUNBOOK.md` maps each tier to an operator action. Every finding carries its own basis
(`signature`, `heuristic`, `taint`, and the memory-view bases) and its evidence string, so a verdict
can be judged on what it actually found rather than on a number in a table.

## Checking it yourself

The honest answer to "how good is it" on your estate is to run it on your estate. A sweep over a
webroot you already understand — one with known-clean applications — measures the false-positive
cost you actually care about, which is the one that consumes your triage time. `-views disk` over a
production webroot is cheap and non-destructive; see `docs/RUNBOOK.md`.

If you need the research figures for a procurement or assurance decision, ask us directly rather
than inferring them from this repository.
