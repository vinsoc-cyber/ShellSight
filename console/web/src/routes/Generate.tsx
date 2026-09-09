import { useState } from 'react'
import { Link } from 'react-router-dom'
import { api } from '../api'
import type { Build, ComponentsDoc } from '../api/types'
import { Empty, ErrorBox, Loading } from '../components/States'
import { asError, useAsync } from '../lib/useAsync'

// Assembly, never compilation (G2). Every executable byte in the archive is copied out of a
// published release this console already holds; nothing here compiles scanner code, and there is no
// payload stamping -- the single self-extracting binary is C5, deferred by G1 in favour of a zip.

// Only disk is offered. Every other view is rendered DISABLED WITH ITS REASON rather than hidden
// (G3, spec 7): hiding implies the capability does not exist, while showing it disabled says it
// exists and is deliberately not offered yet, which is the true statement and the one that stops
// someone re-specifying it from scratch.
//
// This set is the whole of the gate. Enabling a memory view is adding a name here -- everything
// else, including whether a rule set applies at all, is read out of the release's own declaration.
const SELECTABLE = new Set(['disk'])

// viewReason is why a view is not on offer, or null when it is.
//
// A view's own host requirement wins over the generic reason, and it comes from components.json:
// Windows java-mem reads "a Java runtime on the target host" because the scanner declared that,
// not because this form carries the string.
export function viewReason(doc: ComponentsDoc, view: string): string | null {
  if (SELECTABLE.has(view)) return null
  return doc.views[view]?.host_requires || 'not a v1 claim'
}

export type RuleSetNeed = 'no-views' | 'not-applicable' | 'required'

// ruleSetNeed says whether this selection needs a frozen rule set at all, derived from the
// declaration's `rules` flag and never from a view's name -- so enabling a memory view later is a
// config change rather than a form change (spec 7).
//
// 'no-views' is a third state on purpose. Written the obvious way, as "no selected view scans with
// YARA", the not-applicable case is VACUOUSLY TRUE for an empty selection -- Array.every over
// nothing returns true -- so a form that had lost its selection would report "this build carries no
// YARA rules" about a build that carries nothing at all, and let it be generated. An empty
// selection is a different refusal, and the server makes it too: "a build must carry at least one
// view; one carrying none would examine nothing and report a clean sweep".
export function ruleSetNeed(doc: ComponentsDoc | null, views: string[]): RuleSetNeed {
  if (views.length === 0) return 'no-views'
  return views.some((v) => doc?.views[v]?.rules === true) ? 'required' : 'not-applicable'
}

// blockedBecause is why generation is refused right now, or null when it is not.
//
// Pure, and exported, so the refusals are testable without a DOM. Every one of them is also
// enforced by the server -- this is the form saying so before the round trip, never the only place
// it is decided.
export function blockedBecause(s: {
  doc: ComponentsDoc | null
  views: string[]
  ruleSetID: number | null
  resolvedCount: number | null
}): string | null {
  if (!s.doc) return 'the release declaration has not loaded'
  switch (ruleSetNeed(s.doc, s.views)) {
    case 'no-views':
      return 'select at least one view — a build carrying none would examine nothing and report a clean sweep of a host it never looked at'
    case 'not-applicable':
      return null
    case 'required':
      break
  }
  if (s.ruleSetID === null) return 'select a frozen rule set — the selected views scan with YARA'
  // Not "allowed until proven otherwise": the count is what G7 refuses on, so the button waits for
  // it rather than letting a click through and finding out from a 422.
  if (s.resolvedCount === null) return 'waiting for the rule set to resolve'
  if (s.resolvedCount === 0) {
    return 'this set applies no rules, so the agent would scan every file and report nothing'
  }
  return null
}

export function Generate() {
  const releases = useAsync(() => api.releases.list(), [])
  const sets = useAsync(() => api.rulesets.list(), [])

  const [pickedRelease, setPickedRelease] = useState<number | null>(null)
  const [pickedSet, setPickedSet] = useState<number | null>(null)
  const [pickedViews, setPickedViews] = useState<string[] | null>(null)
  const [busy, setBusy] = useState(false)
  const [built, setBuilt] = useState<Build | null>(null)
  const [genError, setGenError] = useState<Error | null>(null)
  // The two settings spec 6.6 bakes as the build's DEFAULT rather than its law: the host flag still
  // wins. "" means the analyst chose nothing, which the server writes as JSON null so the scanner's
  // built-in default applies -- distinct from choosing today's default, which is a real choice and
  // beats it.
  const [outputFormat, setOutputFormat] = useState('')
  const [priority, setPriority] = useState('')
  // One path per line, because a webroot can contain a space and a comma-separated box makes that
  // ambiguous. Joined into a list on submit; empty means the build bakes no scope and the agent
  // auto-discovers.
  const [scope, setScope] = useState('')

  // Defaults are DERIVED, not seeded from an effect. Seeding leaves one commit in which the
  // controls exist and hold nothing, and a click in that commit is a silent no-op -- the reason
  // SelectionEditor seeds at mount rather than in a useEffect.
  const releaseID = pickedRelease ?? releases.data?.[0]?.id ?? null
  // Every set is OFFERED; a draft is offered DISABLED, with its reason.
  //
  // Filtering drafts out made the console answer a different question than the analyst asked: three
  // sets exist, two appear, and nothing says where the third went. The spec states the rule for
  // views and it holds here too -- hiding implies the thing does not exist, while showing it
  // disabled says it exists and cannot be used yet, which is the true statement and the one that
  // tells the analyst what to do about it.
  const all = sets.data ?? []
  const frozen = all.filter((s) => s.frozen_at !== null)

  const comps = useAsync(
    () => (releaseID === null ? Promise.resolve(null) : api.releases.components(releaseID)),
    [releaseID],
  )
  const doc = comps.data
  const views = pickedViews ?? (doc && doc.views['disk'] ? ['disk'] : [])
  const need = ruleSetNeed(doc, views)
  const ruleSetID = need === 'required' ? pickedSet ?? frozen[0]?.id ?? null : null

  const resolved = useAsync(
    () => (ruleSetID === null ? Promise.resolve(null) : api.rulesets.resolvedCount(ruleSetID)),
    [ruleSetID],
  )
  const count = resolved.data?.count ?? null
  const blocked = blockedBecause({ doc, views, ruleSetID, resolvedCount: count })

  function toggle(view: string) {
    setBuilt(null)
    setPickedViews(views.includes(view) ? views.filter((v) => v !== view) : [...views, view])
  }

  // A release change resets the selection rather than carrying it over: view names are declared per
  // target, so a name carried across releases can be one the new declaration has no entry for --
  // which the server refuses, correctly, as a view the target does not support.
  function chooseRelease(id: number) {
    setPickedRelease(id)
    setPickedViews(null)
    setPickedSet(null)
    setBuilt(null)
  }

  async function generate() {
    if (releaseID === null) return
    setBusy(true)
    setGenError(null)
    try {
      setBuilt(
        await api.builds.create({
          release_id: releaseID,
          rule_set_id: ruleSetID,
          views,
          scan_scope: scope
            .split('\n')
            .map((line) => line.trim())
            .filter((line) => line !== ''),
          // "" is sent as "nothing chosen", which the server renders as JSON null so the scanner's
          // own default wins. Sending "" as a VALUE would be one the scanner rejects.
          output_format: outputFormat,
          process_priority: priority,
        }),
      )
    } catch (e) {
      setGenError(asError(e))
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="panel">
      <h3>Generate an agent</h3>
      <details className="explain">
        <summary>What this produces</summary>
        <div className="explain-body">
          <p>
            Assembled from a published release, never compiled here: every byte comes out of the
            blob store this console already holds.
          </p>
          <p>
            The result is a zip — unpack it on the target host and run <code>shellsight</code>. It
            carries its own <code>agent.json</code>, so no flags are needed.
          </p>
        </div>
      </details>

      {releases.loading && <Loading what="published releases" />}
      {releases.error && <ErrorBox error={releases.error} retry={releases.reload} />}
      {releases.data?.length === 0 && (
        <Empty>
          No release has been published, so there is nothing to assemble an agent from. Publish one
          with <code>console publish</code>.
        </Empty>
      )}

      {releaseID !== null && (
        <>
          <div className="row">
            <label htmlFor="gen-release">Release</label>
            <select
              id="gen-release"
              value={releaseID}
              onChange={(e) => chooseRelease(Number(e.target.value))}
            >
              {(releases.data ?? []).map((r) => (
                <option key={r.id} value={r.id}>
                  {r.version} — {r.target}
                </option>
              ))}
            </select>
            <span className="muted small">
              The target is the release's, not a separate choice: a release is published per target.
            </span>
          </div>

          {comps.loading && <Loading what="what this release says each view needs" />}
          {comps.error && <ErrorBox error={comps.error} retry={comps.reload} />}

          {doc && (
            <>
              <div className="row">
                <span className="muted small">Views</span>
                {Object.keys(doc.views)
                  .sort()
                  .map((v) => {
                    const reason = viewReason(doc, v)
                    return (
                      <label key={v} className="chk">
                        <input
                          type="checkbox"
                          aria-label={v}
                          disabled={reason !== null}
                          checked={views.includes(v)}
                          onChange={() => toggle(v)}
                        />
                        {v}
                        {reason && <span className="note-inline"> — {reason}</span>}
                      </label>
                    )
                  })}
              </div>

              {need === 'not-applicable' && (
                <p className="qualify small">
                  Rule set <strong>not applicable</strong>: this selection carries no YARA rules, so
                  there is nothing for a compiled set to be part of. Read from the declaration's{' '}
                  <code>rules</code> flag, not from the view names.
                </p>
              )}

              {need === 'required' && (
                <>
                  <div className="row">
                    <label htmlFor="gen-set">Rule set</label>
                    <select
                      id="gen-set"
                      value={ruleSetID ?? ''}
                      onChange={(e) => {
                        setPickedSet(Number(e.target.value))
                        setBuilt(null)
                      }}
                    >
                      {all.map((s) => (
                        <option key={s.id} value={s.id} disabled={s.frozen_at === null}>
                          {s.name}
                          {s.frozen_at === null
                            ? ' — not frozen, so it has no compiled blob to carry'
                            : ` v${s.version}`}
                        </option>
                      ))}
                    </select>
                    {resolved.loading && <Loading what="the resolved count" />}
                    {resolved.error && <ErrorBox error={resolved.error} retry={resolved.reload} />}
                    {count !== null && (
                      <strong>
                        Resolves to {count.toLocaleString()} {count === 1 ? 'rule' : 'rules'}
                      </strong>
                    )}
                  </div>
                  {frozen.length === 0 && (
                    <p className="qualify small">
                      No rule set is frozen, and a draft has no compiled blob to carry.{' '}
                      <Link to="/rulesets">Freeze one</Link> first.
                    </p>
                  )}
                </>
              )}

              <div className="group">
                <div className="group-head">
                  <strong>Baked defaults</strong>
                  <span className="muted small">
                    Written into <code>agent.json</code> as this build's default. The host flag still
                    wins, so an operator can override either on the box.
                  </span>
                </div>
                <div className="row">
                  <label htmlFor="gen-scope">Scan scope</label>
                  <textarea
                    id="gen-scope"
                    rows={3}
                    placeholder={'/var/www\n/srv/http'}
                    value={scope}
                    onChange={(e) => {
                      setScope(e.target.value)
                      setBuilt(null)
                    }}
                  />
                  <span className="muted small" style={{ flex: '1 1 20rem' }}>
                    One webroot per line. <strong>Naming any path turns auto-discovery off.</strong>
                    <details className="explain">
                      <summary>What that changes</summary>
                      <div className="explain-body">
                        <p>
                          The agent scans these and nothing else, and the report records each root
                          as <code>mechanism: explicit</code>.
                        </p>
                        <p>
                          Leave it empty and the agent discovers webroots from the host's own IIS,
                          Apache, nginx and Tomcat configuration instead.
                        </p>
                        <p>
                          Either way <code>-path</code> on the host overrides this, so it cannot
                          restrict the scan.
                        </p>
                      </div>
                    </details>
                  </span>
                </div>

                <div className="row">
                  <label htmlFor="gen-format">Output format</label>
                  <select
                    id="gen-format"
                    value={outputFormat}
                    onChange={(e) => {
                      setOutputFormat(e.target.value)
                      setBuilt(null)
                    }}
                  >
                    <option value="">not chosen — the scanner's own default</option>
                    <option value="text">text</option>
                    <option value="json">json</option>
                  </select>
                  <label htmlFor="gen-priority">Process priority</label>
                  <select
                    id="gen-priority"
                    value={priority}
                    onChange={(e) => {
                      setPriority(e.target.value)
                      setBuilt(null)
                    }}
                  >
                    <option value="">not chosen — the scanner's own default</option>
                    <option value="normal">normal</option>
                    <option value="low">low</option>
                  </select>
                </div>
                <details className="explain">
                  <summary>Why nothing else is baked in</summary>
                  <div className="explain-body">
                    Everything else the CLI accepts stays a host flag on purpose — a webroot, a
                    discovery refusal, a mounted image, a timeout and an output directory are facts
                    about a box nobody had seen when this build was made.
                  </div>
                </details>
              </div>

              <div className="row">
                <button
                  type="button"
                  className="primary"
                  disabled={busy || blocked !== null}
                  onClick={generate}
                >
                  {busy ? 'Generating…' : 'Generate agent'}
                </button>
                {blocked && <span className="flag">{blocked}</span>}
              </div>
            </>
          )}
        </>
      )}

      {genError && <ErrorBox error={genError} />}

      {built && (
        <div className="group">
          <div className="group-head">
            <strong>Built</strong>
            {/* An <a href>, not a fetch: api/http.ts always calls res.json(), so a zip cannot come
                back through the wrapper. */}
            <a href={api.builds.downloadURL(built.id)} download>
              Download the agent zip
            </a>
          </div>
          <dl className="facts">
            <dt className="muted small">Build id</dt>
            <dd>
              <code>{built.build_id}</code>
            </dd>
            <dt className="muted small">Size</dt>
            <dd>{built.size_bytes.toLocaleString()} bytes</dd>
            <dt className="muted small">SHA-256</dt>
            <dd>
              <code className="mono small">{built.sha256}</code>
            </dd>
            <dt className="muted small">Views</dt>
            <dd>{built.views.join(', ')}</dd>
          </dl>
        </div>
      )}
    </div>
  )
}
