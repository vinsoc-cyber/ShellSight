import { useMemo, useState } from 'react'
import { Link } from 'react-router-dom'
import { api } from '../api'
import type { Exclusion, FrozenMember, RuleSet } from '../api/types'
import { Pager } from '../components/Pager'
import { Empty, ErrorBox, Loading } from '../components/States'
import { asError, useAsync } from '../lib/useAsync'
import { usePaged } from '../lib/usePaged'
import { when } from './Cases'
import { SelectionEditor } from './SelectionEditor'

export function RuleSets() {
  const sets = useAsync(() => api.rulesets.list(), [])
  // The SELECTED ID, never a copy of the row.
  //
  // Holding the RuleSet object itself made the detail panel a snapshot taken at click time: after
  // freezing, sets.reload() replaced every row with a fresh one, but `selected` still pointed at
  // the old object whose frozen_at was null -- so the panel went on offering Freeze for a set that
  // was already frozen, and only a page refresh (which resets this state to null) showed the
  // truth. Deriving from the list means one source for what a set IS.
  const [selectedID, setSelectedID] = useState<number | null>(null)
  const [name, setName] = useState('')
  const [q, setQ] = useState('')
  const [createError, setCreateError] = useState<Error | null>(null)
  const [creating, setCreating] = useState(false)

  async function create() {
    setCreateError(null)
    setCreating(true)
    try {
      // Select what was just created: an analyst names a set in order to work on it, and the new
      // row is otherwise indistinguishable in a list of eight.
      const { id } = await api.rulesets.create(name.trim())
      setName('')
      setSelectedID(id)
      sets.reload()
    } catch (e) {
      setCreateError(asError(e))
    } finally {
      setCreating(false)
    }
  }

  const all = useMemo(() => sets.data ?? [], [sets.data])
  const matching = useMemo(() => {
    const needle = q.trim().toLowerCase()
    if (needle === '') return all
    return all.filter((s) => s.name.toLowerCase().includes(needle))
  }, [all, q])
  const paged = usePaged(matching, q, 25)
  const selected = all.find((s) => s.id === selectedID) ?? null

  return (
    <>
      <div className="panel">
        <div className="toolbar">
          <h3>Rule sets</h3>
          <span className={`count-chip${q.trim() !== '' ? ' filtered' : ''}`}>
            {matching.length.toLocaleString()} sets
          </span>
          <div className="search">
            <input
              aria-label="Search sets"
              placeholder="set name"
              value={q}
              onChange={(e) => setQ(e.target.value)}
            />
          </div>
          <span className="grow" />
          <Pager page={paged} unit="sets" onPage={paged.setPage} onPerPage={paged.setPerPage} />
        </div>

        <div className="row">
          <label htmlFor="newset">New rule set</label>
          <input id="newset" value={name} onChange={(e) => setName(e.target.value)} />
          <button type="button" disabled={creating || name.trim() === ''} onClick={create}>
            {creating ? 'Creating…' : 'Create set'}
          </button>
        </div>
        {createError && <ErrorBox error={createError} />}

        {sets.loading && <Loading what="rule sets" />}
        {sets.error && <ErrorBox error={sets.error} retry={sets.reload} />}
        {!sets.loading && all.length === 0 && <Empty>No rule sets yet. Create one above.</Empty>}
        {all.length > 0 && matching.length === 0 && <Empty>No set matches that name.</Empty>}
        {paged.rows.length > 0 && (
          <div className="scroll">
            <table>
              <thead>
                <tr>
                  <th>Set</th>
                  <th>State</th>
                  <th>Compiled blob</th>
                  <th>Created by</th>
                </tr>
              </thead>
              <tbody>
                {paged.rows.map((s) => (
                  <tr key={s.id} className={selectedID === s.id ? 'row-selected' : undefined}>
                    <td>
                      <button type="button" className="link" onClick={() => setSelectedID(s.id)}>
                        {s.name}
                      </button>
                    </td>
                    <td>
                      {s.frozen_at ? (
                        <>
                          <strong>v{s.version}</strong>{' '}
                          <span className="muted">frozen {when(s.frozen_at)}</span>
                        </>
                      ) : (
                        <span className="muted">draft</span>
                      )}
                    </td>
                    {/* The yarc hash ties a scan back to the exact rule bytes that produced it. It
                        is an identity to compare, not prose: one line, with the full value in the
                        title, instead of the widest column on the screen. */}
                    <td>
                      {s.yarc_sha256 ? (
                        <span className="mono hash" title={s.yarc_sha256}>
                          {s.yarc_sha256}
                        </span>
                      ) : (
                        <span className="muted">—</span>
                      )}
                    </td>
                    <td>{s.created_by}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {selected && <SetDetail set={selected} onChanged={sets.reload} />}
    </>
  )
}

function SetDetail({ set, onChanged }: { set: RuleSet; onChanged: () => void }) {
  const selection = useAsync(() => api.rulesets.selection(set.id), [set.id])
  const exclusions = useAsync(() => api.rulesets.exclusions(set.id), [set.id])
  const frozen = set.frozen_at !== null
  // rule_set_members is written ONLY at freeze, so a draft pins nothing by construction and
  // fetching its members would be a request that can only ever return [].
  const members = useAsync(
    () => (frozen ? api.rulesets.members(set.id) : Promise.resolve([])),
    [set.id, frozen],
  )
  const [filter, setFilter] = useState('')

  const [ruleID, setRuleID] = useState('')
  const [identifier, setIdentifier] = useState('')
  const [reason, setReason] = useState('')
  const [version, setVersion] = useState('')
  const [error, setError] = useState<Error | null>(null)
  // One in-flight mutation at a time. Both of these are refused by the server on a second call --
  // "already excluded", "already frozen" -- so an un-guarded double click reports a failure for
  // work that actually succeeded.
  const [busy, setBusy] = useState(false)

  async function exclude() {
    setError(null)
    setBusy(true)
    try {
      await api.rulesets.exclude(set.id, Number(ruleID), identifier.trim(), reason.trim())
      setRuleID('')
      setIdentifier('')
      setReason('')
      exclusions.reload()
    } catch (e) {
      // The backend REFUSES an exclusion that would break a dependent rule rather than warning
      // about it. Its message names the dependency, so show it verbatim.
      setError(asError(e))
    } finally {
      setBusy(false)
    }
  }

  async function freeze() {
    setError(null)
    setBusy(true)
    try {
      await api.rulesets.freeze(set.id, Number(version))
      onChanged()
    } catch (e) {
      setError(asError(e))
    } finally {
      setBusy(false)
    }
  }

  // Pinned revisions ARE a frozen set's contents, so there they lead. On a draft they are an
  // explanation of what freezing will do, so there they follow the thing being edited. Same
  // section, two positions, one definition.
  const pinned = (
    <>
      <h4>Pinned rules</h4>
      <PinnedRules members={members} filter={filter} onFilter={setFilter} />
    </>
  )

  return (
    <div className="panel">
      <div className="toolbar">
        <h3>{set.name}</h3>
        <span className="count-chip">{frozen ? `frozen · v${set.version}` : 'draft'}</span>
      </div>

      {/* FREEZE LIVES HERE, at the head of the screen it belongs to.
          It used to render last -- after the selection editor and the whole rule browser -- which
          on a real library put the button 8,360px down an 8,429px page. It was reported as a
          missing feature, and that is the correct reading of a control nobody can find: a screen's
          own verb belongs at its head, not behind its data. */}
      {frozen ? (
        <p className="qualify" data-testid="frozen-banner">
          <strong>Frozen as v{set.version}</strong> on {when(set.frozen_at ?? '')} by{' '}
          {set.frozen_by || 'unknown'}, compiled to <code>{set.yarc_sha256 || 'no blob recorded'}</code>.
          A frozen set <strong>cannot be changed</strong> — its rule revisions are pinned, so the
          blob an agent already carries stays reconstructible. Its contents are the pinned
          revisions listed below.
        </p>
      ) : (
        <>
          <div className="actions">
            <label htmlFor="ver">Version</label>
            <input
              id="ver"
              inputMode="numeric"
              placeholder="5"
              value={version}
              onChange={(e) => setVersion(e.target.value)}
            />
            <button
              type="button"
              className="primary"
              disabled={busy || version.trim() === ''}
              onClick={freeze}
            >
              {busy ? 'Freezing…' : 'Freeze'}
            </button>
            <span className="sep" />
            <span className="muted small">
              Pins every rule revision and compiles the blob an agent will carry.{' '}
              <strong>It cannot be undone.</strong>
            </span>
          </div>

          {selection.loading && <Loading what="the selection" />}
          {selection.error && <ErrorBox error={selection.error} retry={selection.reload} />}
          {selection.data && (
            <SelectionEditor
              setID={set.id}
              initial={selection.data}
              exclusions={exclusions.data?.length ?? 0}
            />
          )}
        </>
      )}

      {frozen && pinned}

      <h4>Exclusions</h4>
      {exclusions.loading && <Loading what="exclusions" />}
      {exclusions.error && <ErrorBox error={exclusions.error} retry={exclusions.reload} />}
      <ExclusionList rows={exclusions.data ?? []} loading={exclusions.loading} />

      {!frozen && (
        <div className="row" style={{ marginTop: 'var(--s3)' }}>
          <label htmlFor="exid">Rule id</label>
          <input id="exid" style={{ width: '5rem' }} value={ruleID} onChange={(e) => setRuleID(e.target.value)} />
          <label htmlFor="exident">Identifier</label>
          <input id="exident" value={identifier} onChange={(e) => setIdentifier(e.target.value)} />
          <label htmlFor="exreason">Reason</label>
          <input
            id="exreason"
            style={{ flex: '1 1 14rem' }}
            placeholder="why this rule stops firing for this set"
            value={reason}
            onChange={(e) => setReason(e.target.value)}
          />
          {/* The reason is the audit trail for why a set stopped catching something. An
              exclusion without one is unexplainable six months later. */}
          <button
            type="button"
            disabled={
              busy || ruleID.trim() === '' || identifier.trim() === '' || reason.trim() === ''
            }
            onClick={exclude}
          >
            Exclude
          </button>
        </div>
      )}

      {!frozen && pinned}

      {error && <ErrorBox error={error} />}
    </div>
  )
}

// Exclusions are few by design, but "few" is not "bounded": a long engagement accumulates them,
// and the reason column is the widest text on the screen.
function ExclusionList({ rows, loading }: { rows: Exclusion[]; loading: boolean }) {
  const paged = usePaged(rows, rows.length, 25)
  if (loading) return null
  if (rows.length === 0) return <Empty>Nothing excluded from this set.</Empty>

  return (
    <>
      <div className="scroll">
        <table>
          <thead>
            <tr>
              <th>Rule</th>
              <th>Reason</th>
              <th>Excluded by</th>
            </tr>
          </thead>
          <tbody>
            {paged.rows.map((e) => (
              <tr key={e.rule_id}>
                <td className="mono">{e.identifier}</td>
                <td>{e.reason}</td>
                <td className="muted">
                  {e.author} · {when(e.created_at)}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {paged.pages > 1 && (
        <div className="pager-foot">
          <Pager page={paged} unit="exclusions" onPage={paged.setPage} onPerPage={paged.setPerPage} />
        </div>
      )}
    </>
  )
}

function PinnedRules({
  members,
  filter,
  onFilter,
}: {
  members: { data: FrozenMember[] | null; error: Error | null; loading: boolean; reload: () => void }
  filter: string
  onFilter: (v: string) => void
}) {
  const all = members.data ?? []
  const q = filter.trim().toLowerCase()
  const matching = useMemo(
    () =>
      q === ''
        ? all
        : all.filter(
            (m) => m.identifier.toLowerCase().includes(q) || m.layer.toLowerCase().includes(q),
          ),
    [all, q],
  )
  // A real set pins thousands of revisions. They used to render as the first 200 with a note
  // saying so, which left the rest of the set unviewable from the screen that claims to show it.
  const paged = usePaged(matching, q)

  if (members.loading) return <Loading what="pinned rules" />
  if (members.error) return <ErrorBox error={members.error} retry={members.reload} />

  if (all.length === 0) {
    return (
      <Empty>
        This set <strong>pins nothing yet</strong>. Freezing it pins one revision per selected
        rule, and that pinned list is what an agent carries.
      </Empty>
    )
  }

  return (
    <>
      <div className="row">
        <span className="count-chip">
          Pins {all.length.toLocaleString()} rule {all.length === 1 ? 'revision' : 'revisions'}
        </span>
        <label htmlFor="pinfilter">Filter</label>
        <input
          id="pinfilter"
          value={filter}
          placeholder="identifier or layer"
          onChange={(e) => onFilter(e.target.value)}
        />
        <span style={{ flex: '1 1 auto' }} />
        <Pager page={paged} unit="revisions" onPage={paged.setPage} onPerPage={paged.setPerPage} />
      </div>

      {matching.length === 0 ? (
        <Empty>Nothing pinned here matches that filter.</Empty>
      ) : (
        <>
          <div className="scroll">
            <table>
              <thead>
                <tr>
                  <th>Rule</th>
                  <th>Layer</th>
                  <th className="num">Pinned revision</th>
                </tr>
              </thead>
              <tbody>
                {paged.rows.map((m) => (
                  <tr key={m.rule_id}>
                    <td className="mono">
                      <Link to={`/rules/${m.rule_id}`}>{m.identifier}</Link>
                    </td>
                    <td>{m.layer}</td>
                    <td className="mono num">{m.revision}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <div className="pager-foot">
            <Pager
              page={paged}
              unit="revisions"
              onPage={paged.setPage}
              onPerPage={paged.setPerPage}
              showPerPage={false}
            />
          </div>
        </>
      )}
    </>
  )
}
