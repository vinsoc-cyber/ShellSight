import { useMemo, useState } from 'react'
import { Link } from 'react-router-dom'
import { api } from '../api'
import { Pager } from '../components/Pager'
import { Empty, ErrorBox, Loading } from '../components/States'
import { useAsync } from '../lib/useAsync'
import { usePaged } from '../lib/usePaged'

// Layers as the store uses them. "foundation" rules are exclude-only -- their text is never
// editable -- so the library shows their source pack instead of inviting an edit.
const LAYERS = ['', 'foundation', 'own'] as const

export function Rules() {
  const [layer, setLayer] = useState('')
  const [q, setQ] = useState('')
  // The layer goes to the API rather than being filtered here: client-side filtering works today
  // and quietly stops working at 5,800 rules.
  const { data, error, loading, reload } = useAsync(() => api.rules.list(layer || undefined), [layer])

  const all = useMemo(() => data ?? [], [data])
  // Search IS client-side, and deliberately: the response is already in memory, the library is
  // ~5,900 rows, and a keystroke-latency round trip to filter what the browser is holding would be
  // slower and would fail offline. If the library outgrows the single /api/rules response, the
  // search moves to the server with it -- that is one change, in one place.
  const matching = useMemo(() => {
    const needle = q.trim().toLowerCase()
    if (needle === '') return all
    return all.filter(
      (r) =>
        r.identifier.toLowerCase().includes(needle) ||
        (r.source_pack ?? '').toLowerCase().includes(needle),
    )
  }, [all, q])

  // Page 1 whenever the population changes, so a filter never lands on an empty page 40.
  const paged = usePaged(matching, `${layer}|${q}`)

  return (
    <div className="panel">
      <div className="toolbar">
        <h3>Rule library</h3>
        <span className={`count-chip${q.trim() !== '' ? ' filtered' : ''}`}>
          {matching.length.toLocaleString()}
          {q.trim() !== '' && ` of ${all.length.toLocaleString()}`} rules
        </span>

        <div className="search">
          <input
            id="rulesearch"
            aria-label="Search rules"
            placeholder="identifier or pack"
            value={q}
            onChange={(e) => setQ(e.target.value)}
          />
        </div>

        <label htmlFor="layer">Layer</label>
        <select id="layer" value={layer} onChange={(e) => setLayer(e.target.value)}>
          {LAYERS.map((l) => (
            <option key={l} value={l}>
              {l === '' ? 'all' : l}
            </option>
          ))}
        </select>

        <span className="grow" />
        <Pager page={paged} unit="rules" onPage={paged.setPage} onPerPage={paged.setPerPage} />
        <Link to="/rules/new" className="btn-link">
          Write a rule
        </Link>
      </div>

      {loading && <Loading what="rules" />}
      {error && <ErrorBox error={error} retry={reload} />}
      {!loading && !error && all.length === 0 && (
        <Empty>
          No rules in this view. Write one, or bring a pack in with{' '}
          <code>console import-pack</code>.
        </Empty>
      )}
      {all.length > 0 && matching.length === 0 && (
        <Empty>
          No rule matches <code>{q}</code>. The search covers the identifier and the source pack.
        </Empty>
      )}
      {paged.rows.length > 0 && (
        <>
          <div className="scroll">
            <table>
              <thead>
                <tr>
                  <th>Rule</th>
                  <th>Layer</th>
                  <th>Source</th>
                </tr>
              </thead>
              <tbody>
                {paged.rows.map((r) => (
                  <tr key={r.id}>
                    <td className="mono">
                      <Link to={`/rules/${r.id}`}>{r.identifier}</Link>
                    </td>
                    <td className="nowrap">{r.layer}</td>
                    <td className="muted nowrap">{r.source_pack || 'written here'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <div className="pager-foot">
            <Pager
              page={paged}
              unit="rules"
              onPage={paged.setPage}
              onPerPage={paged.setPerPage}
              showPerPage={false}
            />
          </div>
        </>
      )}
    </div>
  )
}
