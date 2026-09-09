import { useMemo, useState } from 'react'
import type { RuleIndexRow } from '../api/types'
import { Pager } from '../components/Pager'
import { Empty } from '../components/States'
import { EMPTY_FILTER, countBy, matches, unjudgedByScore } from '../lib/rulefilter'
import { usePaged } from '../lib/usePaged'

const LAYERS = ['foundation', 'own', 'custom'] as const

export function RuleBrowser({
  rows,
  selected,
  onAdd,
  onRemove,
}: {
  rows: RuleIndexRow[]
  selected: Set<number>
  onAdd: (ids: number[]) => void
  onRemove: (ids: number[]) => void
}) {
  const [filter, setFilter] = useState(EMPTY_FILTER)

  const layerCounts = useMemo(() => countBy(rows, 'layer'), [rows])
  const packCounts = useMemo(() => countBy(rows, 'source_pack'), [rows])
  const matching = useMemo(() => rows.filter((r) => matches(r, filter)), [rows, filter])
  const unjudged = unjudgedByScore(rows, filter)

  // Rendering 5,872 rows is slow; rendering the first 200 and saying so is honest but leaves rows
  // 201..5,872 unreachable by anything the screen offers -- the analyst's only route to a rule in
  // the tail was to guess a filter that isolated it. A page is bounded work AND complete reach.
  // Bulk actions still act on the whole match set, never on the visible page.
  const paged = usePaged(matching, JSON.stringify(filter))

  function toggleIn(key: 'layers' | 'packs', value: string) {
    setFilter((f) => {
      const cur = f[key]
      return { ...f, [key]: cur.includes(value) ? cur.filter((v) => v !== value) : [...cur, value] }
    })
  }

  const filtered = matching.length !== rows.length

  return (
    <>
      <h4>Browse the library</h4>

      <div className="filters">
        <div className="field">
          <label htmlFor="fid">Identifier</label>
          <input
            id="fid"
            placeholder="godzilla"
            value={filter.identifier}
            onChange={(e) => setFilter({ ...filter, identifier: e.target.value })}
          />
        </div>
        <div className="field">
          <label htmlFor="fdesc">Description</label>
          <input
            id="fdesc"
            placeholder="obfuscated eval"
            value={filter.description}
            onChange={(e) => setFilter({ ...filter, description: e.target.value })}
          />
        </div>
        <div className="field">
          <label htmlFor="fscore">Minimum score</label>
          <input
            id="fscore"
            style={{ width: '6rem' }}
            value={filter.minScore === null ? '' : String(filter.minScore)}
            placeholder="any"
            onChange={(e) => {
              const n = Number.parseInt(e.target.value, 10)
              setFilter({ ...filter, minScore: Number.isNaN(n) ? null : n })
            }}
          />
        </div>

        <div className="field field-wide">
          <span className="field-label">Layer</span>
          <div className="chk-group">
            {LAYERS.map((l) => (
              <label key={l} className={`chk${(layerCounts[l] ?? 0) === 0 ? ' off' : ''}`}>
                <input
                  type="checkbox"
                  checked={filter.layers.includes(l)}
                  onChange={() => toggleIn('layers', l)}
                />
                {l} <span className="muted">{layerCounts[l] ?? 0}</span>
              </label>
            ))}
          </div>
        </div>

        <div className="field field-wide">
          <span className="field-label">Pack</span>
          <div className="chk-group">
            {Object.keys(packCounts)
              .sort()
              .map((p) => (
                <label key={p} className="chk">
                  <input
                    type="checkbox"
                    checked={filter.packs.includes(p)}
                    onChange={() => toggleIn('packs', p)}
                  />
                  {p} <span className="muted">{packCounts[p]}</span>
                </label>
              ))}
          </div>
        </div>

        {filtered && (
          <button type="button" onClick={() => setFilter(EMPTY_FILTER)}>
            Clear filters
          </button>
        )}
      </div>

      {unjudged > 0 && (
        <p className="qualify small">
          {unjudged} {unjudged === 1 ? 'rule declares' : 'rules declare'} no score and could not be
          judged by this filter. They are excluded while a minimum score is set.
        </p>
      )}

      <div className="row" style={{ marginTop: 'var(--s3)' }}>
        <span className={`count-chip${filtered ? ' filtered' : ''}`}>
          {matching.length.toLocaleString()} matching
        </span>
        {/* Bulk actions name their own size. "Add all" next to a filter that happens to match the
            whole library is a 5,872-rule edit, and the button must say so before it is clicked. */}
        <button
          type="button"
          disabled={matching.length === 0}
          onClick={() => onAdd(matching.map((r) => r.id))}
        >
          Add all {matching.length.toLocaleString()}
        </button>
        <button
          type="button"
          disabled={matching.length === 0}
          onClick={() => onRemove(matching.map((r) => r.id))}
        >
          Remove all {matching.length.toLocaleString()}
        </button>
        <span className="grow" style={{ flex: '1 1 auto' }} />
        <Pager page={paged} unit="rules" onPage={paged.setPage} onPerPage={paged.setPerPage} />
      </div>

      {matching.length === 0 ? (
        <Empty>No rules match these filters.</Empty>
      ) : (
        <>
          <div className="scroll">
            <table>
              <thead>
                <tr>
                  <th>In set</th>
                  <th>Rule</th>
                  <th>Layer</th>
                  <th>Pack</th>
                  <th className="num">Score</th>
                  <th>Description</th>
                </tr>
              </thead>
              <tbody>
                {paged.rows.map((r) => {
                  const isIn = selected.has(r.id)
                  return (
                    <tr key={r.id}>
                      <td>
                        <input
                          type="checkbox"
                          aria-label={`select rule ${r.identifier}`}
                          checked={isIn}
                          onChange={() => (isIn ? onRemove([r.id]) : onAdd([r.id]))}
                        />
                      </td>
                      <td className="mono">{r.identifier}</td>
                      <td className="nowrap">{r.layer}</td>
                      <td className="muted nowrap">{r.source_pack || '—'}</td>
                      {/* A rule that declared no score shows an em dash. A zero would read as
                          "scored 0", a different and worse claim than "declared none". */}
                      <td className="mono num">{r.score === undefined ? '—' : r.score}</td>
                      <td className="small">{r.description || '—'}</td>
                    </tr>
                  )
                })}
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
    </>
  )
}
