import { useCallback, useMemo, useState } from 'react'
import { useParams } from 'react-router-dom'
import { api } from '../api'
import type { Coverage, Group } from '../api/types'
import { CoveragePanel } from '../components/Coverage'
import { Pager } from '../components/Pager'
import { Empty, ErrorBox, Loading } from '../components/States'
import { Tier } from '../components/Tier'
import { TIER_ORDER } from '../lib/tier'
import { asError, useAsync } from '../lib/useAsync'
import { usePaged } from '../lib/usePaged'
import { when } from './Cases'
import { FindingGroup } from './FindingGroup'

// Total targets a view declined to examine. This is what turns a bare verdict into a qualified
// one; it is a sum over the same counters the coverage panel itemises.
export function notExamined(coverage: Coverage[]): number {
  return coverage.reduce(
    (n, c) => n + c.non_regular + c.unreadable + c.oversize_skipped + c.no_language_detector,
    0,
  )
}

// countByTier is the queue's shape before its contents. An analyst opening a scan asks "how much
// of this is confirmed" first; the screen used to answer only by being scrolled and counted.
export function countByTier(groups: Group[]): Record<string, number> {
  const out: Record<string, number> = {}
  for (const g of groups) out[g.tier] = (out[g.tier] ?? 0) + 1
  return out
}

// A group is decided when a judgement already stands against its content. It is the difference
// between "34 findings" and "34 findings, 9 of which someone has already answered".
export function decidedCount(groups: Group[]): number {
  return groups.filter((g) => g.prior_decisions.length > 0).length
}

export function Scan() {
  const { scanID } = useParams()
  const id = Number(scanID)
  const detail = useAsync(() => api.scans.get(id), [id])

  if (detail.loading) return <Loading what="this scan" />
  if (detail.error) return <ErrorBox error={detail.error} retry={detail.reload} />
  if (!detail.data) return null

  const { scan, verdict, coverage } = detail.data
  const missed = notExamined(coverage)

  return (
    <>
      <div className="panel">
        <div className="verdict">
          <div>
            <Tier tier={verdict.tier} score={verdict.score} large />
            {verdict.incomplete && <span className="flag"> incomplete</span>}
          </div>
          <dl className="facts">
            <dt>Run</dt>
            <dd className="mono">{scan.run_id}</dd>
            <dt>Host</dt>
            <dd>{scan.host}</dd>
            <dt>Scanner</dt>
            <dd>{scan.tool_version || '—'}</dd>
            <dt>Ran as</dt>
            <dd>{scan.operator || '—'}</dd>
            <dt>Rule set</dt>
            <dd>{scan.rule_set || '—'}</dd>
            <dt>Imported</dt>
            <dd>{when(scan.imported_at)}</dd>
          </dl>
        </div>
        {missed > 0 && (
          <p className="qualify">
            This scan <strong>did not examine everything</strong> it was pointed at —{' '}
            {missed.toLocaleString()} targets were skipped. Read the verdict as covering only what
            the coverage below accounts for.
          </p>
        )}
      </div>

      <CoveragePanel coverage={coverage} />

      <Findings scanID={id} caseID={undefined} />
    </>
  )
}

function Findings({ scanID, caseID }: { scanID: number; caseID?: number }) {
  const groups = useAsync(() => api.scans.findings(scanID), [scanID])
  const [decideError, setDecideError] = useState<Error | null>(null)
  // null = every band. A queue is worked worst-first, and the fastest way to do that is to be
  // able to say "just the confirmed ones" without reading past everything else.
  const [band, setBand] = useState<string | null>(null)
  const [hideDecided, setHideDecided] = useState(false)

  const all = useMemo(() => groups.data ?? [], [groups.data])
  const counts = useMemo(() => countByTier(all), [all])
  const decided = useMemo(() => decidedCount(all), [all])

  const matching = useMemo(
    () =>
      all.filter(
        (g) =>
          (band === null || g.tier === band) &&
          (!hideDecided || g.prior_decisions.length === 0),
      ),
    [all, band, hideDecided],
  )
  const paged = usePaged(matching, `${band}|${hideDecided}`, 25)

  const decide = useCallback(
    async (contentKey: string, verdict: string, note: string) => {
      setDecideError(null)
      try {
        await api.decisions.record({
          content_key: contentKey,
          verdict,
          note: note || undefined,
          case_id: caseID,
        })
      } catch (e) {
        // A swallowed rejection is worse than a visible one: the analyst believes the queue is
        // shrinking while the server recorded nothing.
        setDecideError(asError(e))
        return
      }
      // Reload so the decision just made appears as a prior decision -- the same view a colleague
      // will get. Rendering it optimistically would show a state the server never confirmed.
      groups.reload()
    },
    [caseID, groups],
  )

  // Worst band first, and only bands this scan actually produced: rendering an empty "confirmed 0"
  // chip next to a real one makes the zero as loud as the finding.
  const bands = [...TIER_ORDER].reverse().filter((t) => (counts[t] ?? 0) > 0)

  return (
    <div className="panel">
      <div className="toolbar">
        <h3>Findings</h3>
        <span className={`count-chip${matching.length !== all.length ? ' filtered' : ''}`}>
          {matching.length.toLocaleString()}
          {matching.length !== all.length && ` of ${all.length.toLocaleString()}`}
        </span>
        <span className="grow" />
        {matching.length > 0 && (
          <Pager page={paged} unit="findings" onPage={paged.setPage} onPerPage={paged.setPerPage} />
        )}
      </div>

      {decideError && <ErrorBox error={decideError} />}
      {groups.loading && <Loading what="findings" />}
      {groups.error && <ErrorBox error={groups.error} retry={groups.reload} />}

      {all.length > 0 && (
        <>
          <div className="stats">
            {bands.map((t) => (
              <button
                type="button"
                key={t}
                className={`stat stat-${t}${band === t ? ' on' : ''}`}
                aria-pressed={band === t}
                onClick={() => setBand(band === t ? null : t)}
              >
                <span className="stat-n">{counts[t]}</span>
                {t}
              </button>
            ))}
            <span style={{ flex: '1 1 auto' }} />
            <label className="chk">
              <input
                type="checkbox"
                checked={hideDecided}
                onChange={() => setHideDecided(!hideDecided)}
              />
              Hide {decided} decided
            </label>
          </div>

          {band !== null && (
            <p className="muted small" style={{ marginTop: 'var(--s2)' }}>
              Showing the <strong>{band}</strong> band only.{' '}
              <button type="button" className="link" onClick={() => setBand(null)}>
                Show all {all.length}
              </button>
            </p>
          )}
        </>
      )}

      {!groups.loading && all.length === 0 && (
        <Empty>
          Nothing was flagged in this scan. Check the coverage above before reading that as a clean
          host.
        </Empty>
      )}
      {all.length > 0 && matching.length === 0 && (
        <Empty>Nothing in this scan matches that filter.</Empty>
      )}

      {paged.rows.map((g) => (
        <FindingGroup key={g.content_key} group={g} onDecide={decide} />
      ))}

      {matching.length > 0 && paged.pages > 1 && (
        <div className="pager-foot">
          <Pager page={paged} unit="findings" onPage={paged.setPage} onPerPage={paged.setPerPage} />
        </div>
      )}
    </div>
  )
}
