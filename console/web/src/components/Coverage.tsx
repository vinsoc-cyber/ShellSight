import type { Coverage } from '../api/types'

// A verdict rendered without its coverage is how a scanner tells a comfortable lie. Coverage is
// already machine-readable precisely so a consumer need not parse prose -- this panel is that
// consumer, and it never hides a skip count behind a tooltip.

const SKIPS = [
  ['unreadable', 'unreadable'],
  ['non_regular', 'not regular files'],
  ['oversize_skipped', 'over the size cap'],
  ['no_language_detector', 'no language detector'],
] as const

function skipped(c: Coverage): { label: string; n: number }[] {
  return SKIPS.map(([key, label]) => ({ label, n: c[key] })).filter((s) => s.n > 0)
}

export function CoveragePanel({ coverage }: { coverage: Coverage[] }) {
  if (coverage.length === 0) {
    return (
      <div className="panel warn">
        This scan <strong>reported no coverage</strong>. Nothing here states what was examined, so
        its verdict cannot be read as covering anything in particular.
      </div>
    )
  }
  return (
    <div className="panel">
      <h3>Coverage</h3>
      <div className="scroll">
        <table>
          <thead>
            <tr>
              <th>View</th>
              <th>Status</th>
              <th>Examined</th>
              <th>Not examined</th>
            </tr>
          </thead>
          <tbody>
            {coverage.map((c) => (
              <CoverageRow key={c.view} c={c} />
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}

function CoverageRow({ c }: { c: Coverage }) {
  const skips = skipped(c)
  // "n/a" means the view was never shipped in this build. It did not fail, and presenting it as a
  // failure would make every disk-only agent look broken.
  const absent = c.status === 'n/a'
  const failed = c.status === 'failed'
  const missed = skips.reduce((n, s) => n + s.n, 0)

  return (
    <tr className={failed ? 'row-bad' : undefined}>
      <td className="mono">{c.view}</td>
      <td>
        {absent ? (
          <span className="muted">not included in this build</span>
        ) : failed ? (
          <>
            <strong className="flag">failed</strong>
            {c.reason && <span className="muted"> — {c.reason}</span>}
          </>
        ) : (
          <>
            {c.status}
            {c.reason && <span className="muted"> — {c.reason}</span>}
          </>
        )}
      </td>
      <td>{absent ? '—' : c.targets_scanned.toLocaleString()}</td>
      <td>
        {missed === 0 ? (
          <span className="muted">—</span>
        ) : (
          <>
            <strong>{missed.toLocaleString()} — not complete</strong>
            <span className="muted small">
              {' '}
              ({skips.map((s) => `${s.n.toLocaleString()} ${s.label}`).join(', ')})
            </span>
          </>
        )}
      </td>
    </tr>
  )
}
