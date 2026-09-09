import { useMemo, useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import { api } from '../api'
import { Pager } from '../components/Pager'
import { Empty, ErrorBox, Loading } from '../components/States'
import { Tier } from '../components/Tier'
import { isAlerting } from '../lib/tier'
import { useAsync } from '../lib/useAsync'
import { usePaged } from '../lib/usePaged'
import { when } from './Cases'
import { ImportRuns } from './ImportRuns'

// The per-build HMAC key is extractable from the agent binary, so this detects opportunistic
// tampering and NOT a determined attacker. Each note says so; a label implying proof would be
// worse than no label at all.
const INTEGRITY_NOTE: Record<string, string> = {
  verified:
    'Matches its manifest. Detects opportunistic tampering only — the signing key is extractable from the agent binary.',
  unverified:
    'No manifest accompanied this report, so nothing was checked. Detects opportunistic tampering only — the signing key is extractable from the agent binary.',
  altered:
    'This report does NOT match its own manifest. It is kept and shown because refusing it would discard evidence; read its contents with that in mind.',
}

export function Scans() {
  const { caseID } = useParams()
  const id = Number(caseID)
  const { data, error, loading, reload } = useAsync(() => api.cases.scans(id), [id])
  const [q, setQ] = useState('')
  // An estate sweep files dozens of scans under one case, most of them clean. The bands worth
  // opening are the alerting ones, so offer that as one control rather than as a read-through.
  const [alertingOnly, setAlertingOnly] = useState(false)

  const all = useMemo(() => data ?? [], [data])
  const alerting = useMemo(() => all.filter((s) => isAlerting(s.tier)).length, [all])
  const matching = useMemo(() => {
    const needle = q.trim().toLowerCase()
    return all.filter(
      (s) =>
        (!alertingOnly || isAlerting(s.tier)) &&
        (needle === '' ||
          s.host.toLowerCase().includes(needle) ||
          s.run_id.toLowerCase().includes(needle)),
    )
  }, [all, q, alertingOnly])
  const paged = usePaged(matching, `${q}|${alertingOnly}`, 25)

  return (
    <>
      <ImportRuns caseID={id} onImported={reload} />

      <div className="panel">
      <div className="toolbar">
        <h3>Scans in this case</h3>
        <span className={`count-chip${matching.length !== all.length ? ' filtered' : ''}`}>
          {matching.length.toLocaleString()}
          {matching.length !== all.length && ` of ${all.length.toLocaleString()}`} scans
        </span>
        <div className="search">
          <input
            aria-label="Search scans"
            placeholder="host or run id"
            value={q}
            onChange={(e) => setQ(e.target.value)}
          />
        </div>
        {alerting > 0 && (
          <label className="chk">
            <input
              type="checkbox"
              checked={alertingOnly}
              onChange={() => setAlertingOnly(!alertingOnly)}
            />
            Only the {alerting} alerting
          </label>
        )}
        <span className="grow" />
        <Pager page={paged} unit="scans" onPage={paged.setPage} onPerPage={paged.setPerPage} />
      </div>

      {loading && <Loading what="scans" />}
      {error && <ErrorBox error={error} retry={reload} />}
      {!loading && all.length === 0 && (
        <Empty>
          Nothing imported into this case yet. Select a run folder above, or import in bulk with{' '}
          <code>console import-report -dir &lt;run folders&gt; -case &lt;name&gt;</code>.
        </Empty>
      )}
      {all.length > 0 && matching.length === 0 && <Empty>No scan matches that filter.</Empty>}
      {paged.rows.length > 0 && (
        <>
          <div className="scroll">
            <table>
              <thead>
                <tr>
                  <th>Run</th>
                  <th>Host</th>
                  <th>Verdict</th>
                  <th>Report integrity</th>
                  <th>Imported</th>
                </tr>
              </thead>
              <tbody>
                {paged.rows.map((s) => (
                  <tr key={s.id}>
                    <td>
                      <Link to={`/scans/${s.id}`} className="mono">
                        {s.run_id}
                      </Link>
                    </td>
                    <td>{s.host}</td>
                    <td>
                      <Tier tier={s.tier} score={s.score} />
                      {s.incomplete && <span className="flag"> incomplete</span>}
                    </td>
                    <td>
                      <span
                        className={s.integrity === 'altered' ? 'flag' : 'muted'}
                        title={
                          INTEGRITY_NOTE[s.integrity] ??
                          'This console does not recognise that integrity state.'
                        }
                      >
                        {s.integrity}
                      </span>
                    </td>
                    <td className="muted">{when(s.imported_at)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          {paged.pages > 1 && (
            <div className="pager-foot">
              <Pager
                page={paged}
                unit="scans"
                onPage={paged.setPage}
                onPerPage={paged.setPerPage}
                showPerPage={false}
              />
            </div>
          )}
        </>
      )}
      </div>
    </>
  )
}
