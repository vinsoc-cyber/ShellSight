import { useMemo, useState } from 'react'
import { Link } from 'react-router-dom'
import { api } from '../api'
import { Pager } from '../components/Pager'
import { Empty, ErrorBox, Loading } from '../components/States'
import { asError, useAsync } from '../lib/useAsync'
import { usePaged } from '../lib/usePaged'

// Cases are the unit of evidence retention: every scan is filed under one, and a decision records
// the case it was made in so a later engagement can see where a judgement came from.
export function Cases() {
  const { data, error, loading, reload } = useAsync(() => api.cases.list(), [])
  const [name, setName] = useState('')
  const [q, setQ] = useState('')
  const [busy, setBusy] = useState(false)
  const [createError, setCreateError] = useState<Error | null>(null)

  async function create() {
    setBusy(true)
    setCreateError(null)
    try {
      await api.cases.create(name.trim())
      // Only clear the field on success. Wiping it on failure would lose what was typed along
      // with the reason it was rejected.
      setName('')
      reload()
    } catch (e) {
      setCreateError(asError(e))
    } finally {
      setBusy(false)
    }
  }

  const all = useMemo(() => data ?? [], [data])
  // A console that has run for a year holds hundreds of cases, and the one being worked is
  // usually known by name.
  const matching = useMemo(() => {
    const needle = q.trim().toLowerCase()
    if (needle === '') return all
    return all.filter(
      (c) =>
        c.name.toLowerCase().includes(needle) || c.created_by.toLowerCase().includes(needle),
    )
  }, [all, q])
  const paged = usePaged(matching, q, 25)

  return (
    <>
      <div className="panel">
        <h3>Open a case</h3>
        <div className="row">
          <label htmlFor="newcase">New case</label>
          <input
            id="newcase"
            style={{ flex: '1 1 18rem' }}
            value={name}
            placeholder="IR-2026-014 Acme"
            onChange={(e) => setName(e.target.value)}
          />
          <button
            type="button"
            className="primary"
            disabled={name.trim() === '' || busy}
            onClick={create}
          >
            Open case
          </button>
        </div>
        {createError && <ErrorBox error={createError} />}
      </div>

      <div className="panel">
        <div className="toolbar">
          <h3>Cases</h3>
          <span className={`count-chip${q.trim() !== '' ? ' filtered' : ''}`}>
            {matching.length.toLocaleString()} cases
          </span>
          <div className="search">
            <input
              aria-label="Search cases"
              placeholder="case or analyst"
              value={q}
              onChange={(e) => setQ(e.target.value)}
            />
          </div>
          <span className="grow" />
          <Pager page={paged} unit="cases" onPage={paged.setPage} onPerPage={paged.setPerPage} />
        </div>

        {loading && <Loading what="cases" />}
        {error && <ErrorBox error={error} retry={reload} />}
        {!loading && all.length === 0 && (
          <Empty>No cases yet. Open one above, then import a run folder into it.</Empty>
        )}
        {all.length > 0 && matching.length === 0 && <Empty>No case matches that search.</Empty>}
        {paged.rows.length > 0 && (
          <div className="scroll">
            <table>
              <thead>
                <tr>
                  <th>Case</th>
                  <th>Opened by</th>
                  <th>Opened</th>
                </tr>
              </thead>
              <tbody>
                {paged.rows.map((c) => (
                  <tr key={c.id}>
                    <td>
                      <Link to={`/cases/${c.id}`}>{c.name}</Link>
                    </td>
                    <td>{c.created_by}</td>
                    <td className="muted">{when(c.created_at)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </>
  )
}

// A timestamp this console cannot parse is shown verbatim rather than as "Invalid Date".
export function when(ts: string): string {
  if (!ts) return '—'
  const d = new Date(ts)
  return Number.isNaN(d.getTime()) ? ts : d.toLocaleString()
}
