import { useRef, useState } from 'react'
import { api } from '../api'
import type { Ingested } from '../api/types'
import { ErrorBox } from '../components/States'
import { type RunUpload, groupRunFolders } from '../lib/runfolders'
import { asError } from '../lib/useAsync'

// Importing a scan without a shell on the console box.
//
// Until now the only way in was `console import-report`, which takes a -dsn and talks to Postgres
// directly -- so importing required a database URL and a terminal on the server. The scanner runs
// on the TARGET host, so its run folders are on the analyst's laptop or a share, never on the
// console. This is the same ingest, reached over HTTP.

type Outcome = Ingested & { name: string }
type Failure = { name: string; message: string }

export function ImportRuns({ caseID, onImported }: { caseID: number; onImported: () => void }) {
  const [picked, setPicked] = useState<ReturnType<typeof groupRunFolders> | null>(null)
  const [busy, setBusy] = useState(false)
  // Progress is per-run, not a spinner: forty folders is a minute of uploading and an analyst
  // watching a blank button cannot tell a slow import from a stuck one.
  const [done, setDone] = useState<Outcome[]>([])
  const [failed, setFailed] = useState<Failure[]>([])
  const [error, setError] = useState<Error | null>(null)
  const folderInput = useRef<HTMLInputElement>(null)
  const fileInput = useRef<HTMLInputElement>(null)

  function choose(list: FileList | null) {
    setDone([])
    setFailed([])
    setError(null)
    setPicked(list ? groupRunFolders(Array.from(list)) : null)
  }

  async function send(runs: RunUpload[]) {
    setBusy(true)
    setError(null)
    setDone([])
    setFailed([])
    const ok: Outcome[] = []
    const bad: Failure[] = []
    for (const run of runs) {
      try {
        const res = await api.cases.importReport(caseID, run.report, run.manifest)
        ok.push({ ...res, name: run.name })
      } catch (e) {
        // One bad folder must not abandon the other thirty-nine -- the same rule the CLI follows.
        bad.push({ name: run.name, message: asError(e).message })
      }
      setDone([...ok])
      setFailed([...bad])
    }
    setBusy(false)
    setPicked(null)
    if (folderInput.current) folderInput.current.value = ''
    if (fileInput.current) fileInput.current.value = ''
    if (ok.length > 0) onImported()
  }

  const runs = picked?.runs ?? []

  return (
    <div className="panel">
      <div className="toolbar">
        <h3>Import a scan</h3>
        <span className="grow" />
      </div>

      <div className="row">
        <label htmlFor="run-folder">Run folders</label>
        <input
          id="run-folder"
          ref={folderInput}
          type="file"
          multiple
          // Not in the TS DOM types: a directory pick is what makes bulk import one action.
          {...({ webkitdirectory: '', directory: '' } as Record<string, string>)}
          onChange={(e) => choose(e.target.files)}
        />
        <span className="muted small">or</span>
        <label htmlFor="run-files">Individual files</label>
        <input
          id="run-files"
          ref={fileInput}
          type="file"
          multiple
          accept="application/json,.json"
          onChange={(e) => choose(e.target.files)}
        />
      </div>

      <details className="explain">
        <summary>What to select</summary>
        <div className="explain-body">
          <p>
            Point <strong>Run folders</strong> at the directory holding your{' '}
            <code>run_&lt;host&gt;_&lt;id&gt;</code> folders — one pick imports all of them.
          </p>
          <p>
            Only <code>report.json</code> is read: it is the one file carrying the verdict,
            coverage and skips. <code>manifest.json</code> is sent when present and is what makes
            a scan <em>verified</em> rather than <em>unverified</em>; the check is
            self-consistency, not proof of origin. <code>summary.txt</code> and{' '}
            <code>findings.ndjson</code> are ignored.
          </p>
          <p>
            Re-importing a run already filed here is not an error — it is reported as already
            present and nothing is duplicated.
          </p>
        </div>
      </details>

      {picked && runs.length === 0 && (
        <p className="qualify small">
          Nothing here to import. A run folder is one containing <code>report.json</code>.
        </p>
      )}

      {picked && picked.incomplete.length > 0 && (
        <p className="qualify small">
          {picked.incomplete.length}{' '}
          {picked.incomplete.length === 1 ? 'folder has' : 'folders have'} a manifest but no{' '}
          <code>report.json</code>, so {picked.incomplete.length === 1 ? 'it was' : 'they were'}{' '}
          skipped: <span className="mono">{picked.incomplete.join(', ')}</span>
        </p>
      )}

      {runs.length > 0 && (
        <div className="row">
          <span className="count-chip">
            {runs.length} {runs.length === 1 ? 'run' : 'runs'} ready
          </span>
          <span className="muted small">
            {runs.filter((r) => r.manifest).length} with a manifest
          </span>
          <button type="button" className="primary" disabled={busy} onClick={() => send(runs)}>
            {busy ? `Importing… ${done.length + failed.length} of ${runs.length}` : 'Import'}
          </button>
        </div>
      )}

      {error && <ErrorBox error={error} />}

      {(done.length > 0 || failed.length > 0) && (
        <div className="scroll">
          <table>
            <thead>
              <tr>
                <th>Run folder</th>
                <th>Result</th>
                <th>Host</th>
                <th className="num">Findings</th>
                <th>Integrity</th>
              </tr>
            </thead>
            <tbody>
              {done.map((d) => (
                <tr key={d.name}>
                  <td className="mono">{d.name}</td>
                  <td className={d.created ? 'ok' : 'muted'}>
                    {d.created ? 'imported' : 'already present'}
                  </td>
                  <td>{d.host}</td>
                  <td className="num">{d.findings.toLocaleString()}</td>
                  <td className={d.integrity === 'altered' ? 'flag' : 'muted'}>{d.integrity}</td>
                </tr>
              ))}
              {failed.map((f) => (
                <tr key={f.name} className="row-bad">
                  <td className="mono">{f.name}</td>
                  <td colSpan={4}>
                    <strong className="flag">failed</strong>{' '}
                    <span className="muted">— {f.message}</span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}
