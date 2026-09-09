import { useState } from 'react'
import { VERDICTS } from '../api/types'
import type { Group } from '../api/types'
import { Tier } from '../components/Tier'
import { when } from './Cases'

// One group is one thing an analyst decides about.
//
// The scanner emits one finding per RULE that matched, so a single webshell can arrive as five.
// An analyst asked to judge the same file five times judges it inconsistently, and the fifth
// judgement teaches them the queue is noise. The group is keyed on the file's content hash, so one
// shell copied into twelve directories across four hosts is one item -- and a decision recorded
// against it reaches the next engagement that finds the same bytes.
export function FindingGroup({
  group,
  onDecide,
}: {
  group: Group
  onDecide: (contentKey: string, verdict: string, note: string) => Promise<void>
}) {
  const [open, setOpen] = useState(false)
  // The decide row is opened, not always shown. Rendered for every group it put a text field and
  // four buttons on screen 34 times over -- 136 buttons down one page, of which an analyst uses
  // the four belonging to the one group they are reading. Collapsed, the queue is a list of
  // findings again rather than a wall of identical controls.
  const [deciding, setDeciding] = useState(false)
  const [note, setNote] = useState('')
  const [busy, setBusy] = useState(false)
  const ruleCount = group.rules.length || group.findings.length
  const judged = group.prior_decisions.length > 0

  async function decide(verdict: string) {
    setBusy(true)
    try {
      await onDecide(group.content_key, verdict, note)
      setDeciding(false)
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className={`group group-${group.tier}${judged ? ' decided' : ''}`}>
      <div className="group-head">
        <Tier tier={group.tier} score={group.score} />
        <button type="button" className="link" onClick={() => setOpen(!open)}>
          {open ? '▾' : '▸'} {ruleCount} {ruleCount === 1 ? 'rule' : 'rules'} matched
        </button>
        <span className="muted">
          {group.locations} {group.locations === 1 ? 'location' : 'locations'} ·{' '}
          {group.hosts.length} {group.hosts.length === 1 ? 'host' : 'hosts'}
        </span>
        <span style={{ flex: '1 1 auto' }} />
        {!deciding && (
          <button type="button" onClick={() => setDeciding(true)}>
            {judged ? 'Judge again' : 'Judge'}
          </button>
        )}
      </div>

      <div className="group-meta">
        <span>{group.hosts.join(', ')}</span>
        {/* The content key is the identity a decision is recorded against, so it must be present
            and comparable -- but it is 64 characters of hex and not something anyone reads. */}
        <span className="mono hash" title={group.content_key}>
          {group.content_key}
        </span>
      </div>

      {group.prior_decisions.length > 0 && (
        <div className="prior">
          <strong>Already judged:</strong>
          <ul>
            {group.prior_decisions.map((d) => (
              <li key={d.id}>
                <span className={`verdict-${d.verdict}`}>{d.verdict}</span> by {d.author}
                {d.case_name && <> in {d.case_name}</>} on {when(d.decided_at)}
                {d.note && <> — {d.note}</>}
              </li>
            ))}
          </ul>
        </div>
      )}

      {open && (
        <div className="scroll">
          <table>
            <thead>
              <tr>
                <th>Rule</th>
                <th>Basis</th>
                <th>Where</th>
                <th>Evidence</th>
              </tr>
            </thead>
            <tbody>
              {group.findings.map((f) => (
                <tr key={f.id}>
                  <td className="mono">{f.knowledge_ref || f.ref}</td>
                  <td>{f.basis}</td>
                  <td className="mono small">{whereOf(f)}</td>
                  {/* Evidence is a matched substring of attacker-controlled content. React escapes
                      it; it must never be handed to dangerouslySetInnerHTML. */}
                  <td className="mono small evidence">{f.evidence || '—'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {deciding && (
        <div className="row decide">
          <label htmlFor={`note-${group.content_key}`}>Note</label>
          <input
            id={`note-${group.content_key}`}
            value={note}
            placeholder="why (optional)"
            onChange={(e) => setNote(e.target.value)}
          />
          {VERDICTS.map((v) => (
            <button key={v} type="button" data-verdict={v} disabled={busy} onClick={() => decide(v)}>
              {v}
            </button>
          ))}
          <button type="button" className="link" onClick={() => setDeciding(false)}>
            cancel
          </button>
        </div>
      )}
    </div>
  )
}

// A memory-view finding carries no file, so showing a blank cell would hide what was found. Fall
// back to the artifact identity -- a class or module name -- which is what those findings group on.
export function whereOf(f: {
  file_path?: string
  artifact_id?: string
  artifact_kind?: string
  host: string
}): string {
  if (f.file_path) return f.file_path
  if (f.artifact_id) return f.artifact_kind ? `${f.artifact_kind} ${f.artifact_id}` : f.artifact_id
  return f.host
}
