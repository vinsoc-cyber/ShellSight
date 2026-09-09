import { useState } from 'react'
import { useNavigate, useParams } from 'react-router-dom'
import { api } from '../api'
import { ApiError } from '../api/http'
import type { Rule, RuleRevision } from '../api/types'
import { ErrorBox, Loading } from '../components/States'
import { asError, useAsync } from '../lib/useAsync'

// Rule authoring is free: no approval, no lifecycle, no measurement gate. The only refusal is a
// rule that does not compile, and the console answers that with 422 -- a CONTENT rejection, not a
// protocol error. So the compiler's message belongs beside the text an analyst is editing, and a
// 500 belongs in a failure banner. Collapsing the two would tell an analyst their console is
// broken when their rule is.
//
// This outer component ONLY loads. The editor below is not mounted until its initial text is
// known, so its state can be seeded by useState at mount. Seeding from a useEffect instead leaves
// one commit in which the textarea exists holding "" -- and in that commit Save is disabled,
// because empty text disables it, so a click lands on a no-op. That is not a test artifact: an
// analyst who reached the field that fast would see an empty editor for a rule that has text.
export function RuleEditor() {
  const { ruleID } = useParams()
  const isNew = ruleID === undefined
  const id = Number(ruleID)

  const langs = useAsync(() => api.rules.langs(), [])
  const existing = useAsync(() => (isNew ? Promise.resolve(null) : api.rules.get(id)), [id, isNew])

  if (existing.loading || langs.loading) return <Loading what="the rule" />
  if (existing.error) return <ErrorBox error={existing.error} retry={existing.reload} />

  return (
    <Editor
      isNew={isNew}
      id={id}
      rule={existing.data?.rule ?? null}
      revision={existing.data?.revision ?? null}
      langs={langs.data ?? []}
    />
  )
}

function Editor({
  isNew,
  id,
  rule,
  revision,
  langs,
}: {
  isNew: boolean
  id: number
  rule: Rule | null
  revision: RuleRevision | null
  langs: string[]
}) {
  // Seeded at mount, which is only reached once the revision has loaded.
  const [text, setText] = useState(revision?.text ?? '')
  const [lang, setLang] = useState(revision?.lang ?? '')
  const [compileError, setCompileError] = useState<string | null>(null)
  const [failure, setFailure] = useState<Error | null>(null)
  const [saved, setSaved] = useState<number | null>(null)
  const [busy, setBusy] = useState(false)
  const navigate = useNavigate()

  // D7: foundation rule text is never editable. Offering a save the API will refuse would be a
  // lie told by the UI, so the editor is read-only and says why.
  const readOnly = rule?.layer === 'foundation'

  async function save() {
    setBusy(true)
    setCompileError(null)
    setFailure(null)
    setSaved(null)
    try {
      if (isNew) {
        // Go to the rule that was just created, so this screen stops being "write a rule" the
        // instant one exists. Staying put left the same text in an enabled editor, and a second
        // Save -- a double click, or an analyst who did not see the confirmation line -- wrote a
        // SECOND rule with identical text. The busy flag cannot catch that: it is already false.
        const { id } = await api.rules.create('own', text, lang)
        navigate(`/rules/${id}`, { replace: true })
        return
      } else {
        const { revision: next } = await api.rules.edit(id, text, lang)
        setSaved(next)
      }
    } catch (e) {
      if (e instanceof ApiError && e.rejectedContent) {
        setCompileError(e.message)
      } else {
        setFailure(asError(e))
      }
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="panel">
      <div className="row">
        <h3>{isNew ? 'Write a rule' : rule?.identifier}</h3>
        {revision && (
          <span className="muted">
            revision {revision.revision} · {revision.author}
          </span>
        )}
        {rule?.source_pack && <span className="muted">from {rule.source_pack}</span>}
      </div>

      {readOnly && (
        <p className="qualify">
          Foundation rules are <strong>exclude-only</strong>: their text is never edited here. To
          stop this rule firing for an engagement, exclude it from that rule set instead.
        </p>
      )}

      <div className="row">
        <label htmlFor="lang">Language</label>
        <select id="lang" value={lang} disabled={readOnly} onChange={(e) => setLang(e.target.value)}>
          <option value="">none declared</option>
          {langs.map((l) => (
            <option key={l} value={l}>
              {l}
            </option>
          ))}
        </select>
      </div>

      <label htmlFor="text" className="block-label">
        Rule text
      </label>
      <textarea
        id="text"
        className="mono editor"
        value={text}
        readOnly={readOnly}
        spellCheck={false}
        onChange={(e) => setText(e.target.value)}
      />

      {compileError && (
        <pre className="compile-error mono" data-testid="compile-error">
          {compileError}
        </pre>
      )}
      {failure && <ErrorBox error={failure} />}
      {saved !== null && <p className="ok">Saved as revision {saved}.</p>}

      {!readOnly && (
        <div className="row">
          <button type="button" disabled={busy || text.trim() === ''} onClick={save}>
            Save
          </button>
          <span className="muted small">
            The only check is that it compiles. There is no approval step.
          </span>
        </div>
      )}
    </div>
  )
}
