import { useState } from 'react'
import { api } from '../api'
import type { Selection } from '../api/types'
import { ErrorBox, Loading } from '../components/States'
import { asError, useAsync } from '../lib/useAsync'
import { RuleBrowser } from './RuleBrowser'

const LAYERS = ['foundation', 'own', 'custom'] as const

// Edits a DRAFT set's selection. It is mounted only once the saved selection has loaded, so
// useState seeds at mount -- seeding from a useEffect instead leaves one commit in which the
// controls exist but hold nothing, and a click in that commit is a silent no-op.
export function SelectionEditor({
  setID,
  initial,
  exclusions,
}: {
  setID: number
  initial: Selection
  exclusions: number
}) {
  const index = useAsync(() => api.rules.index(), [])
  // `exclusions` is in the deps because an exclusion CHANGES THE COUNT: the resolver subtracts
  // excluded rules, so a set that resolved to 4,402 resolves to 4,401 the moment one is excluded.
  // Keyed on setID alone, the number stayed at the pre-exclusion figure until the panel was
  // remounted -- an analyst excluding three rules watched the count not move and reasonably
  // concluded the exclusions had not taken.
  const resolved = useAsync(() => api.rulesets.resolvedCount(setID), [setID, exclusions])

  const [layers, setLayers] = useState<string[]>(initial.layers ?? [])
  const [rules, setRules] = useState<number[]>(initial.rules ?? [])
  const [dirty, setDirty] = useState(false)
  const [saveError, setSaveError] = useState<Error | null>(null)
  const [busy, setBusy] = useState(false)

  function add(ids: number[]) {
    setRules((cur) => Array.from(new Set([...cur, ...ids])))
    setDirty(true)
  }
  function remove(ids: number[]) {
    const drop = new Set(ids)
    setRules((cur) => cur.filter((id) => !drop.has(id)))
    setDirty(true)
  }
  function toggleLayer(l: string) {
    setLayers((cur) => (cur.includes(l) ? cur.filter((v) => v !== l) : [...cur, l]))
    setDirty(true)
  }

  async function save() {
    setBusy(true)
    setSaveError(null)
    try {
      await api.rulesets.setSelection(setID, { layers, rules })
      setDirty(false)
      // Re-read rather than adjusting a local number: the count depends on union semantics and on
      // exclusions, so only the server knows it.
      resolved.reload()
    } catch (e) {
      setSaveError(asError(e))
    } finally {
      setBusy(false)
    }
  }

  return (
    <>
      <div className="row">
        <span className="muted small">Layers</span>
        {LAYERS.map((l) => (
          <label key={l} className="chk">
            <input
              type="checkbox"
              aria-label={`include layer ${l}`}
              checked={layers.includes(l)}
              onChange={() => toggleLayer(l)}
            />
            {l}
          </label>
        ))}
        <span className="muted">Named rules: {rules.length}</span>
        <span className="muted">Exclusions: {exclusions}</span>
      </div>

      <div className="row">
        {resolved.loading && <Loading what="the resolved count" />}
        {resolved.error && <ErrorBox error={resolved.error} retry={resolved.reload} />}
        {resolved.data && (
          <strong>
            Resolves to {resolved.data.count.toLocaleString()}{' '}
            {resolved.data.count === 1 ? 'rule' : 'rules'}
          </strong>
        )}
        {dirty && (
          <span className="flag">
            unsaved — the count above is for the saved selection until you save
          </span>
        )}
        <button type="button" disabled={busy || !dirty} onClick={save}>
          Save selection
        </button>
      </div>

      {resolved.data?.count === 0 && (
        <p className="qualify small">
          This set applies no rules, so generating an agent from it <strong>would be refused</strong>.
          Select a layer or add rules below.
        </p>
      )}

      {saveError && <ErrorBox error={saveError} />}

      {index.loading && <Loading what="the rule library" />}
      {index.error && <ErrorBox error={index.error} retry={index.reload} />}
      {index.data && (
        <RuleBrowser
          rows={index.data}
          selected={new Set(rules)}
          onAdd={add}
          onRemove={remove}
        />
      )}
    </>
  )
}
