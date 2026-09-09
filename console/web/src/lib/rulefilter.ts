import type { RuleIndexRow } from '../api/types'

// The rule browser's filter, as data. Kept out of the component so the rules about what matches
// what are tested directly instead of through a rendered table.
export type RuleFilter = {
  identifier: string
  description: string
  layers: string[]
  packs: string[]
  minScore: number | null
}

export const EMPTY_FILTER: RuleFilter = {
  identifier: '',
  description: '',
  layers: [],
  packs: [],
  minScore: null,
}

function has(haystack: string | undefined, needle: string): boolean {
  return (haystack ?? '').toLowerCase().includes(needle.trim().toLowerCase())
}

export function matches(r: RuleIndexRow, f: RuleFilter): boolean {
  if (f.identifier.trim() !== '' && !has(r.identifier, f.identifier)) return false
  if (f.description.trim() !== '' && !has(r.description, f.description)) return false
  // An empty checkbox group means "no constraint", never "match nothing" -- otherwise a fresh
  // screen would look like an empty library.
  if (f.layers.length > 0 && !f.layers.includes(r.layer)) return false
  if (f.packs.length > 0 && !f.packs.includes(r.source_pack ?? '(none)')) return false
  // A rule that declared no score cannot satisfy "at least N". Including it would put unscored
  // rules in a set the analyst believes is score-filtered.
  if (f.minScore !== null && (r.score === undefined || r.score < f.minScore)) return false
  return true
}

// unjudgedByScore is how many rules the score filter could not judge, because they declare no
// score. Design C4: a filter on an optional key must say so rather than silently shrinking the
// library. Returns 0 when no score filter is active.
export function unjudgedByScore(rows: RuleIndexRow[], f: RuleFilter): number {
  if (f.minScore === null) return 0
  return rows.filter((r) => r.score === undefined).length
}

// countBy gives each checkbox its population, so an empty layer reads as empty rather than broken.
export function countBy(rows: RuleIndexRow[], key: 'layer' | 'source_pack'): Record<string, number> {
  const out: Record<string, number> = {}
  for (const r of rows) {
    const v = (key === 'layer' ? r.layer : r.source_pack) || '(none)'
    out[v] = (out[v] ?? 0) + 1
  }
  return out
}
