import type { RuleIndexRow } from '../api/types'
import { EMPTY_FILTER, countBy, matches, unjudgedByScore } from './rulefilter'

const ROWS: RuleIndexRow[] = [
  { id: 1, identifier: 'AcmeShell', layer: 'own', source_pack: 'shellsight', score: 80,
    description: 'detects the Acme uploader backdoor' },
  { id: 2, identifier: 'DodgyPhp', layer: 'foundation', source_pack: 'yara-forge-core', score: 75,
    description: 'generic php obfuscation' },
  { id: 3, identifier: 'WebShell_ASPX', layer: 'foundation',
    source_pack: 'signature-base-thor-webshells', description: 'aspx webshell, no score declared' },
]

test('an empty filter matches everything', () => {
  expect(ROWS.filter((r) => matches(r, EMPTY_FILTER))).toHaveLength(3)
})

test('identifier is a case-insensitive substring', () => {
  const got = ROWS.filter((r) => matches(r, { ...EMPTY_FILTER, identifier: 'shell' }))
  expect(got.map((r) => r.id)).toEqual([1, 3])
})

test('description is a case-insensitive substring', () => {
  // The primary curation lever: description is present on ~99% of the library.
  const got = ROWS.filter((r) => matches(r, { ...EMPTY_FILTER, description: 'BACKDOOR' }))
  expect(got.map((r) => r.id)).toEqual([1])
})

test('no selected layers means all layers, not none', () => {
  // An empty checkbox group must not filter everything out; that would make a fresh screen look
  // like an empty library.
  expect(ROWS.filter((r) => matches(r, { ...EMPTY_FILTER, layers: [] }))).toHaveLength(3)
  expect(
    ROWS.filter((r) => matches(r, { ...EMPTY_FILTER, layers: ['foundation'] })).map((r) => r.id),
  ).toEqual([2, 3])
})

test('packs filter the same way', () => {
  const got = ROWS.filter((r) =>
    matches(r, { ...EMPTY_FILTER, packs: ['shellsight', 'signature-base-thor-webshells'] }),
  )
  expect(got.map((r) => r.id)).toEqual([1, 3])
})

test('a minimum score excludes rules that declared no score', () => {
  // 5,450 of 5,872 rules declare a score. A rule with none cannot satisfy "at least 75", and
  // pretending otherwise would put unscored rules in a set the analyst believes is score-filtered.
  const got = ROWS.filter((r) => matches(r, { ...EMPTY_FILTER, minScore: 75 }))
  expect(got.map((r) => r.id)).toEqual([1, 2])
})

test('filters compose with AND', () => {
  const got = ROWS.filter((r) =>
    matches(r, { ...EMPTY_FILTER, layers: ['foundation'], description: 'php' }),
  )
  expect(got.map((r) => r.id)).toEqual([2])
})

test('unjudgedByScore counts what a score filter could not judge, and only while it is active', () => {
  // Design C4: a filter on an optional key must say how many rules it could not judge.
  expect(unjudgedByScore(ROWS, EMPTY_FILTER)).toBe(0)
  expect(unjudgedByScore(ROWS, { ...EMPTY_FILTER, minScore: 75 })).toBe(1)
})

test('countBy gives each checkbox its population', () => {
  expect(countBy(ROWS, 'layer')).toEqual({ own: 1, foundation: 2 })
  expect(countBy(ROWS, 'source_pack')).toEqual({
    shellsight: 1,
    'yara-forge-core': 1,
    'signature-base-thor-webshells': 1,
  })
})

test('countBy tolerates a missing pack rather than dropping the row', () => {
  const rows: RuleIndexRow[] = [{ id: 9, identifier: 'X', layer: 'own' }]
  expect(countBy(rows, 'source_pack')).toEqual({ '(none)': 1 })
})
