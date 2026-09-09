import { fireEvent, render, screen } from '@testing-library/react'
import type { RuleIndexRow } from '../api/types'
import { RuleBrowser } from './RuleBrowser'

const ROWS: RuleIndexRow[] = [
  { id: 1, identifier: 'AcmeShell', layer: 'own', source_pack: 'shellsight', score: 80,
    description: 'detects the Acme uploader backdoor' },
  { id: 2, identifier: 'DodgyPhp', layer: 'foundation', source_pack: 'yara-forge-core', score: 75,
    description: 'generic php obfuscation' },
  { id: 3, identifier: 'WebShell_ASPX', layer: 'foundation',
    source_pack: 'signature-base-thor-webshells', description: 'aspx webshell, no score' },
]

function show(over: Partial<Parameters<typeof RuleBrowser>[0]> = {}) {
  const added: number[][] = []
  const removed: number[][] = []
  render(
    <RuleBrowser
      rows={ROWS}
      selected={new Set<number>()}
      onAdd={(ids) => added.push(ids)}
      onRemove={(ids) => removed.push(ids)}
      {...over}
    />,
  )
  return { added, removed }
}

test('lists every rule with its layer, pack and score', () => {
  show()
  expect(screen.getByText('AcmeShell')).toBeTruthy()
  expect(screen.getByText('detects the Acme uploader backdoor')).toBeTruthy()
  expect(screen.getByRole('cell', { name: 'shellsight' })).toBeTruthy()
  expect(screen.getByRole('cell', { name: '80' })).toBeTruthy()
})

test('a rule that declared no score shows so, rather than a zero', () => {
  // A zero would read as "scored 0", which is a different and worse claim than "declared none".
  show()
  const cells = screen.getAllByRole('cell', { name: '—' })
  expect(cells.length).toBeGreaterThan(0)
})

test('filtering by description narrows the list', () => {
  show()
  fireEvent.change(screen.getByLabelText(/description/i), { target: { value: 'obfuscation' } })
  expect(screen.getByText('DodgyPhp')).toBeTruthy()
  expect(screen.queryByText('AcmeShell')).toBeNull()
})

test('filtering by identifier narrows the list', () => {
  show()
  fireEvent.change(screen.getByLabelText(/identifier/i), { target: { value: 'acme' } })
  expect(screen.getByText('AcmeShell')).toBeTruthy()
  expect(screen.queryByText('DodgyPhp')).toBeNull()
})

test('a score filter states how many rules it could not judge', () => {
  // Design C4. Without this line an analyst reads "3 matching" as the whole library.
  show()
  expect(screen.queryByText(/could not be judged/i)).toBeNull()
  fireEvent.change(screen.getByLabelText(/minimum score/i), { target: { value: '78' } })
  expect(screen.getByText(/1 rule declares no score and could not be judged/i)).toBeTruthy()
})

test('offers no language filter', () => {
  // Design C5 / D4: lang is empty for every imported rule, so a language filter would match at
  // most 56 of 5,872 while appearing to cover the library.
  show()
  expect(screen.queryByLabelText(/language/i)).toBeNull()
})

test('adding all matching passes exactly the matching ids', () => {
  const { added } = show()
  fireEvent.change(screen.getByLabelText(/identifier/i), { target: { value: 'shell' } })
  fireEvent.click(screen.getByRole('button', { name: /add all 2/i }))
  expect(added).toEqual([[1, 3]])
})

test('removing all matching passes exactly the matching ids', () => {
  const { removed } = show({ selected: new Set([1, 2, 3]) })
  fireEvent.change(screen.getByLabelText(/identifier/i), { target: { value: 'php' } })
  fireEvent.click(screen.getByRole('button', { name: /remove all 1/i }))
  expect(removed).toEqual([[2]])
})

test('a row checkbox reflects membership and toggles one rule', () => {
  const { added, removed } = show({ selected: new Set([2]) })
  const boxes = screen.getAllByRole('checkbox', { name: /select rule/i })
  expect((boxes[0] as HTMLInputElement).checked).toBe(false)
  expect((boxes[1] as HTMLInputElement).checked).toBe(true)

  fireEvent.click(boxes[0] as HTMLElement)
  expect(added).toEqual([[1]])
  fireEvent.click(boxes[1] as HTMLElement)
  expect(removed).toEqual([[2]])
})

test('an empty result says so instead of showing an empty table', () => {
  show()
  fireEvent.change(screen.getByLabelText(/identifier/i), { target: { value: 'zzzz' } })
  expect(screen.getByText(/no rules match/i)).toBeTruthy()
})

const many = (n: number): RuleIndexRow[] =>
  Array.from({ length: n }, (_, i) => ({
    id: i + 1,
    identifier: `rule_${String(i).padStart(4, '0')}`,
    layer: 'foundation',
    source_pack: 'yara-forge-core',
  }))

test('a long result is paged, and the page states the range and the total', () => {
  // This used to render the first 200 and say so. Honest, but it left rows 201..n reachable only
  // by guessing a filter that isolated them -- the library has 5,872.
  show({ rows: many(260) })
  expect(screen.getAllByText(/1–50/).length).toBeGreaterThan(0)
  expect(screen.getAllByText(/of 260 rules/).length).toBeGreaterThan(0)
  expect(screen.getAllByRole('row').length).toBe(51) // 50 rules + the header row
  // Add-all must still act on ALL matches, not on the rendered page.
  expect(screen.getByRole('button', { name: /add all 260/i })).toBeTruthy()
})

test('the tail of a long result is reachable by paging to it', () => {
  // The whole point of replacing the cap: rule 260 has to be viewable from this screen.
  show({ rows: many(260) })
  expect(screen.queryByText('rule_0259')).toBeNull()
  fireEvent.click(screen.getAllByRole('button', { name: /last page/i })[0] as HTMLElement)
  expect(screen.getByText('rule_0259')).toBeTruthy()
})

test('filtering down from a deep page does not land on an empty one', () => {
  // An analyst on page 6 types a filter matching three rules. An unclamped slice would show them
  // an empty table and the words "no rules match" about a filter that matches three.
  show({ rows: many(260) })
  fireEvent.click(screen.getAllByRole('button', { name: /last page/i })[0] as HTMLElement)
  fireEvent.change(screen.getByLabelText(/identifier/i), { target: { value: 'rule_0007' } })
  expect(screen.getByText('rule_0007')).toBeTruthy()
  expect(screen.queryByText(/no rules match/i)).toBeNull()
})
