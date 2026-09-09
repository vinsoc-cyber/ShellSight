import { fireEvent, render, screen } from '@testing-library/react'
import type { Finding, Group } from '../api/types'
import { FindingGroup } from './FindingGroup'

const finding = (over: Partial<Finding> = {}): Finding => ({
  id: 1,
  ref: 'aaa-ObfuscatedPhp',
  content_key: 'sha256:70d72d557',
  host: 'web-01',
  view: 'disk',
  file_path: 'C:\\www\\shell.php',
  file_sha256: '70d72d557',
  basis: 'signature',
  knowledge_ref: 'kb:yara/ObfuscatedPhp',
  evidence: 'eval($_POST',
  score: 90,
  tier: 'confirmed',
  ...over,
})

const group = (over: Partial<Group> = {}): Group => ({
  content_key: 'sha256:70d72d557',
  tier: 'confirmed',
  score: 90,
  locations: 1,
  hosts: ['web-01'],
  rules: ['kb:yara/ObfuscatedPhp', 'kb:yara/DodgyPhp'],
  findings: [finding(), finding({ id: 2, ref: 'aaa-DodgyPhp', knowledge_ref: 'kb:yara/DodgyPhp' })],
  prior_decisions: [],
  ...over,
})

test('one group is one queue item, however many rules matched', () => {
  render(<FindingGroup group={group()} onDecide={async () => {}} />)
  // Two rules fired on one file. The analyst sees ONE item saying so.
  expect(screen.getByText(/2 rules/i)).toBeTruthy()
})

test('shows how many places the content was found, and on which hosts', () => {
  render(
    <FindingGroup
      group={group({ locations: 12, hosts: ['web-01', 'web-02', 'web-03', 'web-04'] })}
      onDecide={async () => {}}
    />,
  )
  expect(screen.getByText(/12 locations/i)).toBeTruthy()
  expect(screen.getByText(/4 hosts/i)).toBeTruthy()
})

test('the content hash is shown, because it is what the decision attaches to', () => {
  render(<FindingGroup group={group()} onDecide={async () => {}} />)
  expect(screen.getByText(/sha256:70d72d557/)).toBeTruthy()
})

test('a prior decision is surfaced BEFORE the analyst decides again', () => {
  // The point of keying decisions on content: a judgement made on one engagement must reach the
  // analyst on the next host holding the same bytes, before they re-litigate it.
  render(
    <FindingGroup
      group={group({
        prior_decisions: [
          {
            id: 1,
            content_key: 'sha256:70d72d557',
            verdict: 'false-positive',
            note: 'vendor plugin, minified',
            author: 'v.quannh67',
            case_name: 'IR-2026-002 Globex',
            decided_at: '2026-08-11T09:00:00Z',
          },
        ],
      })}
      onDecide={async () => {}}
    />,
  )
  // Assert against the prior-decision LINE, not the page. Every verdict string is also a decide
  // button label, so a page-wide getByText(/false-positive/) matches two elements and throws --
  // and getAllByText would let a missing prior line pass so long as the button exists, which
  // destroys the thing this test exists to prove.
  const prior = screen.getByRole('listitem')
  expect(prior.textContent).toMatch(/false-positive/)
  expect(prior.textContent).toMatch(/IR-2026-002 Globex/)
  expect(prior.textContent).toMatch(/vendor plugin, minified/)
  expect(prior.textContent).toMatch(/v\.quannh67/)
})

test('expanding shows each matching rule with its evidence and basis', () => {
  render(<FindingGroup group={group()} onDecide={async () => {}} />)
  fireEvent.click(screen.getByRole('button', { name: /2 rules/i }))
  expect(screen.getByText('kb:yara/ObfuscatedPhp')).toBeTruthy()
  expect(screen.getByText('kb:yara/DodgyPhp')).toBeTruthy()
  expect(screen.getAllByText(/eval\(\$_POST/).length).toBeGreaterThan(0)
  expect(screen.getAllByText('signature').length).toBeGreaterThan(0)
})

test('evidence from a report is rendered as text, never as markup', () => {
  // Evidence is a matched substring of attacker-controlled content. This is the sharpest XSS
  // surface in the whole console.
  const { container } = render(
    <FindingGroup
      group={group({
        rules: ['kb:yara/ObfuscatedPhp'],
        findings: [finding({ evidence: '<img src=x onerror=alert(1)>' })],
      })}
      onDecide={async () => {}}
    />,
  )
  fireEvent.click(screen.getByRole('button', { name: /1 rule/i }))
  expect(screen.getByText(/onerror/)).toBeTruthy()
  expect(container.querySelector('img')).toBeNull()
})

test('a memory finding with no file shows its artifact identity instead of blank', () => {
  render(
    <FindingGroup
      group={group({
        content_key: 'artifact:org.apache.Filter',
        rules: ['kb:yara/ObfuscatedPhp'],
        findings: [
          finding({
            file_path: undefined,
            file_sha256: undefined,
            view: 'java-mem',
            artifact_kind: 'class',
            artifact_id: 'org.apache.Filter',
          }),
        ],
      })}
      onDecide={async () => {}}
    />,
  )
  fireEvent.click(screen.getByRole('button', { name: /1 rule/i }))
  // The identity also appears in the header's content_key, so match the WHERE cell specifically:
  // whereOf() renders "<kind> <identity>", which only that cell produces.
  expect(screen.getByText('class org.apache.Filter')).toBeTruthy()
})

test('deciding reports the content key and the chosen verdict', async () => {
  const seen: { key: string; verdict: string; note: string }[] = []
  render(
    <FindingGroup
      group={group()}
      onDecide={async (key, verdict, note) => {
        seen.push({ key, verdict, note })
      }}
    />,
  )
  // The decide row opens on demand. Rendered for every group it put a note field and four buttons
  // on screen once per finding -- 136 buttons down a 34-group queue.
  fireEvent.click(screen.getByRole('button', { name: /^judge$/i }))
  fireEvent.change(screen.getByLabelText(/note/i), { target: { value: 'confirmed by hand' } })
  fireEvent.click(screen.getByRole('button', { name: /^malicious$/i }))

  expect(seen).toEqual([
    { key: 'sha256:70d72d557', verdict: 'malicious', note: 'confirmed by hand' },
  ])
})

test('offers exactly the four verdicts the API accepts', () => {
  render(<FindingGroup group={group()} onDecide={async () => {}} />)
  fireEvent.click(screen.getByRole('button', { name: /^judge$/i }))
  for (const v of ['malicious', 'false-positive', 'benign-noteworthy', 'undecided']) {
    expect(screen.getByRole('button', { name: new RegExp(`^${v}$`, 'i') })).toBeTruthy()
  }
})

test('the decide controls stay closed until asked for', () => {
  // A queue is read before it is answered. 34 groups each rendering a note field and four verdict
  // buttons is 136 controls competing with the findings they are about.
  render(<FindingGroup group={group()} onDecide={async () => {}} />)
  expect(screen.queryByRole('button', { name: /^malicious$/i })).toBeNull()
  expect(screen.queryByLabelText(/note/i)).toBeNull()
  expect(screen.getByRole('button', { name: /^judge$/i })).toBeTruthy()
})

test('a group that already carries a judgement offers to judge it AGAIN, not afresh', () => {
  // "Judge" on a group someone already answered invites a second opinion without saying one
  // exists; the prior decision is rendered right above, and the verb should agree with it.
  render(
    <FindingGroup
      group={group({
        prior_decisions: [
          {
            id: 1,
            content_key: 'sha256:70d72d557',
            verdict: 'malicious',
            author: 'lan.nguyen',
            decided_at: '2026-08-22T10:40:00Z',
          },
        ],
      })}
      onDecide={async () => {}}
    />,
  )
  expect(screen.getByRole('button', { name: /judge again/i })).toBeTruthy()
})
