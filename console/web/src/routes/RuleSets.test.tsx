import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { RuleSets } from './RuleSets'

const SETS = [
  {
    id: 2,
    name: 'sweep-feb',
    version: null,
    created_by: 'v.quannh67',
    frozen_at: null,
  },
  {
    id: 1,
    name: 'sweep-jan',
    version: 4,
    created_by: 'v.quannh67',
    frozen_at: '2026-08-11T09:00:00Z',
    frozen_by: 'v.quannh67',
    yarc_sha256: 'ab12cd34ef56',
  },
]

// Deliberately does NOT reuse the exclusion fixture's identifier: a frozen set renders both the
// pinned table and the exclusions table, so a shared name makes every query ambiguous.
const MEMBERS = [
  { rule_id: 3, identifier: 'DodgyPhp', layer: 'foundation', revision: 2 },
  { rule_id: 9, identifier: 'AcmeShell', layer: 'own', revision: 1 },
]

// A draft's panel now loads the whole rule library through GET /api/rules/index. Identifiers are
// chosen not to collide with MEMBERS or the exclusion fixture, for the reason given above.
const INDEX = [
  { id: 11, identifier: 'LibShellOne', layer: 'own', source_pack: 'shellsight', score: 80 },
  { id: 12, identifier: 'LibShellTwo', layer: 'custom', source_pack: 'analyst', score: 70 },
]

function server(
  opts: {
    excludeStatus?: number
    excludeError?: string
    members?: { rule_id: number; identifier: string; layer: string; revision: number }[]
  } = {},
) {
  const sent: { url: string; init: RequestInit }[] = []
  vi.stubGlobal(
    'fetch',
    vi.fn((url: string, init?: RequestInit) => {
      const method = init?.method ?? 'GET'
      if (method !== 'GET') {
        sent.push({ url, init: init as RequestInit })
        const status = url.includes('/exclusions') ? (opts.excludeStatus ?? 201) : 200
        if (status >= 400) {
          return Promise.resolve({
            ok: false,
            status,
            statusText: 'ERR',
            json: () => Promise.resolve({ error: opts.excludeError ?? 'rejected' }),
          } as Response)
        }
        return Promise.resolve({
          ok: true,
          status,
          statusText: 'OK',
          json: () => Promise.resolve({}),
        } as Response)
      }
      let body: unknown = SETS
      // A draft's panel also asks the SERVER for the resolved count. Without these two branches
      // the fall-through default (SETS) reaches SelectionEditor as {count: undefined}, whose
      // .toLocaleString() throws during render and empties the whole tree.
      if (url.includes('/api/rules/index')) body = INDEX
      else if (url.includes('/resolved-count')) body = { count: 57 }
      else if (url.includes('/members')) body = opts.members ?? MEMBERS
      else if (url.includes('/selection')) body = { layers: ['foundation'], rules: [7] }
      else if (url.includes('/exclusions')) {
        body = [
          {
            rule_id: 3,
            identifier: 'NoisyPhp',
            reason: 'fires on the vendor bundle',
            author: 'v.quannh67',
            created_at: '2026-08-12T09:00:00Z',
          },
        ]
      }
      return Promise.resolve({
        ok: true,
        status: 200,
        statusText: 'OK',
        json: () => Promise.resolve(body),
      } as Response)
    }),
  )
  return { sent }
}

function show() {
  return render(
    <MemoryRouter>
      <RuleSets />
    </MemoryRouter>,
  )
}

test('lists rule sets, newest first', async () => {
  server()
  show()
  expect(await screen.findByText('sweep-feb')).toBeTruthy()
  expect(screen.getByText('sweep-jan')).toBeTruthy()
})

test('a frozen set shows its version and the blob it froze to', async () => {
  // A frozen set is the only thing an agent can be built from, and the yarc hash is what ties a
  // scan back to the exact bytes that produced it.
  server()
  show()
  await screen.findByText('sweep-jan')
  expect(screen.getByText(/v4/)).toBeTruthy()
  expect(screen.getByText(/ab12cd34ef56/)).toBeTruthy()
})

test('a draft set is distinguished from a frozen one', async () => {
  server()
  show()
  expect(await screen.findByText(/draft/i)).toBeTruthy()
})

test('selecting a set shows its selection and its exclusions', async () => {
  server()
  show()
  fireEvent.click(await screen.findByRole('button', { name: /sweep-feb/i }))
  expect(await screen.findByText('NoisyPhp')).toBeTruthy()
  expect(screen.getByText(/fires on the vendor bundle/)).toBeTruthy()
  // Scoped to the CHECKED state of the layer control, not a page-wide /foundation/: the draft panel
  // now renders that word as a constant label twice (the selection editor and the browser's layer
  // filter), so the old query matched two elements -- intermittently, since it raced the rule-index
  // fetch. The checkbox state is the stronger claim anyway: it can only be true if the SAVED
  // selection {layers:['foundation']} actually loaded.
  const foundation = (await screen.findByRole('checkbox', {
    name: /include layer foundation/i,
  })) as HTMLInputElement
  expect(foundation.checked).toBe(true)
})

test('an exclusion refused because another rule depends on it is reported verbatim', async () => {
  // The backend refuses rather than warns: 50 of 5,872 rules reference another rule, and
  // excluding one of those silently breaks every rule that names it.
  server({
    excludeStatus: 409,
    excludeError: 'IsPhp is referenced by DodgyPhp; excluding it would break that rule',
  })
  show()
  fireEvent.click(await screen.findByRole('button', { name: /sweep-feb/i }))
  await screen.findByText('NoisyPhp')

  fireEvent.change(screen.getByLabelText(/rule id/i), { target: { value: '7' } })
  // Scoped by selector: the browser's own "Identifier" filter now carries the same label text, so
  // an unscoped query matches two inputs. #exident is the exclusion form's.
  fireEvent.change(screen.getByLabelText(/identifier/i, { selector: '#exident' }), {
    target: { value: 'IsPhp' },
  })
  fireEvent.change(screen.getByLabelText(/reason/i), { target: { value: 'noisy' } })
  fireEvent.click(screen.getByRole('button', { name: /exclude/i }))

  expect(await screen.findByText(/would break that rule/)).toBeTruthy()
})

test('an exclusion requires a reason, because the reason is the audit trail', async () => {
  server()
  show()
  fireEvent.click(await screen.findByRole('button', { name: /sweep-feb/i }))
  await screen.findByText('NoisyPhp')
  fireEvent.change(screen.getByLabelText(/rule id/i), { target: { value: '7' } })
  // Scoped by selector: the browser's own "Identifier" filter now carries the same label text, so
  // an unscoped query matches two inputs. #exident is the exclusion form's.
  fireEvent.change(screen.getByLabelText(/identifier/i, { selector: '#exident' }), {
    target: { value: 'IsPhp' },
  })
  expect((screen.getByRole('button', { name: /exclude/i }) as HTMLButtonElement).disabled).toBe(true)
})

test('creating a set posts the name', async () => {
  const { sent } = server()
  show()
  await screen.findByText('sweep-feb')
  fireEvent.change(screen.getByLabelText(/new rule set/i), { target: { value: 'sweep-mar' } })
  fireEvent.click(screen.getByRole('button', { name: /create set/i }))

  await waitFor(() => expect(sent.length).toBeGreaterThan(0))
  expect(sent[0]?.url).toBe('/api/rulesets')
  expect(JSON.parse(String(sent[0]?.init.body))).toEqual({ name: 'sweep-mar' })
})

test('freezing posts the version', async () => {
  const { sent } = server()
  show()
  fireEvent.click(await screen.findByRole('button', { name: /sweep-feb/i }))
  await screen.findByText('NoisyPhp')
  fireEvent.change(screen.getByLabelText(/version/i), { target: { value: '5' } })
  fireEvent.click(screen.getByRole('button', { name: /^freeze$/i }))

  await waitFor(() => expect(sent.some((s) => s.url.includes('/freeze'))).toBe(true))
  const frozen = sent.find((s) => s.url.includes('/freeze'))
  expect(JSON.parse(String(frozen?.init.body))).toEqual({ version: 5 })
})

test('freezing updates the panel in place, without a page refresh', async () => {
  // The bug this pins: the detail panel used to hold a COPY of the row taken at click time, so
  // after a successful freeze it went on rendering the set as a draft -- still offering Freeze for
  // a set that was already frozen -- until the page was reloaded, which reset that state to null.
  // Server state belongs in one place; the panel derives the set from the list.
  let frozen = false
  vi.stubGlobal(
    'fetch',
    vi.fn((url: string, init?: RequestInit) => {
      const method = init?.method ?? 'GET'
      if (method !== 'GET') {
        if (url.includes('/freeze')) frozen = true
        return Promise.resolve({ ok: true, status: 200, statusText: 'OK', json: () => Promise.resolve({}) } as Response)
      }
      let body: unknown
      if (url.includes('/api/rules/index')) body = INDEX
      else if (url.includes('/resolved-count')) body = { count: 57 }
      else if (url.includes('/members')) body = MEMBERS
      else if (url.includes('/selection')) body = { layers: ['foundation'], rules: [7] }
      else if (url.includes('/exclusions')) body = []
      else {
        // The list is the single source of truth for what a set IS, so it answers differently
        // once the freeze has happened.
        body = [
          frozen
            ? { id: 2, name: 'sweep-feb', version: 5, created_by: 'v.quannh67',
                frozen_at: '2026-09-04T10:00:00Z', frozen_by: 'v.quannh67', yarc_sha256: 'ff00ff00' }
            : { id: 2, name: 'sweep-feb', version: null, created_by: 'v.quannh67', frozen_at: null },
        ]
      }
      return Promise.resolve({ ok: true, status: 200, statusText: 'OK', json: () => Promise.resolve(body) } as Response)
    }),
  )

  show()
  fireEvent.click(await screen.findByRole('button', { name: /sweep-feb/i }))
  fireEvent.change(await screen.findByLabelText(/version/i), { target: { value: '5' } })
  fireEvent.click(screen.getByRole('button', { name: /^freeze$/i }))

  // The panel becomes the frozen one on its own.
  expect(await screen.findByTestId('frozen-banner')).toBeTruthy()
  // And stops offering an action the server would now refuse.
  await waitFor(() => expect(screen.queryByRole('button', { name: /^freeze$/i })).toBeNull())
})

test('a frozen set offers no freeze control', async () => {
  server()
  show()
  fireEvent.click(await screen.findByRole('button', { name: /sweep-jan/i }))
  await screen.findByText('NoisyPhp')
  expect(screen.queryByRole('button', { name: /^freeze$/i })).toBeNull()
})

test('a frozen set says so, with the version, who froze it and the blob', async () => {
  // Previously a frozen set simply lost its controls with no explanation, which reads as broken
  // rather than as immutable. Asserted through a testid: the word "frozen" also appears in the
  // list row above, so a page-wide query would match two elements.
  server()
  show()
  fireEvent.click(await screen.findByRole('button', { name: /sweep-jan/i }))

  const banner = await screen.findByTestId('frozen-banner')
  expect(banner.textContent).toMatch(/v4/)
  expect(banner.textContent).toMatch(/v\.quannh67/)
  expect(banner.textContent).toMatch(/ab12cd34ef56/)
  expect(banner.textContent).toMatch(/cannot be changed/i)
})

test('a frozen set says how many rule revisions it pins', async () => {
  // The single most useful fact about a frozen set, and the one the screen used to omit entirely.
  server()
  show()
  fireEvent.click(await screen.findByRole('button', { name: /sweep-jan/i }))
  expect(await screen.findByText(/pins 2 rule revisions/i)).toBeTruthy()
  expect(screen.getByText('AcmeShell')).toBeTruthy()
})

test('the pinned list can be filtered, because a real set holds thousands', async () => {
  server()
  show()
  fireEvent.click(await screen.findByRole('button', { name: /sweep-jan/i }))
  await screen.findByText('AcmeShell')

  fireEvent.change(screen.getByLabelText(/filter/i), { target: { value: 'acme' } })
  expect(screen.getByText('AcmeShell')).toBeTruthy()
  expect(screen.queryByText('DodgyPhp')).toBeNull()
})

test('a long pinned list is paged rather than truncated', async () => {
  // Rendering 5,872 rows is slow, and rendering 200 with a note saying so left the rest of the
  // set unviewable from the screen that claims to show its contents.
  const many = Array.from({ length: 250 }, (_, i) => ({
    rule_id: i + 1,
    identifier: `rule_${String(i).padStart(4, '0')}`,
    layer: 'foundation',
    revision: 1,
  }))
  server({ members: many })
  show()
  fireEvent.click(await screen.findByRole('button', { name: /sweep-jan/i }))
  expect(await screen.findByText(/pins 250 rule revisions/i)).toBeTruthy()
  expect(screen.getAllByText(/of 250 revisions/).length).toBeGreaterThan(0)
  // And the tail is reachable, which under the cap it was not.
  expect(screen.queryByText('rule_0249')).toBeNull()
  fireEvent.click(screen.getAllByRole('button', { name: /last page/i })[0] as HTMLElement)
  expect(screen.getByText('rule_0249')).toBeTruthy()
})

test('a draft set offers Freeze without scrolling past the rule browser', async () => {
  // Regression guard for a control that was PRESENT but unreachable: rendered last, after the
  // selection editor and a 200-row rule table, it sat 8,360px down an 8,429px page and was
  // reported as a missing feature. It must precede the library it applies to.
  server()
  const { container } = show()
  fireEvent.click(await screen.findByRole('button', { name: /sweep-feb/i }))
  const freeze = await screen.findByRole('button', { name: /^freeze$/i })
  const browser = await screen.findByText(/browse the library/i)
  expect(
    freeze.compareDocumentPosition(browser) & Node.DOCUMENT_POSITION_FOLLOWING,
  ).toBeTruthy()
  expect(container).toBeTruthy()
})

test('a draft set says it pins nothing yet, rather than looking empty', async () => {
  // The other half of "why does clicking a set show nothing": a draft genuinely holds no pinned
  // revisions, and saying so is more useful than an empty panel.
  server({ members: [] })
  show()
  fireEvent.click(await screen.findByRole('button', { name: /sweep-feb/i }))
  expect(await screen.findByText(/pins nothing yet/i)).toBeTruthy()
  expect(screen.queryByTestId('frozen-banner')).toBeNull()
})
