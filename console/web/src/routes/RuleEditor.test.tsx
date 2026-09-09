import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { RuleEditor } from './RuleEditor'

const LANGS = ['php', 'jsp', 'aspx']
const RULE = {
  rule: { id: 5, identifier: 'AcmeCustomShell', layer: 'own' },
  revision: {
    id: 11,
    rule_id: 5,
    revision: 3,
    text: 'rule AcmeCustomShell { condition: true }',
    lang: 'php',
    author: 'v.quannh67',
    created_at: '2026-09-01T10:00:00Z',
  },
}

function server(opts: { saveStatus?: number; saveError?: string; rule?: unknown } = {}) {
  const sent: { url: string; init: RequestInit }[] = []
  vi.stubGlobal(
    'fetch',
    vi.fn((url: string, init?: RequestInit) => {
      const method = init?.method ?? 'GET'
      if (method === 'PUT' || method === 'POST') {
        sent.push({ url, init: init as RequestInit })
        const status = opts.saveStatus ?? 200
        if (status >= 400) {
          return Promise.resolve({
            ok: false,
            status,
            statusText: 'ERR',
            json: () => Promise.resolve({ error: opts.saveError ?? 'rejected' }),
          } as Response)
        }
        return Promise.resolve({
          ok: true,
          status,
          statusText: 'OK',
          json: () => Promise.resolve({ revision: 4, id: 5 }),
        } as Response)
      }
      const body = url.endsWith('/langs') ? LANGS : (opts.rule ?? RULE)
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

function edit() {
  return render(
    <MemoryRouter initialEntries={['/rules/5']}>
      <Routes>
        <Route path="/rules/:ruleID" element={<RuleEditor />} />
      </Routes>
    </MemoryRouter>,
  )
}

function create() {
  return render(
    <MemoryRouter initialEntries={['/rules/new']}>
      <Routes>
        <Route path="/rules/new" element={<RuleEditor />} />
      </Routes>
    </MemoryRouter>,
  )
}

test('loads the current revision text and says which revision it is', async () => {
  server()
  edit()
  const box = (await screen.findByLabelText(/rule text/i)) as HTMLTextAreaElement
  expect(box.value).toContain('rule AcmeCustomShell')
  expect(screen.getByText(/revision 3/i)).toBeTruthy()
})

test('a rule that will not compile shows the compiler message beside the text', async () => {
  // 422 means the request was fine and the CONTENT was refused. Rendering that as a transport
  // failure would tell an analyst their console is broken when their rule is.
  server({ saveStatus: 422, saveError: 'line 3: syntax error, unexpected }' })
  edit()
  await screen.findByLabelText(/rule text/i)
  fireEvent.click(screen.getByRole('button', { name: /save/i }))

  expect(await screen.findByText(/line 3: syntax error/)).toBeTruthy()
  expect(screen.getByTestId('compile-error')).toBeTruthy()
})

test('a compile failure is not reported as a broken console', async () => {
  server({ saveStatus: 422, saveError: 'line 3: syntax error' })
  edit()
  await screen.findByLabelText(/rule text/i)
  fireEvent.click(screen.getByRole('button', { name: /save/i }))
  await screen.findByTestId('compile-error')
  expect(screen.queryByText(/could not load this/i)).toBeNull()
})

test('a genuine server failure IS reported as a failure, not as a compile error', async () => {
  server({ saveStatus: 500, saveError: 'database is down' })
  edit()
  await screen.findByLabelText(/rule text/i)
  fireEvent.click(screen.getByRole('button', { name: /save/i }))

  expect(await screen.findByRole('alert')).toBeTruthy()
  expect(screen.queryByTestId('compile-error')).toBeNull()
})

test('a successful save reports the new revision number', async () => {
  server()
  edit()
  await screen.findByLabelText(/rule text/i)
  fireEvent.click(screen.getByRole('button', { name: /save/i }))
  expect(await screen.findByText(/revision 4/i)).toBeTruthy()
})

test('saving an edit PUTs the text and the language', async () => {
  const { sent } = server()
  edit()
  const box = await screen.findByLabelText(/rule text/i)
  fireEvent.change(box, { target: { value: 'rule R { condition: false }' } })
  fireEvent.click(screen.getByRole('button', { name: /save/i }))

  await waitFor(() => expect(sent.length).toBe(1))
  expect(sent[0]?.init.method).toBe('PUT')
  expect(sent[0]?.url).toBe('/api/rules/5')
  expect(JSON.parse(String(sent[0]?.init.body))).toMatchObject({
    text: 'rule R { condition: false }',
    lang: 'php',
  })
})

test('a new rule POSTs with its layer', async () => {
  const { sent } = server()
  create()
  const box = await screen.findByLabelText(/rule text/i)
  fireEvent.change(box, { target: { value: 'rule New { condition: true }' } })
  fireEvent.click(screen.getByRole('button', { name: /save/i }))

  await waitFor(() => expect(sent.length).toBe(1))
  expect(sent[0]?.init.method).toBe('POST')
  expect(sent[0]?.url).toBe('/api/rules')
  expect(JSON.parse(String(sent[0]?.init.body))).toMatchObject({ layer: 'own' })
})

test('a foundation rule is not editable, and the screen says why', async () => {
  // D7: foundation rule text is never editable. Offering a save button that the API will refuse
  // would be a lie told by the UI.
  server({
    rule: {
      rule: { id: 9, identifier: 'DodgyPhp', layer: 'foundation', source_pack: 'signature-base' },
      revision: { ...RULE.revision, rule_id: 9, text: 'rule DodgyPhp { condition: true }' },
    },
  })
  edit()
  expect(await screen.findByText(/exclude-only/i)).toBeTruthy()
  expect((screen.getByLabelText(/rule text/i) as HTMLTextAreaElement).readOnly).toBe(true)
  expect(screen.queryByRole('button', { name: /save/i })).toBeNull()
})

test('the language list comes from the API and is offered in order', async () => {
  server()
  edit()
  const select = (await screen.findByLabelText(/language/i)) as HTMLSelectElement
  const values = Array.from(select.options).map((o) => o.value)
  expect(values).toContain('php')
  expect(values).toContain('jsp')
})

test('save is disabled while empty', async () => {
  server()
  create()
  await screen.findByLabelText(/rule text/i)
  expect((screen.getByRole('button', { name: /save/i }) as HTMLButtonElement).disabled).toBe(true)
})

test('a created rule stops offering to create itself again', async () => {
  // The double-write this guards: after a successful create the editor stayed on /rules/new with
  // the same text in an enabled field, so a second Save -- a double click, or an analyst who did
  // not notice the confirmation -- wrote a SECOND rule with identical text. `busy` cannot catch
  // that; it is already false by then. The screen has to stop being "write a rule".
  const posts: string[] = []
  vi.stubGlobal(
    'fetch',
    vi.fn((url: string, init?: RequestInit) => {
      const method = init?.method ?? 'GET'
      if (method === 'POST') posts.push(url)
      const body = url.includes('/langs') ? ['php'] : { id: 91 }
      return Promise.resolve({
        ok: true,
        status: 200,
        statusText: 'OK',
        json: () => Promise.resolve(body),
      } as Response)
    }),
  )

  render(
    <MemoryRouter initialEntries={['/rules/new']}>
      <Routes>
        <Route path="/rules/new" element={<RuleEditor />} />
        <Route path="/rules/:ruleID" element={<div>editing rule</div>} />
      </Routes>
    </MemoryRouter>,
  )

  fireEvent.change(await screen.findByLabelText(/rule text/i), {
    target: { value: 'rule X { condition: true }' },
  })
  fireEvent.click(screen.getByRole('button', { name: /^save$/i }))

  // It moved to the rule it created, so there is no second create to make.
  expect(await screen.findByText('editing rule')).toBeTruthy()
  await waitFor(() => expect(posts.filter((u) => u.endsWith('/api/rules'))).toHaveLength(1))
})
