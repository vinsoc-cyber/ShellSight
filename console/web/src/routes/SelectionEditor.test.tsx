import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import type { RuleIndexRow, Selection } from '../api/types'
import { SelectionEditor } from './SelectionEditor'

const ROWS: RuleIndexRow[] = [
  { id: 1, identifier: 'AcmeShell', layer: 'own', source_pack: 'shellsight', score: 80,
    description: 'acme uploader' },
  { id: 2, identifier: 'DodgyPhp', layer: 'foundation', source_pack: 'yara-forge-core', score: 75,
    description: 'php obfuscation' },
]

function server(opts: { saveStatus?: number; saveError?: string; count?: number } = {}) {
  const sent: { url: string; init: RequestInit }[] = []
  vi.stubGlobal(
    'fetch',
    vi.fn((url: string, init?: RequestInit) => {
      const method = init?.method ?? 'GET'
      if (method === 'PUT') {
        sent.push({ url, init: init as RequestInit })
        const status = opts.saveStatus ?? 200
        if (status >= 400) {
          return Promise.resolve({
            ok: false, status, statusText: 'ERR',
            json: () => Promise.resolve({ error: opts.saveError ?? 'rejected' }),
          } as Response)
        }
        return Promise.resolve({
          ok: true, status: 200, statusText: 'OK', json: () => Promise.resolve({}),
        } as Response)
      }
      const body = url.includes('/resolved-count') ? { count: opts.count ?? 42 } : ROWS
      return Promise.resolve({
        ok: true, status: 200, statusText: 'OK', json: () => Promise.resolve(body),
      } as Response)
    }),
  )
  return { sent }
}

const initial: Selection = { layers: ['own'], rules: [2] }

function show(sel: Selection = initial) {
  return render(<SelectionEditor setID={7} initial={sel} exclusions={1} />)
}

test('shows the saved selection and the resolved count from the server', async () => {
  server({ count: 57 })
  show()
  expect(await screen.findByText(/resolves to 57 rules/i)).toBeTruthy()
  expect(screen.getByText(/named rules: 1/i)).toBeTruthy()
  expect(screen.getByText(/exclusions: 1/i)).toBeTruthy()
})

test('a layer checkbox reflects the saved selection', async () => {
  server()
  show()
  await screen.findByText(/resolves to/i)
  const own = screen.getByRole('checkbox', { name: /include layer own/i }) as HTMLInputElement
  const foundation = screen.getByRole('checkbox', {
    name: /include layer foundation/i,
  }) as HTMLInputElement
  expect(own.checked).toBe(true)
  expect(foundation.checked).toBe(false)
})

test('the resolved count is marked stale once there are unsaved changes', async () => {
  // The server only knows the SAVED selection, and the count depends on union semantics and
  // exclusions. Recomputing it in the browser would produce a number that disagrees with the one
  // freezing will use, so the screen marks it stale instead of guessing.
  server({ count: 57 })
  show()
  await screen.findByText(/resolves to 57 rules/i)
  fireEvent.click(screen.getByRole('checkbox', { name: /include layer foundation/i }))
  expect(screen.getByText(/unsaved/i)).toBeTruthy()
})

test('saving PUTs the whole selection and nothing else', async () => {
  const { sent } = server()
  show()
  await screen.findByText(/resolves to/i)
  fireEvent.click(screen.getByRole('checkbox', { name: /include layer foundation/i }))
  fireEvent.click(screen.getByRole('button', { name: /save selection/i }))

  await waitFor(() => expect(sent).toHaveLength(1))
  expect(sent[0]?.url).toBe('/api/rulesets/7/selection')
  expect(sent[0]?.init.method).toBe('PUT')
  expect(JSON.parse(String(sent[0]?.init.body))).toEqual({
    layers: ['own', 'foundation'],
    rules: [2],
  })
})

test('adding from the browser adds to the named rules', async () => {
  const { sent } = server()
  show()
  await screen.findByText(/resolves to/i)
  fireEvent.click(screen.getByRole('checkbox', { name: /select rule AcmeShell/i }))
  fireEvent.click(screen.getByRole('button', { name: /save selection/i }))

  await waitFor(() => expect(sent).toHaveLength(1))
  expect(JSON.parse(String(sent[0]?.init.body)).rules.sort()).toEqual([1, 2])
})

test('adding a rule twice does not duplicate it', async () => {
  const { sent } = server()
  show()
  await screen.findByText(/resolves to/i)
  // DodgyPhp (id 2) is already in the selection; bulk-adding everything must not add it again.
  fireEvent.click(screen.getByRole('button', { name: /add all 2/i }))
  fireEvent.click(screen.getByRole('button', { name: /save selection/i }))

  await waitFor(() => expect(sent).toHaveLength(1))
  expect(JSON.parse(String(sent[0]?.init.body)).rules.sort()).toEqual([1, 2])
})

test('a rejected save is reported and the selection is not cleared', async () => {
  server({ saveStatus: 409, saveError: 'rule set 7 is frozen or does not exist' })
  show()
  await screen.findByText(/resolves to/i)
  fireEvent.click(screen.getByRole('checkbox', { name: /include layer foundation/i }))
  fireEvent.click(screen.getByRole('button', { name: /save selection/i }))

  expect(await screen.findByText(/is frozen or does not exist/)).toBeTruthy()
  const foundation = screen.getByRole('checkbox', {
    name: /include layer foundation/i,
  }) as HTMLInputElement
  expect(foundation.checked).toBe(true)
})

test('an empty selection is allowed but warns that generation would refuse it', async () => {
  server({ count: 0 })
  show({ layers: [], rules: [] })
  expect(await screen.findByText(/resolves to 0 rules/i)).toBeTruthy()
  expect(screen.getByText(/would be refused/i)).toBeTruthy()
})
