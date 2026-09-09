import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { Cases } from './Cases'

function ok(body: unknown, status = 200) {
  return { ok: true, status, statusText: 'OK', json: () => Promise.resolve(body) } as Response
}
function fail(status: number, error: string) {
  return {
    ok: false,
    status,
    statusText: 'ERR',
    json: () => Promise.resolve({ error }),
  } as Response
}

function show() {
  return render(
    <MemoryRouter>
      <Cases />
    </MemoryRouter>,
  )
}

test('lists cases with a link into each one', async () => {
  vi.stubGlobal(
    'fetch',
    vi.fn(() =>
      Promise.resolve(
        ok([
          {
            id: 4,
            name: 'IR-2026-014 Acme',
            created_by: 'v.quannh67',
            created_at: '2026-09-03T06:40:32Z',
          },
        ]),
      ),
    ),
  )
  show()
  const link = await screen.findByRole('link', { name: /IR-2026-014 Acme/ })
  expect(link.getAttribute('href')).toBe('/cases/4')
})

test('an empty console says so instead of looking broken', async () => {
  vi.stubGlobal('fetch', vi.fn(() => Promise.resolve(ok([]))))
  show()
  expect(await screen.findByText(/no cases yet/i)).toBeTruthy()
})

test('a failure to load is reported, not silently empty', async () => {
  vi.stubGlobal('fetch', vi.fn(() => Promise.resolve(fail(500, 'database is down'))))
  show()
  expect(await screen.findByText(/database is down/)).toBeTruthy()
})

test('a case name is rendered as text, never as markup', async () => {
  // Case names are analyst-entered, but scan-derived strings reach other screens the same way.
  // This is the regression guard for anyone reaching for dangerouslySetInnerHTML later.
  vi.stubGlobal(
    'fetch',
    vi.fn(() =>
      Promise.resolve(
        ok([{ id: 1, name: '<img src=x onerror=alert(1)>', created_by: 'a', created_at: '' }]),
      ),
    ),
  )
  const { container } = show()
  await screen.findByText(/onerror/)
  expect(container.querySelector('img')).toBeNull()
})

test('the create button is disabled until a name is typed', async () => {
  vi.stubGlobal('fetch', vi.fn(() => Promise.resolve(ok([]))))
  show()
  await screen.findByText(/no cases yet/i)
  const button = screen.getByRole('button', { name: /open case/i }) as HTMLButtonElement
  expect(button.disabled).toBe(true)
  fireEvent.change(screen.getByLabelText(/new case/i), { target: { value: 'IR-new' } })
  expect(button.disabled).toBe(false)
})

test('creating a case posts the name and reloads the list', async () => {
  let created = false
  const fetchMock = vi.fn((_url: string, init?: RequestInit) => {
    if ((init?.method ?? 'GET') === 'POST') {
      created = true
      return Promise.resolve(ok({ id: 9 }, 201))
    }
    return Promise.resolve(
      ok(created ? [{ id: 9, name: 'IR-new', created_by: 'a', created_at: '' }] : []),
    )
  })
  vi.stubGlobal('fetch', fetchMock)

  show()
  await screen.findByText(/no cases yet/i)
  fireEvent.change(screen.getByLabelText(/new case/i), { target: { value: 'IR-new' } })
  fireEvent.click(screen.getByRole('button', { name: /open case/i }))

  await waitFor(() => expect(created).toBe(true))
  expect(await screen.findByRole('link', { name: /IR-new/ })).toBeTruthy()
  const posted = fetchMock.mock.calls.find((c) => (c[1] as RequestInit)?.method === 'POST')
  expect((posted?.[1] as RequestInit).body).toBe(JSON.stringify({ name: 'IR-new' }))
})

test('a rejected create reports why and keeps what was typed', async () => {
  vi.stubGlobal(
    'fetch',
    vi.fn((_url: string, init?: RequestInit) =>
      (init?.method ?? 'GET') === 'POST'
        ? Promise.resolve(fail(400, 'name is required'))
        : Promise.resolve(ok([])),
    ),
  )
  show()
  await screen.findByText(/no cases yet/i)
  fireEvent.change(screen.getByLabelText(/new case/i), { target: { value: 'x' } })
  fireEvent.click(screen.getByRole('button', { name: /open case/i }))

  expect(await screen.findByText(/name is required/)).toBeTruthy()
  expect((screen.getByLabelText(/new case/i) as HTMLInputElement).value).toBe('x')
})
