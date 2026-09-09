import { ApiError, del, get, post } from './http'

function res(body: unknown, init: { status?: number; json?: boolean } = {}) {
  const status = init.status ?? 200
  return {
    ok: status >= 200 && status < 300,
    status,
    statusText: 'STATUS',
    json: () =>
      init.json === false ? Promise.reject(new Error('not json')) : Promise.resolve(body),
  } as Response
}

test('returns the decoded body on success', async () => {
  vi.stubGlobal('fetch', vi.fn(() => Promise.resolve(res([{ id: 1 }]))))
  await expect(get<{ id: number }[]>('/api/cases')).resolves.toEqual([{ id: 1 }])
})

test('surfaces the API error message, not the bare status', async () => {
  vi.stubGlobal('fetch', vi.fn(() => Promise.resolve(res({ error: 'no such scan' }, { status: 404 }))))
  await expect(get('/api/scans/9')).rejects.toThrow(/no such scan/)
})

test('a 422 is flagged as a content rejection, not a protocol error', async () => {
  // The console answers 422 for a rule that will not compile: the request was fine, the content
  // was not. The editor renders the compiler message inline instead of as a failure banner.
  vi.stubGlobal(
    'fetch',
    vi.fn(() => Promise.resolve(res({ error: 'line 3: syntax error' }, { status: 422 }))),
  )
  await expect(post('/api/rules', {})).rejects.toMatchObject({
    status: 422,
    rejectedContent: true,
    message: expect.stringContaining('syntax error'),
  })
})

test('falls back to the status when the error body is not JSON', async () => {
  vi.stubGlobal(
    'fetch',
    vi.fn(() => Promise.resolve(res(null, { status: 500, json: false }))),
  )
  await expect(get('/api/cases')).rejects.toThrow(/500/)
})

test('a 204 resolves without trying to parse a body', async () => {
  // DELETE /api/rules/{id} answers 204 with NO body. Parsing it unconditionally turns a
  // successful delete into a thrown error.
  const json = vi.fn(() => Promise.reject(new Error('there is no body')))
  vi.stubGlobal(
    'fetch',
    vi.fn(() => Promise.resolve({ ok: true, status: 204, statusText: '', json } as unknown as Response)),
  )
  await expect(del('/api/rules/1')).resolves.toBeUndefined()
  expect(json).not.toHaveBeenCalled()
})

test('sends the analyst name as X-Console-Actor', async () => {
  localStorage.setItem('shellsight.actor', 'v.quannh67')
  // The mock must DECLARE its parameters. With a zero-arg `vi.fn(() => ...)`, TypeScript infers
  // mock.calls as [] tuples, so calls[0][1] does not typecheck -- and vitest never notices,
  // because esbuild strips types without checking them. `npm run build` runs tsc and would fail.
  const fetchMock = vi.fn((_url: string, _init?: RequestInit) =>
    Promise.resolve(res({ id: 1 }, { status: 201 })),
  )
  vi.stubGlobal('fetch', fetchMock)
  await post('/api/cases', { name: 'IR-1' })

  const init = fetchMock.mock.calls[0]?.[1]
  if (!init) throw new Error('fetch was never called')
  const headers = new Headers(init.headers)
  expect(headers.get('X-Console-Actor')).toBe('v.quannh67')
  expect(init.method).toBe('POST')
  expect(init.body).toBe(JSON.stringify({ name: 'IR-1' }))
})

test('ApiError carries the status so callers can branch on it', () => {
  const e = new ApiError('boom', 409)
  expect(e).toBeInstanceOf(Error)
  expect(e.status).toBe(409)
  expect(e.rejectedContent).toBe(false)
})
