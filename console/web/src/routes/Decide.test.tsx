import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { Scan } from './Scan'

const DETAIL = {
  scan: {
    id: 1,
    run_id: 'r1',
    host: 'web-01',
    tier: 'confirmed',
    score: 90,
    incomplete: false,
    integrity: 'verified',
    imported_at: '',
  },
  verdict: { tier: 'confirmed', score: 90, incomplete: false },
  coverage: [
    {
      view: 'disk',
      status: 'ran',
      targets_scanned: 3,
      non_regular: 0,
      unreadable: 0,
      oversize_skipped: 0,
      no_language_detector: 0,
    },
  ],
}

const GROUP = {
  content_key: 'sha256:abc123',
  tier: 'confirmed',
  score: 90,
  locations: 1,
  hosts: ['web-01'],
  rules: ['kb:yara/DodgyPhp'],
  findings: [
    {
      id: 4242,
      ref: 'abc-DodgyPhp',
      content_key: 'sha256:abc123',
      host: 'web-01',
      view: 'disk',
      file_path: '/var/www/shell.php',
      basis: 'signature',
      knowledge_ref: 'kb:yara/DodgyPhp',
      score: 90,
      tier: 'confirmed',
    },
  ],
  prior_decisions: [],
}

function server(opts: { decideStatus?: number; decideError?: string } = {}) {
  const posts: RequestInit[] = []
  let decided = false
  vi.stubGlobal(
    'fetch',
    vi.fn((url: string, init?: RequestInit) => {
      const method = init?.method ?? 'GET'
      if (method === 'POST' && url === '/api/decisions') {
        posts.push(init as RequestInit)
        const status = opts.decideStatus ?? 201
        if (status >= 400) {
          return Promise.resolve({
            ok: false,
            status,
            statusText: 'ERR',
            json: () => Promise.resolve({ error: opts.decideError ?? 'rejected' }),
          } as Response)
        }
        decided = true
        return Promise.resolve({
          ok: true,
          status: 201,
          statusText: '',
          json: () => Promise.resolve({ id: 7 }),
        } as Response)
      }
      const body = url.endsWith('/findings')
        ? [
            decided
              ? {
                  ...GROUP,
                  prior_decisions: [
                    {
                      id: 7,
                      content_key: 'sha256:abc123',
                      verdict: 'malicious',
                      author: 'v.quannh67',
                      decided_at: '2026-09-03T07:00:00Z',
                    },
                  ],
                }
              : GROUP,
          ]
        : DETAIL
      return Promise.resolve({
        ok: true,
        status: 200,
        statusText: 'OK',
        json: () => Promise.resolve(body),
      } as Response)
    }),
  )
  return { posts }
}

function show() {
  return render(
    <MemoryRouter initialEntries={['/scans/1']}>
      <Routes>
        <Route path="/scans/:scanID" element={<Scan />} />
      </Routes>
    </MemoryRouter>,
  )
}

test('posts the CONTENT key, not the finding id', async () => {
  // The whole schema rests on this. A decision keyed on a finding row dies with the scan that
  // produced it, and the team re-litigates the same bytes on the next engagement.
  const { posts } = server()
  show()
  fireEvent.click(await screen.findByRole('button', { name: /^judge$/i }))
  fireEvent.click(screen.getByRole('button', { name: /^malicious$/i }))

  await waitFor(() => expect(posts.length).toBe(1))
  const body = JSON.parse(String(posts[0]?.body)) as Record<string, unknown>
  expect(body.content_key).toBe('sha256:abc123')
  expect(body.verdict).toBe('malicious')
  expect(JSON.stringify(body)).not.toContain('4242')
})

test('omits an empty note rather than sending an empty string', async () => {
  const { posts } = server()
  show()
  fireEvent.click(await screen.findByRole('button', { name: /^judge$/i }))
  fireEvent.click(screen.getByRole('button', { name: /^undecided$/i }))

  await waitFor(() => expect(posts.length).toBe(1))
  const body = JSON.parse(String(posts[0]?.body)) as Record<string, unknown>
  expect('note' in body ? body.note : undefined).toBeUndefined()
})

test('the decision just made comes back as a prior decision', async () => {
  // Reloading rather than rendering optimistically means the analyst sees what the server
  // actually recorded -- the same view a colleague will get.
  server()
  show()
  fireEvent.click(await screen.findByRole('button', { name: /^judge$/i }))
  fireEvent.click(screen.getByRole('button', { name: /^malicious$/i }))
  expect(await screen.findByText(/already judged/i)).toBeTruthy()
})

test('a rejected decision is reported and not shown as recorded', async () => {
  server({ decideStatus: 400, decideError: 'verdict must be one of malicious, false-positive, benign-noteworthy, undecided' })
  show()
  fireEvent.click(await screen.findByRole('button', { name: /^judge$/i }))
  fireEvent.click(screen.getByRole('button', { name: /^malicious$/i }))

  expect(await screen.findByText(/verdict must be one of/)).toBeTruthy()
  expect(screen.queryByText(/already judged/i)).toBeNull()
})
