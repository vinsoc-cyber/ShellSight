import { render, screen } from '@testing-library/react'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import type { ScanDetail } from '../api/types'
import { Scan } from './Scan'

const detail = (over: Partial<ScanDetail> = {}): ScanDetail => ({
  scan: {
    id: 1,
    run_id: '20260903_064021',
    host: 'web-01',
    tool_version: '1.0.0',
    operator: 'svc-ir',
    tier: 'clean',
    score: 0,
    incomplete: false,
    integrity: 'verified',
    imported_at: '2026-09-03T06:40:32Z',
  },
  verdict: { tier: 'clean', score: 0, incomplete: false },
  coverage: [
    {
      view: 'disk',
      status: 'ran',
      targets_scanned: 1200,
      non_regular: 0,
      unreadable: 0,
      oversize_skipped: 0,
      no_language_detector: 0,
    },
  ],
  ...over,
})

function stub(byPath: (path: string) => unknown) {
  vi.stubGlobal(
    'fetch',
    vi.fn((url: string) =>
      Promise.resolve({
        ok: true,
        status: 200,
        statusText: 'OK',
        json: () => Promise.resolve(byPath(url)),
      } as Response),
    ),
  )
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

test('shows the run, the host and the verdict', async () => {
  stub((u) => (u.endsWith('/findings') ? [] : detail()))
  show()
  expect(await screen.findByText('web-01')).toBeTruthy()
  expect(screen.getByText('20260903_064021')).toBeTruthy()
  expect(screen.getByText('clean')).toBeTruthy()
})

test('the coverage always renders beside the verdict', async () => {
  // The single most important property of this screen. A verdict without coverage is how a
  // scanner tells a comfortable lie.
  stub((u) => (u.endsWith('/findings') ? [] : detail()))
  show()
  // Target the HEADING. Task 9's empty-findings copy also says "coverage", and a page-wide match
  // is then safe only by mount ordering -- one render-order change from throwing on two matches.
  expect(await screen.findByRole('heading', { name: /coverage/i })).toBeTruthy()
  expect(screen.getByText(/1,200|1200/)).toBeTruthy()
})

test('a clean verdict over an incompletely examined host is qualified, not presented as clean', async () => {
  // 398 unreadable files usually means the scan ran without the permissions it needed. A screen
  // that shows "clean" without qualifying it is the exact failure this design set out to avoid.
  stub((u) =>
    u.endsWith('/findings')
      ? []
      : detail({
          coverage: [
            {
              view: 'disk',
              status: 'ran',
              targets_scanned: 802,
              non_regular: 0,
              unreadable: 398,
              oversize_skipped: 0,
              no_language_detector: 0,
            },
          ],
        }),
  )
  show()
  // Scan renders the qualifying sentence AND the coverage panel, so three elements carry this
  // number. Match the sentence that only the qualifier can produce.
  expect(await screen.findByText(/398 targets were skipped/)).toBeTruthy()
  expect(screen.getByText(/did not examine everything/i)).toBeTruthy()
})

test('an incomplete scan says so next to the verdict', async () => {
  stub((u) =>
    u.endsWith('/findings')
      ? []
      : detail({ verdict: { tier: 'unknown', score: 0, incomplete: true } }),
  )
  show()
  expect(await screen.findByText(/incomplete/i)).toBeTruthy()
})

test('a scan that does not exist reports the API message', async () => {
  vi.stubGlobal(
    'fetch',
    vi.fn(() =>
      Promise.resolve({
        ok: false,
        status: 404,
        statusText: 'NF',
        json: () => Promise.resolve({ error: 'no such scan' }),
      } as Response),
    ),
  )
  show()
  expect(await screen.findByText(/no such scan/)).toBeTruthy()
})

test('the operator string from a report is rendered as text', async () => {
  stub((u) =>
    u.endsWith('/findings')
      ? []
      : detail({ scan: { ...detail().scan, operator: '<script>alert(1)</script>' } }),
  )
  const { container } = show()
  await screen.findByText(/alert\(1\)/)
  expect(container.querySelector('script')).toBeNull()
})
