import { render, screen } from '@testing-library/react'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import type { Scan } from '../api/types'
import { Scans } from './Scans'

const scan = (over: Partial<Scan> = {}): Scan => ({
  id: 1,
  run_id: '20260903_064021',
  host: 'web-01',
  tier: 'confirmed',
  score: 90,
  incomplete: false,
  integrity: 'verified',
  imported_at: '2026-09-03T06:40:32Z',
  ...over,
})

function stub(body: unknown) {
  vi.stubGlobal(
    'fetch',
    vi.fn(() =>
      Promise.resolve({
        ok: true,
        status: 200,
        statusText: 'OK',
        json: () => Promise.resolve(body),
      } as Response),
    ),
  )
}

function show() {
  return render(
    <MemoryRouter initialEntries={['/cases/4']}>
      <Routes>
        <Route path="/cases/:caseID" element={<Scans />} />
      </Routes>
    </MemoryRouter>,
  )
}

test('lists scans with host, verdict and a link into the scan', async () => {
  stub([scan()])
  show()
  expect(await screen.findByText('web-01')).toBeTruthy()
  expect(screen.getByText('confirmed')).toBeTruthy()
  expect(screen.getByRole('link', { name: /20260903_064021/ }).getAttribute('href')).toBe('/scans/1')
})

test('an unverified report is labelled, and the label does not claim proof', async () => {
  // The per-build HMAC key is extractable from the agent binary, so integrity detects
  // opportunistic tampering and not a determined attacker. The UI must say that.
  stub([scan({ integrity: 'unverified' })])
  show()
  expect(await screen.findByText('unverified')).toBeTruthy()
  expect(screen.getByTitle(/opportunistic tampering/i)).toBeTruthy()
})

test('an altered report is shown and flagged, never hidden', async () => {
  // Refusing an altered report would discard evidence from a live engagement. The analyst needs
  // to read what it says AND to know it does not match its own manifest.
  stub([scan({ integrity: 'altered' })])
  show()
  expect(await screen.findByText('altered')).toBeTruthy()
  expect(screen.getByRole('link', { name: /20260903_064021/ })).toBeTruthy()
  expect(screen.getByTitle(/does NOT match/i)).toBeTruthy()
})

test('an incomplete scan is marked in the list, not only inside the scan', async () => {
  stub([scan({ incomplete: true })])
  show()
  expect(await screen.findByText(/incomplete/i)).toBeTruthy()
})

test('a case with no scans explains what to do next', async () => {
  stub([])
  show()
  expect(await screen.findByText(/import-report/)).toBeTruthy()
})
