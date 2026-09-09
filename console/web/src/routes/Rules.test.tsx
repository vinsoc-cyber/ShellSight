import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { Rules } from './Rules'

const RULES = [
  { id: 1, identifier: 'DodgyPhp', layer: 'foundation', source_pack: 'signature-base' },
  { id: 2, identifier: 'AcmeCustomShell', layer: 'own' },
]

function stub(byUrl: (url: string) => unknown) {
  const urls: string[] = []
  vi.stubGlobal(
    'fetch',
    vi.fn((url: string) => {
      urls.push(url)
      return Promise.resolve({
        ok: true,
        status: 200,
        statusText: 'OK',
        json: () => Promise.resolve(byUrl(url)),
      } as Response)
    }),
  )
  return urls
}

function show() {
  return render(
    <MemoryRouter>
      <Rules />
    </MemoryRouter>,
  )
}

test('lists rules with their layer and a link into the editor', async () => {
  stub(() => RULES)
  show()
  const link = await screen.findByRole('link', { name: 'AcmeCustomShell' })
  expect(link.getAttribute('href')).toBe('/rules/2')
  // The layer filter renders <option>foundation</option> too, so match the table CELL.
  expect(screen.getByRole('cell', { name: 'foundation' })).toBeTruthy()
})

test('a foundation rule shows where it came from, since its text cannot be edited', async () => {
  // Foundation rules are exclude-only: their text is never editable, so the useful thing to show
  // is the pack they arrived in.
  stub(() => RULES)
  show()
  expect(await screen.findByText('signature-base')).toBeTruthy()
})

test('filtering by layer asks the API for that layer', async () => {
  // Filtering client-side would work today and quietly stop working at 5,800 rules. The API takes
  // a layer parameter; use it.
  const urls = stub(() => RULES)
  show()
  await screen.findByRole('link', { name: 'AcmeCustomShell' })
  fireEvent.change(screen.getByLabelText(/layer/i), { target: { value: 'own' } })
  await waitFor(() => expect(urls.some((u) => u.includes('layer=own'))).toBe(true))
})

test('an empty library points at where rules come from', async () => {
  stub(() => [])
  show()
  // The <p> says "Write one..." and the <code> says "console import-pack", so an alternation
  // matches both. Assert the command, which is the actionable half.
  expect(await screen.findByText('console import-pack')).toBeTruthy()
})

test('a rule identifier is rendered as text', async () => {
  stub(() => [{ id: 1, identifier: '<img src=x onerror=alert(1)>', layer: 'own' }])
  const { container } = show()
  await screen.findByText(/onerror/)
  expect(container.querySelector('img')).toBeNull()
})
