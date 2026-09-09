import { fireEvent, render, screen } from '@testing-library/react'
import { usePaged } from './usePaged'

const ROWS = Array.from({ length: 260 }, (_, i) => `row_${String(i).padStart(3, '0')}`)

// A harness rather than a hook-testing library: the reset-on-key behaviour is a RENDER-phase
// state adjustment, and the thing worth asserting is what a component ends up rendering.
function Harness({ rows, filter }: { rows: string[]; filter: string }) {
  const paged = usePaged(rows, filter, 50)
  return (
    <div>
      <span data-testid="range">
        {paged.from}-{paged.to} of {paged.total}
      </span>
      <span data-testid="page">
        {paged.page}/{paged.pages}
      </span>
      <span data-testid="first">{paged.rows[0] ?? 'none'}</span>
      <button type="button" onClick={() => paged.setPage(paged.page + 1)}>
        next
      </button>
      <button type="button" onClick={() => paged.setPerPage(100)}>
        bigger
      </button>
    </div>
  )
}

test('starts on the first page and slices it', () => {
  render(<Harness rows={ROWS} filter="" />)
  expect(screen.getByTestId('range').textContent).toBe('1-50 of 260')
  expect(screen.getByTestId('first').textContent).toBe('row_000')
})

test('advancing a page advances the slice', () => {
  render(<Harness rows={ROWS} filter="" />)
  fireEvent.click(screen.getByRole('button', { name: 'next' }))
  expect(screen.getByTestId('page').textContent).toBe('2/6')
  expect(screen.getByTestId('first').textContent).toBe('row_050')
})

test('a changed filter returns to the first page', () => {
  // Clamping alone would keep the table non-empty, but leaving an analyst on page 5 after they
  // typed a filter hides the best matches behind a control they did not know they had moved.
  const { rerender } = render(<Harness rows={ROWS} filter="" />)
  fireEvent.click(screen.getByRole('button', { name: 'next' }))
  fireEvent.click(screen.getByRole('button', { name: 'next' }))
  expect(screen.getByTestId('page').textContent).toBe('3/6')

  rerender(<Harness rows={ROWS.slice(0, 3)} filter="row_00" />)
  expect(screen.getByTestId('page').textContent).toBe('1/1')
  expect(screen.getByTestId('first').textContent).toBe('row_000')
})

test('a list that shrinks under an unchanged filter still renders rows', () => {
  // The clamp, separately from the reset: same filter key, fewer rows -- a reload that returned a
  // shorter list, say. Page 3 of a 3-row list must show the 3 rows, not an empty table.
  const { rerender } = render(<Harness rows={ROWS} filter="x" />)
  fireEvent.click(screen.getByRole('button', { name: 'next' }))
  fireEvent.click(screen.getByRole('button', { name: 'next' }))
  rerender(<Harness rows={ROWS.slice(0, 3)} filter="x" />)
  expect(screen.getByTestId('range').textContent).toBe('1-3 of 3')
  expect(screen.getByTestId('first').textContent).toBe('row_000')
})

test('changing the page size returns to the first page', () => {
  // Keeping the page number while the size changes lands the analyst somewhere unrelated: page 3
  // of 50 starts at row 100, page 3 of 100 at row 200.
  render(<Harness rows={ROWS} filter="" />)
  fireEvent.click(screen.getByRole('button', { name: 'next' }))
  fireEvent.click(screen.getByRole('button', { name: 'bigger' }))
  expect(screen.getByTestId('range').textContent).toBe('1-100 of 260')
  expect(screen.getByTestId('first').textContent).toBe('row_000')
})

test('an empty list renders no rows without throwing', () => {
  render(<Harness rows={[]} filter="" />)
  expect(screen.getByTestId('range').textContent).toBe('0-0 of 0')
  expect(screen.getByTestId('first').textContent).toBe('none')
})
