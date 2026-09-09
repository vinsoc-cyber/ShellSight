import { fireEvent, render, screen } from '@testing-library/react'
import { paginate } from '../lib/paginate'
import { Pager } from './Pager'

function show(total: number, page: number, perPage = 50) {
  const pages: number[] = []
  const sizes: number[] = []
  render(
    <Pager
      page={paginate(total, page, perPage)}
      unit="rules"
      onPage={(n) => pages.push(n)}
      onPerPage={(n) => sizes.push(n)}
    />,
  )
  return { pages, sizes }
}

test('states the range and the total, not just the page number', () => {
  // "Page 3 of 118" says nothing about how big the library is. The range and the total are what an
  // analyst is actually asking when they look at the bottom of a list.
  show(5872, 3)
  expect(screen.getByText(/101–150/)).toBeTruthy()
  expect(screen.getByText(/of 5,872 rules/)).toBeTruthy()
})

test('the first page cannot go back and the last cannot go forward', () => {
  show(5872, 1)
  expect((screen.getByRole('button', { name: /first page/i }) as HTMLButtonElement).disabled).toBe(true)
  expect((screen.getByRole('button', { name: /previous page/i }) as HTMLButtonElement).disabled).toBe(true)
  expect((screen.getByRole('button', { name: /next page/i }) as HTMLButtonElement).disabled).toBe(false)
})

test('the last page disables forward movement', () => {
  show(5872, 118)
  expect((screen.getByRole('button', { name: /next page/i }) as HTMLButtonElement).disabled).toBe(true)
  expect((screen.getByRole('button', { name: /last page/i }) as HTMLButtonElement).disabled).toBe(true)
})

test('moving pages reports the page asked for', () => {
  const { pages } = show(5872, 3)
  fireEvent.click(screen.getByRole('button', { name: /next page/i }))
  fireEvent.click(screen.getByRole('button', { name: /previous page/i }))
  fireEvent.click(screen.getByRole('button', { name: /last page/i }))
  fireEvent.click(screen.getByRole('button', { name: /first page/i }))
  expect(pages).toEqual([4, 2, 118, 1])
})

test('a list that fits on one page offers no navigation but still states its size', () => {
  // The count is the useful half and it must not disappear just because the list is short.
  show(12, 1)
  expect(screen.queryByRole('button', { name: /next page/i })).toBeNull()
  expect(screen.getByText(/of 12 rules/)).toBeTruthy()
})

test('an empty list says so rather than showing 0–0', () => {
  show(0, 1)
  expect(screen.getByText(/no rules/i)).toBeTruthy()
})

test('the page size is offered and reported', () => {
  const { sizes } = show(5872, 1)
  fireEvent.change(screen.getByLabelText(/per page/i), { target: { value: '200' } })
  expect(sizes).toEqual([200])
})
