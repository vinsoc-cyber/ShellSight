import { DEFAULT_PER_PAGE, pageSlice, paginate } from './paginate'

test('the first page of a long list reports its human range', () => {
  const p = paginate(5872, 1, 50)
  expect(p.pages).toBe(118)
  expect([p.from, p.to]).toEqual([1, 50])
  expect([p.start, p.end]).toEqual([0, 50])
})

test('the last page is short rather than padded', () => {
  // 5872 = 117*50 + 22. The last page holds 22 rows and must say so.
  const p = paginate(5872, 118, 50)
  expect([p.from, p.to]).toEqual([5851, 5872])
  expect(p.end - p.start).toBe(22)
})

test('an empty list is page 1 of 1, showing 0 of 0', () => {
  // "Page 1 of 0" is not a thing, and a screen that renders it looks broken rather than empty.
  const p = paginate(0, 1, 50)
  expect([p.page, p.pages]).toEqual([1, 1])
  expect([p.from, p.to]).toEqual([0, 0])
  expect(pageSlice([], p)).toEqual([])
})

test('a page beyond the end is clamped to the last page that exists', () => {
  // THE bug this module exists to kill. An analyst on page 40 filters the library down to 3 rows;
  // an unclamped slice(1950, 2000) of a 3-row array returns nothing, and the screen reads "no
  // rules match" about a filter that matches three.
  const rows = [1, 2, 3]
  const p = paginate(rows.length, 40, 50)
  expect(p.page).toBe(1)
  expect(pageSlice(rows, p)).toEqual([1, 2, 3])
})

test('a page below the first is clamped up', () => {
  expect(paginate(100, 0, 25).page).toBe(1)
  expect(paginate(100, -7, 25).page).toBe(1)
})

test('a nonsense page number falls back to the first page rather than emptying the table', () => {
  expect(paginate(100, Number.NaN, 25).page).toBe(1)
})

test('a nonsense page size cannot divide by zero', () => {
  // perPage reaches here from a <select>, so it is a string away from being 0 or NaN. Either one
  // makes ceil(n/size) Infinity or NaN, and every downstream count unrenderable.
  expect(paginate(100, 1, 0).perPage).toBe(1)
  expect(paginate(100, 1, Number.NaN).perPage).toBe(1)
  expect(paginate(100, 1, 0).pages).toBe(100)
})

test('pageSlice returns exactly the rows the range claims', () => {
  const rows = Array.from({ length: 250 }, (_, i) => i)
  const p = paginate(rows.length, 3, DEFAULT_PER_PAGE)
  const got = pageSlice(rows, p)
  expect(got).toHaveLength(50)
  expect(got[0]).toBe(100)
  expect(got.at(-1)).toBe(149)
  // The human range and the actual rows must agree, or the footer is a second, contradictory
  // account of what is on screen.
  expect([p.from, p.to]).toEqual([101, 150])
})

test('a list shorter than one page is still one whole page', () => {
  const p = paginate(3, 1, 50)
  expect(p.pages).toBe(1)
  expect([p.from, p.to]).toEqual([1, 3])
})
