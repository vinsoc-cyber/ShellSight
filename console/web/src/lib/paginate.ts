// Pagination as arithmetic, kept out of the components so the rules about what a page IS are
// tested directly rather than through a rendered table.
//
// Every list this console shows is unbounded in practice -- 5,872 rules, 4,210 pinned revisions,
// a triage queue of whatever the scan found. The screens used to answer that by rendering
// everything (the rule library: 29,401 DOM nodes and a 211,179px page) or by rendering the first
// 200 and saying so, which is honest but leaves rows 201..n unreachable by any means the UI
// offers. A page is the third answer: bounded work per render, and every row still reachable.

export type Page = {
  // 1-based and CLAMPED into [1, pages]. See below for why clamping is the whole point.
  page: number
  perPage: number
  // At least 1, so an empty list reads "page 1 of 1" rather than "page 1 of 0".
  pages: number
  total: number
  // 0-based slice bounds, for rows.slice(start, end).
  start: number
  end: number
  // 1-based inclusive human range, "showing from..to of total". Both 0 when the list is empty,
  // which is the only honest way to write "0 of 0".
  from: number
  to: number
}

export const PER_PAGE_CHOICES = [25, 50, 100, 200] as const
export const DEFAULT_PER_PAGE = 50

// paginate clamps rather than trusting the caller's page number.
//
// This is not defensive tidiness, it is the one bug class this module exists to kill: an analyst
// on page 40 of the rule library types "godzilla" into the filter, the match set drops to 3 rows,
// and an unclamped slice(1950, 2000) of a 3-row array returns nothing. The screen then reads
// "no rules match" about a filter that matches three -- the console lying about its own data,
// which is the failure this whole codebase is written against. Clamping puts them on the last
// page that exists instead.
export function paginate(total: number, page: number, perPage: number): Page {
  // NaN is guarded explicitly rather than by Math.max: Math.max(1, NaN) is NaN, so a page size
  // that arrived as a string from a <select> would propagate NaN through every count on the
  // screen. `|| fallback` is exactly right here — the other falsy value, 0, is also invalid.
  const size = Math.max(1, Math.floor(perPage) || 1)
  const count = Math.max(0, Math.floor(total) || 0)
  const pages = Math.max(1, Math.ceil(count / size))
  const current = Math.min(Math.max(1, Math.floor(page) || 1), pages)
  const start = (current - 1) * size
  const end = Math.min(start + size, count)
  return {
    page: current,
    perPage: size,
    pages,
    total: count,
    start,
    end,
    from: count === 0 ? 0 : start + 1,
    to: end,
  }
}

// pageSlice is paginate's companion, so a caller never hand-rolls the slice and never slices with
// an unclamped page.
export function pageSlice<T>(rows: T[], p: Page): T[] {
  return rows.slice(p.start, p.end)
}
