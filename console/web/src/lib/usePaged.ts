import { useState } from 'react'
import { DEFAULT_PER_PAGE, type Page, pageSlice, paginate } from './paginate'

export type Paged<T> = Page & {
  rows: T[]
  setPage: (n: number) => void
  setPerPage: (n: number) => void
}

// usePaged holds the page state for one list and hands back the slice to render.
//
// resetKey is whatever narrows the list -- a filter string, a selected set's id. When it changes
// the page returns to 1. Clamping alone would be enough to keep the table non-empty (paginate
// guarantees that), but leaving an analyst on "page 12 of 12" after they typed a filter hides the
// best matches behind a control they did not know they had moved.
//
// The reset happens DURING RENDER, not in a useEffect. React documents this as the way to adjust
// state when an input changes: the component re-renders immediately with page 1 and nothing is
// committed to the DOM in between. An effect would paint one frame of the wrong page first, which
// on a 200-row table is a visible flash of rows that do not match what was typed.
export function usePaged<T>(
  rows: T[],
  resetKey: unknown,
  initialPerPage: number = DEFAULT_PER_PAGE,
): Paged<T> {
  const [page, setPage] = useState(1)
  const [perPage, setPerPage] = useState(initialPerPage)
  const [seenKey, setSeenKey] = useState(resetKey)

  if (seenKey !== resetKey) {
    setSeenKey(resetKey)
    setPage(1)
  }

  const p = paginate(rows.length, page, perPage)
  return {
    ...p,
    rows: pageSlice(rows, p),
    setPage,
    // Changing the page size while deep in a list would otherwise land the analyst somewhere
    // unrelated; going back to the first page is the predictable answer.
    setPerPage: (n: number) => {
      setPerPage(n)
      setPage(1)
    },
  }
}
