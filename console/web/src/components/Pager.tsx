import { PER_PAGE_CHOICES, type Page } from '../lib/paginate'

// One pager, used by every list in the console.
//
// It always states the RANGE and the TOTAL, never just the page number. "Page 3 of 118" tells an
// analyst nothing about how big the library is; "101–150 of 5,872 rules" is the sentence they
// actually need, and it is the same sentence the old screens only managed as a truncation warning
// at the bottom of a list they could not page through.
export function Pager({
  page,
  unit,
  onPage,
  onPerPage,
  showPerPage = true,
}: {
  page: Page
  // Plural noun for what is being paged: "rules", "findings", "scans".
  unit: string
  onPage: (n: number) => void
  onPerPage?: (n: number) => void
  showPerPage?: boolean
}) {
  const { from, to, total, page: current, pages } = page
  const first = current <= 1
  const last = current >= pages

  return (
    <nav className="pager" aria-label={`${unit} pagination`}>
      <span className="pager-range">
        {total === 0 ? (
          <>No {unit}</>
        ) : (
          <>
            <strong>
              {from.toLocaleString()}–{to.toLocaleString()}
            </strong>{' '}
            of {total.toLocaleString()} {unit}
          </>
        )}
      </span>

      {/* One page of one is not a thing to navigate. The range above still renders, so the count
          never disappears just because it fits on a screen. */}
      {pages > 1 && (
        <>
          <span className="pager-btns">
            <button type="button" aria-label="first page" disabled={first} onClick={() => onPage(1)}>
              «
            </button>
            <button
              type="button"
              aria-label="previous page"
              disabled={first}
              onClick={() => onPage(current - 1)}
            >
              ‹
            </button>
            <button
              type="button"
              aria-label="next page"
              disabled={last}
              onClick={() => onPage(current + 1)}
            >
              ›
            </button>
            <button
              type="button"
              aria-label="last page"
              disabled={last}
              onClick={() => onPage(pages)}
            >
              »
            </button>
          </span>
          <span className="pager-pos">
            Page {current.toLocaleString()} of {pages.toLocaleString()}
          </span>
        </>
      )}

      {showPerPage && onPerPage && (
        <>
          <label htmlFor={`per-${unit}`} className="muted">
            Per page
          </label>
          <select
            id={`per-${unit}`}
            value={page.perPage}
            onChange={(e) => onPerPage(Number(e.target.value))}
          >
            {PER_PAGE_CHOICES.map((n) => (
              <option key={n} value={n}>
                {n}
              </option>
            ))}
          </select>
        </>
      )}
    </nav>
  )
}
