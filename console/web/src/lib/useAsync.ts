import { useEffect, useRef, useState } from 'react'

type State<T> = { data: T | null; error: Error | null; loading: boolean }

// useAsync is deliberately small: load / error / data, with a reload trigger. A query library
// would add caching and retries that a single-operator internal console does not need, at the
// price of the SPA's dependency count.
export function useAsync<T>(fn: () => Promise<T>, deps: unknown[]) {
  const [state, setState] = useState<State<T>>({ data: null, error: null, loading: true })
  const [nonce, setNonce] = useState(0)
  const seen = useRef<unknown[] | null>(null)

  useEffect(() => {
    let live = true
    // A RELOAD keeps what is on screen; a DEPS CHANGE clears it. The distinction is the whole
    // point of this ref.
    //
    // Blanking on every run meant every mutation emptied the screen it had just changed: freezing
    // a set unmounted the set's own panel, judging a finding replaced the queue with "Loading
    // findings…" and lost the reader's place, and excluding a rule blanked the exclusions table
    // for a round trip. Reloading the SAME query is a refresh of what is already true, so the old
    // rows stay until the new ones arrive.
    //
    // Clearing on a deps change is not tidiness, it is the guard: without it a slow response for
    // scan 1 could paint under scan 2's heading, and the components that seed useState at mount
    // (SelectionEditor, RuleEditor) rely on unmounting between subjects to re-seed.
    const sameQuery =
      seen.current !== null &&
      seen.current.length === deps.length &&
      seen.current.every((d, i) => Object.is(d, deps[i]))
    seen.current = deps

    setState((prev) =>
      sameQuery
        ? { ...prev, loading: true, error: null }
        : { data: null, error: null, loading: true },
    )

    fn().then(
      (data) => {
        // Guard against a response arriving after the component moved on, which would otherwise
        // render one scan's findings under another scan's heading.
        if (live) setState({ data, error: null, loading: false })
      },
      (err: unknown) => {
        // A failed reload drops the stale rows: showing yesterday's data next to an error is how
        // an analyst comes to believe a failed refresh succeeded.
        if (live) setState({ data: null, error: asError(err), loading: false })
      },
    )
    return () => {
      live = false
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [...deps, nonce])

  return { ...state, reload: () => setNonce((n) => n + 1) }
}

// A rejection can carry anything. Rendering "[object Object]" at an analyst is useless.
export function asError(err: unknown): Error {
  return err instanceof Error ? err : new Error(typeof err === 'string' ? err : JSON.stringify(err))
}
