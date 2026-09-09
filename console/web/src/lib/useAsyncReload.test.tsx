import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { useState } from 'react'
import { useAsync } from './useAsync'

// What a reload must and must not blank. These are the rules every mutation in the console
// depends on, so they are asserted directly rather than through a screen.

function Probe({ subject, load }: { subject: string; load: (s: string) => Promise<string> }) {
  const a = useAsync(() => load(subject), [subject])
  return (
    <div>
      <span data-testid="data">{a.data ?? 'none'}</span>
      <span data-testid="loading">{a.loading ? 'loading' : 'idle'}</span>
      <span data-testid="error">{a.error ? a.error.message : 'none'}</span>
      <button type="button" onClick={a.reload}>
        reload
      </button>
    </div>
  )
}

function Harness({ load }: { load: (s: string) => Promise<string> }) {
  const [subject, setSubject] = useState('a')
  return (
    <>
      <Probe subject={subject} load={load} />
      <button type="button" onClick={() => setSubject('b')}>
        switch
      </button>
    </>
  )
}

test('a reload keeps the rows on screen while it refetches', async () => {
  // The whole point. Blanking on reload meant every mutation emptied the screen it had just
  // changed: freezing a set unmounted the set's own panel, and judging a finding replaced the
  // queue with "Loading findings…" and lost the analyst's place.
  let n = 0
  let release: (v: string) => void = () => {}
  const load = () =>
    new Promise<string>((res) => {
      n++
      if (n === 1) res('first')
      else release = res
    })

  render(<Harness load={load} />)
  await waitFor(() => expect(screen.getByTestId('data').textContent).toBe('first'))

  fireEvent.click(screen.getByRole('button', { name: 'reload' }))
  // Mid-flight: still loading, and the previous answer is STILL THERE.
  expect(screen.getByTestId('loading').textContent).toBe('loading')
  expect(screen.getByTestId('data').textContent).toBe('first')

  release('second')
  await waitFor(() => expect(screen.getByTestId('data').textContent).toBe('second'))
})

test('changing the subject clears the old answer immediately', async () => {
  // Not tidiness -- the guard. Without it a slow response for scan 1 can paint under scan 2's
  // heading, and the editors that seed useState at mount rely on unmounting between subjects.
  let release: (v: string) => void = () => {}
  let n = 0
  const load = (s: string) =>
    new Promise<string>((res) => {
      n++
      if (n === 1) res(`data-for-${s}`)
      else release = res
    })

  render(<Harness load={load} />)
  await waitFor(() => expect(screen.getByTestId('data').textContent).toBe('data-for-a'))

  fireEvent.click(screen.getByRole('button', { name: 'switch' }))
  expect(screen.getByTestId('data').textContent).toBe('none')

  release('data-for-b')
  await waitFor(() => expect(screen.getByTestId('data').textContent).toBe('data-for-b'))
})

test('a failed reload drops the stale rows rather than showing them beside the error', async () => {
  // Showing yesterday's data next to a failure is how an analyst comes to believe a failed
  // refresh succeeded.
  let n = 0
  const load = () => {
    n++
    return n === 1 ? Promise.resolve('first') : Promise.reject(new Error('connection refused'))
  }

  render(<Harness load={load} />)
  await waitFor(() => expect(screen.getByTestId('data').textContent).toBe('first'))

  fireEvent.click(screen.getByRole('button', { name: 'reload' }))
  await waitFor(() => expect(screen.getByTestId('error').textContent).toBe('connection refused'))
  expect(screen.getByTestId('data').textContent).toBe('none')
})

test('a reload clears a previous error', async () => {
  // Otherwise a recovered request leaves its old failure banner on screen.
  let n = 0
  const load = () => {
    n++
    return n === 1 ? Promise.reject(new Error('boom')) : Promise.resolve('recovered')
  }

  render(<Harness load={load} />)
  await waitFor(() => expect(screen.getByTestId('error').textContent).toBe('boom'))

  fireEvent.click(screen.getByRole('button', { name: 'reload' }))
  await waitFor(() => expect(screen.getByTestId('data').textContent).toBe('recovered'))
  expect(screen.getByTestId('error').textContent).toBe('none')
})
