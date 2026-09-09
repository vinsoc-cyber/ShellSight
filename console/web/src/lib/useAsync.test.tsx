import { render, screen, waitFor } from '@testing-library/react'
import { useAsync } from './useAsync'

function Probe({ fn }: { fn: () => Promise<string> }) {
  const { data, error, loading } = useAsync(fn, [])
  if (loading) return <p>loading</p>
  if (error) return <p>error: {error.message}</p>
  return <p>data: {data}</p>
}

test('reports loading, then the value', async () => {
  render(<Probe fn={() => Promise.resolve('ok')} />)
  expect(screen.getByText('loading')).toBeTruthy()
  await waitFor(() => expect(screen.getByText('data: ok')).toBeTruthy())
})

test('reports the error instead of hanging on loading forever', async () => {
  render(<Probe fn={() => Promise.reject(new Error('nope'))} />)
  await waitFor(() => expect(screen.getByText('error: nope')).toBeTruthy())
})

test('a non-Error rejection still produces a readable message', async () => {
  // A rejected fetch can throw anything. Rendering "[object Object]" at an analyst is useless.
  render(<Probe fn={() => Promise.reject('plain string')} />)
  await waitFor(() => expect(screen.getByText('error: plain string')).toBeTruthy())
})
