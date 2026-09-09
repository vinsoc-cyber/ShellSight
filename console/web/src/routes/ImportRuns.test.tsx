import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { ImportRuns } from './ImportRuns'

function file(relPath: string, body = '{}'): File {
  const name = relPath.slice(relPath.lastIndexOf('/') + 1)
  const f = new File([body], name, { type: 'application/json' })
  Object.defineProperty(f, 'webkitRelativePath', { value: relPath })
  return f
}

// Drive the folder input the way a picker would, since jsdom will not open one.
function pick(files: File[]) {
  const input = screen.getByLabelText(/run folders/i) as HTMLInputElement
  Object.defineProperty(input, 'files', { value: files, configurable: true })
  fireEvent.change(input)
}

type Sent = { url: string; report: string; manifest: string | null }

function server(opts: { fail?: string[]; alreadyPresent?: string[] } = {}) {
  const sent: Sent[] = []
  vi.stubGlobal(
    'fetch',
    vi.fn(async (url: string, init?: RequestInit) => {
      const form = init?.body as FormData
      const report = form.get('report') as File
      const manifest = form.get('manifest') as File | null
      sent.push({ url, report: report.name, manifest: manifest ? manifest.name : null })

      const dir = (report as File & { webkitRelativePath?: string }).webkitRelativePath ?? ''
      if (opts.fail?.some((f) => dir.includes(f))) {
        return {
          ok: false,
          status: 422,
          statusText: 'UNPROCESSABLE',
          json: async () => ({ error: 'report.json is not a scanner report' }),
        } as Response
      }
      const created = !opts.alreadyPresent?.some((a) => dir.includes(a))
      return {
        ok: true,
        status: created ? 201 : 200,
        statusText: 'OK',
        json: async () => ({
          scan_id: 1,
          run_id: 'r1',
          host: 'WEB-IIS-07',
          created,
          findings: 3,
          integrity: manifest ? 'verified' : 'unverified',
        }),
      } as Response
    }),
  )
  return sent
}

function show(onImported = () => {}) {
  render(<ImportRuns caseID={7} onImported={onImported} />)
}

test('a picked directory reports how many runs it found before sending anything', () => {
  // Nothing is uploaded on selection. An analyst who pointed at the wrong directory finds out
  // from a count, not from forty rows of results.
  server()
  show()
  pick([
    file('sweep/run_web-01_a1/report.json'),
    file('sweep/run_web-01_a1/manifest.json'),
    file('sweep/run_web-02_b2/report.json'),
  ])
  expect(screen.getByText(/2 runs ready/i)).toBeTruthy()
  expect(screen.getByText(/1 with a manifest/i)).toBeTruthy()
  expect(fetch).not.toHaveBeenCalled()
})

test('importing posts each run to the case in the URL', async () => {
  const sent = server()
  show()
  pick([
    file('sweep/run_web-01_a1/report.json'),
    file('sweep/run_web-01_a1/manifest.json'),
    file('sweep/run_web-02_b2/report.json'),
  ])
  fireEvent.click(screen.getByRole('button', { name: /^import$/i }))

  await waitFor(() => expect(sent).toHaveLength(2))
  expect(sent.every((s) => s.url === '/api/cases/7/reports')).toBe(true)
  // The manifest is sent only for the run that had one -- never invented.
  expect(sent.map((s) => s.manifest)).toEqual(['manifest.json', null])
})

test('the result of each run is reported, including its integrity', async () => {
  server()
  show()
  pick([file('sweep/run_web-01_a1/report.json'), file('sweep/run_web-01_a1/manifest.json')])
  fireEvent.click(screen.getByRole('button', { name: /^import$/i }))

  expect(await screen.findByText('run_web-01_a1')).toBeTruthy()
  expect(screen.getByText('imported')).toBeTruthy()
  // Scoped to the CELL: the help text above also uses the word "verified", so a page-wide query
  // matches two elements and would pass on the wrong one.
  expect(screen.getByRole('cell', { name: 'verified' })).toBeTruthy()
})

test('a run already filed under this case says so rather than looking like a failure', async () => {
  // Re-importing a folder is ordinary; bulk import is the primary import.
  server({ alreadyPresent: ['run_web-01_a1'] })
  show()
  pick([file('sweep/run_web-01_a1/report.json')])
  fireEvent.click(screen.getByRole('button', { name: /^import$/i }))

  expect(await screen.findByText(/already present/i)).toBeTruthy()
})

test('one bad folder does not abandon the others', async () => {
  // The rule the CLI follows, and the reason an import of forty is worth doing in one action.
  const sent = server({ fail: ['run_web-02_b2'] })
  show()
  pick([
    file('sweep/run_web-01_a1/report.json'),
    file('sweep/run_web-02_b2/report.json'),
    file('sweep/run_web-03_c3/report.json'),
  ])
  fireEvent.click(screen.getByRole('button', { name: /^import$/i }))

  await waitFor(() => expect(sent).toHaveLength(3))
  expect(await screen.findByText(/failed/i)).toBeTruthy()
  // And the server's own words about the file it refused.
  expect(screen.getByText(/is not a scanner report/i)).toBeTruthy()
  expect(screen.getAllByText('imported')).toHaveLength(2)
})

test('a successful import asks the scan list to reload', async () => {
  // The imported scan has to appear without a page refresh, or the analyst cannot tell the import
  // worked from the screen that is supposed to show it.
  let reloaded = 0
  server()
  show(() => {
    reloaded++
  })
  pick([file('sweep/run_web-01_a1/report.json')])
  fireEvent.click(screen.getByRole('button', { name: /^import$/i }))
  await waitFor(() => expect(reloaded).toBe(1))
})

test('a directory with no report.json says so instead of offering an empty import', () => {
  server()
  show()
  pick([file('notes/todo.txt')])
  expect(screen.getByText(/nothing here to import/i)).toBeTruthy()
  expect(screen.queryByRole('button', { name: /^import$/i })).toBeNull()
})

test('a half-copied run folder is named rather than silently skipped', () => {
  server()
  show()
  pick([file('sweep/run_web-01_a1/report.json'), file('sweep/run_web-99_zz/manifest.json')])
  expect(screen.getByText(/run_web-99_zz/)).toBeTruthy()
  expect(screen.getByText(/1 run ready/i)).toBeTruthy()
})
