import { groupRunFolders } from './runfolders'

// jsdom's File carries no webkitRelativePath, and it is read-only on the real thing, so it is
// defined here rather than assigned.
function file(relPath: string): File {
  const name = relPath.slice(relPath.lastIndexOf('/') + 1)
  const f = new File(['{}'], name, { type: 'application/json' })
  Object.defineProperty(f, 'webkitRelativePath', { value: relPath })
  return f
}

test('a directory of run folders becomes one run each', () => {
  // Bulk is the primary import: forty hosts, forty folders, one pick.
  const got = groupRunFolders([
    file('sweep/run_web-01_a1/report.json'),
    file('sweep/run_web-01_a1/manifest.json'),
    file('sweep/run_web-02_b2/report.json'),
    file('sweep/run_web-02_b2/manifest.json'),
  ])
  expect(got.runs.map((r) => r.name)).toEqual(['run_web-01_a1', 'run_web-02_b2'])
  expect(got.runs.every((r) => r.manifest !== undefined)).toBe(true)
  expect(got.incomplete).toEqual([])
})

test('a run folder without a manifest is still a run', () => {
  // The manifest decides verified vs unverified. Its absence is not a refusal, here or on the
  // server, and treating it as one would reject perfectly good evidence.
  const got = groupRunFolders([file('sweep/run_web-03_c3/report.json')])
  expect(got.runs).toHaveLength(1)
  expect(got.runs[0]?.manifest).toBeUndefined()
})

test('the scanner’s other outputs are ignored, not uploaded', () => {
  // summary.txt is for humans and findings.ndjson is a lossy OCSF projection for SIEMs. Only
  // report.json carries the coverage and the verdict, so only it is sent.
  const got = groupRunFolders([
    file('run_web-01_a1/report.json'),
    file('run_web-01_a1/manifest.json'),
    file('run_web-01_a1/summary.txt'),
    file('run_web-01_a1/findings.ndjson'),
  ])
  expect(got.runs).toHaveLength(1)
  expect(got.ignored).toBe(2)
})

test('a folder holding a manifest but no report is named, not silently dropped', () => {
  // A half-copied run folder. Saying which one was skipped beats letting the analyst work out
  // why forty folders produced thirty-nine scans.
  const got = groupRunFolders([
    file('sweep/run_web-01_a1/report.json'),
    file('sweep/run_web-99_zz/manifest.json'),
  ])
  expect(got.runs.map((r) => r.name)).toEqual(['run_web-01_a1'])
  expect(got.incomplete).toEqual(['sweep/run_web-99_zz'])
})

test('files picked individually rather than as a folder are one run', () => {
  // webkitRelativePath is empty for a plain multi-file pick, which is the "I selected report.json
  // and manifest.json myself" case and must not be mistaken for forty runs in a root folder.
  const plain = (name: string) => new File(['{}'], name, { type: 'application/json' })
  const got = groupRunFolders([plain('report.json'), plain('manifest.json')])
  expect(got.runs).toHaveLength(1)
  expect(got.runs[0]?.manifest).toBeDefined()
})

test('an unrelated folder contributes nothing and is not reported as incomplete', () => {
  const got = groupRunFolders([file('notes/todo.txt'), file('notes/scratch.md')])
  expect(got.runs).toEqual([])
  expect(got.incomplete).toEqual([])
  expect(got.ignored).toBe(2)
})

test('matching is case-insensitive on the file name', () => {
  const got = groupRunFolders([file('run_x/REPORT.JSON'), file('run_x/Manifest.json')])
  expect(got.runs).toHaveLength(1)
  expect(got.runs[0]?.manifest).toBeDefined()
})

test('an empty selection is not an error', () => {
  expect(groupRunFolders([])).toEqual({ runs: [], incomplete: [], ignored: 0 })
})
