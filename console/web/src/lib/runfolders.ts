// Turning a file picker's flat list back into run folders.
//
// The scanner writes one folder per run -- report.json, manifest.json, summary.txt,
// findings.ndjson -- and BULK IS THE PRIMARY IMPORT: a sweep of forty hosts produces forty of
// them, which is why the CLI takes a directory rather than a folder. The browser gives a
// directory picker back as one flat FileList with a relative path on each entry, so the grouping
// the CLI gets from the filesystem has to be reconstructed here.

export type RunUpload = {
  // The folder name, shown to the analyst before anything is sent.
  name: string
  report: File
  // Optional, exactly as it is for the CLI: no manifest means "unverified", not a refusal.
  manifest?: File
}

export type Grouped = {
  runs: RunUpload[]
  // Folders that look like a run but have no report.json, named so the analyst is told which
  // folder was skipped rather than left to count the difference.
  incomplete: string[]
  // Files that are part of no run at all: summary.txt, findings.ndjson, anything else selected.
  ignored: number
}

// dirOf is the folder a picked file sat in. webkitRelativePath is set only by a DIRECTORY pick;
// files chosen one by one carry an empty string, which groups them together as a single unnamed
// run -- the "I selected report.json and manifest.json myself" case.
function dirOf(f: File): string {
  const rel = f.webkitRelativePath || ''
  const cut = rel.lastIndexOf('/')
  return cut === -1 ? '' : rel.slice(0, cut)
}

function baseName(path: string): string {
  const cut = path.lastIndexOf('/')
  return cut === -1 ? path : path.slice(cut + 1)
}

// groupRunFolders sorts a flat selection into the runs it contains.
//
// Matching is on the file NAME, not on content: report.json is the scanner's own name for the
// only artefact the console ingests, and a file that merely parses as a report is not one. The
// server re-checks anyway -- this is the browser saving a round trip, never the decision.
export function groupRunFolders(files: File[]): Grouped {
  const byDir = new Map<string, { report?: File; manifest?: File; others: number }>()

  for (const f of files) {
    const dir = dirOf(f)
    const entry = byDir.get(dir) ?? { others: 0 }
    const name = baseName(f.name).toLowerCase()
    if (name === 'report.json') entry.report = f
    else if (name === 'manifest.json') entry.manifest = f
    else entry.others++
    byDir.set(dir, entry)
  }

  const runs: RunUpload[] = []
  const incomplete: string[] = []
  let ignored = 0

  for (const [dir, entry] of byDir) {
    ignored += entry.others
    if (!entry.report) {
      // A directory holding only a manifest is a half-copied run folder and worth naming. A
      // directory holding neither is just an unrelated folder the picker swept up.
      if (entry.manifest) incomplete.push(dir || '(selected files)')
      continue
    }
    runs.push({
      name: dir === '' ? entry.report.name : baseName(dir),
      report: entry.report,
      manifest: entry.manifest,
    })
  }

  // Stable order, so re-picking the same folder lists the runs the same way twice.
  runs.sort((a, b) => a.name.localeCompare(b.name))
  incomplete.sort()
  return { runs, incomplete, ignored }
}
