// Wire types, mirroring the Go `json` tags exactly. Every string that originated in a scan report
// is attacker-authored: it is rendered as text by React and must never reach
// dangerouslySetInnerHTML or be interpolated into a URL without encoding.

export type Case = { id: number; name: string; created_by: string; created_at: string }

export type Coverage = {
  view: string
  status: string
  reason?: string
  targets_scanned: number
  non_regular: number
  unreadable: number
  oversize_skipped: number
  no_language_detector: number
}

export type Scan = {
  id: number
  run_id: string
  host: string
  started?: string
  finished?: string
  tool_version?: string
  operator?: string
  invocation?: string
  build_id?: string
  rule_set?: string
  tier: string
  score: number
  incomplete: boolean
  integrity: string
  source?: string
  imported_at: string
}

export type Finding = {
  id: number
  ref: string
  content_key: string
  host: string
  view: string
  file_path?: string
  file_sha256?: string
  artifact_kind?: string
  artifact_id?: string
  basis: string
  knowledge_ref?: string
  evidence?: string
  score: number
  tier: string
  mitre?: string[]
  fingerprint?: string
}

export type Decision = {
  id: number
  content_key: string
  verdict: string
  note?: string
  author: string
  case_id?: number
  case_name?: string
  decided_at: string
}

export type Group = {
  content_key: string
  tier: string
  score: number
  locations: number
  hosts: string[]
  rules: string[]
  findings: Finding[]
  prior_decisions: Decision[]
}

export type ScanDetail = {
  scan: Scan
  verdict: { tier: string; score: number; incomplete: boolean }
  coverage: Coverage[]
}

export type Rule = { id: number; identifier: string; layer: string; source_pack?: string }

// One rule as the browser needs it. No rule text: it is the bulk of the payload and the browser
// never shows it.
export type RuleIndexRow = {
  id: number
  identifier: string
  layer: string
  source_pack?: string
  score?: number
  description?: string
}

export type RuleRevision = {
  id: number
  rule_id: number
  revision: number
  text: string
  lang?: string
  author: string
  created_at: string
}

export type RuleSet = {
  id: number
  name: string
  version: number | null
  created_by: string
  frozen_at: string | null
  frozen_by?: string
  yarc_sha256?: string
}

export type Selection = { layers: string[]; rules: number[] }

// One rule pinned into a frozen set, without its text. The server omits the text deliberately:
// at 5,872 rules it would be megabytes, and the text is already reachable per rule.
export type FrozenMember = {
  rule_id: number
  identifier: string
  layer: string
  revision: number
}

export type Exclusion = {
  rule_id: number
  identifier: string
  reason: string
  author: string
  created_at: string
}

export type Release = {
  id: number
  version: string
  target: string
  published_at: string
  published_by: string
}

// One recorded build. agent_json is optional here and not because the server omits it: it is a
// base64 []byte on the wire and the form never reads it, so declaring it required would only make
// every fixture carry a field nothing renders.
export type Build = {
  id: number
  build_id: string
  release_id: number
  rule_set_id: number | null
  views: string[]
  sha256: string
  size_bytes: number
  agent_json?: string
  generated_at: string
  generated_by: string
}

// The scanner's own declaration of what each view needs, read out of a release. The console never
// keeps its own copy (G5), which is why this is fetched rather than hardcoded.
export type ComponentsView = {
  binaries?: string[]
  data?: string[]
  rules: boolean
  host_requires?: string
}

export type ComponentsDoc = {
  schema_version: string
  target: string
  release: string
  always: string[]
  views: Record<string, ComponentsView>
}

// One ingested run, as reports.Result puts it on the wire. `created` is false when the run was
// already filed under this case -- re-importing a folder is ordinary, not a failure.
export type Ingested = {
  scan_id: number
  run_id: string
  host: string
  created: boolean
  findings: number
  integrity: string
}

export const VERDICTS = ['malicious', 'false-positive', 'benign-noteworthy', 'undecided'] as const
export type Verdict = (typeof VERDICTS)[number]
