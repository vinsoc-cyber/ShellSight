import { del, get, post, postForm, put } from './http'
import type {
  Build,
  Case,
  ComponentsDoc,
  ComponentsView,
  Decision,
  Exclusion,
  FrozenMember,
  Group,
  Ingested,
  Release,
  Rule,
  RuleIndexRow,
  RuleRevision,
  RuleSet,
  ScanDetail,
  Scan,
  Selection,
} from './types'

export const api = {
  cases: {
    list: () => get<Case[]>('/api/cases'),
    create: (name: string) => post<{ id: number }>('/api/cases', { name }),
    scans: (caseID: number) => get<Scan[]>(`/api/cases/${caseID}/scans`),
    // Import one run. The manifest is optional and is what decides verified vs unverified, so it
    // is sent when the analyst selected it and omitted otherwise -- never faked.
    importReport: (caseID: number, report: File, manifest?: File) => {
      const form = new FormData()
      form.append('report', report)
      if (manifest) form.append('manifest', manifest)
      return postForm<Ingested>(`/api/cases/${caseID}/reports`, form)
    },
  },
  scans: {
    get: (id: number) => get<ScanDetail>(`/api/scans/${id}`),
    findings: (id: number) => get<Group[]>(`/api/scans/${id}/findings`),
  },
  decisions: {
    record: (d: { content_key: string; verdict: string; note?: string; case_id?: number }) =>
      post<{ id: number }>('/api/decisions', d),
  },
  releases: {
    list: () => get<Release[]>('/api/releases'),
    // The scanner's declaration of what each view needs, parsed by the server. Fetched rather
    // than hardcoded (G5): the console holding its own copy is how the two diverge.
    components: (id: number) => get<ComponentsDoc>(`/api/releases/${id}/components`),
  },
  builds: {
    list: () => get<Build[]>('/api/builds'),
    create: (body: {
      release_id: number
      rule_set_id: number | null
      views: string[]
      scan_scope?: string[]
      output_format?: string
      process_priority?: string
    }) => post<Build>('/api/builds', body),
    // Deliberately a URL rather than a fetch: api/http.ts always calls res.json(), so a zip cannot
    // come back through the wrapper. The browser downloads this directly.
    downloadURL: (id: number) => `/api/builds/${id}/download`,
  },
  rules: {
    list: (layer?: string) =>
      get<Rule[]>(layer ? `/api/rules?layer=${encodeURIComponent(layer)}` : '/api/rules'),
    langs: () => get<string[]>('/api/rules/langs'),
    index: () => get<RuleIndexRow[]>('/api/rules/index'),
    get: (id: number) => get<{ rule: Rule; revision: RuleRevision }>(`/api/rules/${id}`),
    create: (layer: string, text: string, lang: string) =>
      post<{ id: number }>('/api/rules', { layer, text, lang }),
    edit: (id: number, text: string, lang: string) =>
      put<{ revision: number }>(`/api/rules/${id}`, { text, lang }),
    remove: (id: number) => del(`/api/rules/${id}`),
  },
  rulesets: {
    list: () => get<RuleSet[]>('/api/rulesets'),
    create: (name: string) => post<{ id: number }>('/api/rulesets', { name }),
    get: (id: number) => get<RuleSet>(`/api/rulesets/${id}`),
    selection: (id: number) => get<Selection>(`/api/rulesets/${id}/selection`),
    setSelection: (id: number, sel: Selection) => put<Selection>(`/api/rulesets/${id}/selection`, sel),
    exclusions: (id: number) => get<Exclusion[]>(`/api/rulesets/${id}/exclusions`),
    members: (id: number) => get<FrozenMember[]>(`/api/rulesets/${id}/members`),
    exclude: (id: number, ruleID: number, identifier: string, reason: string) =>
      post<void>(`/api/rulesets/${id}/exclusions`, {
        rule_id: ruleID,
        identifier,
        reason,
      }),
    freeze: (id: number, version: number) =>
      post<void>(`/api/rulesets/${id}/freeze`, { version }),
    resolvedCount: (id: number) => get<{ count: number }>(`/api/rulesets/${id}/resolved-count`),
  },
}

export type {
  Build,
  Case,
  ComponentsDoc,
  ComponentsView,
  Decision,
  Exclusion,
  FrozenMember,
  Group,
  Ingested,
  Release,
  Rule,
  RuleIndexRow,
  RuleRevision,
  RuleSet,
  ScanDetail,
  Scan,
  Selection,
}
