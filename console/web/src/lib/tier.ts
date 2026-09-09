// Tier ordering, mirroring internal/triage's tierRank. The API has already sorted findings
// worst-first; if this list disagreed with the backend's, the UI would present a second,
// contradictory order of the same findings.
export const TIER_ORDER = [
  'clean',
  'unknown',
  'suspicious',
  'likely-malicious',
  'confirmed',
] as const

export type Tier = (typeof TIER_ORDER)[number]

// A tier string comes from a scan report. A scanner version that adds a band must degrade to
// "least severe I recognise" rather than blank the screen, so an unknown value ranks -1.
export function tierRank(tier: string): number {
  return TIER_ORDER.indexOf(tier as Tier)
}

export function worstTier(tiers: string[]): string {
  let worst = 'unknown'
  for (const t of tiers) {
    if (tierRank(t) > tierRank(worst)) worst = t
  }
  return worst
}

// The bands an analyst should look at before anything else.
export function isAlerting(tier: string): boolean {
  return tierRank(tier) >= tierRank('suspicious')
}
