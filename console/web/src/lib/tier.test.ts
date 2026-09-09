import { TIER_ORDER, tierRank, worstTier } from './tier'

test('ranks the bands the way the backend does', () => {
  // Mirrors internal/triage's tierRank. If these disagree, the UI sorts findings differently from
  // the API that already sorted them, and the analyst sees two contradictory orders.
  expect(TIER_ORDER).toEqual(['clean', 'unknown', 'suspicious', 'likely-malicious', 'confirmed'])
  expect(tierRank('confirmed')).toBeGreaterThan(tierRank('likely-malicious'))
  expect(tierRank('suspicious')).toBeGreaterThan(tierRank('unknown'))
  expect(tierRank('clean')).toBe(0)
})

test('an unknown tier string ranks lowest rather than throwing', () => {
  // The tier comes from a report. A scanner version that adds a band must not blank the screen.
  expect(tierRank('a-band-we-have-never-seen')).toBe(-1)
})

test('worstTier picks the most severe, not the first', () => {
  expect(worstTier(['clean', 'confirmed', 'suspicious'])).toBe('confirmed')
  expect(worstTier([])).toBe('unknown')
})
