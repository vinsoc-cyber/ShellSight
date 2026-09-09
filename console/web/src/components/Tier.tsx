import { tierRank } from '../lib/tier'

// The tier is the first thing an analyst reads. It carries its own text rather than relying on
// colour alone, because a badge distinguished only by hue is unreadable to a colourblind analyst
// working a triage queue -- and the CSS gives it a filled dot for the same reason, so the badge
// survives greyscale and a badly-calibrated monitor too.
export function Tier({
  tier,
  score,
  large = false,
}: {
  tier: string
  score?: number
  // The headline verdict of a scan is not a table cell and should not be sized like one.
  large?: boolean
}) {
  const known = tierRank(tier) >= 0
  return (
    <span
      className={`tier tier-${known ? tier : 'unrecognised'}${large ? ' tier-lg' : ''}`}
      title={known ? undefined : 'this console does not recognise that tier'}
    >
      {tier}
      {score !== undefined && <span className="tier-score">{score}</span>}
    </span>
  )
}
