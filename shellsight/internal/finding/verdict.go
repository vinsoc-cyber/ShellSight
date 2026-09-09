package finding

// Rank orders tiers low→high. Used for "worst tier" rollups and exit codes.
// (Real scoring lives in internal/fusion; this is just the intrinsic tier ordering.)
func (t Tier) Rank() int {
	switch t {
	case TierConfirmed:
		return 3
	case TierLikely:
		return 2
	case TierSuspicious:
		return 1
	default:
		return 0 // clean / unknown
	}
}
