package core

// Risk is the declared blast radius of a tool. Hosts use it to decide approval
// and UI affordances; the runtime also enforces a minimum gate.
type Risk string

const (
	RiskLow    Risk = "low"
	RiskMedium Risk = "medium"
	RiskHigh   Risk = "high"
)

func (r Risk) rank() int {
	switch r {
	case RiskHigh:
		return 3
	case RiskMedium:
		return 2
	case RiskLow:
		return 1
	default:
		return 0
	}
}

// AtLeast reports whether r is at least as risky as other.
func (r Risk) AtLeast(other Risk) bool { return r.rank() >= other.rank() }

// Valid reports whether r is a known risk level.
func (r Risk) Valid() bool { return r.rank() > 0 }
