package reporting

import (
	"strings"

	"github.com/xalgord/xalgorix/v4/internal/reporting/i18n"
)

// SeverityCounts is the per-severity rollup the cover page and the
// executive-summary stat cards consume. It mirrors the inline counter
// previously embedded in [Generate], extracted into a named type so the
// Worker_Pool, the cloud API surface, and unit tests can compute it
// without re-implementing the case-folding rules.
//
// The field shapes intentionally match the cover-page card order
// (Critical, High, Medium, Low, Info) so callers iterating in that
// order produce stable output. Total is a precomputed convenience —
// it is always equal to the sum of the per-severity buckets.
//
// Validates: Requirements 6.5.
type SeverityCounts struct {
	Critical int
	High     int
	Medium   int
	Low      int
	// Info captures every finding whose Severity does not match one
	// of the four named bands. This includes empty severities, the
	// canonical "informational" / "info" labels, and any custom
	// severity an upstream classifier emits.
	Info  int
	Total int
}

// RollupSeverities computes the [SeverityCounts] for a slice of
// findings. Severity matching is case-insensitive ("Critical",
// "CRITICAL", "critical" all roll up the same bucket).
//
// A nil or empty input returns the zero value, which is safe to embed
// directly in a cover-page render.
//
// Validates: Requirements 6.5.
func RollupSeverities(vulns []Vuln) SeverityCounts {
	var counts SeverityCounts
	for _, v := range vulns {
		switch strings.ToLower(v.Severity) {
		case "critical":
			counts.Critical++
		case "high":
			counts.High++
		case "medium":
			counts.Medium++
		case "low":
			counts.Low++
		default:
			counts.Info++
		}
	}
	counts.Total = len(vulns)
	return counts
}

// SeverityLabel maps a severity string (as stored on Vuln.Severity — the
// same canonicalized set RollupSeverities recognizes) to its localized
// display label.
//
// Unrecognized values (custom labels, typos, integers-as-strings) fall
// back to the bundle's SevInfo label so they still render as something
// readable. This matches RollupSeverities' own convention of routing
// unknowns to the Info bucket, so the displayed label and the
// counted bucket always agree.
func SeverityLabel(sev string, b *i18n.Bundle) string {
	switch strings.ToLower(sev) {
	case "critical":
		return b.SevCritical
	case "high":
		return b.SevHigh
	case "medium":
		return b.SevMedium
	case "low":
		return b.SevLow
	}
	return b.SevInfo
}
