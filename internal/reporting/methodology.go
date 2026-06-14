package reporting

import "github.com/xalgord/xalgorix/v4/internal/reporting/i18n"

// MethodologyPhaseNames maps each phase number in the Xalgorix 22-phase
// methodology to its display name. The map is the single source of truth
// consumed by both the PDF report and the autonomous-mode phase-filter
// instruction builder in internal/web.
var MethodologyPhaseNames = map[int]string{
	1:  "Deep Reconnaissance & Attack Surface Mapping",
	2:  "Manual Vulnerability Discovery",
	3:  "Directory & File Discovery",
	4:  "CORS & Cookie Analysis",
	5:  "Authentication & Session Testing",
	6:  "Injection Testing",
	7:  "SSRF Testing",
	8:  "IDOR & Broken Access Control",
	9:  "API & GraphQL Testing",
	10: "File Upload Testing",
	11: "Deserialization & RCE",
	12: "Race Conditions & Business Logic",
	13: "Subdomain Takeover",
	14: "Open Redirect Testing",
	15: "Email Security Testing",
	16: "Cloud & Infrastructure",
	17: "WebSocket Testing",
	18: "CMS-Specific Testing",
	19: "Broken Link Hijacking & Content Spoofing",
	20: "Exploit Verification",
	21: "Zero-Day & Novel Vulnerability Discovery",
	22: "Final Report",
}

// OWASPCategories lists the OWASP Top 10 (2021) categories in canonical
// order. The slice is package-level so the report renderer doesn't
// allocate a fresh copy for each generation.
var OWASPCategories = []struct {
	ID   string
	Name string
}{
	{"A01", "Broken Access Control"},
	{"A02", "Cryptographic Failures"},
	{"A03", "Injection"},
	{"A04", "Insecure Design"},
	{"A05", "Security Misconfiguration"},
	{"A06", "Vulnerable and Outdated Components"},
	{"A07", "Identification and Authentication Failures"},
	{"A08", "Software and Data Integrity Failures"},
	{"A09", "Security Logging and Monitoring Failures"},
	{"A10", "Server-Side Request Forgery (SSRF)"},
}

// Phase is a typed wrapper around the 22-phase methodology index. The
// zero value (Phase 0) is intentionally invalid; only Phases 1..22 are
// renderable. Defined as `int` so JSON encoders round-trip naturally
// when a future API surface ships the phase id.
type Phase int

// Name returns the localized display name for this phase from the
// supplied bundle. Phases outside 1..22 return "" so the caller can
// decide whether to render a placeholder, skip the row, or log a
// "bad phase" warning — rather than this helper guessing a default.
func (p Phase) Name(b *i18n.Bundle) string {
	if p < 1 || p > 22 {
		return ""
	}
	return b.PhaseNames[p]
}
