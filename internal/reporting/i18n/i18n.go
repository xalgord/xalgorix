// Package i18n provides localized string bundles for the reporting package.
// F-001 introduces a Chinese PDF report; this package centralizes the
// English and Chinese string sets so the PDF renderer can pick a bundle
// per-scan instead of hard-coding literals.
//
// Design notes:
//
//   - Bundle is a pure value type. No reflection, no init-time state, no
//     I/O at lookup time. Callers (Generate, etc.) call Get once per
//     report and read fields directly.
//   - The 22-phase array and the 10-row OWASP array are sized to their
//     fixed upper bounds (with index 0 unused for phases) so callers
//     never have to nil-check.
//   - ParseLang is permissive: unknown values fall back to LangZH (the
//     project default per F-001 requirements). The caller is expected
//     to log a warning when this happens; ParseLang itself does not
//     import a logger to keep this package dependency-free.
package i18n

// Lang identifies a localized string bundle.
type Lang string

const (
	// LangEN is English.
	LangEN Lang = "en"
	// LangZH is Simplified Chinese. This is the project default for F-001.
	LangZH Lang = "zh"
)

// ParseLang canonicalizes a raw config string to a Lang. Unknown values
// (including the empty string) resolve to LangZH, which is the F-001
// default. Callers that want to surface "user typo'd the env var" should
// compare the raw input to the returned Lang and emit a warning.
func ParseLang(s string) Lang {
	switch s {
	case "en":
		return LangEN
	case "zh":
		return LangZH
	default:
		return LangZH
	}
}

// Get returns the localized Bundle for the given language. It always
// returns a non-nil pointer so callers can dereference without a nil
// check. The returned value is a copy and may be safely mutated by
// the caller if they really want to.
func Get(lang Lang) *Bundle {
	switch lang {
	case LangEN:
		return newBundleEn()
	case LangZH:
		return newBundleZh()
	default:
		return newBundleZh()
	}
}

// Bundle is the complete set of user-visible strings used by
// internal/reporting/generate.go. Add a field here when you need a new
// translatable string; mirror the field in en.go and zh.go.
//
// Field names use the Go convention TitleCase. The English and Chinese
// bundles must keep the field set in sync; any drift is caught by
// TestBundles_FieldsMatch.
type Bundle struct {
	Lang Lang

	// ── Cover & top-level brand ──────────────────────────────────────
	CoverBrand           string // e.g. "Xalgorix"
	CoverSubtitle        string // e.g. "Autonomous AI-powered security assessment"
	CoverScanIDLabel     string // e.g. "SCAN ID"
	CoverReportName      string // e.g. "Security Assessment Report"
	LabelTotalVulns      string // e.g. "Total Vulnerabilities"
	LabelToolCalls       string // e.g. "Tool Calls"
	LabelTotalTokens     string // e.g. "Total Tokens"
	LabelScanStart       string // e.g. "Scan Start"
	LabelScanEnd         string // e.g. "Scan End"
	LabelReconIPs        string // e.g. "Resolved IP Addresses"
	LabelReconPorts      string // e.g. "Open Ports & Services"
	LabelReconTechs      string // e.g. "Detected Technologies"
	LabelReconURLs       string // e.g. "Observed URLs & Endpoints"
	CategoryIntelGather  string // methodology category: "Intelligence Gathering"
	CategoryVulnAnalysis string // methodology category: "Vulnerability Analysis"
	LabelNotRecorded     string // e.g. "not recorded" — placeholder when scan.ID empty

	// ── Section titles (big headings) ────────────────────────────────
	SectionExecSummary string
	SectionRiskAssess  string
	SectionScanDetails string
	SectionMethodology string
	SectionRecon       string
	SectionBlueTeam    string
	SectionFindings    string
	SectionVulnDetail  string
	SectionEndpoints   string
	SectionRefIndex    string
	SectionCWERef      string
	SectionOWASPRef    string
	SectionPTESMap     string
	SectionDisclaimer  string

	// ── Severity labels (used as-is in tables and badges) ────────────
	SevCritical string
	SevHigh     string
	SevMedium   string
	SevLow      string
	SevInfo     string

	// ── Table column headers ─────────────────────────────────────────
	LabelID       string
	LabelFinding  string
	LabelSeverity string
	LabelCVSS     string
	LabelCVE      string
	LabelCWE      string
	LabelOWASP    string
	LabelName     string // e.g. "CWE NAME"
	LabelTitle    string // e.g. "FINDING TITLE"
	LabelPhase    string // e.g. "PTES PHASE"
	LabelFindings string // plural, table column
	LabelStatus   string
	LabelCategory string // e.g. "OWASP CATEGORY"

	// ── Status indicators (small badges) ─────────────────────────────
	StatusFound    string
	StatusClear    string
	StatusTested   string
	StatusExecuted string
	StatusSkipped  string

	// ── Field labels (label-value pairs) ─────────────────────────────
	LabelCVSSValue string // e.g. "CVSS:"
	LabelCVEValue  string // e.g. "CVE:"
	LabelMethod    string // e.g. "Method:"
	LabelVerified  string // e.g. "Verified via: %s" (printf-style)
	LabelRiskScore string // e.g. "OVERALL RISK SCORE"

	// ── Phase row template ───────────────────────────────────────────
	// PDF renderer prints "Phase %d: <name>" for each row in the
	// methodology table; the formatter is here so translations that
	// reorder the number+name (e.g. zh: "第 %d 阶段：%s") can do so.
	PhaseRowFmt string // e.g. "Phase %d: %s" / "第 %d 阶段：%s"

	// ── 22-phase methodology (index 0 unused; phase N lives at index N) ──
	PhaseNames [23]string

	// ── OWASP Top 10 (2021) categories (10 fixed rows) ──────────────
	OWASPCategories [10]struct {
		ID   string
		Name string
	}

	// ── Disclaimer (multi-line, full text) ───────────────────────────
	Disclaimer string
}
