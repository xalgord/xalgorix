package i18n

// newBundleEn returns the English (default-existing) string bundle.
//
// IMPORTANT: every string here MUST match the literal that the current
// (pre-F-001) internal/reporting/generate.go prints. When the F-001
// refactor swaps inline literals for bundle.* fields, the resulting PDF
// must be visually identical to today's English report.
func newBundleEn() *Bundle {
	return &Bundle{
		Lang: LangEN,

		// Cover & brand
		CoverBrand:       "Xalgorix",
		CoverSubtitle:    "Autonomous AI-powered security assessment",
		CoverScanIDLabel: "SCAN ID",

		// Section titles
		SectionExecSummary: "Executive Summary",
		SectionRiskAssess:  "Risk Assessment",
		SectionScanDetails: "Scan Details",
		SectionMethodology: "Testing Methodology",
		SectionRecon:       "Reconnaissance Findings",
		SectionBlueTeam:    "Blue Team Reference Timestamps",
		SectionFindings:    "Findings Summary",
		SectionVulnDetail:  "Vulnerability Details",
		SectionEndpoints:   "Tested Endpoints & URLs",
		SectionRefIndex:    "Reference Index",
		SectionCWERef:      "CWE Reference Table",
		SectionOWASPRef:    "OWASP Top 10 (2021) Coverage",
		SectionPTESMap:     "PTES Phase Mapping",
		SectionDisclaimer:  "Disclaimer",

		// Severity labels
		SevCritical: "Critical",
		SevHigh:     "High",
		SevMedium:   "Medium",
		SevLow:      "Low",
		SevInfo:     "Info",

		// Table column headers
		LabelID:       "ID",
		LabelFinding:  "FINDING",
		LabelSeverity: "SEVERITY",
		LabelCVSS:     "CVSS",
		LabelCVE:      "CVE",
		LabelCWE:      "CWE",
		LabelOWASP:    "OWASP",
		LabelName:     "CWE NAME",
		LabelTitle:    "FINDING TITLE",
		LabelPhase:    "PTES PHASE",
		LabelFindings: "FINDINGS",
		LabelStatus:   "STATUS",
		LabelCategory: "OWASP CATEGORY",

		// Status indicators
		StatusFound:    "FOUND",
		StatusClear:    "CLEAR",
		StatusTested:   "TESTED",
		StatusExecuted: "Executed",
		StatusSkipped:  "Skipped",

		// Field labels
		LabelCVSSValue: "CVSS:",
		LabelCVEValue:  "CVE:",
		LabelMethod:    "Method:",
		LabelVerified:  "Verified via: %s",
		LabelRiskScore: "OVERALL RISK SCORE",

		// Phase row template
		PhaseRowFmt: "Phase %d: %s",

		// 22-phase methodology — mirrors reporting.MethodologyPhaseNames.
		// If you change one, change the other. A contract test in
		// reporting/methodology_test.go asserts they stay in sync.
		PhaseNames: [23]string{
			0:  "",
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
		},

		// OWASP Top 10 (2021) — mirrors reporting.OWASPCategories.
		OWASPCategories: [10]struct{ ID, Name string }{
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
		},

		// Disclaimer — verbatim from generate.go:1014-1031
		Disclaimer: `This penetration test was conducted by Xalgorix, an autonomous AI-powered security assessment tool. The findings in this report are based on automated testing and manual verification where possible.

IMPORTANT NOTICES:

* Scope: This assessment was limited to the target systems explicitly listed in this report. Any systems or services outside the defined scope were not tested.

* False Positives: While Xalgorix attempts to verify findings before reporting, some findings may require manual validation. We recommend validating all critical and high-severity findings before taking remediation actions.

* Limitations: Automated testing cannot discover all vulnerabilities. Manual testing, code review, and other complementary security activities are recommended for comprehensive security coverage.

* Legal: This assessment was conducted with authorization from the target owner. Unauthorized security testing is illegal. Ensure you have proper authorization before testing any system.

* Report Accuracy: This report is provided "as is" without warranties of any kind. The testing methodology and findings are based on the tools and techniques available at the time of testing.

* Remediation: For any vulnerabilities found, follow industry best practices for remediation. Consult with security professionals for complex vulnerabilities.

Generated by Xalgorix - Autonomous AI Pentesting Engine
https://github.com/xalgord/xalgorix`,
	}
}
