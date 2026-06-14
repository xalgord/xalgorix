package reporting

import (
	"testing"

	"github.com/xalgord/xalgorix/v4/internal/reporting/i18n"
)

// TestRollupSeverities_Empty asserts the zero-vuln rollup is the zero
// value. The cover-page render relies on this so a freshly created
// scan with no findings still produces a valid PDF.
//
// Validates: Requirements 6.5.
func TestRollupSeverities_Empty(t *testing.T) {
	got := RollupSeverities(nil)
	if got != (SeverityCounts{}) {
		t.Errorf("nil input: got %+v, want zero value", got)
	}
	got = RollupSeverities([]Vuln{})
	if got != (SeverityCounts{}) {
		t.Errorf("empty slice: got %+v, want zero value", got)
	}
}

// TestRollupSeverities_FixedFindings is the rollup-correctness anchor
// the cover-page snapshot test depends on. The fixed input mirrors the
// canonical mixed-severity finding list used in cover_test.go so the
// two tests stay in lock-step.
//
// Validates: Requirements 6.5.
func TestRollupSeverities_FixedFindings(t *testing.T) {
	findings := []Vuln{
		{Severity: "critical"},
		{Severity: "Critical"}, // case-insensitive
		{Severity: "high"},
		{Severity: "HIGH"},
		{Severity: "high"},
		{Severity: "medium"},
		{Severity: "low"},
		{Severity: "low"},
		{Severity: "informational"}, // unknown band → Info bucket
		{Severity: ""},              // empty → Info bucket
	}
	got := RollupSeverities(findings)
	want := SeverityCounts{
		Critical: 2,
		High:     3,
		Medium:   1,
		Low:      2,
		Info:     2,
		Total:    10,
	}
	if got != want {
		t.Errorf("got %+v, want %+v", got, want)
	}
	if got.Total != got.Critical+got.High+got.Medium+got.Low+got.Info {
		t.Errorf("Total %d != sum of buckets %d", got.Total,
			got.Critical+got.High+got.Medium+got.Low+got.Info)
	}
}

// TestRollupSeverities_UnknownSeverityIsInfo asserts that unrecognized
// severity strings (custom labels, typos, integers-as-strings) all
// roll up into the Info bucket rather than silently dropped. This is
// the production-safety net the cover page relies on so the displayed
// total always matches len(scan.Vulns).
//
// Validates: Requirements 6.5.
func TestRollupSeverities_UnknownSeverityIsInfo(t *testing.T) {
	findings := []Vuln{
		{Severity: "Severity-Unknown"},
		{Severity: "5"},
		{Severity: "info"},
		{Severity: "informational"},
	}
	got := RollupSeverities(findings)
	if got.Info != 4 {
		t.Errorf("Info bucket = %d, want 4 (got %+v)", got.Info, got)
	}
	if got.Total != 4 {
		t.Errorf("Total = %d, want 4", got.Total)
	}
	if got.Critical != 0 || got.High != 0 || got.Medium != 0 || got.Low != 0 {
		t.Errorf("named buckets must be zero: got %+v", got)
	}
}

// TestRollupSeverities_TotalEqualsLen asserts the invariant that
// Total is always equal to len(input), independent of the per-bucket
// breakdown. A drifted Total would silently misreport the cover-page
// "Total Vulnerabilities" stat card.
//
// Validates: Requirements 6.5.
func TestRollupSeverities_TotalEqualsLen(t *testing.T) {
	cases := []struct {
		name  string
		input []Vuln
	}{
		{"single critical", []Vuln{{Severity: "critical"}}},
		{"all info", []Vuln{{Severity: "info"}, {Severity: "info"}, {Severity: "info"}}},
		{"mixed", []Vuln{
			{Severity: "critical"}, {Severity: "high"}, {Severity: "medium"},
			{Severity: "low"}, {Severity: ""},
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := RollupSeverities(tc.input)
			if got.Total != len(tc.input) {
				t.Errorf("Total = %d, want %d", got.Total, len(tc.input))
			}
			if sum := got.Critical + got.High + got.Medium + got.Low + got.Info; sum != got.Total {
				t.Errorf("bucket sum %d != Total %d", sum, got.Total)
			}
		})
	}
}

// TestSeverityLabel_BothLanguages is the F-001 anchor test for the
// "severity is translated" decision. It asserts:
//   - English bundle: Critical/High/Medium/Low
//   - Chinese bundle: 严重/高/中/低
//   - Unknown values fall back to Info in both languages
//   - Matching is case-insensitive (mirrors RollupSeverities)
func TestSeverityLabel_BothLanguages(t *testing.T) {
	en := i18n.Get(i18n.LangEN)
	zh := i18n.Get(i18n.LangZH)

	cases := []struct {
		severity string
		wantEN   string
		wantZH   string
	}{
		{"critical", en.SevCritical, zh.SevCritical}, // 严重
		{"high", en.SevHigh, zh.SevHigh},             // 高
		{"medium", en.SevMedium, zh.SevMedium},       // 中
		{"low", en.SevLow, zh.SevLow},                // 低
		{"CRITICAL", en.SevCritical, zh.SevCritical}, // case-insensitive
		{"High", en.SevHigh, zh.SevHigh},
		{"", en.SevInfo, zh.SevInfo},              // empty → info
		{"unknown", en.SevInfo, zh.SevInfo},       // unknown → info
		{"informational", en.SevInfo, zh.SevInfo}, // informational → info
	}
	for _, c := range cases {
		gotEN := SeverityLabel(c.severity, en)
		if gotEN != c.wantEN {
			t.Errorf("EN: SeverityLabel(%q) = %q, want %q", c.severity, gotEN, c.wantEN)
		}
		gotZH := SeverityLabel(c.severity, zh)
		if gotZH != c.wantZH {
			t.Errorf("ZH: SeverityLabel(%q) = %q, want %q", c.severity, gotZH, c.wantZH)
		}
	}
}

// TestSeverityLabel_CriticalValuesAnchored is a sharper version of
// TestSeverityLabel_BothLanguages that asserts the Chinese bundle's
// "严重"/"高"/"中"/"低" values explicitly. This guards against a
// silent re-translation regression: if a future refactor changes the
// zh bundle's SevCritical to "紧要" or "危急" by accident, this test
// fails with a clear message even if SeverityLabel itself is correct.
func TestSeverityLabel_CriticalValuesAnchored(t *testing.T) {
	zh := i18n.Get(i18n.LangZH)

	if got := SeverityLabel("critical", zh); got != "严重" {
		t.Errorf("SeverityLabel('critical', zh) = %q, want %q", got, "严重")
	}
	if got := SeverityLabel("high", zh); got != "高" {
		t.Errorf("SeverityLabel('high', zh) = %q, want %q", got, "高")
	}
	if got := SeverityLabel("medium", zh); got != "中" {
		t.Errorf("SeverityLabel('medium', zh) = %q, want %q", got, "中")
	}
	if got := SeverityLabel("low", zh); got != "低" {
		t.Errorf("SeverityLabel('low', zh) = %q, want %q", got, "低")
	}
}
