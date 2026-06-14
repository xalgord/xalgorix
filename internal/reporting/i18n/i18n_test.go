package i18n

import "testing"

func TestParseLang(t *testing.T) {
	cases := []struct {
		in   string
		want Lang
	}{
		{"", LangZH}, // empty → default (F-001 spec)
		{"en", LangEN},
		{"EN", LangZH}, // case-sensitive on purpose
		{"zh", LangZH},
		{"jp", LangZH}, // unknown → default
		{"fr", LangZH}, // unknown → default
		{"anything", LangZH},
	}
	for _, c := range cases {
		got := ParseLang(c.in)
		if got != c.want {
			t.Errorf("ParseLang(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestGet_NeverNil(t *testing.T) {
	// Get() must always return a non-nil pointer, regardless of input.
	inputs := []Lang{"", LangEN, LangZH, Lang("xx")}
	for _, in := range inputs {
		b := Get(in)
		if b == nil {
			t.Errorf("Get(%q) returned nil", in)
		}
	}
}

func TestBundleEn_NonEmpty(t *testing.T) {
	b := Get(LangEN)
	checkNonEmpty(t, "en", b)
}

func TestBundleZh_NonEmpty(t *testing.T) {
	b := Get(LangZH)
	checkNonEmpty(t, "zh", b)
}

// checkNonEmpty asserts every Bundle string field is non-empty. This
// catches two bug classes: (a) forgetful developers who add a field to
// Bundle but forget to populate it in one of the bundles, and (b)
// refactors that drop a value to "" by accident.
func checkNonEmpty(t *testing.T, lang string, b *Bundle) {
	t.Helper()

	stringFields := []struct {
		name  string
		value string
	}{
		{"CoverBrand", b.CoverBrand},
		{"CoverSubtitle", b.CoverSubtitle},
		{"CoverScanIDLabel", b.CoverScanIDLabel},
		{"SectionExecSummary", b.SectionExecSummary},
		{"SectionRiskAssess", b.SectionRiskAssess},
		{"SectionScanDetails", b.SectionScanDetails},
		{"SectionMethodology", b.SectionMethodology},
		{"SectionRecon", b.SectionRecon},
		{"SectionBlueTeam", b.SectionBlueTeam},
		{"SectionFindings", b.SectionFindings},
		{"SectionVulnDetail", b.SectionVulnDetail},
		{"SectionEndpoints", b.SectionEndpoints},
		{"SectionRefIndex", b.SectionRefIndex},
		{"SectionCWERef", b.SectionCWERef},
		{"SectionOWASPRef", b.SectionOWASPRef},
		{"SectionPTESMap", b.SectionPTESMap},
		{"SectionDisclaimer", b.SectionDisclaimer},
		{"SevCritical", b.SevCritical},
		{"SevHigh", b.SevHigh},
		{"SevMedium", b.SevMedium},
		{"SevLow", b.SevLow},
		{"SevInfo", b.SevInfo},
		{"LabelID", b.LabelID},
		{"LabelFinding", b.LabelFinding},
		{"LabelSeverity", b.LabelSeverity},
		{"LabelCVSS", b.LabelCVSS},
		{"LabelCVE", b.LabelCVE},
		{"LabelCWE", b.LabelCWE},
		{"LabelOWASP", b.LabelOWASP},
		{"LabelName", b.LabelName},
		{"LabelTitle", b.LabelTitle},
		{"LabelPhase", b.LabelPhase},
		{"LabelFindings", b.LabelFindings},
		{"LabelStatus", b.LabelStatus},
		{"LabelCategory", b.LabelCategory},
		{"CoverReportName", b.CoverReportName},
		{"LabelTotalVulns", b.LabelTotalVulns},
		{"LabelToolCalls", b.LabelToolCalls},
		{"LabelTotalTokens", b.LabelTotalTokens},
		{"LabelScanStart", b.LabelScanStart},
		{"LabelScanEnd", b.LabelScanEnd},
		{"LabelReconIPs", b.LabelReconIPs},
		{"LabelReconPorts", b.LabelReconPorts},
		{"LabelReconTechs", b.LabelReconTechs},
		{"LabelReconURLs", b.LabelReconURLs},
		{"CategoryIntelGather", b.CategoryIntelGather},
		{"CategoryVulnAnalysis", b.CategoryVulnAnalysis},
		{"LabelNotRecorded", b.LabelNotRecorded},
		{"StatusFound", b.StatusFound},
		{"StatusClear", b.StatusClear},
		{"StatusTested", b.StatusTested},
		{"StatusExecuted", b.StatusExecuted},
		{"StatusSkipped", b.StatusSkipped},
		{"LabelCVSSValue", b.LabelCVSSValue},
		{"LabelCVEValue", b.LabelCVEValue},
		{"LabelMethod", b.LabelMethod},
		{"LabelVerified", b.LabelVerified},
		{"LabelRiskScore", b.LabelRiskScore},
		{"PhaseRowFmt", b.PhaseRowFmt},
		{"Disclaimer", b.Disclaimer},
	}
	for _, f := range stringFields {
		if f.value == "" {
			t.Errorf("[%s] field %q is empty", lang, f.name)
		}
	}

	// PhaseNames: index 0 must be empty (intentional unused slot), 1..22 non-empty.
	if b.PhaseNames[0] != "" {
		t.Errorf("[%s] PhaseNames[0] should be empty (unused slot), got %q", lang, b.PhaseNames[0])
	}
	for i := 1; i <= 22; i++ {
		if b.PhaseNames[i] == "" {
			t.Errorf("[%s] PhaseNames[%d] is empty", lang, i)
		}
	}

	// OWASP categories: every row's ID and Name must be non-empty.
	for i, cat := range b.OWASPCategories {
		if cat.ID == "" {
			t.Errorf("[%s] OWASPCategories[%d].ID is empty", lang, i)
		}
		if cat.Name == "" {
			t.Errorf("[%s] OWASPCategories[%d].Name is empty", lang, i)
		}
	}
}

func TestBundleEn_PhaseNamesUnique(t *testing.T) {
	// Catches a copy-paste bug where two phase rows end up with the same name.
	b := Get(LangEN)
	seen := map[string]int{}
	for i := 1; i <= 22; i++ {
		name := b.PhaseNames[i]
		if prev, ok := seen[name]; ok {
			t.Errorf("PhaseNames[%d] duplicates PhaseNames[%d] = %q", i, prev, name)
		}
		seen[name] = i
	}
}

func TestBundleZh_PhaseNamesUnique(t *testing.T) {
	b := Get(LangZH)
	seen := map[string]int{}
	for i := 1; i <= 22; i++ {
		name := b.PhaseNames[i]
		if prev, ok := seen[name]; ok {
			t.Errorf("PhaseNames[%d] duplicates PhaseNames[%d] = %q", i, prev, name)
		}
		seen[name] = i
	}
}

func TestBundleEn_OWASPCategoriesUnique(t *testing.T) {
	b := Get(LangEN)
	seen := map[string]int{}
	for i, cat := range b.OWASPCategories {
		if prev, ok := seen[cat.ID]; ok {
			t.Errorf("OWASPCategories[%d].ID %q duplicates row %d", i, cat.ID, prev)
		}
		seen[cat.ID] = i
	}
}

func TestBundleZh_OWASPCategoriesUnique(t *testing.T) {
	b := Get(LangZH)
	seen := map[string]int{}
	for i, cat := range b.OWASPCategories {
		if prev, ok := seen[cat.ID]; ok {
			t.Errorf("OWASPCategories[%d].ID %q duplicates row %d", i, cat.ID, prev)
		}
		seen[cat.ID] = i
	}
}
