package reporting

import (
	"testing"

	"github.com/xalgord/xalgorix/v4/internal/reporting/i18n"
)

// TestPhaseName_AllPhases exercises Phase.Name for every valid phase
// (1..22) in both languages, asserting the bundle's value comes
// through unchanged. This is the i18n plumbing check — the contract
// that Phase.Name and i18n.Bundle stay in lock-step is asserted in
// TestContract_MethodologyPhaseNames_MatchI18nEn below.
func TestPhaseName_AllPhases(t *testing.T) {
	en := i18n.Get(i18n.LangEN)
	zh := i18n.Get(i18n.LangZH)

	for i := 1; i <= 22; i++ {
		p := Phase(i)
		if got, want := p.Name(en), en.PhaseNames[i]; got != want {
			t.Errorf("EN: Phase(%d).Name = %q, want %q", i, got, want)
		}
		if got, want := p.Name(zh), zh.PhaseNames[i]; got != want {
			t.Errorf("ZH: Phase(%d).Name = %q, want %q", i, got, want)
		}
	}
}

// TestPhaseName_OutOfRange asserts Phase.Name returns "" for phases
// outside 1..22 so the caller can decide what to render (placeholder,
// skip, log) without this helper guessing.
func TestPhaseName_OutOfRange(t *testing.T) {
	en := i18n.Get(i18n.LangEN)
	zh := i18n.Get(i18n.LangZH)
	bad := []Phase{0, -1, 23, 100, -100}
	for _, p := range bad {
		if got := p.Name(en); got != "" {
			t.Errorf("Phase(%d).Name(en) = %q, want \"\"", p, got)
		}
		if got := p.Name(zh); got != "" {
			t.Errorf("Phase(%d).Name(zh) = %q, want \"\"", p, got)
		}
	}
}

// TestContract_MethodologyPhaseNames_MatchI18nEn is the drift guard
// for the dual source-of-truth we have for English phase names: the
// map at the top of this file (consumed by internal/web's phase-filter
// builder) and the i18n.Bundle (consumed by the renderer in Task 7+).
// If somebody updates one and forgets the other, this test fails with
// a clear "phase N: reporting=X, i18n.en=Y" message pointing at the
// exact row that drifted.
func TestContract_MethodologyPhaseNames_MatchI18nEn(t *testing.T) {
	en := i18n.Get(i18n.LangEN)
	for i := 1; i <= 22; i++ {
		got := MethodologyPhaseNames[i]
		want := en.PhaseNames[i]
		if got != want {
			t.Errorf("phase %d drift: reporting.MethodologyPhaseNames=%q, i18n.en.PhaseNames=%q (must stay in sync)", i, got, want)
		}
	}
}

// TestContract_OWASPCategories_MatchI18nEn is the drift guard for the
// OWASP Top 10 (2021) table. Same logic as the phase-names contract
// test above; ten rows, two fields per row.
func TestContract_OWASPCategories_MatchI18nEn(t *testing.T) {
	en := i18n.Get(i18n.LangEN)
	if len(OWASPCategories) != len(en.OWASPCategories) {
		t.Fatalf("OWASP row count drift: reporting=%d, i18n.en=%d",
			len(OWASPCategories), len(en.OWASPCategories))
	}
	for i := range OWASPCategories {
		if OWASPCategories[i].ID != en.OWASPCategories[i].ID {
			t.Errorf("OWASP[%d] ID drift: reporting=%q, i18n.en=%q",
				i, OWASPCategories[i].ID, en.OWASPCategories[i].ID)
		}
		if OWASPCategories[i].Name != en.OWASPCategories[i].Name {
			t.Errorf("OWASP[%d] Name drift: reporting=%q, i18n.en=%q",
				i, OWASPCategories[i].Name, en.OWASPCategories[i].Name)
		}
	}
}
