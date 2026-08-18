package web

import (
	"strings"
	"testing"
)

func TestReportTr_EnglishPassThrough(t *testing.T) {
	if got := reportTr("en", "Executive Summary"); got != "Executive Summary" {
		t.Errorf("English should pass through, got %q", got)
	}
	if got := reportTr("", "Executive Summary"); got != "Executive Summary" {
		t.Errorf("default should pass through, got %q", got)
	}
}

func TestReportTr_ChineseHeadings(t *testing.T) {
	cases := []string{
		"Executive Summary", "Risk Assessment", "Scan Details",
		"Testing Methodology", "Vulnerability Details", "Disclaimer",
		"Deep Reconnaissance & Attack Surface Mapping", "Final Report",
	}
	for _, en := range cases {
		zh := reportTr("zh-CN", en)
		if zh == en {
			t.Errorf("missing zh-CN translation for %q", en)
		}
	}
}

// The disclaimer is looked up by the shared const; verify it resolves so the
// two copies never drift out of sync.
func TestReportTr_DisclaimerResolves(t *testing.T) {
	zh := reportTr("zh-CN", reportDisclaimerEN)
	if zh == reportDisclaimerEN {
		t.Fatal("disclaimer zh-CN translation did not resolve (key mismatch)")
	}
	if !strings.Contains(zh, "免责") && !strings.Contains(zh, "渗透测试") {
		t.Errorf("disclaimer translation looks wrong: %q", zh[:min(60, len(zh))])
	}
}

func TestReportTr_FormatStringsPreservePlaceholder(t *testing.T) {
	for _, en := range []string{"Verified via: %s", "Phase %d: %s", "UNVERIFIED — manual review required (reported via %s)"} {
		zh := reportTr("zh-CN", en)
		if zh == en {
			t.Errorf("missing translation for %q", en)
			continue
		}
		// The %s / %d placeholders must survive translation.
		if strings.Count(en, "%") != strings.Count(zh, "%") {
			t.Errorf("placeholder count mismatch for %q -> %q", en, zh)
		}
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
