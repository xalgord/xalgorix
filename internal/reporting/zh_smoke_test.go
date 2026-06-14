package reporting

// zh_smoke_test.go — F-001 end-to-end smoke for the Chinese PDF report.
//
// This is NOT a byte-exact golden test. The goal is to verify that
// Generate() with ReportLanguage="zh" produces a non-empty PDF that:
//   1. Has the PDF magic bytes (%PDF-1.x)
//   2. Has a reasonable file size (multi-KB, not a 0-byte blank)
//   3. Contains CJK Unicode codepoints inside the encoded content stream
//      (proves the Chinese strings made it from the bundle into the PDF
//      and were not silently ToUpper-ed or stripped)
//
// The rendered PDF is written to testdata/chinese_smoke.pdf so a human
// can open it in any PDF viewer and confirm the Chinese characters
// actually render as glyphs (not tofu). On systems without a PDF viewer
// at hand, `strings` + grep for U+4E00..U+9FFF can confirm the bytes
// are present.
//
// The test fixture is intentionally tiny — one vulnerability, two
// events — so it stays a "smoke" and doesn't drift with every scan
// schema change. Anything more elaborate belongs in a dedicated
// integration test.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf8"
)

func TestGenerate_Chinese_Smoke(t *testing.T) {
	scan := &Scan{
		ID:          "smoke-zh-001",
		Name:        "Smoke Test",
		Target:      "https://example.test",
		StartedAt:   "2024-01-01T00:00:00Z",
		FinishedAt:  "2024-01-01T01:00:00Z",
		Status:      "finished",
		CompanyName: "Acme Corp",
		Phases:      []int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22},
		Iterations:  42,
		ToolCalls:   100,
		TotalTokens: 50000,
		Vulns: []Vuln{
			{
				ID:                 "V-001",
				Title:              "SQL Injection in login form",
				Severity:           "critical",
				Target:             "https://example.test/login",
				Endpoint:           "/login",
				CVSS:               9.8,
				CVSSVector:         "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
				Description:        "The login form is vulnerable to SQL injection via the username parameter.",
				Impact:             "Authentication bypass and full database access.",
				Method:             "Manual testing",
				CVE:                "CVE-2024-9999",
				CWE:                "CWE-89",
				OWASP:              "A03",
				VerificationMethod: "manual",
			},
		},
	}

	dir := t.TempDir()
	out, err := Generate(scan, Options{
		ScanDir:        dir,
		ReportLanguage: "zh",
	})
	if err != nil {
		t.Fatalf("Generate(zh) returned error: %v", err)
	}

	// Land a copy in testdata/ for human inspection. The test itself
	// doesn't compare against this file; the assertion is below.
	humanCopy := filepath.Join("testdata", "chinese_smoke.pdf")
	body, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("read generated PDF: %v", err)
	}
	if err := os.MkdirAll("testdata", 0o755); err != nil {
		t.Fatalf("mkdir testdata: %v", err)
	}
	if err := os.WriteFile(humanCopy, body, 0o644); err != nil {
		t.Fatalf("write humanCopy: %v", err)
	}

	// ── Assertion 1: PDF magic bytes ──────────────────────────────────
	if !strings.HasPrefix(string(body[:min(8, len(body))]), "%PDF-1.") {
		t.Errorf("PDF missing magic header; first 8 bytes: %q", body[:min(8, len(body))])
	}

	// ── Assertion 2: non-trivial size (a blank PDF would be ~600B) ────
	if len(body) < 5_000 {
		t.Errorf("PDF suspiciously small: %d bytes (a real report is multi-KB)", len(body))
	}

	// ── Assertion 3: at least some CJK codepoints appear in the body ──
	// fpdf encodes text as ASCII in the content stream with parens, so
	// even UTF-8 strings show up as raw bytes here. We scan the whole
	// file for any character in the CJK Unified Ideographs blocks
	// (U+4E00..U+9FFF) and common punctuation (U+3000..U+303F, U+FF00..U+FFEF).
	cjkCount := 0
	for _, r := range string(body) {
		if !utf8.ValidRune(r) {
			continue
		}
		if (r >= 0x4E00 && r <= 0x9FFF) || (r >= 0x3000 && r <= 0x303F) || (r >= 0xFF00 && r <= 0xFFEF) {
			cjkCount++
		}
	}
	if cjkCount < 50 {
		t.Errorf("PDF body has only %d CJK codepoints; expected at least 50 from the Chinese bundle", cjkCount)
	}
	t.Logf("chinese_smoke.pdf: %d bytes, %d CJK codepoints — saved to %s", len(body), cjkCount, humanCopy)
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
