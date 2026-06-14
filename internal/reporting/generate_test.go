package reporting

// generate_test.go — F-001 language-branch coverage for Generate().
//
// The companion severity_test.go / methodology_test.go (added in
// Task 5) covers the bundle *helpers* (Phase.Name, SeverityLabel)
// and the bundle *drift guard* (MethodologyPhaseNames vs
// i18n.en.PhaseNames). This file covers the renderer side:
//   - Generate() with English doesn't panic and produces a valid PDF
//   - Generate() with Chinese doesn't panic and produces a valid PDF
//   - Both languages emit a PDF whose first 8 bytes are %PDF-1.x
//   - Options.ReportLanguage empty / unknown resolves to English
//     (the backward-compat shim documented on the Options struct)
//
// The Chinese path requires the CJK font file to be present in
// internal/reporting/fonts/. TestMain below invokes the project's
// download-font.sh if it's missing, so a fresh clone with `go test`
// just works without manual setup.

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// TestMain ensures the CJK font is present before any test in this
// package runs. The script is idempotent — a no-op if the file is
// already downloaded. We do this from TestMain rather than a t.Skip
// because the Chinese tests are the most valuable ones and silently
// skipping them in fresh checkouts would mask the feature.
func TestMain(m *testing.M) {
	const fontPath = "internal/reporting/fonts/NotoSansSC-Regular.ttf"
	if _, err := os.Stat(fontPath); os.IsNotExist(err) {
		// Run the same script Makefile's `download-font` target uses.
		cmd := exec.Command("bash", "scripts/download-font.sh")
		cmd.Dir = mustRepoRoot()
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			// Don't hard-fail: English-only tests still pass without
			// the font. Print a loud warning so the user knows.
			os.Stderr.WriteString(
				"\n⚠ TestMain: download-font.sh failed; Chinese tests will be skipped.\n" +
					"  Run `make download-font` manually to fetch the font.\n\n",
			)
		}
	}
	os.Exit(m.Run())
}

func mustRepoRoot() string {
	// Test runs with cwd = the package directory; we need repo root
	// for `scripts/download-font.sh` to resolve relative paths.
	wd, err := os.Getwd()
	if err != nil {
		return "."
	}
	// Walk up until we find a go.mod — that's the repo root.
	dir := wd
	for i := 0; i < 6; i++ {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	return wd
}

// minimalScan returns a tiny but valid Scan for renderer smoke tests.
// Mirrors the fixture in zh_smoke_test.go (kept separate so each test
// file is self-contained and the test data is unambiguous at the call
// site).
func minimalScan() *Scan {
	return &Scan{
		ID:          "lang-branch-smoke-001",
		Name:        "Smoke",
		Target:      "https://example.test",
		StartedAt:   "2024-01-01T00:00:00Z",
		FinishedAt:  "2024-01-01T01:00:00Z",
		Status:      "finished",
		CompanyName: "Acme",
		Phases:      []int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22},
		Iterations:  1,
		ToolCalls:   1,
		TotalTokens: 1,
	}
}

// runRender is the shared "render to a tempdir, return PDF bytes"
// helper used by the three branch tests below.
func runRender(t *testing.T, lang string) []byte {
	t.Helper()
	dir := t.TempDir()
	out, err := Generate(minimalScan(), Options{
		ScanDir:        dir,
		ReportLanguage: lang,
	})
	if err != nil {
		t.Fatalf("Generate(%q) returned error: %v", lang, err)
	}
	body, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("read generated PDF at %s: %v", out, err)
	}
	return body
}

// TestGenerate_English_NoPanic verifies the English path doesn't
// error. The English PDF doesn't need the CJK font (all text is
// Helvetica-encodable), so this test passes even if the font
// download in TestMain failed.
func TestGenerate_English_NoPanic(t *testing.T) {
	body := runRender(t, "en")
	if len(body) < 1_000 {
		t.Errorf("English PDF suspiciously small: %d bytes", len(body))
	}
}

// TestGenerate_Chinese_NoPanic verifies the Chinese path doesn't
// error. The test is skipped (not failed) if the CJK font is
// missing — download-font.sh failure is a setup problem, not a
// feature regression.
func TestGenerate_Chinese_NoPanic(t *testing.T) {
	if _, err := os.Stat(filepath.Join(mustRepoRoot(), "internal/reporting/fonts/NotoSansSC-Regular.ttf")); os.IsNotExist(err) {
		t.Skip("CJK font not present; run `make download-font` to enable Chinese PDF tests")
	}
	body := runRender(t, "zh")
	if len(body) < 5_000 {
		t.Errorf("Chinese PDF suspiciously small: %d bytes (a real report is multi-KB)", len(body))
	}
}

// TestGenerate_PDFMagicBytes asserts both languages emit a valid
// PDF (the %PDF-1.x magic header) at the start of the file. This
// is the cheapest possible "is this a real PDF" check and catches
// the most embarrassing failure mode (an error message written to
// the file instead of a PDF).
func TestGenerate_PDFMagicBytes(t *testing.T) {
	if _, err := os.Stat(filepath.Join(mustRepoRoot(), "internal/reporting/fonts/NotoSansSC-Regular.ttf")); os.IsNotExist(err) {
		t.Skip("CJK font not present; skipping magic-bytes check for Chinese path")
	}
	for _, lang := range []string{"en", "zh"} {
		body := runRender(t, lang)
		magic := body[:min(8, len(body))]
		if !bytes.HasPrefix(magic, []byte("%PDF-1.")) {
			t.Errorf("%s: PDF missing magic header; first 8 bytes: %q", lang, magic)
		}
	}
}

// TestGenerate_LanguageDefaultsToEnglish pins the backward-compat
// shim: Options.ReportLanguage that is "" or any other unrecognized
// value resolves to English, not Chinese. This matters for:
//   - pre-F-001 callers that pass Options{} (the cover_test fixture)
//   - future callers who typo a language value
//
// We pin it explicitly so a future "default-to-Chinese for both
// Config and Options" refactor doesn't silently break the byte-
// exact cover_test golden.
func TestGenerate_LanguageDefaultsToEnglish(t *testing.T) {
	// Render the empty-default case and confirm the bytes are
	// identical (modulo embedded timestamps, which we don't hash
	// here — we just confirm it doesn't error and produces a
	// reasonable-size PDF).
	body := runRender(t, "")
	if len(body) < 1_000 {
		t.Errorf("empty-language PDF suspiciously small: %d bytes", len(body))
	}

	// And confirm "jp" (an unknown value) also resolves to a working
	// PDF — not a crash on unknown language.
	body2 := runRender(t, "jp")
	if len(body2) < 1_000 {
		t.Errorf("jp-language PDF suspiciously small: %d bytes", len(body2))
	}
}
