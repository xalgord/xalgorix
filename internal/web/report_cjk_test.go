package web

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLanguageNeedsEmbeddedFont(t *testing.T) {
	if !languageNeedsEmbeddedFont("zh-CN") {
		t.Error("zh-CN should need an embedded font")
	}
	if languageNeedsEmbeddedFont("en") {
		t.Error("English should not need an embedded font")
	}
	if languageNeedsEmbeddedFont("") {
		t.Error("default (English) should not need an embedded font")
	}
}

func TestFileExt(t *testing.T) {
	cases := map[string]string{
		"/a/b/font.ttf": ".ttf",
		"/a/b/font.TTF": ".TTF",
		"/a/b/font.ttc": ".ttc",
		"/a/b/noext":    "",
	}
	for in, want := range cases {
		if got := fileExt(in); got != want {
			t.Errorf("fileExt(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestResolveCJKFontBytes_RejectsNonTTF(t *testing.T) {
	// A .ttc path (even if present) must be rejected because fpdf can't parse it.
	dir := t.TempDir()
	ttc := filepath.Join(dir, "font.ttc")
	if err := os.WriteFile(ttc, []byte("not really a font"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("XALGORIX_PDF_CJK_FONT", ttc)
	if got := resolveCJKFontBytes(); got != nil {
		// It may still find a system .ttf; only assert the .ttc itself wasn't used.
		if string(got) == "not really a font" {
			t.Error("resolveCJKFontBytes must not accept a .ttc file")
		}
	}
}

// newReportPDF must always fall back cleanly to the core-font path (no CJK
// family) when the language does not need an embedded font, regardless of any
// font on disk.
func TestNewReportPDF_EnglishIsPassThrough(t *testing.T) {
	pdf := newReportPDF("en")
	if pdf.cjkFamily != "" {
		t.Errorf("English report should not activate a CJK family, got %q", pdf.cjkFamily)
	}
	pdf.AddPage()
	pdf.SetFont("Helvetica", "B", 12)
	pdf.Cell(40, 10, "Security Assessment Report")
	if pdf.Err() {
		t.Fatalf("core-font render errored: %v", pdf.Error())
	}
}

// When a real CJK .ttf is available, newReportPDF("zh-CN") must activate the
// embedded font and render Chinese text without error. The font is sourced from
// XALGORIX_PDF_CJK_FONT; the test is skipped when no such font is provided so
// CI without a CJK font still passes.
func TestNewReportPDF_CJKRendersChinese(t *testing.T) {
	fontPath := os.Getenv("XALGORIX_TEST_CJK_FONT")
	if fontPath == "" {
		// Fall back to the probe font extracted during development, if present.
		if _, err := os.Stat("/tmp/wqy-face0.ttf"); err == nil {
			fontPath = "/tmp/wqy-face0.ttf"
		}
	}
	if fontPath == "" {
		t.Skip("no CJK .ttf available; set XALGORIX_TEST_CJK_FONT to run")
	}
	t.Setenv("XALGORIX_PDF_CJK_FONT", fontPath)

	pdf := newReportPDF("zh-CN")
	if pdf.cjkFamily == "" {
		t.Fatal("zh-CN with a valid font should activate the CJK family")
	}
	pdf.AddPage()
	// Even a "Helvetica" request must be rerouted to the CJK font.
	pdf.SetFont("Helvetica", "B", 14)
	pdf.Cell(0, 10, "漏洞发现：未授权访问导致敏感信息泄露")
	if pdf.Err() {
		t.Fatalf("CJK render errored: %v", pdf.Error())
	}
	out := filepath.Join(t.TempDir(), "cjk.pdf")
	if err := pdf.OutputFileAndClose(out); err != nil {
		t.Fatalf("output: %v", err)
	}
	fi, err := os.Stat(out)
	if err != nil || fi.Size() == 0 {
		t.Fatalf("expected a non-empty PDF, err=%v", err)
	}
}
