package web

import (
	"log"
	"os"
	"strings"
	"sync"

	"github.com/go-pdf/fpdf"
	"github.com/xalgord/xalgorix/v4/internal/config"
)

// reportPDF wraps *fpdf.Fpdf so the report generator can transparently render
// non-Latin scripts (e.g. Simplified Chinese) that the built-in cp1252 core
// fonts (Helvetica/Courier) cannot represent.
//
// When cjkFamily is set, every SetFont call is rerouted to the registered
// embedded UTF-8 TrueType font regardless of the requested core family/style,
// so all the existing pdf.SetFont("Helvetica"/"Courier", ...) call sites in
// generateReport keep working unmodified. When cjkFamily is empty the wrapper
// is a pure pass-through and the PDF is byte-identical to before.
//
// Every other *fpdf.Fpdf method is promoted via the embedded pointer, so the
// wrapper is a drop-in replacement for the concrete type.
type reportPDF struct {
	*fpdf.Fpdf
	cjkFamily string
}

// SetFont shadows (*fpdf.Fpdf).SetFont. In CJK mode the embedded TrueType font
// is regular-weight only, so bold/italic styling is dropped in exchange for
// correct glyph coverage — legible localized text beats a missing glyph.
func (p *reportPDF) SetFont(family, style string, size float64) {
	if p.cjkFamily != "" {
		p.Fpdf.SetFont(p.cjkFamily, "", size)
		return
	}
	p.Fpdf.SetFont(family, style, size)
}

// reportCJKFontFamily is the internal family name used for the embedded font.
const reportCJKFontFamily = "XalgorixCJK"

// languageNeedsEmbeddedFont reports whether a language uses a script the core
// PDF fonts cannot render and therefore needs an embedded TrueType font.
func languageNeedsEmbeddedFont(lang string) bool {
	switch config.NormalizeLanguage(lang) {
	case "zh-CN":
		return true
	default:
		return false
	}
}

// candidateCJKFontPaths lists common filesystem locations for a CJK-capable
// TrueType font. fpdf can only parse standalone .ttf (glyf-outline) files — it
// does NOT support TrueType Collections (.ttc) or CFF/OpenType (.otf) — so only
// .ttf candidates are listed here. Operators whose distro only ships .ttc/.otf
// CJK fonts can point XALGORIX_PDF_CJK_FONT at any .ttf they extract/install.
var candidateCJKFontPaths = []string{
	"/usr/share/fonts/truetype/noto/NotoSansCJKsc-Regular.ttf",
	"/usr/share/fonts/truetype/noto/NotoSansSC-Regular.ttf",
	"/usr/share/fonts/opentype/noto/NotoSansCJKsc-Regular.ttf",
	"/usr/share/fonts/truetype/arphic/uming.ttf",
	"/usr/local/share/fonts/NotoSansSC-Regular.ttf",
}

var (
	cjkFontOnce  sync.Once
	cjkFontBytes []byte
)

// loadEmbeddedCJKFont resolves and caches the CJK TrueType font bytes. It is
// consulted only for languages that need it. Resolution order:
//  1. XALGORIX_PDF_CJK_FONT — explicit operator-supplied .ttf path.
//  2. A short list of common system .ttf locations.
//
// Returns nil when no usable .ttf is found; the caller then falls back to the
// ASCII/core-font path so report generation never fails just because a font is
// missing.
func loadEmbeddedCJKFont() []byte {
	cjkFontOnce.Do(func() {
		cjkFontBytes = resolveCJKFontBytes()
	})
	return cjkFontBytes
}

// resolveCJKFontBytes performs the (uncached) font lookup. Split out from the
// sync.Once wrapper so it can be unit-tested directly. Returns nil when no
// usable .ttf is found.
func resolveCJKFontBytes() []byte {
	var paths []string
	if custom := strings.TrimSpace(os.Getenv("XALGORIX_PDF_CJK_FONT")); custom != "" {
		paths = append(paths, custom)
	}
	paths = append(paths, candidateCJKFontPaths...)

	for _, path := range paths {
		if !strings.EqualFold(fileExt(path), ".ttf") {
			if strings.TrimSpace(path) != "" {
				log.Printf("[report] skipping CJK font %q: only .ttf is supported (not .ttc/.otf)", path)
			}
			continue
		}
		data, err := os.ReadFile(path) //nolint:gosec // operator-configured font path
		if err != nil {
			continue
		}
		if len(data) == 0 {
			continue
		}
		log.Printf("[report] loaded CJK PDF font from %s (%d bytes)", path, len(data))
		return data
	}
	return nil
}

func fileExt(path string) string {
	if i := strings.LastIndexByte(path, '.'); i >= 0 {
		return path[i:]
	}
	return ""
}

// newReportPDF builds the report PDF wrapper and, when the configured output
// language needs a non-Latin script AND a usable embedded font is available,
// registers that font and activates CJK rendering. On any failure it cleanly
// falls back to the core-font path (cjkFamily stays empty).
func newReportPDF(language string) *reportPDF {
	base := fpdf.New("P", "mm", "A4", "")
	pdf := &reportPDF{Fpdf: base}

	if !languageNeedsEmbeddedFont(language) {
		return pdf
	}
	fontBytes := loadEmbeddedCJKFont()
	if len(fontBytes) == 0 {
		log.Printf("[report] output language %q needs an embedded CJK font, but none was found; "+
			"set XALGORIX_PDF_CJK_FONT to a .ttf to render non-Latin text in the PDF. "+
			"Falling back to core fonts (non-Latin glyphs will not render).",
			config.NormalizeLanguage(language))
		return pdf
	}
	// Guard against a malformed font aborting the whole PDF: register, then
	// verify fpdf did not record an error before trusting the family.
	func() {
		defer func() {
			if r := recover(); r != nil {
				log.Printf("[report] CJK font registration panicked (%v); using core fonts", r)
				base.ClearError()
			}
		}()
		base.AddUTF8FontFromBytes(reportCJKFontFamily, "", fontBytes)
	}()
	if base.Err() {
		log.Printf("[report] CJK font could not be parsed by fpdf (%v); using core fonts", base.Error())
		base.ClearError()
		return pdf
	}
	pdf.cjkFamily = reportCJKFontFamily
	return pdf
}
