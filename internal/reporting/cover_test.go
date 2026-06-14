package reporting

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/go-pdf/fpdf"
)

// textShowRe matches PDF text-show operators — a parenthesized string
// (with escaped parens handled) followed by Tj. This is the visible
// text the cover page renders.
var textShowRe = regexp.MustCompile(`(?s)\((?:[^\\)]|\\.)*\)\s*Tj`)

// fontSetRe matches font-selection operators (`/F<sha1> <size> Tf`) in
// the content stream. The sequence of font switches is part of the
// rendered layout; the SHA-1 id is collapsed to a placeholder so the
// projection ignores fpdf's per-run font-id churn.
var fontSetRe = regexp.MustCompile(`/F[0-9a-f]{40}\s+[0-9.]+\s+Tf`)

// fontIDRe matches fpdf's font resource identifiers — an "F" followed
// by the 40-char hex SHA-1 of the font definition (see go-pdf/fpdf
// generateFontID).
var fontIDRe = regexp.MustCompile(`F[0-9a-f]{40}`)

// canonicalizeReportPDF projects a rendered report down to the
// deterministic slice of its content and returns those bytes for
// hashing.
//
// WHY: fpdf v0.9.0 emits font objects by ranging an unordered map
// (putfonts: `for key = range f.fonts`). Across runs this shuffles the
// object numbers assigned to each font, the order font references are
// listed in every page /Font dictionary, the byte positions of the
// /BaseFont object definitions, and consequently the entire xref table.
// A raw-byte SHA-256 of the PDF is therefore non-deterministic even
// though the rendered content is identical — which made the previous
// snapshot test flaky (it alternated between several hashes run-to-run).
//
// The projection keeps exactly the parts that reflect cover-page
// CONTENT and are invariant to fpdf's object bookkeeping:
//   - every text-show operator (the literal text drawn on the page), in
//     document order;
//   - every font-selection operator, with the volatile SHA-1 font id
//     replaced by a fixed placeholder (the order of font switches is
//     meaningful; the id itself is not).
//
// Geometry, colors, dates and compression are already pinned by
// freezeFPDF, and the text/Tf stream is emitted in deterministic
// document order, so this projection is stable across runs while still
// failing on a genuine cover-page content change.
func canonicalizeReportPDF(raw []byte) []byte {
	normFonts := fontIDRe.ReplaceAll(raw, []byte("FONT"))
	var buf []byte
	for _, m := range textShowRe.FindAll(raw, -1) {
		buf = append(buf, m...)
		buf = append(buf, '\n')
	}
	for _, m := range fontSetRe.FindAll(normFonts, -1) {
		buf = append(buf, m...)
		buf = append(buf, '\n')
	}
	return buf
}

// updateGoldenEnv toggles in-place rewrite of the cover-page snapshot
// golden. Setting `UPDATE_GOLDEN=1` while running the cover-page tests
// rewrites `testdata/cover.sha256` from the bytes the renderer
// produced on the current run; this is how the golden is bootstrapped
// and how a deliberate cover-page redesign is replatformed.
const updateGoldenEnv = "UPDATE_GOLDEN"

// fixedRenderTime is the deterministic timestamp injected into fpdf's
// CreationDate / ModDate slots so the rendered PDF is byte-stable
// across runs. The value is intentionally far in the past so it is
// unmistakable as a test fixture if it ever leaks into a real report.
var fixedRenderTime = time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)

// freezeFPDF pins fpdf's package-level non-determinism (creation /
// modification date, compression) so the rendered bytes are stable.
// Compression is disabled so a watermark text search can run against
// the raw PDF bytes without paying for a pdfcpu round-trip.
//
// fpdf carries the relevant knobs in package-global state, so the
// helper installs t.Cleanup hooks that revert to the fpdf defaults
// (zero-time → time.Now, compression → on) after the test returns.
// Tests that call freezeFPDF must run sequentially — the cover-page
// snapshot tests do not call t.Parallel.
func freezeFPDF(t *testing.T) {
	t.Helper()
	fpdf.SetDefaultCreationDate(fixedRenderTime)
	fpdf.SetDefaultModificationDate(fixedRenderTime)
	fpdf.SetDefaultCompression(false)
	t.Cleanup(func() {
		fpdf.SetDefaultCreationDate(time.Time{})
		fpdf.SetDefaultModificationDate(time.Time{})
		fpdf.SetDefaultCompression(true)
	})
}

// fixedScan returns the canonical cover-page input. The vulnerability
// list mirrors the rollup fixture in TestRollupSeverities_FixedFindings
// so the cover-page severity cards and the rollup unit test share the
// same expected counts (2 critical, 3 high, 1 medium, 2 low, 2 info).
func fixedScan(companyName string) *Scan {
	return &Scan{
		ID:          "scan-fixture-001",
		Name:        "Cover Snapshot Fixture",
		Target:      "https://example.test",
		StartedAt:   "2024-01-01T00:00:00Z",
		FinishedAt:  "2024-01-01T01:00:00Z",
		Status:      "completed",
		CompanyName: companyName,
		Iterations:  3,
		ToolCalls:   42,
		TotalTokens: 12345,
		Vulns: []Vuln{
			{ID: "v1", Title: "Reflected XSS", Severity: "critical", CVSS: 9.0},
			{ID: "v2", Title: "Stored XSS", Severity: "Critical", CVSS: 9.5},
			{ID: "v3", Title: "Open Redirect", Severity: "high", CVSS: 7.5},
			{ID: "v4", Title: "SSRF", Severity: "HIGH", CVSS: 7.8},
			{ID: "v5", Title: "Auth Bypass", Severity: "high", CVSS: 7.2},
			{ID: "v6", Title: "Verbose Error", Severity: "medium", CVSS: 5.0},
			{ID: "v7", Title: "Mixed Content", Severity: "low", CVSS: 2.5},
			{ID: "v8", Title: "Missing Header", Severity: "low", CVSS: 2.5},
			{ID: "v9", Title: "Server Banner", Severity: "informational"},
			{ID: "v10", Title: "Robots.txt", Severity: ""},
		},
	}
}

// renderFixture renders the cover-page fixture into a temp dir and
// returns the rendered bytes alongside the lowercase-hex SHA-256
// digest of the CANONICALIZED bytes. Canonicalization removes fpdf's
// font-emission-order non-determinism (see canonicalizeReportPDF) so
// the digest is stable across runs while still pinning content. The
// raw (un-canonicalized) bytes are returned for callers that scan for
// literal substrings. The temp dir is removed automatically via
// t.TempDir.
func renderFixture(t *testing.T, scan *Scan) ([]byte, string) {
	t.Helper()
	dir := t.TempDir()
	// F-001: explicitly request English so this fixture's byte-level
	// SHA256 check (testdata/cover.sha256) stays stable. Pre-F-001
	// the empty Options would default to English; post-F-001 the
	// default would be Chinese, so we pin it.
	out, err := Generate(scan, Options{ScanDir: dir, ReportLanguage: "en"})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	body, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("read rendered pdf: %v", err)
	}
	sum := sha256.Sum256(canonicalizeReportPDF(body))
	return body, hex.EncodeToString(sum[:])
}

// TestCoverPage_DeterministicSnapshot is the structural-hash snapshot
// of the cover page. It pins fpdf's package-level non-determinism with
// freezeFPDF, renders the canonical fixture, and compares the SHA-256
// of the rendered bytes to testdata/cover.sha256.
//
// On mismatch the rendered PDF is dumped next to the golden as
// `cover.actual.pdf` so the diff can be inspected manually. Set
// UPDATE_GOLDEN=1 to rewrite the golden after a deliberate cover-page
// redesign.
//
// Validates: Requirements 6.5.
func TestCoverPage_DeterministicSnapshot(t *testing.T) {
	freezeFPDF(t)

	body, gotHash := renderFixture(t, fixedScan("Acme Corp"))

	goldenPath := filepath.Join("testdata", "cover.sha256")
	want, err := os.ReadFile(goldenPath)
	if errors.Is(err, fs.ErrNotExist) || os.Getenv(updateGoldenEnv) == "1" {
		if err := os.MkdirAll("testdata", 0o755); err != nil {
			t.Fatalf("mkdir testdata: %v", err)
		}
		if err := os.WriteFile(goldenPath, []byte(gotHash+"\n"), 0o644); err != nil {
			t.Fatalf("write golden: %v", err)
		}
		t.Logf("wrote golden %s = %s", goldenPath, gotHash)
		return
	}
	if err != nil {
		t.Fatalf("read golden: %v", err)
	}
	wantHash := strings.TrimSpace(string(want))
	if gotHash != wantHash {
		dump := filepath.Join("testdata", "cover.actual.pdf")
		_ = os.WriteFile(dump, body, 0o644)
		t.Fatalf(
			"cover snapshot drift: got %s, want %s\n"+
				"actual PDF written to %s\n"+
				"if this drift is intentional, re-run with %s=1 to refresh the golden",
			gotHash, wantHash, dump, updateGoldenEnv,
		)
	}
}

// TestCoverPage_SeverityRollupRendered asserts the cover-page severity
// cards reflect the same counts RollupSeverities computes for the
// fixture. The check is performed against the deterministic
// uncompressed PDF stream so we can see the literal "2", "3", "1",
// "2", "2" stat-card values land in the rendered cover page (in the
// expected adjacency to their labels).
//
// Validates: Requirements 6.5.
func TestCoverPage_SeverityRollupRendered(t *testing.T) {
	freezeFPDF(t)

	scan := fixedScan("Acme Corp")
	body, _ := renderFixture(t, scan)

	got := RollupSeverities(scan.Vulns)
	want := SeverityCounts{Critical: 2, High: 3, Medium: 1, Low: 2, Info: 2, Total: 10}
	if got != want {
		t.Fatalf("rollup drift before render check: got %+v, want %+v", got, want)
	}

	// Each stat card in the executive summary writes the per-bucket
	// label and then the count number. Asserting both substrings
	// land in the same rendered PDF gives confidence the cover
	// numbers reflect the rollup the API consumers see.
	checks := []struct {
		label string
		count string
	}{
		{"Critical", "2"},
		{"High", "3"},
		{"Medium", "1"},
		{"Low", "2"},
		{"Info", "2"},
		{"Total Vulnerabilities", "10"},
	}
	for _, c := range checks {
		if !bytes.Contains(body, []byte(c.label)) {
			t.Errorf("rendered PDF missing severity label %q", c.label)
		}
		if !bytes.Contains(body, []byte("("+c.count+")")) {
			// fpdf wraps every text-show payload in parentheses.
			// Asserting the parenthesised form rules out
			// coincidental matches against object lengths or
			// stream offsets in the binary PDF body.
			t.Errorf("rendered PDF missing %s count %q", c.label, c.count)
		}
	}
}

// TestCoverPage_FreePlanWatermarkPresent asserts that when the cover
// page is rendered with a watermarked company name, the trial watermark
// text lands in the rendered PDF bytes.
func TestCoverPage_FreePlanWatermarkPresent(t *testing.T) {
	freezeFPDF(t)

	const watermarked = "TRIAL — XALGORIX FREE — Acme Corp"
	body, _ := renderFixture(t, fixedScan(watermarked))

	// "TRIAL" and "XALGORIX FREE" are ASCII substrings of the
	// watermark prefix the cloud Generator stamps onto Free-plan
	// reports. Searching for the ASCII chunks (rather than the full
	// em-dash-bearing string) keeps the test robust against fpdf's
	// non-UTF8 text encoding.
	for _, marker := range []string{"TRIAL", "XALGORIX FREE"} {
		if !bytes.Contains(body, []byte(marker)) {
			t.Errorf("Free-plan PDF missing watermark marker %q", marker)
		}
	}
}

// TestCoverPage_PaidPlanNoWatermark asserts a paid-plan render
// produces a PDF that does NOT contain the trial watermark prefix.
// Together with TestCoverPage_FreePlanWatermarkPresent this is the
// regression seam guarding "Watermark Free-plan reports (no custom
// branding)" — paid plans must never accidentally inherit it.
//
// Validates: Requirements 6.5, 6.11.
func TestCoverPage_PaidPlanNoWatermark(t *testing.T) {
	freezeFPDF(t)

	body, _ := renderFixture(t, fixedScan("Acme Corp"))

	for _, marker := range []string{"TRIAL", "XALGORIX FREE"} {
		if bytes.Contains(body, []byte(marker)) {
			t.Errorf("paid-plan PDF unexpectedly contains watermark marker %q", marker)
		}
	}
	if !bytes.Contains(body, []byte("Acme Corp")) {
		t.Errorf("paid-plan PDF missing the unmodified company name")
	}
}
