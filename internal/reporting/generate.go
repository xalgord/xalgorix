package reporting

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/go-pdf/fpdf"

	"github.com/xalgord/xalgorix/v4/internal/reporting/fonts"
	"github.com/xalgord/xalgorix/v4/internal/reporting/i18n"
)

// Options configures a single Generate invocation.
//
// LogoPath is an OPTIONAL pre-resolved, pre-validated absolute path to a
// PNG/JPEG logo. When empty, the cover page falls back to a monogram of
// the brand initials. Callers in the web layer typically resolve and
// validate the path with ValidLogo before populating this field.
//
// ScanDir is the per-scan working directory. When non-empty the report
// is written to <ScanDir>/<filename>; otherwise it is written to
// <FallbackDir>/<filename>. The naming and fallback rules match the
// previous (*Server).generateReport behavior exactly.
//
// FallbackDir is consulted only when ScanDir is empty.
//
// ReportLanguage (F-001) selects the i18n bundle. Allowed values:
// "en", "zh"; anything else (including "") falls back to "en" inside
// Generate so pre-F-001 callers that pass Options{} keep getting the
// English report their snapshot tests expect. Callers that want the
// new Chinese-first default should populate this from
// config.Config.ReportLanguage, which defaults to "zh".
//
// FontPath (F-001) is an optional override for the embedded Noto Sans
// CJK SC font. Empty means use the embedded font (always available
// when the binary is built via `make build`).
type Options struct {
	LogoPath       string
	ScanDir        string
	FallbackDir    string
	ReportLanguage string
	FontPath       string
}

// Generate renders the branded PDF report for scan and writes it to disk.
// It returns the absolute output path on success.
//
// Behavior is byte-identical to the previous in-package implementation
// in internal/web/report.go — the function body was moved verbatim, with
// only the Server-state references rewritten as Options fields and the
// type names rewritten for the local Vuln / Event / Scan transport
// types.
func Generate(scan *Scan, opts Options) (string, error) {
	pdf := fpdf.New("P", "mm", "A4", "")
	pdf.SetAutoPageBreak(true, 20)

	// F-001: pick the i18n bundle. An empty ReportLanguage (or anything
	// outside the allowed set) resolves to English so callers that pass
	// Options{} keep producing English reports — only the config-driven
	// flow that populates ReportLanguage from cfg.ReportLanguage (which
	// defaults to "zh") gets Chinese by default.
	lang := opts.ReportLanguage
	if lang != "en" && lang != "zh" {
		lang = "en"
	}
	bundle := i18n.Get(i18n.ParseLang(lang))

	// F-001: load the CJK font. Load() returns the embedded Noto Sans
	// CJK SC unless opts.FontPath is set, in which case the user
	// override path takes priority. Errors are explicit — a typo'd
	// XALGORIX_REPORT_FONT_PATH must surface, not be silently masked
	// by falling back to the embedded font.
	fontBytes, err := fonts.Load(opts.FontPath)
	if err != nil {
		return "", fmt.Errorf("report: load font: %w", err)
	}
	// Register the CJK font with fpdf under the family name "noto".
	// Registering it doesn't change anything yet (the renderer still
	// uses Helvetica); Task 8 will switch specific text elements to
	// this font. Registering now is the load-bearing step that proves
	// fpdf accepts the OTF for our use — if it errored, we'd see it
	// here at Generate() entry, not deep in the layout pass.
	pdf.AddUTF8FontFromBytes("noto", "", fontBytes)

	palette := ThemePalette()
	darkBg := palette.BG
	coral := palette.Accent
	teal := palette.Accent
	white := palette.FG
	gray := palette.Subtle
	red := palette.Critical
	orange := palette.High
	amber := palette.Medium
	greenLow := palette.Low
	cyan := palette.Subtle
	sectionBg := palette.Card
	codeBg := palette.Code
	border := palette.Border

	startTime := ParseTime(scan.StartedAt)
	endTime := ParseTime(scan.FinishedAt)
	duration := FormatDuration(startTime, endTime)
	brandName := BrandName(scan)
	logoPath := opts.LogoPath
	hasLogo := logoPath != ""

	// Helper: set text color
	setColor := func(c [3]int) {
		pdf.SetTextColor(c[0], c[1], c[2])
	}

	// Helper: draw a colored rect
	drawRect := func(x, y, w, h float64, c [3]int) {
		pdf.SetFillColor(c[0], c[1], c[2])
		pdf.Rect(x, y, w, h, "F")
	}

	drawStrokeRect := func(x, y, w, h float64, c [3]int) {
		pdf.SetDrawColor(c[0], c[1], c[2])
		pdf.Rect(x, y, w, h, "D")
	}

	// fpdf can create pages implicitly when MultiCell content crosses a page
	// boundary. Paint every implicit page before content lands on it.
	pdf.SetHeaderFunc(func() {
		drawRect(0, 0, 210, 297, darkBg)
		drawRect(0, 0, 210, 1.5, coral)
	})

	drawLogoOrInitials := func(x, y, w, h float64) {
		drawRect(x, y, w, h, palette.Muted)
		drawStrokeRect(x, y, w, h, border)
		if hasLogo {
			info := pdf.RegisterImage(logoPath, "")
			if info != nil && info.Height() > 0 && info.Width() > 0 {
				maxW := w - 6
				maxH := h - 6
				imgW := maxW
				imgH := info.Height() * imgW / info.Width()
				if imgH > maxH {
					imgH = maxH
					imgW = info.Width() * imgH / info.Height()
				}
				pdf.ImageOptions(logoPath, x+(w-imgW)/2, y+(h-imgH)/2, imgW, imgH, false, fpdf.ImageOptions{}, 0, "")
				return
			}
		}
		pdf.SetFont("Helvetica", "B", 16)
		setColor(white)
		pdf.SetXY(x, y+h/2-4)
		pdf.CellFormat(w, 8, Initials(brandName), "", 0, "C", false, 0, "")
	}

	// Helper: severity color
	sevColor := func(sev string) [3]int {
		switch strings.ToLower(sev) {
		case "critical":
			return red
		case "high":
			return orange
		case "medium":
			return amber
		case "low":
			return greenLow
		default:
			return cyan
		}
	}

	// ─── COVER PAGE ────────────────────────────────────────
	pdf.AddPage()
	drawRect(0, 0, 210, 297, darkBg)

	drawRect(0, 0, 210, 3, coral)
	drawRect(14, 28, 182, 82, sectionBg)
	drawStrokeRect(14, 28, 182, 82, border)
	drawRect(14, 28, 2, 82, coral)
	drawLogoOrInitials(26, 44, 38, 38)

	pdf.SetXY(74, 41)
	pdf.SetFont("Helvetica", "B", 23)
	setColor(white)
	pdf.MultiCell(112, 9, bundle.CoverReportName, "", "L", false)

	pdf.SetXY(74, 62)
	pdf.SetFont("Helvetica", "B", 14)
	setColor(coral)
	pdf.MultiCell(112, 7, DisplayText(brandName, "Target", 60), "", "L", false)

	pdf.SetXY(74, 78)
	pdf.SetFont("Courier", "", 8)
	setColor(gray)
	pdf.MultiCell(112, 4.5, DisplayText(scan.Target, "No target recorded", 95), "", "L", false)

	pdf.SetY(124)
	coverRisk := RiskLabel(RiskScore(scan.Vulns))
	coverCards := []struct {
		label string
		value string
		color [3]int
	}{
		{"Status", strings.ToUpper(DisplayText(scan.Status, "unknown", 18)), coral},
		{"Risk", coverRisk, sevColor(strings.ToLower(coverRisk))},
		{"Findings", fmt.Sprintf("%d", len(scan.Vulns)), red},
		{"Started", FormatDate(startTime), gray},
	}
	coverCardW := 42.5
	for i, c := range coverCards {
		x := 14 + float64(i)*(coverCardW+4)
		drawRect(x, 124, coverCardW, 27, sectionBg)
		drawStrokeRect(x, 124, coverCardW, 27, border)
		drawRect(x, 124, coverCardW, 1.2, c.color)
		pdf.SetXY(x+4, 131)
		pdf.SetFont("Helvetica", "", 7.5)
		setColor(gray)
		pdf.CellFormat(coverCardW-8, 4, strings.ToUpper(c.label), "", 1, "L", false, 0, "")
		pdf.SetXY(x+4, 138)
		pdf.SetFont("Helvetica", "B", 11)
		setColor(c.color)
		pdf.CellFormat(coverCardW-8, 6, c.value, "", 0, "L", false, 0, "")
	}

	pdf.SetXY(14, 176)
	pdf.SetFont("Helvetica", "B", 10)
	setColor(gray)
	pdf.CellFormat(182, 6, bundle.CoverScanIDLabel, "", 1, "L", false, 0, "")
	pdf.SetX(14)
	pdf.SetFont("Courier", "", 10)
	setColor(white)
	pdf.CellFormat(182, 7, DisplayText(scan.ID, bundle.LabelNotRecorded, 90), "", 1, "L", false, 0, "")

	pdf.SetY(248)
	drawRect(14, pdf.GetY(), 182, 0.3, border)
	pdf.Ln(8)
	pdf.SetFont("Helvetica", "B", 10)
	setColor(white)
	pdf.CellFormat(182, 5, bundle.CoverBrand, "", 1, "L", false, 0, "")
	pdf.SetFont("Helvetica", "", 8)
	setColor(gray)
	pdf.CellFormat(182, 5, bundle.CoverSubtitle, "", 1, "L", false, 0, "")
	drawRect(0, 294, 210, 3, coral)

	// ─── EXECUTIVE SUMMARY ─────────────────────────────────
	pdf.AddPage()
	drawRect(0, 0, 210, 297, darkBg)
	drawRect(0, 0, 210, 1.5, coral)

	pdf.SetY(15)
	pdf.SetFont("Helvetica", "B", 22)
	setColor(coral)
	pdf.CellFormat(190, 12, bundle.SectionExecSummary, "", 1, "L", false, 0, "")
	drawRect(10, pdf.GetY()+2, 50, 0.8, coral)
	pdf.Ln(8)

	// Summary stats cards
	type statCard struct {
		label string
		value string
		color [3]int
	}

	// Count severity. The rollup is delegated to RollupSeverities so
	// the cover-page numbers stay in lock-step with the value
	// returned to API callers (e.g. the cloud Reports list endpoint).
	rollup := RollupSeverities(scan.Vulns)
	critCount := rollup.Critical
	highCount := rollup.High
	medCount := rollup.Medium
	lowCount := rollup.Low
	infoCount := rollup.Info

	cards := []statCard{
		{bundle.LabelTotalVulns, fmt.Sprintf("%d", len(scan.Vulns)), coral},
		{bundle.SevCritical, fmt.Sprintf("%d", critCount), red},
		{bundle.SevHigh, fmt.Sprintf("%d", highCount), orange},
		{bundle.SevMedium, fmt.Sprintf("%d", medCount), amber},
		{bundle.SevLow, fmt.Sprintf("%d", lowCount), greenLow},
		{"Info", fmt.Sprintf("%d", infoCount), cyan},
	}

	// Draw stat cards in 2 rows of 3
	cardW := 55.0
	cardH := 28.0
	startX := 12.0
	y := pdf.GetY()
	for i, c := range cards {
		col := i % 3
		row := i / 3
		x := startX + float64(col)*(cardW+7)
		cy := y + float64(row)*(cardH+6)

		drawRect(x, cy, cardW, cardH, sectionBg)
		// Top accent on card
		drawRect(x, cy, cardW, 2, c.color)

		pdf.SetXY(x+4, cy+6)
		pdf.SetFont("Helvetica", "", 9)
		setColor(gray)
		pdf.CellFormat(cardW-8, 5, c.label, "", 1, "L", false, 0, "")

		pdf.SetXY(x+4, cy+14)
		pdf.SetFont("Helvetica", "B", 18)
		setColor(c.color)
		pdf.CellFormat(cardW-8, 10, c.value, "", 0, "L", false, 0, "")
	}

	pdf.SetY(y + 2*(cardH+6) + 10)

	// ── Overall Risk Score ──
	score := RiskScore(scan.Vulns)
	label := RiskLabel(score)
	var riskColor [3]int
	switch label {
	case "CRITICAL":
		riskColor = red
	case "HIGH":
		riskColor = orange
	case "MEDIUM":
		riskColor = amber
	case "LOW":
		riskColor = greenLow
	default:
		riskColor = cyan
	}

	riskY := pdf.GetY()
	drawRect(10, riskY, 190, 22, sectionBg)
	drawRect(10, riskY, 190, 2.5, riskColor)
	pdf.SetXY(14, riskY+5)
	pdf.SetFont("Helvetica", "B", 11)
	setColor(gray)
	pdf.CellFormat(60, 6, bundle.LabelRiskScore, "", 0, "L", false, 0, "")
	pdf.SetFont("Helvetica", "B", 22)
	setColor(riskColor)
	pdf.CellFormat(25, 10, fmt.Sprintf("%.1f", score), "", 0, "L", false, 0, "")
	pdf.SetFont("Helvetica", "B", 14)
	pdf.CellFormat(50, 10, label, "", 0, "L", false, 0, "")
	pdf.SetY(riskY + 26)

	// ── Executive Risk Narrative ──
	pdf.SetFont("Helvetica", "B", 11)
	setColor(white)
	pdf.CellFormat(190, 7, bundle.SectionRiskAssess, "", 1, "L", false, 0, "")
	pdf.SetFont("Helvetica", "", 9)
	setColor(white)
	narrative := fmt.Sprintf(
		"The automated penetration test of %s identified %d vulnerabilities "+
			"(%d critical, %d high, %d medium, %d low, %d informational). ",
		scan.Target, len(scan.Vulns), critCount, highCount, medCount, lowCount, infoCount,
	)
	if critCount > 0 || highCount > 0 {
		narrative += fmt.Sprintf(
			"The overall risk is assessed as %s (%.1f/10). Immediate remediation is recommended for the %d critical "+
				"and %d high severity findings, as they may allow unauthorized access, data exfiltration, or service disruption. ",
			label, score, critCount, highCount,
		)
	} else if medCount > 0 {
		narrative += fmt.Sprintf(
			"The overall risk is assessed as %s (%.1f/10). While no critical or high-severity issues were found, "+
				"the %d medium findings should be addressed in the next maintenance cycle to reduce attack surface. ",
			label, score, medCount,
		)
	} else {
		narrative += fmt.Sprintf(
			"The overall risk is assessed as %s (%.1f/10). The target demonstrates a strong security posture "+
				"with only low-severity or informational findings. Continuous monitoring is recommended. ",
			label, score,
		)
	}
	pdf.SetX(10)
	pdf.MultiCell(190, 4.5, narrative, "", "L", false)
	pdf.Ln(6)

	// Scan metadata
	pdf.SetFont("Helvetica", "B", 13)
	setColor(white)
	pdf.CellFormat(190, 8, bundle.SectionScanDetails, "", 1, "L", false, 0, "")
	pdf.Ln(2)

	metaItems := [][2]string{
		{"Target", scan.Target},
		{"Status", strings.ToUpper(scan.Status)},
		{"Duration", duration},
		{"Iterations", fmt.Sprintf("%d", scan.Iterations)},
		{"Tool Calls", fmt.Sprintf("%d", scan.ToolCalls)},
		{"Total Tokens", fmt.Sprintf("%d", scan.TotalTokens)},
		{"Started", FormatTimestamp(startTime)},
		{"Finished", FormatTimestamp(endTime)},
	}

	for i, m := range metaItems {
		bgColor := darkBg
		if i%2 == 0 {
			bgColor = sectionBg
		}
		drawRect(10, pdf.GetY(), 190, 8, bgColor)
		pdf.SetFont("Helvetica", "B", 9)
		setColor(gray)
		pdf.CellFormat(45, 8, "  "+m[0], "", 0, "L", false, 0, "")
		pdf.SetFont("Helvetica", "", 9)
		setColor(white)
		pdf.CellFormat(145, 8, m[1], "", 1, "L", false, 0, "")
	}

	// ─── METHODOLOGY ──────────────────────────────────────
	pdf.AddPage()
	drawRect(0, 0, 210, 297, darkBg)
	drawRect(0, 0, 210, 1.5, coral)

	pdf.SetY(15)
	pdf.SetFont("Helvetica", "B", 22)
	setColor(coral)
	pdf.CellFormat(190, 12, bundle.SectionMethodology, "", 1, "L", false, 0, "")
	drawRect(10, pdf.GetY()+2, 50, 0.8, coral)
	pdf.Ln(8)

	pdf.SetFont("Helvetica", "", 9)
	setColor(white)
	pdf.SetX(10)
	pdf.MultiCell(190, 4.5, "Xalgorix follows a comprehensive 22-phase penetration testing methodology "+
		"aligned with OWASP, PTES, and industry best practices. Each phase is executed by an autonomous AI agent "+
		"with tool access to terminal, browser, and specialized security utilities.", "", "L", false)
	pdf.Ln(4)

	// Determine which phases were executed
	executedPhases := scan.Phases
	allPhases := len(executedPhases) == 0 // empty = all phases
	for phaseNum := 1; phaseNum <= 22; phaseNum++ {
		name, ok := MethodologyPhaseNames[phaseNum]
		if !ok {
			continue
		}
		executed := allPhases
		if !allPhases {
			for _, p := range executedPhases {
				if p == phaseNum {
					executed = true
					break
				}
			}
		}
		rowY := pdf.GetY()
		if rowY > 270 {
			pdf.AddPage()
			drawRect(0, 0, 210, 297, darkBg)
			drawRect(0, 0, 210, 1.5, coral)
			pdf.SetY(15)
			rowY = pdf.GetY()
		}
		bgColor := darkBg
		if phaseNum%2 == 0 {
			bgColor = sectionBg
		}
		if executed {
			bgColor = palette.Muted
		}
		drawRect(10, rowY, 190, 7, bgColor)
		// Status indicator
		if executed {
			drawRect(10, rowY, 3, 7, teal)
			drawRect(14, rowY+1.5, 4, 4, teal)
		} else {
			drawRect(14, rowY+1.5, 4, 4, gray)
		}
		pdf.SetXY(22, rowY)
		pdf.SetFont("Helvetica", "", 8)
		if executed {
			setColor(white)
		} else {
			setColor(gray)
		}
		status := "SKIPPED"
		if executed {
			status = "SELECTED"
		}
		pdf.CellFormat(145, 7, fmt.Sprintf(bundle.PhaseRowFmt, phaseNum, name), "", 0, "L", false, 0, "")
		pdf.SetFont("Helvetica", "B", 7)
		if executed {
			setColor(teal)
		} else {
			setColor(gray)
		}
		pdf.CellFormat(25, 7, status, "", 1, "R", false, 0, "")
	}

	// Legend
	pdf.Ln(4)
	pdf.SetFont("Helvetica", "", 7)
	setColor(gray)
	pdf.SetX(10)
	drawRect(12, pdf.GetY()+1, 3, 3, teal)
	pdf.SetX(18)
	pdf.CellFormat(30, 5, "= "+bundle.StatusExecuted, "", 0, "L", false, 0, "")
	drawRect(50, pdf.GetY()+1, 3, 3, gray)
	pdf.SetX(56)
	pdf.CellFormat(30, 5, "= "+bundle.StatusSkipped, "", 1, "L", false, 0, "")

	// ─── RECONNAISSANCE FINDINGS ─────────────────────────
	recon := CollectReconSummary(scan.Events)
	if recon.HasData() {
		pdf.AddPage()
		drawRect(0, 0, 210, 297, darkBg)
		drawRect(0, 0, 210, 1.5, teal)

		pdf.SetY(15)
		pdf.SetFont("Helvetica", "B", 22)
		setColor(teal)
		pdf.CellFormat(190, 12, bundle.SectionRecon, "", 1, "L", false, 0, "")
		drawRect(10, pdf.GetY()+2, 62, 0.8, teal)
		pdf.Ln(8)

		pdf.SetFont("Helvetica", "", 9)
		setColor(white)
		pdf.SetX(10)
		pdf.MultiCell(190, 4.5, "The following non-exploit reconnaissance observations were extracted from the scan feed and tool outputs. These are included for attack-surface documentation and operational handoff.", "", "L", false)
		pdf.Ln(5)

		drawReconList := func(title string, items []string) {
			if len(items) == 0 {
				return
			}
			if pdf.GetY() > 245 {
				pdf.AddPage()
				drawRect(0, 0, 210, 297, darkBg)
				drawRect(0, 0, 210, 1.5, teal)
				pdf.SetY(15)
			}
			headerY := pdf.GetY()
			drawRect(10, headerY, 190, 8, sectionBg)
			pdf.SetXY(14, headerY+1)
			pdf.SetFont("Helvetica", "B", 9)
			setColor(teal)
			pdf.CellFormat(180, 6, strings.ToUpper(title), "", 1, "L", false, 0, "")
			pdf.Ln(2)
			pdf.SetFont("Courier", "", 7)
			setColor(white)
			for _, item := range items {
				if pdf.GetY() > 270 {
					pdf.AddPage()
					drawRect(0, 0, 210, 297, darkBg)
					drawRect(0, 0, 210, 1.5, teal)
					pdf.SetY(15)
				}
				pdf.SetX(14)
				pdf.MultiCell(182, 4, "- "+item, "", "L", false)
			}
			pdf.Ln(4)
		}

		drawReconList("DNS Records", recon.DNSRecords)
		drawReconList(bundle.LabelReconIPs, recon.IPAddresses)
		drawReconList(bundle.LabelReconPorts, recon.Ports)
		drawReconList(bundle.LabelReconTechs, recon.Technologies)
		drawReconList(bundle.LabelReconURLs, recon.URLs)
	}

	// ─── BLUE TEAM TIMESTAMPS ─────────────────────────────
	pdf.Ln(10)
	if pdf.GetY() > 230 {
		pdf.AddPage()
		drawRect(0, 0, 210, 297, darkBg)
		drawRect(0, 0, 210, 1.5, coral)
		pdf.SetY(15)
	}
	pdf.SetFont("Helvetica", "B", 16)
	setColor(coral)
	pdf.CellFormat(190, 10, bundle.SectionBlueTeam, "", 1, "L", false, 0, "")
	drawRect(10, pdf.GetY()+1, 50, 0.8, teal)
	pdf.Ln(6)

	pdf.SetFont("Helvetica", "", 8)
	setColor(gray)
	pdf.SetX(10)
	pdf.MultiCell(190, 4, "The following RFC3339 timestamps enable Blue Team operators to correlate "+
		"scan activity with SIEM/log sources for use-case development and alert tuning.", "", "L", false)
	pdf.Ln(3)

	tsItems := [][2]string{
		{bundle.LabelScanStart, scan.StartedAt},
		{bundle.LabelScanEnd, scan.FinishedAt},
	}
	// Add per-vulnerability discovery timestamps
	for i, v := range scan.Vulns {
		if i >= 20 {
			break // Limit to 20 to avoid excessive pages
		}
		ts := scan.StartedAt // fallback
		if v.CVSS > 0 {
			ts = scan.StartedAt
		}
		tsItems = append(tsItems, [2]string{
			fmt.Sprintf("Vuln #%d: %s", i+1, v.Title),
			ts,
		})
	}

	for i, ts := range tsItems {
		if pdf.GetY() > 270 {
			pdf.AddPage()
			drawRect(0, 0, 210, 297, darkBg)
			drawRect(0, 0, 210, 1.5, coral)
			pdf.SetY(15)
		}
		bgColor := darkBg
		if i%2 == 0 {
			bgColor = sectionBg
		}
		drawRect(10, pdf.GetY(), 190, 7, bgColor)
		pdf.SetFont("Helvetica", "B", 7)
		setColor(gray)
		titleStr := ts[0]
		if titleRunes := []rune(titleStr); len(titleRunes) > 75 {
			titleStr = string(titleRunes[:72]) + "..."
		}
		pdf.CellFormat(120, 7, "  "+titleStr, "", 0, "L", false, 0, "")
		pdf.SetFont("Courier", "", 7)
		setColor(teal)
		pdf.CellFormat(70, 7, ts[1], "", 1, "L", false, 0, "")
	}

	// Pre-compute all vuln mappings once for the entire report.
	allMappings := make([]Mappings, len(scan.Vulns))
	owaspCounts := make(map[string]int)
	ptesCounts := make(map[string]int)
	for i, v := range scan.Vulns {
		allMappings[i] = InferMappings(v)
		if allMappings[i].OWASP != "" {
			owaspCounts[allMappings[i].OWASP]++
		}
		if allMappings[i].PTES != "" {
			ptesCounts[allMappings[i].PTES]++
		}
	}

	// ─── FINDINGS SUMMARY TABLE ──────────────────────────
	if len(scan.Vulns) > 0 {
		pdf.AddPage()
		drawRect(0, 0, 210, 297, darkBg)
		drawRect(0, 0, 210, 1.5, coral)

		pdf.SetY(15)
		pdf.SetFont("Helvetica", "B", 22)
		setColor(coral)
		pdf.CellFormat(190, 12, bundle.SectionFindings, "", 1, "L", false, 0, "")
		drawRect(10, pdf.GetY()+2, 50, 0.8, coral)
		pdf.Ln(8)

		pdf.SetFont("Helvetica", "", 8)
		setColor(white)
		pdf.SetX(10)
		pdf.MultiCell(190, 4, "The following table summarizes all findings with their security framework mappings (CWE, OWASP Top 10 2021). Detailed write-ups follow in the Vulnerability Details section.", "", "L", false)
		pdf.Ln(4)

		// Table header
		thY := pdf.GetY()
		drawRect(10, thY, 190, 8, sectionBg)
		pdf.SetFont("Helvetica", "B", 7)
		setColor(coral)
		pdf.SetXY(12, thY+1)
		pdf.CellFormat(10, 6, bundle.LabelID, "", 0, "L", false, 0, "")
		pdf.CellFormat(68, 6, bundle.LabelFinding, "", 0, "L", false, 0, "")
		pdf.CellFormat(20, 6, bundle.LabelSeverity, "", 0, "C", false, 0, "")
		pdf.CellFormat(14, 6, bundle.LabelCVSS, "", 0, "C", false, 0, "")
		pdf.CellFormat(40, 6, bundle.LabelCVE, "", 0, "L", false, 0, "")
		pdf.CellFormat(18, 6, bundle.LabelCWE, "", 0, "L", false, 0, "")
		pdf.CellFormat(20, 6, bundle.LabelOWASP, "", 0, "L", false, 0, "")
		pdf.Ln(8)

		// Table rows
		for i, v := range scan.Vulns {
			if pdf.GetY() > 268 {
				pdf.AddPage()
				drawRect(0, 0, 210, 297, darkBg)
				drawRect(0, 0, 210, 1.5, coral)
				pdf.SetY(15)
			}

			mappings := allMappings[i]
			rowY := pdf.GetY()
			rowBg := darkBg
			if i%2 == 0 {
				rowBg = sectionBg
			}
			drawRect(10, rowY, 190, 7, rowBg)

			// Severity accent
			sc := sevColor(v.Severity)
			drawRect(10, rowY, 2, 7, sc)

			pdf.SetXY(12, rowY)
			pdf.SetFont("Helvetica", "B", 7)
			setColor(gray)
			pdf.CellFormat(10, 7, fmt.Sprintf("F-%02d", i+1), "", 0, "L", false, 0, "")

			pdf.SetFont("Helvetica", "", 7)
			setColor(white)
			titleStr := v.Title
			if titleRunes := []rune(titleStr); len(titleRunes) > 40 {
				titleStr = string(titleRunes[:37]) + "..."
			}
			pdf.CellFormat(68, 7, titleStr, "", 0, "L", false, 0, "")

			pdf.SetFont("Helvetica", "B", 7)
			pdf.SetTextColor(sc[0], sc[1], sc[2])
			pdf.CellFormat(20, 7, strings.ToUpper(SeverityLabel(v.Severity, bundle)), "", 0, "C", false, 0, "")

			setColor(white)
			pdf.SetFont("Helvetica", "", 7)
			cvssStr := "—"
			if v.CVSS > 0 {
				cvssStr = fmt.Sprintf("%.1f", v.CVSS)
			}
			pdf.CellFormat(14, 7, cvssStr, "", 0, "C", false, 0, "")

			setColor(gray)
			cveStr := v.CVE
			if len(cveStr) > 22 {
				cveStr = cveStr[:19] + "..."
			}
			if cveStr == "" {
				cveStr = "—"
			}
			pdf.CellFormat(40, 7, cveStr, "", 0, "L", false, 0, "")

			setColor(teal)
			cweStr := mappings.CWEID
			if cweStr == "" {
				cweStr = "—"
			}
			pdf.CellFormat(18, 7, cweStr, "", 0, "L", false, 0, "")

			owaspStr := mappings.OWASP
			if owaspStr == "" {
				owaspStr = "—"
			}
			pdf.CellFormat(20, 7, owaspStr, "", 1, "L", false, 0, "")
		}

		// ─── VULNERABILITY DETAILS ─────────────────────────────
		pdf.AddPage()
		drawRect(0, 0, 210, 297, darkBg)
		drawRect(0, 0, 210, 1.5, coral)

		pdf.SetY(15)
		pdf.SetFont("Helvetica", "B", 22)
		setColor(coral)
		pdf.CellFormat(190, 12, bundle.SectionVulnDetail, "", 1, "L", false, 0, "")
		drawRect(10, pdf.GetY()+2, 50, 0.8, coral)
		pdf.Ln(8)

		for idx, v := range scan.Vulns {
			sc := sevColor(v.Severity)

			// Check if we need a new page (leave 80mm minimum)
			if pdf.GetY() > 220 {
				pdf.AddPage()
				drawRect(0, 0, 210, 297, darkBg)
				drawRect(0, 0, 210, 1.5, coral)
				pdf.SetY(15)
			}

			// Vuln header bar
			headerY := pdf.GetY()
			drawRect(10, headerY, 190, 10, sectionBg)
			drawRect(10, headerY, 3, 10, sc)

			// Truncate title to avoid overlapping with severity badge
			vulnTitle := fmt.Sprintf("#%d  %s", idx+1, v.Title)
			pdf.SetFont("Helvetica", "B", 10)
			maxTitleW := 150.0 // badge starts at x=170, title starts at x=16, leave 4mm gap
			for len(vulnTitle) > 0 && pdf.GetStringWidth(vulnTitle) > maxTitleW {
				runes := []rune(vulnTitle)
				vulnTitle = string(runes[:len(runes)-1])
			}
			if len(vulnTitle) < len(fmt.Sprintf("#%d  %s", idx+1, v.Title)) {
				vulnTitle = strings.TrimSpace(vulnTitle) + "..."
			}

			pdf.SetXY(16, headerY+1)
			setColor(white)
			pdf.CellFormat(maxTitleW, 8, vulnTitle, "", 0, "L", false, 0, "")

			// Severity badge
			pdf.SetXY(170, headerY+2)
			pdf.SetFont("Helvetica", "B", 8)
			drawRect(170, headerY+2, 28, 6, sc)
			pdf.SetTextColor(255, 255, 255)
			pdf.CellFormat(28, 6, strings.ToUpper(SeverityLabel(v.Severity, bundle)), "", 0, "C", false, 0, "")

			pdf.SetY(headerY + 12)

			// Verification method badge
			if v.VerificationMethod != "" {
				pdf.SetFont("Helvetica", "I", 7)
				setColor(teal)
				pdf.SetX(14)
				pdf.CellFormat(0, 5, fmt.Sprintf(bundle.LabelVerified, strings.ToUpper(v.VerificationMethod)), "", 1, "L", false, 0, "")
			}

			// Vuln meta — row 1: CVSS + CVSS vector
			if v.CVSS > 0 {
				metaY := pdf.GetY()
				pdf.SetFont("Helvetica", "", 8)
				setColor(gray)
				pdf.SetXY(14, metaY)
				pdf.CellFormat(15, 5, bundle.LabelCVSSValue, "", 0, "L", false, 0, "")
				setColor(sc)
				pdf.SetFont("Helvetica", "B", 8)
				pdf.CellFormat(15, 5, fmt.Sprintf("%.1f", v.CVSS), "", 0, "L", false, 0, "")
				if v.CVSSVector != "" {
					setColor(gray)
					pdf.SetFont("Helvetica", "", 7)
					pdf.CellFormat(0, 5, v.CVSSVector, "", 0, "L", false, 0, "")
				}
				pdf.Ln(6)
			}

			// Vuln meta — row 2: CVE + Method
			hasCVEOrMethod := v.CVE != "" || v.Method != ""
			if hasCVEOrMethod {
				meta2Y := pdf.GetY()
				pdf.SetXY(14, meta2Y)
				if v.CVE != "" {
					setColor(gray)
					pdf.SetFont("Helvetica", "", 8)
					pdf.CellFormat(12, 5, bundle.LabelCVEValue, "", 0, "L", false, 0, "")
					setColor(white)
					cveText := DisplayText(v.CVE, "", 80)
					pdf.CellFormat(90, 5, cveText, "", 0, "L", false, 0, "")
				}
				if v.Method != "" {
					setColor(gray)
					pdf.SetFont("Helvetica", "", 8)
					pdf.CellFormat(18, 5, bundle.LabelMethod, "", 0, "L", false, 0, "")
					setColor(white)
					pdf.CellFormat(20, 5, v.Method, "", 0, "L", false, 0, "")
				}
				pdf.Ln(6)
			}

			// Vuln meta — row 3: CWE + OWASP badges
			vulnMappings := allMappings[idx]
			hasMappings := vulnMappings.CWEID != "" || vulnMappings.OWASP != ""
			if hasMappings {
				meta3Y := pdf.GetY()
				pdf.SetXY(14, meta3Y)
				if vulnMappings.CWEID != "" {
					// CWE badge
					badgeW := pdf.GetStringWidth(vulnMappings.CWEID) + 6
					pdf.SetFont("Helvetica", "B", 7)
					drawRect(pdf.GetX(), meta3Y, badgeW, 5.5, palette.Muted)
					setColor(teal)
					pdf.CellFormat(badgeW, 5.5, vulnMappings.CWEID, "", 0, "C", false, 0, "")
					pdf.SetX(pdf.GetX() + 2)
					if vulnMappings.CWEName != "" {
						pdf.SetFont("Helvetica", "", 7)
						setColor(gray)
						nameStr := vulnMappings.CWEName
						if nameRunes := []rune(nameStr); len(nameRunes) > 45 {
							nameStr = string(nameRunes[:42]) + "..."
						}
						pdf.CellFormat(0, 5.5, nameStr, "", 0, "L", false, 0, "")
					}
				}
				pdf.Ln(7)
				if vulnMappings.OWASP != "" {
					pdf.SetXY(14, pdf.GetY())
					owaspLabel := vulnMappings.OWASP
					if vulnMappings.OWASPName != "" {
						owaspLabel = vulnMappings.OWASP + " — " + vulnMappings.OWASPName
					}
					badgeW := pdf.GetStringWidth(owaspLabel) + 6
					pdf.SetFont("Helvetica", "B", 7)
					drawRect(pdf.GetX(), pdf.GetY(), badgeW, 5.5, palette.Muted)
					setColor(coral)
					pdf.CellFormat(badgeW, 5.5, owaspLabel, "", 0, "C", false, 0, "")
					pdf.Ln(7)
				}
			}
			pdf.Ln(1)

			// Sections - only add if content exists
			type section struct {
				label   string
				content string
			}

			sections := []section{}
			if v.Endpoint != "" {
				sections = append(sections, section{"ENDPOINT", v.Endpoint})
			}
			if v.Description != "" {
				sections = append(sections, section{"DESCRIPTION", v.Description})
			}
			if v.Impact != "" {
				sections = append(sections, section{"IMPACT", v.Impact})
			}
			if v.TechnicalAnalysis != "" {
				sections = append(sections, section{"TECHNICAL ANALYSIS", v.TechnicalAnalysis})
			}
			if v.PoCDescription != "" {
				sections = append(sections, section{"PROOF OF CONCEPT", v.PoCDescription})
			}
			if v.PoCScript != "" {
				sections = append(sections, section{"POC SCRIPT", v.PoCScript})
			}
			if v.ExploitationProof != "" {
				sections = append(sections, section{"EXPLOITATION PROOF", v.ExploitationProof})
			}
			if v.Remediation != "" {
				sections = append(sections, section{"REMEDIATION", v.Remediation})
			}

			for _, sec := range sections {
				if pdf.GetY() > 250 {
					pdf.AddPage()
					drawRect(0, 0, 210, 297, darkBg)
					drawRect(0, 0, 210, 1.5, coral)
					pdf.SetY(15)
				}

				// Section header with dark background for contrast
				secY := pdf.GetY()
				drawRect(10, secY, 190, 8, sectionBg)

				pdf.SetXY(14, secY+1)
				pdf.SetFont("Helvetica", "B", 8)
				setColor(coral)
				pdf.CellFormat(0, 6, sec.label, "", 0, "L", false, 0, "")

				pdf.SetY(secY + 9)

				// Content
				pdf.SetFont("Helvetica", "", 9)
				if sec.label == "POC SCRIPT" || sec.label == "ENDPOINT" || sec.label == "EXPLOITATION PROOF" {
					// Code-style content with dynamic height
					codeY := pdf.GetY()
					content := PrepareCodeBlock(sec.content, 34, 96)
					// Calculate dynamic height based on content
					lines := strings.Count(content, "\n") + 1
					blockHeight := float64(lines)*4 + 6 // 4mm per line + padding
					if blockHeight < 15 {
						blockHeight = 15
					}
					if blockHeight > 150 {
						blockHeight = 150 // Cap to prevent page overflow
					}
					// Check if we need a new page for this code block
					if codeY+blockHeight > 270 {
						pdf.AddPage()
						drawRect(0, 0, 210, 297, darkBg)
						drawRect(0, 0, 210, 1.5, coral)
						pdf.SetY(15)
						codeY = pdf.GetY()
					}
					drawRect(14, codeY, 182, blockHeight, codeBg)
					pdf.SetXY(17, codeY+3)
					pdf.SetFont("Courier", "", 7)
					if sec.label == "EXPLOITATION PROOF" {
						setColor([3]int{255, 200, 100}) // Gold/amber for exploitation proof
					} else {
						setColor(cyan)
					}
					pdf.MultiCell(175, 4, content, "", "L", false)
				} else {
					setColor(white)
					pdf.SetX(14)
					pdf.MultiCell(182, 5, sec.content, "", "L", false)
				}
				pdf.Ln(4)
			}

			// Separator between vulns
			pdf.Ln(4)
			if idx < len(scan.Vulns)-1 {
				drawRect(30, pdf.GetY(), 150, 0.3, sectionBg)
				pdf.Ln(6)
			}
		}
	}

	// ─── TESTED ENDPOINTS ─────────────────────────────────
	// Only add if there are endpoints
	endpointSet := make(map[string]bool)
	var endpoints []string
	for _, evt := range scan.Events {
		if evt.Type == "tool_call" && evt.ToolName == "terminal_execute" {
			if strings.Contains(evt.ToolArgs["command"], "http") {
				lines := strings.Split(evt.ToolArgs["command"], "\n")
				for _, line := range lines {
					if strings.Contains(line, "http://") || strings.Contains(line, "https://") {
						for _, word := range strings.Fields(line) {
							if strings.Contains(word, "http") {
								u := ExtractURL(word)
								if u != "" && !endpointSet[u] {
									endpointSet[u] = true
									endpoints = append(endpoints, u)
								}
							}
						}
					}
				}
			}
		}
	}

	if len(endpoints) > 0 {
		pdf.AddPage()
		drawRect(0, 0, 210, 297, darkBg)
		drawRect(0, 0, 210, 1.5, coral)

		pdf.SetY(15)
		pdf.SetFont("Helvetica", "B", 22)
		setColor(coral)
		pdf.CellFormat(190, 12, bundle.SectionEndpoints, "", 1, "L", false, 0, "")
		drawRect(10, pdf.GetY()+2, 50, 0.8, coral)
		pdf.Ln(8)

		pdf.SetFont("Helvetica", "", 9)
		setColor(white)
		// Show first 30 endpoints
		displayEndpoints := endpoints
		if len(displayEndpoints) > 30 {
			displayEndpoints = displayEndpoints[:30]
		}
		for _, ep := range displayEndpoints {
			if pdf.GetY() > 265 {
				pdf.AddPage()
				drawRect(0, 0, 210, 297, darkBg)
				drawRect(0, 0, 210, 1.5, coral)
				pdf.SetY(15)
			}
			pdf.SetFont("Courier", "", 8)
			setColor(cyan)
			pdf.CellFormat(190, 5, "- "+ep, "", 1, "L", false, 0, "")
		}
		if len(endpoints) > 30 {
			pdf.Ln(2)
			pdf.SetFont("Helvetica", "", 9)
			setColor(gray)
			pdf.CellFormat(190, 5, fmt.Sprintf("... and %d more endpoints", len(endpoints)-30), "", 1, "L", false, 0, "")
		}
	}

	// ─── DISCLAIMER ──────────────────────────────────────
	pdf.AddPage()
	drawRect(0, 0, 210, 297, darkBg)
	drawRect(0, 0, 210, 1.5, coral)

	pdf.SetY(15)
	pdf.SetFont("Helvetica", "B", 22)
	setColor(red)
	pdf.CellFormat(190, 12, bundle.SectionDisclaimer, "", 1, "L", false, 0, "")
	drawRect(10, pdf.GetY()+2, 50, 0.8, teal)
	pdf.Ln(10)

	disclaimer := bundle.Disclaimer

	pdf.SetFont("Helvetica", "", 10)
	setColor(white)
	pdf.MultiCell(182, 5, disclaimer, "", "L", false)

	// ─── REFERENCE INDEX APPENDIX ──────────────────────────
	if len(scan.Vulns) > 0 {
		pdf.AddPage()
		drawRect(0, 0, 210, 297, darkBg)
		drawRect(0, 0, 210, 1.5, teal)

		pdf.SetY(15)
		pdf.SetFont("Helvetica", "B", 22)
		setColor(teal)
		pdf.CellFormat(190, 12, bundle.SectionRefIndex, "", 1, "L", false, 0, "")
		drawRect(10, pdf.GetY()+2, 50, 0.8, teal)
		pdf.Ln(8)

		pdf.SetFont("Helvetica", "", 8)
		setColor(white)
		pdf.SetX(10)
		pdf.MultiCell(190, 4, "The mappings below are inferred from each finding's vulnerability class and are provided as a consolidated index for traceability and compliance reporting.", "", "L", false)
		pdf.Ln(5)

		// ── CWE Reference Table ──
		pdf.SetFont("Helvetica", "B", 13)
		setColor(teal)
		pdf.CellFormat(190, 8, bundle.SectionCWERef, "", 1, "L", false, 0, "")
		pdf.Ln(2)

		// Table header
		cweThY := pdf.GetY()
		drawRect(10, cweThY, 190, 8, sectionBg)
		pdf.SetFont("Helvetica", "B", 7)
		setColor(teal)
		pdf.SetXY(12, cweThY+1)
		pdf.CellFormat(15, 6, bundle.LabelFinding, "", 0, "L", false, 0, "")
		pdf.CellFormat(22, 6, bundle.LabelCWE, "", 0, "L", false, 0, "")
		pdf.CellFormat(80, 6, bundle.LabelName, "", 0, "L", false, 0, "")
		pdf.CellFormat(63, 6, bundle.LabelTitle, "", 0, "L", false, 0, "")
		pdf.Ln(8)

		for i, v := range scan.Vulns {
			if pdf.GetY() > 268 {
				pdf.AddPage()
				drawRect(0, 0, 210, 297, darkBg)
				drawRect(0, 0, 210, 1.5, teal)
				pdf.SetY(15)
			}
			mappings := allMappings[i]
			rowY := pdf.GetY()
			rowBg := darkBg
			if i%2 == 0 {
				rowBg = sectionBg
			}
			drawRect(10, rowY, 190, 7, rowBg)

			pdf.SetXY(12, rowY)
			pdf.SetFont("Helvetica", "B", 7)
			setColor(gray)
			pdf.CellFormat(15, 7, fmt.Sprintf("F-%02d", i+1), "", 0, "L", false, 0, "")

			setColor(teal)
			cweStr := mappings.CWEID
			if cweStr == "" {
				cweStr = "—"
			}
			pdf.CellFormat(22, 7, cweStr, "", 0, "L", false, 0, "")

			setColor(white)
			pdf.SetFont("Helvetica", "", 7)
			cweName := mappings.CWEName
			if cweName == "" {
				cweName = "—"
			}
			if cweRunes := []rune(cweName); len(cweRunes) > 48 {
				cweName = string(cweRunes[:45]) + "..."
			}
			pdf.CellFormat(80, 7, cweName, "", 0, "L", false, 0, "")

			setColor(gray)
			titleStr := v.Title
			if titleRunes := []rune(titleStr); len(titleRunes) > 38 {
				titleStr = string(titleRunes[:35]) + "..."
			}
			pdf.CellFormat(63, 7, titleStr, "", 1, "L", false, 0, "")
		}

		pdf.Ln(8)

		// ── OWASP Top 10 Coverage Matrix ──
		if pdf.GetY() > 200 {
			pdf.AddPage()
			drawRect(0, 0, 210, 297, darkBg)
			drawRect(0, 0, 210, 1.5, teal)
			pdf.SetY(15)
		}

		pdf.SetFont("Helvetica", "B", 13)
		setColor(teal)
		pdf.CellFormat(190, 8, bundle.SectionOWASPRef, "", 1, "L", false, 0, "")
		pdf.Ln(2)

		// owaspCounts was pre-computed above

		// Table header
		owThY := pdf.GetY()
		drawRect(10, owThY, 190, 8, sectionBg)
		pdf.SetFont("Helvetica", "B", 7)
		setColor(teal)
		pdf.SetXY(12, owThY+1)
		pdf.CellFormat(16, 6, bundle.LabelID, "", 0, "L", false, 0, "")
		pdf.CellFormat(120, 6, bundle.LabelCategory, "", 0, "L", false, 0, "")
		pdf.CellFormat(20, 6, bundle.LabelFindings, "", 0, "C", false, 0, "")
		pdf.CellFormat(24, 6, bundle.LabelStatus, "", 0, "C", false, 0, "")
		pdf.Ln(8)

		for i, cat := range OWASPCategories {
			rowY := pdf.GetY()
			rowBg := darkBg
			if i%2 == 0 {
				rowBg = sectionBg
			}
			drawRect(10, rowY, 190, 7, rowBg)

			count := owaspCounts[cat.ID]
			hasFindings := count > 0

			// Status accent
			if hasFindings {
				drawRect(10, rowY, 2, 7, red)
			} else {
				drawRect(10, rowY, 2, 7, teal)
			}

			pdf.SetXY(12, rowY)
			pdf.SetFont("Helvetica", "B", 7)
			if hasFindings {
				setColor(coral)
			} else {
				setColor(gray)
			}
			pdf.CellFormat(16, 7, cat.ID, "", 0, "L", false, 0, "")

			pdf.SetFont("Helvetica", "", 7)
			if hasFindings {
				setColor(white)
			} else {
				setColor(gray)
			}
			pdf.CellFormat(120, 7, cat.Name, "", 0, "L", false, 0, "")

			pdf.SetFont("Helvetica", "B", 7)
			if hasFindings {
				setColor(red)
				pdf.CellFormat(20, 7, fmt.Sprintf("%d", count), "", 0, "C", false, 0, "")
				pdf.SetFont("Helvetica", "B", 6)
				drawRect(166, rowY+1, 22, 5, red)
				pdf.SetTextColor(255, 255, 255)
				pdf.SetXY(166, rowY+1)
				pdf.CellFormat(22, 5, bundle.StatusFound, "", 0, "C", false, 0, "")
			} else {
				setColor(gray)
				pdf.CellFormat(20, 7, "0", "", 0, "C", false, 0, "")
				pdf.SetFont("Helvetica", "", 6)
				setColor(teal)
				pdf.SetXY(166, rowY+1)
				pdf.CellFormat(22, 5, bundle.StatusClear, "", 0, "C", false, 0, "")
			}
			pdf.Ln(7)
		}

		// ── PTES Phase Mapping ──
		if len(ptesCounts) > 0 {
			pdf.Ln(8)
			if pdf.GetY() > 230 {
				pdf.AddPage()
				drawRect(0, 0, 210, 297, darkBg)
				drawRect(0, 0, 210, 1.5, teal)
				pdf.SetY(15)
			}

			pdf.SetFont("Helvetica", "B", 13)
			setColor(teal)
			pdf.CellFormat(190, 8, bundle.SectionPTESMap, "", 1, "L", false, 0, "")
			pdf.Ln(2)

			ptesPhases := []string{
				bundle.CategoryIntelGather,
				bundle.CategoryVulnAnalysis,
				"Exploitation",
				"Post-Exploitation",
				"Reporting",
			}

			// Table header
			ptThY := pdf.GetY()
			drawRect(10, ptThY, 190, 8, sectionBg)
			pdf.SetFont("Helvetica", "B", 7)
			setColor(teal)
			pdf.SetXY(12, ptThY+1)
			pdf.CellFormat(100, 6, bundle.LabelPhase, "", 0, "L", false, 0, "")
			pdf.CellFormat(30, 6, bundle.LabelFindings, "", 0, "C", false, 0, "")
			pdf.CellFormat(50, 6, bundle.LabelStatus, "", 0, "C", false, 0, "")
			pdf.Ln(8)

			for j, phase := range ptesPhases {
				rowY := pdf.GetY()
				rowBg := darkBg
				if j%2 == 0 {
					rowBg = sectionBg
				}
				drawRect(10, rowY, 190, 7, rowBg)

				count := ptesCounts[phase]
				hasFindings := count > 0

				if hasFindings {
					drawRect(10, rowY, 2, 7, coral)
				} else {
					drawRect(10, rowY, 2, 7, gray)
				}

				pdf.SetXY(12, rowY)
				pdf.SetFont("Helvetica", "", 7)
				if hasFindings {
					setColor(white)
				} else {
					setColor(gray)
				}
				pdf.CellFormat(100, 7, phase, "", 0, "L", false, 0, "")

				pdf.SetFont("Helvetica", "B", 7)
				if hasFindings {
					setColor(coral)
					pdf.CellFormat(30, 7, fmt.Sprintf("%d", count), "", 0, "C", false, 0, "")
					pdf.SetFont("Helvetica", "B", 6)
					setColor(white)
					pdf.CellFormat(50, 7, bundle.StatusTested, "", 0, "C", false, 0, "")
				} else {
					setColor(gray)
					pdf.CellFormat(30, 7, "0", "", 0, "C", false, 0, "")
					pdf.SetFont("Helvetica", "", 6)
					pdf.CellFormat(50, 7, "—", "", 0, "C", false, 0, "")
				}
				pdf.Ln(7)
			}
		}
	}

	// Save PDF — use ScanDir which is the actual scan directory.
	// Mirrors the previous (*Server).generateReport behavior exactly:
	// reportID falls back to filepath.Base(ScanDir) and finally to "scan",
	// and the file is written to ScanDir when set, FallbackDir otherwise.
	reportID := scan.ID
	if strings.TrimSpace(reportID) == "" && opts.ScanDir != "" {
		reportID = filepath.Base(opts.ScanDir)
	}
	if strings.TrimSpace(reportID) == "" {
		reportID = "scan"
	}
	filename := fmt.Sprintf("xalgorix_report_%s.pdf", reportID)
	outPath := filepath.Join(opts.ScanDir, filename)
	if opts.ScanDir == "" {
		outPath = filepath.Join(opts.FallbackDir, filename)
	}
	if err := pdf.OutputFileAndClose(outPath); err != nil {
		return "", fmt.Errorf("failed to generate PDF: %w", err)
	}

	return outPath, nil
}
