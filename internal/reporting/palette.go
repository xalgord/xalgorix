package reporting

// Palette holds the RGB triples used by the branded PDF report. The values
// are byte-identical to the previous internal/web in-line palette so the
// generated artifact is unchanged.
type Palette struct {
	BG       [3]int
	Card     [3]int
	Muted    [3]int
	Border   [3]int
	FG       [3]int
	Subtle   [3]int
	Accent   [3]int
	Critical [3]int
	High     [3]int
	Medium   [3]int
	Low      [3]int
	Info     [3]int
	Code     [3]int
}

// ThemePalette returns the dark-theme palette baked into every Xalgorix
// report. Every value mirrors the design tokens in webui/src/styles.css
// (the actual Xalgorix product theme) so the PDF matches the brand the
// dashboard and marketing surfaces use.
//
// Accent is the one value that previously drifted from the brand: it was
// hard-coded to a green (#10b981) that webui/src/styles.css only uses for
// --color-success, never for the brand itself. The real brand accent is
// --color-brand: oklch(0.56 0.22 20), a restrained crimson — converted to
// sRGB below so fpdf (which only accepts integer RGB) can paint it.
func ThemePalette() Palette {
	return Palette{
		BG:       [3]int{5, 5, 5},       // #050505 — --color-background
		Card:     [3]int{10, 10, 10},    // #0a0a0a — --color-card
		Muted:    [3]int{17, 17, 17},    // #111111 — --color-muted
		Border:   [3]int{38, 38, 38},    // #262626 — --color-border
		FG:       [3]int{250, 250, 250}, // #fafafa — --color-foreground
		Subtle:   [3]int{161, 161, 170}, // #a1a1aa — --color-muted-foreground
		Accent:   [3]int{215, 14, 58},   // #d70e3a — --color-brand
		Critical: [3]int{220, 38, 38},   // #dc2626 — --color-severity-critical
		High:     [3]int{234, 88, 12},   // #ea580c — --color-severity-high
		Medium:   [3]int{202, 138, 4},   // #ca8a04 — --color-severity-medium
		Low:      [3]int{37, 99, 235},   // #2563eb — --color-severity-low
		Info:     [3]int{82, 82, 82},    // #525252 — --color-severity-info
		Code:     [3]int{23, 23, 23},    // #171717 — near --color-secondary
	}
}
