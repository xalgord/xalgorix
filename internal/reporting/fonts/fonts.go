// Package fonts provides the CJK font used by the F-001 Chinese PDF
// report. The font file (Noto Sans CJK SC Regular, ~10MB, Apache 2.0)
// lives next to this Go file and is embedded into the binary via
// //go:embed so the report works on a fresh install with no network
// access.
//
// At build time the Makefile's download-font target ensures the file
// is present. If a developer runs `go build` directly without first
// running `make download-font`, the build will fail at //go:embed
// resolution time with a clear "pattern …: no matching files found"
// error — which is the intended signal.
package fonts

import (
	_ "embed"
	"fmt"
	"os"
)

// embeddedOTF holds the Noto Sans SC Regular TTF bytes, embedded into
// the binary at compile time. The Makefile's download-font target
// places the file at the path below before go build runs.
//
// We embed the Simplified Chinese web subset (Noto Sans SC) rather
// than the full CJK family (Noto Sans CJK SC) because fpdf's UTF8
// font parser rejects OTF files — and the notofonts/noto-cjk
// project distributes the full family only as OTF. The SC TTF
// subset has all the glyphs we need to render a Chinese security
// report; the trade-off is no coverage for Japanese / Korean /
// Traditional Chinese characters, which we do not emit.
//
//go:embed NotoSansSC-Regular.ttf
var embeddedOTF []byte

// Load returns the font bytes the PDF renderer should register with
// fpdf. Resolution order:
//
//  1. If userPath is non-empty, read that file from disk. Errors
//     (missing file, permission denied, etc.) are returned EXPLICITLY
//     — the caller's font is treated as an explicit override, so
//     silently falling back to the embedded font would mask a
//     config error the operator needs to see.
//
//  2. Otherwise, return the embedded font bytes. A zero-length
//     embedded payload means the build did not include the font
//     file (developer ran go build without `make download-font`);
//     that is also an explicit error so the operator notices
//     instead of getting tofu boxes in the rendered PDF.
//
// We intentionally do NOT add a silent fallback from (1) to (2) so
// the user always sees the failure mode they configured.
func Load(userPath string) ([]byte, error) {
	if userPath != "" {
		data, err := os.ReadFile(userPath)
		if err != nil {
			return nil, fmt.Errorf("fonts: read user override %q: %w", userPath, err)
		}
		if len(data) < 1024 {
			return nil, fmt.Errorf("fonts: user override %q is suspiciously small (%d bytes); refusing to use", userPath, len(data))
		}
		return data, nil
	}
	if len(embeddedOTF) == 0 {
		return nil, fmt.Errorf("fonts: embedded font is empty; the binary was built without NotoSansCJKsc-Regular.otf (run `make download-font` before `go build`)")
	}
	return embeddedOTF, nil
}
