package fonts

// fonts_test.go — F-001 user-override font path coverage.
//
// Documents the contract of Load(userPath): a non-empty userPath
// routes through the disk-read path with NO silent fallback to the
// embedded font. This is the user-facing safety property — a typo'd
// XALGORIX_REPORT_FONT_PATH must surface, not be masked.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// embeddedFontPath is the path the Makefile's download-font target
// places the font at. We use the embedded font as the "user
// override" file in success tests so we don't need to ship a second
// TTF in the repo for test fixtures.
func embeddedFontPath(t *testing.T) string {
	t.Helper()
	// The test runs with cwd = the fonts package directory, so the
	// //go:embed'd font is the very next file.
	p := "NotoSansSC-Regular.ttf"
	if _, err := os.Stat(p); err != nil {
		t.Skipf("CJK font not present at %s; run `make download-font` to enable font override tests", p)
	}
	return p
}

// TestFontsLoad_UserOverrideSuccess asserts that Load(userPath) with
// a valid file returns those file's bytes (and ignores the embedded
// payload). Uses the embedded font itself as the user override so
// the test doesn't depend on a second TTF in the repo.
func TestFontsLoad_UserOverrideSuccess(t *testing.T) {
	path := embeddedFontPath(t)
	got, err := Load(path)
	if err != nil {
		t.Fatalf("Load(%q) returned error: %v", path, err)
	}
	if len(got) < 1024 {
		t.Errorf("Load returned suspiciously small payload: %d bytes", len(got))
	}
	// Sanity: the returned bytes match the file on disk.
	onDisk, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read on-disk font: %v", err)
	}
	if len(got) != len(onDisk) {
		t.Errorf("Load returned %d bytes, file on disk is %d bytes", len(got), len(onDisk))
	}
}

// TestFontsLoad_UserPathMissing asserts that Load with a
// nonexistent path returns a non-nil error whose message mentions
// the offending path. This is the safety property the spec requires
// (no silent fallback): the user MUST see the failure mode they
// configured.
func TestFontsLoad_UserPathMissing(t *testing.T) {
	bad := "/nonexistent/xalgorix-test-path/font.ttf"
	got, err := Load(bad)
	if err == nil {
		t.Fatalf("Load(%q) returned no error; want an error (no silent fallback policy)", bad)
	}
	if got != nil {
		t.Errorf("Load returned non-nil bytes alongside error: %d bytes", len(got))
	}
	if !strings.Contains(err.Error(), bad) {
		t.Errorf("error %q does not mention the user path %q — operator can't tell which override failed", err.Error(), bad)
	}
}

// TestFontsLoad_FileTooSmall asserts that Load with a real file
// that's suspiciously small (< 1024 bytes) returns an explicit
// error rather than passing a half-baked font to fpdf. This
// catches the "user pointed me at a 4-byte placeholder file" footgun.
func TestFontsLoad_FileTooSmall(t *testing.T) {
	dir := t.TempDir()
	small := filepath.Join(dir, "tiny.ttf")
	if err := os.WriteFile(small, []byte("not a font"), 0o644); err != nil {
		t.Fatalf("create tiny file: %v", err)
	}
	got, err := Load(small)
	if err == nil {
		t.Fatalf("Load(%q) on a 12-byte file returned no error; want an error", small)
	}
	if got != nil {
		t.Errorf("Load returned non-nil bytes alongside error: %d bytes", len(got))
	}
	if !strings.Contains(err.Error(), "small") {
		t.Errorf("error %q should mention 'small' so the operator can diagnose", err.Error())
	}
}

// TestFontsLoad_EmbeddedWhenEmpty confirms the embedded font path:
// when userPath is empty, Load returns the bytes from //go:embed.
// This is the "user has no preference" default and the test pins
// the embedded payload's existence (the build wiring works).
func TestFontsLoad_EmbeddedWhenEmpty(t *testing.T) {
	got, err := Load("")
	if err != nil {
		t.Fatalf("Load(\"\") returned error: %v", err)
	}
	if len(got) < 1024 {
		t.Errorf("embedded font suspiciously small: %d bytes (the build may not have included it)", len(got))
	}
}
