package reporting

import (
	"strings"
	"testing"
	"unicode/utf8"
)

func TestSanitizeForPDF(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"plain ascii unchanged", "STEP 1: Key validation", "STEP 1: Key validation"},
		{"empty", "", ""},
		{"em dash", "Key validation — encrypted", "Key validation - encrypted"},
		{"en dash", "2832–1184 bytes", "2832-1184 bytes"},
		{"right arrow", "→ The deleteMe response", "-> The deleteMe response"},
		{"smart quotes", "the \u201crememberMe\u201d cookie", `the "rememberMe" cookie`},
		{"apostrophe", "Shiro\u2019s payload", "Shiro's payload"},
		{"ellipsis", "Expires=\u2026", "Expires=..."},
		{"bullet", "\u2022 item", "* item"},
		{"nbsp", "a\u00a0b", "a b"},
		{"newlines preserved", "line1\nline2\tcol", "line1\nline2\tcol"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := sanitizeForPDF(c.in)
			if got != c.want {
				t.Fatalf("sanitizeForPDF(%q) = %q, want %q", c.in, got, c.want)
			}
			if !utf8.ValidString(got) {
				t.Fatalf("result not valid UTF-8: %q", got)
			}
			for i := 0; i < len(got); i++ {
				if got[i] >= 0x80 {
					t.Fatalf("result contains non-ASCII byte at %d: %q", i, got)
				}
			}
		})
	}
}

// The exact string from issue #200's exploitation proof must come out ASCII.
func TestSanitizeExploitProof(t *testing.T) {
	in := "STEP 1: Key validation — Encrypted a Java URLDNS object with the default key\n→ The deleteMe response CONFIRMS Shiro successfully deserialized the payload."
	got := sanitizeForPDF(in)
	for i := 0; i < len(got); i++ {
		if got[i] >= 0x80 {
			t.Fatalf("non-ASCII byte survived: %q", got)
		}
	}
	if !strings.Contains(got, "Key validation - Encrypted") {
		t.Fatalf("em dash not transliterated: %q", got)
	}
	if !strings.Contains(got, "-> The deleteMe") {
		t.Fatalf("arrow not transliterated: %q", got)
	}
}

func TestSanitizeScanForPDFDoesNotMutateOriginal(t *testing.T) {
	orig := &Scan{
		Target: "https://ex\u2014ample.com",
		Vulns: []Vuln{{
			Title:             "SQLi \u2014 dump",
			ExploitationProof: "proof \u2192 done",
		}},
	}
	_ = sanitizeScanForPDF(orig)
	if orig.Vulns[0].Title != "SQLi \u2014 dump" {
		t.Fatalf("original Vuln.Title was mutated: %q", orig.Vulns[0].Title)
	}
	if !strings.Contains(orig.Target, "\u2014") {
		t.Fatalf("original Target was mutated: %q", orig.Target)
	}
}
