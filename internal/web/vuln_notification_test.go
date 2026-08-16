package web

import (
	"strings"
	"testing"
)

// Regression for issue #429: vulnerability notifications must carry the
// concrete exploitation evidence (proof + verification method + verified
// status), not just the descriptive fields — otherwise every alert reads like
// an unsubstantiated claim.
func TestVulnNotificationDetails_IncludesExploitationEvidence(t *testing.T) {
	vs := VulnSummary{
		Title:              "SQLi in /login",
		Severity:           "high",
		CVSS:               8.6,
		Endpoint:           "/login",
		Method:             "POST",
		Description:        "Boolean-based blind SQL injection.",
		Impact:             "Full DB read.",
		TechnicalAnalysis:  "Payload breaks out of the WHERE clause.",
		PoCDescription:     "Inject ' OR 1=1--",
		PoCScript:          "curl -d \"u=' OR 1=1--\" https://t/login",
		ExploitationProof:  "uid=0(root) gid=0(root)\nextracted: admin@site.com",
		VerificationMethod: "data_extracted",
		Verified:           true,
		Remediation:        "Use parameterized queries.",
	}

	out := vulnNotificationDetails(vs)

	if !strings.Contains(out, "Exploitation Proof") {
		t.Error("notification must include an Exploitation Proof section")
	}
	if !strings.Contains(out, "uid=0(root)") {
		t.Error("notification must include the actual exploitation proof output")
	}
	if !strings.Contains(out, "Verified via") || !strings.Contains(out, "data_extracted") {
		t.Error("notification must include the verification method")
	}
	if !strings.Contains(out, "verified — independently reproduced") {
		t.Errorf("verified finding must show verified status; got:\n%s", out)
	}
}

func TestVulnNotificationDetails_UnverifiedStatus(t *testing.T) {
	vs := VulnSummary{
		Title:              "Reflected XSS",
		Severity:           "medium",
		VerificationMethod: "reflected",
		Verified:           false,
	}
	out := vulnNotificationDetails(vs)
	if !strings.Contains(out, "unverified — needs manual review") {
		t.Errorf("unverified finding must show manual-review status; got:\n%s", out)
	}
}

// Fields that are absent must not render empty/placeholder sections.
func TestVulnNotificationDetails_OmitsEmptyEvidence(t *testing.T) {
	vs := VulnSummary{Title: "Info finding", Severity: "info", CVSS: 0}
	out := vulnNotificationDetails(vs)
	if strings.Contains(out, "Exploitation Proof") {
		t.Error("must not render an Exploitation Proof section when proof is empty")
	}
	if strings.Contains(out, "Verified via") {
		t.Error("must not render a verification section when method is empty")
	}
}

func TestTruncateForNotification_RuneSafe(t *testing.T) {
	// A run of multi-byte runes; truncating at a byte cap must not split a rune
	// (the result must remain valid UTF-8).
	s := strings.Repeat("é", 1000) // 2 bytes each → 2000 bytes
	out := truncateForNotification(s, 801)
	if !strings.HasSuffix(out, "... (truncated)") {
		t.Fatal("expected truncation marker")
	}
	body := strings.TrimSuffix(out, "\n... (truncated)")
	for i, r := range body {
		if r == '\uFFFD' {
			t.Fatalf("truncation split a UTF-8 rune at byte %d", i)
		}
	}

	// Short input is returned unchanged.
	if got := truncateForNotification("small", 800); got != "small" {
		t.Fatalf("short input altered: %q", got)
	}
}
