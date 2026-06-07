package reporting

import (
	"strings"
	"sync"
	"testing"
)

func TestCheckFalsePositive_MissingHeaders(t *testing.T) {
	tests := []struct {
		title      string
		desc       string
		severity   string
		proof      string
		wantReject bool
	}{
		{"Missing X-Frame-Options Header", "The X-Frame-Options header is not set", "medium", "", true},
		{"Missing Content-Security-Policy", "CSP is not configured", "high", "", true},
		{"Missing HSTS Header", "Strict-Transport-Security not found", "critical", "", true},
		// Low/info severity should NOT be rejected for headers
		{"Missing X-Frame-Options Header", "Header not set", "info", "", false},
		{"Missing X-Frame-Options Header", "Header not set", "low", "", false},
	}

	for _, tt := range tests {
		result := checkFalsePositive(tt.title, tt.desc, tt.severity, tt.proof)
		gotReject := result != ""
		if gotReject != tt.wantReject {
			t.Errorf("title=%q severity=%q: wantReject=%v gotReject=%v (msg=%s)", tt.title, tt.severity, tt.wantReject, gotReject, result)
		}
	}
}

func TestCheckFalsePositive_VersionDisclosure(t *testing.T) {
	tests := []struct {
		title      string
		severity   string
		wantReject bool
	}{
		{"Server Version Disclosure - Apache 2.4.41", "medium", true},
		{"X-Powered-By Header Reveals Technology", "high", true},
		{"Technology Disclosure via banner", "critical", true},
		{"Server Version Disclosure", "info", false},
	}

	for _, tt := range tests {
		result := checkFalsePositive(tt.title, tt.title, tt.severity, "")
		gotReject := result != ""
		if gotReject != tt.wantReject {
			t.Errorf("title=%q severity=%q: wantReject=%v gotReject=%v", tt.title, tt.severity, tt.wantReject, gotReject)
		}
	}
}

func TestCheckFalsePositive_SSL(t *testing.T) {
	tests := []struct {
		title      string
		wantReject bool
	}{
		{"Weak SSL Cipher Suite", true},
		{"TLS 1.0 Enabled", true},
		{"Expired Certificate", true},
		{"POODLE Vulnerability", true},
	}

	for _, tt := range tests {
		result := checkFalsePositive(tt.title, "", "medium", "")
		gotReject := result != ""
		if gotReject != tt.wantReject {
			t.Errorf("title=%q: wantReject=%v gotReject=%v", tt.title, tt.wantReject, gotReject)
		}
	}
}

func TestCheckFalsePositive_DNS(t *testing.T) {
	tests := []struct {
		title      string
		wantReject bool
	}{
		{"Missing SPF Record", true},
		{"No DMARC Policy", true},
		{"DKIM Not Configured", true},
		{"Email Spoofing Possible via missing SPF", true},
	}

	for _, tt := range tests {
		result := checkFalsePositive(tt.title, "", "high", "")
		gotReject := result != ""
		if gotReject != tt.wantReject {
			t.Errorf("title=%q: wantReject=%v gotReject=%v (msg=%s)", tt.title, tt.wantReject, gotReject, result)
		}
	}
}

func TestCheckFalsePositive_CORSWithoutProof(t *testing.T) {
	// CORS without cookie/token theft proof → rejected at medium+
	result := checkFalsePositive("CORS Misconfiguration", "Access-Control-Allow-Origin reflects input", "high", "curl showed reflected origin")
	if result == "" {
		t.Error("CORS without exploit proof should be rejected at high severity")
	}

	// CORS WITH theft proof → accepted
	result = checkFalsePositive("CORS Misconfiguration", "Allows credential theft", "high", "JavaScript fetch() exfiltrates session cookie via CORS")
	if result != "" {
		t.Errorf("CORS with exploit proof should NOT be rejected, got: %s", result)
	}
}

func TestCheckFalsePositive_OpenRedirectWithoutChain(t *testing.T) {
	// Open redirect alone → rejected at medium+
	result := checkFalsePositive("Open Redirect", "Redirects to attacker URL", "medium", "curl -L shows redirect to evil.com")
	if result == "" {
		t.Error("open redirect without chain should be rejected at medium+")
	}

	// Open redirect chained with OAuth → accepted
	result = checkFalsePositive("Open Redirect to OAuth Token Theft", "Redirect steals OAuth token", "high", "OAuth code redirected via open redirect, token stolen via phishing")
	if result != "" {
		t.Errorf("open redirect with OAuth chain should NOT be rejected, got: %s", result)
	}
}

func TestCheckFalsePositive_CSVInjection(t *testing.T) {
	result := checkFalsePositive("CSV Injection in Export", "Formula injection in CSV export", "medium", "")
	if result == "" {
		t.Error("CSV injection at medium should be rejected")
	}

	result = checkFalsePositive("CSV Injection in Export", "Formula injection", "low", "")
	if result != "" {
		t.Errorf("CSV injection at low should NOT be rejected, got: %s", result)
	}
}

func TestCheckFalsePositive_Clickjacking(t *testing.T) {
	result := checkFalsePositive("Clickjacking on Login Page", "Page can be iframed", "high", "")
	if result == "" {
		t.Error("clickjacking at high should be rejected")
	}

	result = checkFalsePositive("Clickjacking on Login Page", "Page can be iframed", "low", "")
	if result != "" {
		t.Errorf("clickjacking at low should NOT be rejected, got: %s", result)
	}
}

func TestCheckFalsePositive_DirectoryListing(t *testing.T) {
	// Directory listing without sensitive files → rejected
	result := checkFalsePositive("Directory Listing Enabled", "Apache autoindex enabled", "medium", "Shows index of /images/")
	if result == "" {
		t.Error("directory listing without sensitive files should be rejected at medium+")
	}

	// Directory listing WITH sensitive files → accepted
	result = checkFalsePositive("Directory Listing Enabled", "Directory listing exposes backup files", "high", "Found database.sql backup with password hashes")
	if result != "" {
		t.Errorf("directory listing with sensitive files should NOT be rejected, got: %s", result)
	}
}

func TestCheckFalsePositive_TraceMethod(t *testing.T) {
	result := checkFalsePositive("TRACE Method Enabled", "HTTP TRACE method is enabled", "medium", "")
	if result == "" {
		t.Error("TRACE method should be rejected")
	}

	result = checkFalsePositive("OPTIONS Method Enabled", "HTTP OPTIONS reveals methods", "low", "")
	if result == "" {
		t.Error("OPTIONS method should be rejected")
	}
}

func TestCheckFalsePositive_ScannerOnly(t *testing.T) {
	result := checkFalsePositive("Nuclei Detected SQL Injection", "nuclei found potential SQLi", "high", "")
	if result == "" {
		t.Error("scanner-only finding without proof should be rejected")
	}

	result = checkFalsePositive("Nuclei Detected SQL Injection", "nuclei found SQLi, manually verified", "high", "sqlmap confirmed with --dump")
	if result != "" {
		t.Errorf("scanner finding with manual proof should NOT be rejected, got: %s", result)
	}
}

func TestCheckFalsePositive_RealVulns(t *testing.T) {
	// Real vulnerabilities should NOT be rejected
	realVulns := []struct {
		title    string
		desc     string
		severity string
		proof    string
	}{
		{"SQL Injection in login endpoint", "Union-based SQLi", "critical", "sqlmap extracted admin table"},
		{"Stored XSS in comment field", "Script tag stored", "high", "alert(1) reflected in response body"},
		{"SSRF via image URL parameter", "Internal metadata accessed", "critical", "169.254.169.254 metadata returned"},
		{"IDOR in user profile API", "Can access other users", "high", "Changed user_id=1 to user_id=2, got admin data"},
		{"Remote Code Execution via file upload", "PHP shell uploaded", "critical", "whoami returned www-data"},
	}

	for _, tt := range realVulns {
		result := checkFalsePositive(tt.title, tt.desc, tt.severity, tt.proof)
		if result != "" {
			t.Errorf("real vuln %q should NOT be rejected, got: %s", tt.title, result)
		}
	}
}

func TestReportVulnChecksDuplicateBeforeAppending(t *testing.T) {
	contextID := "test-report-duplicate"
	CleanupContext(contextID)
	defer CleanupContext(contextID)

	args := validReportArgs()
	first, err := reportVulnWithContextID(contextID, args)
	if err != nil {
		t.Fatalf("first report error = %v", err)
	}
	if _, ok := first.Metadata["vuln_id"].(string); !ok {
		t.Fatalf("first report metadata = %#v, want vuln_id", first.Metadata)
	}

	duplicateArgs := validReportArgs()
	duplicateArgs["endpoint"] = "https://example.com/login?id=2"
	second, err := reportVulnWithContextID(contextID, duplicateArgs)
	if err != nil {
		t.Fatalf("second report error = %v", err)
	}
	if !strings.Contains(second.Output, "DUPLICATE") {
		t.Fatalf("second report output = %q, want duplicate", second.Output)
	}
	if got, ok := second.Metadata["duplicate"].(bool); !ok || !got {
		t.Fatalf("second report metadata = %#v, want duplicate=true", second.Metadata)
	}
	if got := len(GetVulnerabilitiesForContext(contextID)); got != 1 {
		t.Fatalf("stored vulnerabilities = %d, want 1", got)
	}
}

func TestReportVulnSameFindingAllowedAcrossScanContexts(t *testing.T) {
	contextA := "test-report-context-a"
	contextB := "test-report-context-b"
	CleanupContext(contextA)
	CleanupContext(contextB)
	defer CleanupContext(contextA)
	defer CleanupContext(contextB)

	first, err := reportVulnWithContextID(contextA, validReportArgs())
	if err != nil {
		t.Fatalf("first report error = %v", err)
	}
	if _, ok := first.Metadata["vuln_id"].(string); !ok {
		t.Fatalf("first report metadata = %#v, want vuln_id", first.Metadata)
	}

	second, err := reportVulnWithContextID(contextB, validReportArgs())
	if err != nil {
		t.Fatalf("second report error = %v", err)
	}
	if _, ok := second.Metadata["vuln_id"].(string); !ok {
		t.Fatalf("second report metadata = %#v, want vuln_id", second.Metadata)
	}
	if got, _ := second.Metadata["duplicate"].(bool); got {
		t.Fatalf("second report metadata = %#v, want a new finding in a separate scan context", second.Metadata)
	}

	third, err := reportVulnWithContextID(contextA, validReportArgs())
	if err != nil {
		t.Fatalf("third report error = %v", err)
	}
	if got, ok := third.Metadata["duplicate"].(bool); !ok || !got {
		t.Fatalf("third report metadata = %#v, want duplicate=true within the same scan context", third.Metadata)
	}

	if got := len(GetVulnerabilitiesForContext(contextA)); got != 1 {
		t.Fatalf("context A vulnerabilities = %d, want 1", got)
	}
	if got := len(GetVulnerabilitiesForContext(contextB)); got != 1 {
		t.Fatalf("context B vulnerabilities = %d, want 1", got)
	}
}

func TestReportVulnConcurrentDuplicatesOnlyAppendOnce(t *testing.T) {
	contextID := "test-report-concurrent-duplicate"
	CleanupContext(contextID)
	defer CleanupContext(contextID)

	const attempts = 20
	var wg sync.WaitGroup
	wg.Add(attempts)
	for i := 0; i < attempts; i++ {
		go func() {
			defer wg.Done()
			_, _ = reportVulnWithContextID(contextID, validReportArgs())
		}()
	}
	wg.Wait()

	if got := len(GetVulnerabilitiesForContext(contextID)); got != 1 {
		t.Fatalf("stored vulnerabilities after concurrent duplicates = %d, want 1", got)
	}
}

func validReportArgs() map[string]string {
	return map[string]string{
		"title":               "SQL Injection in Login Endpoint",
		"severity":            "high",
		"description":         "Union-based SQL injection allows extraction of user records from the login endpoint.",
		"exploitation_proof":  "sql injection data extraction confirmed; dumped user data including email address records from database",
		"verification_method": "data_extracted",
		"impact":              "Unauthorized attackers can extract sensitive user data.",
		"target":              "https://example.com",
		"endpoint":            "https://example.com/login?id=1",
		"method":              "GET",
		"cvss":                "7.5",
		"cvss_vector":         "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
	}
}

func TestHasStrongEvidence(t *testing.T) {
	tests := []struct {
		severity string
		proof    string
		desc     string
		want     bool
	}{
		{"critical", "rce: executed whoami, got root", "", true},
		{"critical", "", "", false},
		{"high", "sqli with data extraction", "", true},
		{"high", "found a parameter", "", false},
		{"medium", "reflected input in response", "", true},
		{"low", "anything goes", "", true}, // low/info don't need strong evidence
		{"info", "anything", "", true},
	}

	for _, tt := range tests {
		got := hasStrongEvidence(tt.severity, tt.proof, tt.desc)
		if got != tt.want {
			t.Errorf("severity=%q proof=%q: want=%v got=%v", tt.severity, tt.proof[:min(len(tt.proof), 30)], tt.want, got)
		}
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// TestPromoteToParentViaSetParentContext verifies that:
//  1. A vuln reported into a child context registered via SetParentContext is
//     promoted into the parent context immediately (panic-safe persistence).
//  2. Re-reporting the same finding in the child does not duplicate the entry
//     in the parent (idempotent promotion).
//
// Validates: Property 4 (panic-safe persistence).
func TestPromoteToParentViaSetParentContext(t *testing.T) {
	child := "test-promote-child"
	parent := "test-promote-parent"
	CleanupContext(child)
	CleanupContext(parent)
	defer CleanupContext(child)
	defer CleanupContext(parent)

	SetParentContext(child, parent)

	first, err := reportVulnWithContextID(child, validReportArgs())
	if err != nil {
		t.Fatalf("first report error = %v", err)
	}
	vulnID, ok := first.Metadata["vuln_id"].(string)
	if !ok {
		t.Fatalf("first report metadata = %#v, want vuln_id", first.Metadata)
	}

	parentVulns := GetVulnerabilitiesForContext(parent)
	if len(parentVulns) != 1 {
		t.Fatalf("parent vulnerabilities after promote = %d, want 1", len(parentVulns))
	}
	if parentVulns[0].ID != vulnID {
		t.Fatalf("parent vuln id = %q, want %q", parentVulns[0].ID, vulnID)
	}

	// Re-report the same finding in the child — duplicate-rejected in child,
	// and the parent must not gain a second copy.
	second, err := reportVulnWithContextID(child, validReportArgs())
	if err != nil {
		t.Fatalf("second report error = %v", err)
	}
	if dup, _ := second.Metadata["duplicate"].(bool); !dup {
		t.Fatalf("second report metadata = %#v, want duplicate=true", second.Metadata)
	}
	if got := len(GetVulnerabilitiesForContext(parent)); got != 1 {
		t.Fatalf("parent vulnerabilities after duplicate report = %d, want 1", got)
	}
}

// TestPromoteToParentIdempotent verifies the lower-level PromoteToParent helper
// is a no-op when called twice with the same vulnID.
func TestPromoteToParentIdempotent(t *testing.T) {
	child := "test-promote-idem-child"
	parent := "test-promote-idem-parent"
	CleanupContext(child)
	CleanupContext(parent)
	defer CleanupContext(child)
	defer CleanupContext(parent)

	// Seed the child with a vuln directly so we can call PromoteToParent twice.
	first, err := reportVulnWithContextID(child, validReportArgs())
	if err != nil {
		t.Fatalf("seed report error = %v", err)
	}
	vulnID, _ := first.Metadata["vuln_id"].(string)
	if vulnID == "" {
		t.Fatalf("seed report metadata = %#v, want vuln_id", first.Metadata)
	}

	PromoteToParent(child, parent, vulnID)
	PromoteToParent(child, parent, vulnID)

	if got := len(GetVulnerabilitiesForContext(parent)); got != 1 {
		t.Fatalf("parent vulnerabilities after two PromoteToParent calls = %d, want 1", got)
	}
}

// TestSetParentContextCleanedOnCleanup verifies that CleanupContext also clears
// the child→parent mapping so it does not leak across scan lifecycles.
func TestSetParentContextCleanedOnCleanup(t *testing.T) {
	child := "test-promote-cleanup-child"
	parent := "test-promote-cleanup-parent"
	defer CleanupContext(parent)

	SetParentContext(child, parent)
	if got := GetParentContext(child); got != parent {
		t.Fatalf("GetParentContext = %q, want %q", got, parent)
	}

	CleanupContext(child)
	if got := GetParentContext(child); got != "" {
		t.Fatalf("GetParentContext after cleanup = %q, want empty", got)
	}
}

// TestAutoDowngrade_OneLevelDrop verifies that the auto-downgrade for weak
// evidence drops severity by exactly one level (not nuclear to "info").
func TestAutoDowngrade_OneLevelDrop(t *testing.T) {
	tests := []struct {
		name     string
		severity string
		want     string
	}{
		{"critical drops to high", "critical", "high"},
		{"high drops to medium", "high", "medium"},
		{"medium drops to low", "medium", "low"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			contextID := "test-auto-downgrade-" + tt.severity
			CleanupContext(contextID)
			defer CleanupContext(contextID)

			// Use deliberately weak proof that won't pass hasStrongEvidence
			args := map[string]string{
				"title":               "Some finding on endpoint",
				"severity":            tt.severity,
				"description":         "A potential issue was observed",
				"exploitation_proof":  "The endpoint responded with a 200 status code when tested",
				"verification_method": "manual_verified",
				"target":              "https://example.com",
				"endpoint":            "/api/test-" + tt.severity,
				// No CVSS provided — so CVSS enforcement won't override
			}

			result, err := reportVulnWithContextID(contextID, args)
			if err != nil {
				t.Fatalf("report error: %v", err)
			}

			vulns := GetVulnerabilitiesForContext(contextID)
			if len(vulns) != 1 {
				t.Fatalf("expected 1 vuln, got %d (output: %s)", len(vulns), result.Output)
			}

			if vulns[0].Severity != tt.want {
				t.Errorf("severity = %q, want %q (auto-downgrade should drop one level, not to info)", vulns[0].Severity, tt.want)
			}
		})
	}
}

// TestCVSSEnforcement_OverridesAutoDowngrade verifies that CVSS enforcement
// is truly authoritative — it overrides prior auto-downgrade decisions.
// This was the core bug: CVSS 7.4 should ALWAYS produce "high", regardless
// of what the auto-downgrade gate decided.
func TestCVSSEnforcement_OverridesAutoDowngrade(t *testing.T) {
	tests := []struct {
		name         string
		severity     string // agent-provided severity
		cvss         string // agent-provided CVSS
		wantSeverity string // expected final severity
	}{
		// CVSS 7.4 = high, regardless of what the agent labels it
		{"high with CVSS 7.4", "high", "7.4", "high"},
		{"low with CVSS 7.4", "low", "7.4", "high"},
		{"info with CVSS 7.4", "info", "7.4", "high"},

		// CVSS 9.5 = critical
		{"high with CVSS 9.5", "high", "9.5", "critical"},
		{"medium with CVSS 9.5", "medium", "9.5", "critical"},

		// CVSS 5.5 = medium
		{"critical with CVSS 5.5", "critical", "5.5", "medium"},
		{"high with CVSS 5.5", "high", "5.5", "medium"},

		// CVSS 2.5 = low
		{"high with CVSS 2.5", "high", "2.5", "low"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			contextID := "test-cvss-enforcement-" + tt.name
			CleanupContext(contextID)
			defer CleanupContext(contextID)

			args := map[string]string{
				"title":               "SQL Injection in API endpoint",
				"severity":            tt.severity,
				"description":         "SQL injection allows data extraction from the database",
				"exploitation_proof":  "sql injection data extraction confirmed; email address records dumped from user table via union select",
				"verification_method": "data_extracted",
				"target":              "https://example.com",
				"endpoint":            "/api/vuln-" + tt.name,
				"cvss":                tt.cvss,
			}

			_, err := reportVulnWithContextID(contextID, args)
			if err != nil {
				t.Fatalf("report error: %v", err)
			}

			vulns := GetVulnerabilitiesForContext(contextID)
			if len(vulns) != 1 {
				t.Fatalf("expected 1 vuln, got %d", len(vulns))
			}

			if vulns[0].Severity != tt.wantSeverity {
				t.Errorf("severity = %q, want %q (CVSS %s should always produce %s)", vulns[0].Severity, tt.wantSeverity, tt.cvss, tt.wantSeverity)
			}
		})
	}
}

// TestStoredXSS_CVSS74_AlwaysHigh reproduces the exact scenario from the
// user's bug report: "Stored XSS in ActiveCampaign CRM" with CVSS 7.4
// was classified as HIGH in one run and LOW in another. After the fix,
// CVSS 7.4 must always produce HIGH.
func TestStoredXSS_CVSS74_AlwaysHigh(t *testing.T) {
	// Simulate both scenarios the LLM might produce
	scenarios := []struct {
		name     string
		severity string
		proof    string
	}{
		{
			"strong proof",
			"high",
			"Unauthenticated endpoint /api/activecampaign-lead accepts and stores unsanitized HTML/JavaScript in the firstName and lastName fields. Payload <script>alert(document.cookie)</script> fires in admin panel.",
		},
		{
			"weak proof",
			"high",
			"The endpoint accepts HTML input in the firstName field. The data is stored and displayed.",
		},
		{
			"agent says low",
			"low",
			"Unauthenticated endpoint accepts unsanitized HTML input.",
		},
	}

	for _, sc := range scenarios {
		t.Run(sc.name, func(t *testing.T) {
			contextID := "test-stored-xss-consistency-" + sc.name
			CleanupContext(contextID)
			defer CleanupContext(contextID)

			args := map[string]string{
				"title":               "Stored XSS in ActiveCampaign CRM via /api/activecampaign-lead",
				"severity":            sc.severity,
				"description":         "Unauthenticated endpoint /api/activecampaign-lead accepts and stores unsanitized HTML/JavaScript",
				"exploitation_proof":  sc.proof,
				"verification_method": "reflected",
				"target":              "https://vanhack.com",
				"endpoint":            "/api/activecampaign-lead",
				"method":              "POST",
				"cvss":                "7.4",
			}

			_, err := reportVulnWithContextID(contextID, args)
			if err != nil {
				t.Fatalf("report error: %v", err)
			}

			vulns := GetVulnerabilitiesForContext(contextID)
			if len(vulns) != 1 {
				t.Fatalf("expected 1 vuln, got %d", len(vulns))
			}

			// CVSS 7.4 = HIGH, always. This is the fix.
			if vulns[0].Severity != "high" {
				t.Errorf("severity = %q, want %q — CVSS 7.4 must always produce HIGH regardless of proof strength or agent-provided severity", vulns[0].Severity, "high")
			}
		})
	}
}

// TestClassifySeverity_XSSCaps verifies that stored XSS is capped at
// high (not critical) by classifySeverity, but CVSS enforcement can
// still override this cap.
func TestClassifySeverity_XSSCaps(t *testing.T) {
	// Stored XSS without admin/mass/worm proof → capped at high
	sev, reason := classifySeverity("Stored XSS in comment field", "Persistent XSS stores payload", "critical", "alert(1) fires in page")
	if sev != "high" {
		t.Errorf("classifySeverity for stored XSS at critical = %q (reason=%q), want high", sev, reason)
	}

	// Reflected XSS → capped at medium
	sev, reason = classifySeverity("Reflected XSS in search", "Input reflected in response", "high", "payload reflected")
	if sev != "medium" {
		t.Errorf("classifySeverity for reflected XSS at high = %q (reason=%q), want medium", sev, reason)
	}
}

// TestClassifySeverity_VulnTypeFallback verifies that the vulnType-based
// fallback fires when the LLM uses a different title framing for the same
// vulnerability. This was the exact bug from scan logs where:
// - "Stored XSS in ActiveCampaign CRM" → matched "stored xss" keyword → high cap
// - "Unauthenticated Contact Injection" → matched NO keyword → no cap at all
// After the fix, extractVulnType catches "xss" in both titles/descriptions.
func TestClassifySeverity_VulnTypeFallback(t *testing.T) {
	tests := []struct {
		name     string
		title    string
		desc     string
		severity string
		want     string
	}{
		{
			"stored xss keyword in title → high cap",
			"Stored XSS in ActiveCampaign CRM via /api/activecampaign-lead",
			"Persistent XSS stores payload in CRM firstName field",
			"critical",
			"high",
		},
		{
			"xss in description only → vulnType fallback catches it",
			"Unauthenticated ActiveCampaign Contact Injection — CRM Pollution",
			"Anyone can inject stored XSS payloads via the firstName field",
			"critical",
			"high", // vulnType="xss" + "stored" in desc → high cap
		},
		{
			"xss in description via different wording → vulnType catches it",
			"Unauthenticated CRM Contact Creation — Unsanitized Input",
			"The endpoint stores user-controlled HTML without sanitization, enabling cross-site scripting in the admin panel",
			"critical",
			"high", // vulnType="xss" from "cross-site scripting" + "stored" not present but desc says "stores" → check
		},
		{
			"no xss anywhere → no fallback cap",
			"Unauthenticated ActiveCampaign Contact Creation",
			"Anyone can create arbitrary contacts in the CRM without authentication",
			"critical",
			"critical", // no vuln type detected → no cap
		},
		{
			"reflected xss via vulnType → medium cap",
			"Input Reflection in Search Endpoint",
			"The search parameter reflects user input without encoding — cross-site scripting possible",
			"high",
			"medium", // vulnType="xss", no "stored"/"persistent" → reflected → medium cap
		},
		{
			"csrf via vulnType → medium cap",
			"Unauthenticated State Change in Profile Settings",
			"Missing CSRF protection allows cross-site request forgery on profile update",
			"critical",
			"medium",
		},
		{
			"ssrf via vulnType → high cap",
			"Internal Network Access via URL Parameter",
			"Server-side request forgery allows access to internal services",
			"critical",
			"high",
		},
		{
			"cors via vulnType → low cap",
			"Wildcard Origin Allowed on API",
			"Cross-origin resource sharing misconfiguration reflects any origin",
			"high",
			"low",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, reason := classifySeverity(tt.title, tt.desc, tt.severity, "some proof")
			if got != tt.want {
				t.Errorf("classifySeverity(%q, %q, %q) = %q (reason=%q), want %q",
					tt.title, tt.desc, tt.severity, got, reason, tt.want)
			}
		})
	}
}
