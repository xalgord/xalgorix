// Package reporting provides vulnerability reporting tools with exploit-before-report validation.
package reporting

import (
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/xalgord/xalgorix/v4/internal/scanctx"
	"github.com/xalgord/xalgorix/v4/internal/tools"
)

// Valid verification methods — the agent must specify one when reporting.
var validVerificationMethods = map[string]bool{
	"exploited":         true, // Full exploitation with proof
	"time_based":        true, // Time-based blind confirmation (SQLi, command injection)
	"data_extracted":    true, // Actual data was extracted
	"callback_received": true, // SSRF/XXE/RCE callback received
	"error_based":       true, // Error-based confirmation (SQL error, stack trace)
	"blind_confirmed":   true, // Blind vulnerability confirmed via side-channel
	"reflected":         true, // Payload reflected in response (XSS)
	"authenticated":     true, // Auth bypass / IDOR with evidence
	"manual_verified":   true, // Manually verified via browser / curl
}

// Minimum evidence keywords per severity — used for auto-downgrade heuristics.
var evidenceKeywords = map[string][]string{
	"critical": {"rce", "remote code", "shell", "reverse shell", "command execution", "dump", "database",
		"full access", "admin takeover", "account takeover", "full compromise", "root access",
		"aws key", "secret key", "private key", "all user", "mass data"},
	"high": {"sqli", "sql injection", "data extract", "xss", "cross-site", "ssrf", "idor",
		"auth bypass", "token", "session hijack", "file inclusion", "sensitive data",
		"personal data", "pii", "email address", "phone number", "credit card",
		"password hash", "api key", "access token", "user data", "private information",
		"unauthorized access", "privilege escalation"},
	"medium": {"reflected", "csrf", "redirect", "disclosure", "injection", "traversal",
		"internal ip", "internal path", "config", "source code", "debug", "stack trace"},
}

// Vulnerability represents a found vulnerability.
type Vulnerability struct {
	ID                 string  `json:"id"`
	Title              string  `json:"title"`
	Severity           string  `json:"severity"`
	OriginalSeverity   string  `json:"original_severity,omitempty"` // if auto-downgraded
	Description        string  `json:"description"`
	Impact             string  `json:"impact"`
	Target             string  `json:"target"`
	Endpoint           string  `json:"endpoint"`
	Method             string  `json:"method"`
	CVE                string  `json:"cve"`
	CWE                string  `json:"cwe_id,omitempty"` // e.g. "CWE-79"
	OWASP              string  `json:"owasp,omitempty"`  // e.g. "A03"
	CVSS               float64 `json:"cvss"`
	CVSSVector         string  `json:"cvss_vector,omitempty"` // CVSS 3.1 vector string
	TechnicalAnalysis  string  `json:"technical_analysis"`
	PoCDescription     string  `json:"poc_description"`
	PoCScript          string  `json:"poc_script_code"`
	Remediation        string  `json:"remediation_steps"`
	ExploitationProof  string  `json:"exploitation_proof"`
	VerificationMethod string  `json:"verification_method"`
	Verified           bool    `json:"verified"`
	Timestamp          string  `json:"timestamp"`
	AgentName          string  `json:"agent_name"`
}

// ── Per-instance vulnerability stores ──
// Each scan context gets its own vulnerability list.
// The global functions delegate to the active scan context's store.
var (
	stores   = make(map[string]*vulnStore) // scanContextID → store
	storesMu sync.RWMutex
)

// ── Child → parent context mapping ──
// Decouples the reporting package from web/server.go. The web layer calls
// SetParentContext at session start so PromoteToParent / promoteIfChildOfWildcard
// can resolve the parent without importing or knowing about scanSession.
//
// CleanupContext removes both the vuln store AND the child→parent entry,
// so the map does not leak entries across scan lifecycles.
var parentMap = struct {
	sync.RWMutex
	m map[string]string
}{m: make(map[string]string)}

// SetParentContext declares that vulns reported into childCtxID should also
// be promoted into parentCtxID via PromoteToParent. Idempotent: calling twice
// with the same arguments is a no-op. Passing an empty parentCtxID clears
// any prior mapping.
func SetParentContext(childCtxID, parentCtxID string) {
	if childCtxID == "" {
		return
	}
	parentMap.Lock()
	defer parentMap.Unlock()
	if parentCtxID == "" {
		delete(parentMap.m, childCtxID)
		return
	}
	parentMap.m[childCtxID] = parentCtxID
}

// GetParentContext returns the parent context ID registered for childCtxID,
// or the empty string if none is set.
func GetParentContext(childCtxID string) string {
	parentMap.RLock()
	defer parentMap.RUnlock()
	return parentMap.m[childCtxID]
}

// vulnStore is a per-instance vulnerability list.
type vulnStore struct {
	mu    sync.RWMutex
	vulns []Vulnerability
}

// getStoreByID returns the vulnerability store for a specific context ID.
// Creates a new store if one doesn't exist.
func getStoreByID(id string) *vulnStore {
	storesMu.RLock()
	s, ok := stores[id]
	storesMu.RUnlock()
	if ok {
		return s
	}

	// Create store for this context
	storesMu.Lock()
	defer storesMu.Unlock()
	if s, ok := stores[id]; ok {
		return s // double-check after write lock
	}
	s = &vulnStore{}
	stores[id] = s
	return s
}

// getStore returns the vulnerability store for the default scan context.
// Used by backward-compatible global functions (CLI mode).
func getStore() *vulnStore {
	return getStoreByID(scanctx.Default().ID)
}

// getStoreForContext returns the vulnerability store for a specific context ID.
func getStoreForContext(contextID string) *vulnStore {
	storesMu.RLock()
	s, ok := stores[contextID]
	storesMu.RUnlock()
	if ok {
		return s
	}
	storesMu.Lock()
	defer storesMu.Unlock()
	if s, ok := stores[contextID]; ok {
		return s
	}
	s = &vulnStore{}
	stores[contextID] = s
	return s
}

// Register adds reporting tools to the registry.
// The registry is captured in the closure so tools resolve the correct
// ScanContext via registry.GetScanContextID() instead of scanctx.Default().
func Register(r *tools.Registry) {
	r.Register(&tools.Tool{
		Name: "report_vulnerability",
		Description: `Report a VERIFIED, EXPLOITABLE vulnerability with proof. CRITICAL RULES:
1. You MUST have already EXPLOITED this vulnerability before calling this tool.
2. You MUST provide exploitation_proof showing concrete evidence (extracted data, reflected payload, command output, callback, timing proof).
3. Reports without exploitation proof for severity >= medium will be REJECTED — exploit first, then report.
4. Do NOT report missing headers, version disclosure, or scanner-only findings as vulnerabilities — those are INFO at best.
5. Duplicate checks are scoped to the current scan run only. If the same issue was found in a previous scan and is still exploitable now, report it again for this scan.
6. SEVERITY MUST MATCH CVSS SCORE per HackerOne standards:
   - Critical (9.0-10.0): RCE, full DB dump, mass account takeover, admin access
   - High (7.0-8.9): SQLi with data extraction, stored XSS with session hijack, SSRF to internal services, auth bypass, IDOR exposing PII
   - Medium (4.0-6.9): Reflected XSS, CSRF on non-critical actions, open redirect, info disclosure of internal data
   - Low (0.1-3.9): Clickjacking, missing cookie flags, CORS without credential theft, path disclosure
   - None/Info (0.0): Missing headers, version disclosure, self-XSS, DNS config issues`,
		Parameters: []tools.Parameter{
			{Name: "title", Description: "Vulnerability title", Required: true},
			{Name: "severity", Description: "Severity per HackerOne CVSS ranges: critical (CVSS 9.0-10.0), high (7.0-8.9), medium (4.0-6.9), low (0.1-3.9), info (0.0). Must match your CVSS score.", Required: true},
			{Name: "description", Description: "Detailed description of the vulnerability", Required: true},
			{Name: "exploitation_proof", Description: "REQUIRED for medium+. Concrete evidence of exploitation: extracted data, reflected payload text, command output, timing measurement, callback confirmation. Paste actual output here.", Required: true},
			{Name: "verification_method", Description: "How you verified: exploited, time_based, data_extracted, callback_received, error_based, blind_confirmed, reflected, authenticated, manual_verified", Required: true},
			{Name: "impact", Description: "Real-world impact assessment", Required: false},
			{Name: "target", Description: "Target URL/host", Required: false},
			{Name: "endpoint", Description: "Affected endpoint", Required: false},
			{Name: "method", Description: "HTTP method", Required: false},
			{Name: "cve", Description: "CVE identifier if known", Required: false},
			{Name: "cvss", Description: "CVSS 3.1 base score (0.0-10.0). MUST match severity: critical=9.0-10.0, high=7.0-8.9, medium=4.0-6.9, low=0.1-3.9, info=0.0", Required: true},
			{Name: "cvss_vector", Description: "CVSS 3.1 vector string, e.g. CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H. Components: AV(Attack Vector):N/A/L/P, AC(Attack Complexity):L/H, PR(Privileges Required):N/L/H, UI(User Interaction):N/R, S(Scope):U/C, C(Confidentiality):N/L/H, I(Integrity):N/L/H, A(Availability):N/L/H", Required: false},
			{Name: "technical_analysis", Description: "Technical details of the vulnerability", Required: false},
			{Name: "poc_description", Description: "Step-by-step PoC description", Required: false},
			{Name: "poc_script_code", Description: "Reproducible PoC code (curl, python, etc.)", Required: false},
			{Name: "remediation_steps", Description: "Remediation recommendations", Required: false},
			{Name: "cwe_id", Description: "CWE identifier if known, e.g. CWE-79 for XSS, CWE-89 for SQLi, CWE-78 for command injection", Required: false},
			{Name: "owasp", Description: "OWASP Top 10 (2021) category if known, e.g. A03 for Injection, A01 for Broken Access Control", Required: false},
		},
		Execute: func(args map[string]string) (tools.Result, error) {
			return reportVulnForRegistry(r, args)
		},
	})
}

// reportVulnForRegistry resolves the correct store via the registry's ScanContextID.
func reportVulnForRegistry(reg *tools.Registry, args map[string]string) (tools.Result, error) {
	return reportVulnWithContextID(reg.GetScanContextID(), args)
}

// reportVuln is the backward-compatible version using scanctx.Default().
//
//lint:ignore U1000 kept as a package-level compatibility wrapper for callers in this package.
func reportVuln(args map[string]string) (tools.Result, error) {
	return reportVulnWithContextID(scanctx.Default().ID, args)
}

func reportVulnWithContextID(contextID string, args map[string]string) (tools.Result, error) {
	severity := strings.ToLower(strings.TrimSpace(args["severity"]))
	proof := strings.TrimSpace(args["exploitation_proof"])
	method := strings.ToLower(strings.TrimSpace(args["verification_method"]))
	title := strings.TrimSpace(args["title"])
	target := strings.TrimSpace(args["target"])
	endpoint := strings.TrimSpace(args["endpoint"])

	// ── Gate 0: Fast duplicate check before spending effort on report validation ──
	// This is repeated under the write lock just before append to close races.
	store := getStoreByID(contextID)
	store.mu.RLock()
	if existing, msg, ok := findDuplicateVulnerability(store.vulns, title, args["description"], target, endpoint); ok {
		store.mu.RUnlock()
		return duplicateResult(existing, msg), nil
	}
	store.mu.RUnlock()

	// ── Gate 1: Validate verification method ──
	if method == "" || !validVerificationMethods[method] {
		return tools.Result{
			Output: fmt.Sprintf("❌ REJECTED: Invalid verification_method '%s'. Must be one of: %s\n\nYou must EXPLOIT the vulnerability first, then report with the correct verification method.",
				method, formatValidMethods()),
		}, nil
	}

	// ── Gate 2: Require exploitation proof for medium+ severity ──
	isHighSeverity := severity == "critical" || severity == "high" || severity == "medium"
	if isHighSeverity && (proof == "" || len(proof) < 20) {
		return tools.Result{
			Output: fmt.Sprintf(`❌ REJECTED: '%s' reported as %s but has NO exploitation proof.

XALGORIX RULE: You MUST exploit the vulnerability BEFORE reporting it.

Required steps:
1. You found a potential %s → Good, but not enough to report.
2. Now EXPLOIT it safely — extract data, trigger the payload, confirm the behavior.
3. Paste the ACTUAL OUTPUT of exploitation into 'exploitation_proof'.
4. Then call report_vulnerability again with the proof.

If you cannot exploit it, downgrade severity to 'info' and report as informational.`,
				title, strings.ToUpper(severity), title),
		}, nil
	}

	// ── Gate 3: Check for common false positive patterns ──
	if rejection := checkFalsePositive(title, args["description"], severity, proof); rejection != "" {
		return tools.Result{Output: rejection}, nil
	}

	// ── Gate 4: Smart Deduplication — same vuln type on same endpoint = duplicate ──
	store = getStoreByID(contextID)
	store.mu.RLock()
	if existing, msg, ok := findDuplicateVulnerability(store.vulns, title, args["description"], target, endpoint); ok {
		store.mu.RUnlock()
		return duplicateResult(existing, msg), nil
	}
	store.mu.RUnlock()

	// ── Gate 5: Severity classification — enforce max severity per vuln type ──
	originalSeverity := ""
	if cappedSev, reason := classifySeverity(title, args["description"], severity, proof); cappedSev != severity {
		originalSeverity = severity
		severity = cappedSev
		_ = reason // will be included in output message below
	}

	// ── Auto-downgrade: weak proof for high severity ──
	// Drop by one severity level (not nuclear to "info") so CVSS enforcement
	// can still correct it. E.g. high → medium, critical → high.
	if originalSeverity == "" && isHighSeverity && !hasStrongEvidence(severity, proof, args["description"]) {
		originalSeverity = severity
		switch severity {
		case "critical":
			severity = "high"
		case "high":
			severity = "medium"
		case "medium":
			severity = "low"
		default:
			severity = "info"
		}
	}

	var cvss float64
	if c := args["cvss"]; c != "" {
		_, _ = fmt.Sscanf(c, "%f", &cvss)
	}
	cvssVector := strings.TrimSpace(args["cvss_vector"])

	// ── Gate 6: CVSS-to-Severity enforcement (HackerOne standard) ──
	// If CVSS was provided, ensure severity matches the HackerOne CVSS ranges.
	// CVSS is authoritative: Critical=9.0-10.0, High=7.0-8.9, Medium=4.0-6.9, Low=0.1-3.9, None=0.0
	// This gate overrides all prior adjustments — the CVSS score is the source of truth.
	if cvss > 0 {
		cvssSeverity := severityFromCVSS(cvss)
		if severityRank[severity] > severityRank[cvssSeverity] {
			// Severity label is higher than what CVSS justifies → downgrade
			if originalSeverity == "" {
				originalSeverity = severity
			}
			severity = cvssSeverity
		} else if severityRank[severity] < severityRank[cvssSeverity] {
			// Severity label is lower than CVSS justifies → upgrade to match
			if originalSeverity == "" {
				originalSeverity = severity
			}
			severity = cvssSeverity
		}
	}

	// If no CVSS provided, auto-assign a default CVSS based on severity
	if cvss == 0 {
		switch severity {
		case "critical":
			cvss = 9.5
		case "high":
			cvss = 8.0
		case "medium":
			cvss = 5.5
		case "low":
			cvss = 2.5
		default:
			cvss = 0.0
		}
	}

	store = getStoreByID(contextID) // re-resolve in case of race
	store.mu.Lock()
	if existing, msg, ok := findDuplicateVulnerability(store.vulns, title, args["description"], target, endpoint); ok {
		store.mu.Unlock()
		return duplicateResult(existing, msg), nil
	}

	vuln := Vulnerability{
		ID:                 fmt.Sprintf("XALG-%d", len(store.vulns)+1),
		Title:              title,
		Severity:           severity,
		OriginalSeverity:   originalSeverity,
		Description:        args["description"],
		Impact:             args["impact"],
		Target:             target,
		Endpoint:           endpoint,
		Method:             args["method"],
		CVE:                args["cve"],
		CWE:                strings.TrimSpace(args["cwe_id"]),
		OWASP:              strings.TrimSpace(args["owasp"]),
		CVSS:               cvss,
		CVSSVector:         cvssVector,
		TechnicalAnalysis:  args["technical_analysis"],
		PoCDescription:     args["poc_description"],
		PoCScript:          args["poc_script_code"],
		ExploitationProof:  proof,
		VerificationMethod: method,
		Verified:           proof != "" && method != "",
		Remediation:        args["remediation_steps"],
		Timestamp:          time.Now().Format(time.RFC3339),
	}

	store.vulns = append(store.vulns, vuln)
	store.mu.Unlock()

	// Panic-safe persistence: if this context is a child of a wildcard parent,
	// promote the vuln into the parent immediately so an agent panic before
	// MergeVulnsToContext at session finalization does not lose it.
	promoteIfChildOfWildcard(contextID, vuln.ID)

	msg := fmt.Sprintf("✅ Vulnerability reported: [%s] %s (%s | CVSS %.1f) — Verified: %v", vuln.ID, vuln.Title, strings.ToUpper(vuln.Severity), vuln.CVSS, vuln.Verified)
	if originalSeverity != "" {
		if cvss > 0 {
			msg += fmt.Sprintf("\n⚠️ SEVERITY ADJUSTED from %s → %s (CVSS %.1f = %s per HackerOne standards)", strings.ToUpper(originalSeverity), strings.ToUpper(severity), cvss, strings.ToUpper(severityFromCVSS(cvss)))
		} else {
			msg += fmt.Sprintf("\n⚠️ SEVERITY ADJUSTED from %s → %s", strings.ToUpper(originalSeverity), strings.ToUpper(severity))
		}
	}

	return tools.Result{
		Output:   msg,
		Metadata: map[string]any{"vuln_id": vuln.ID, "verified": vuln.Verified},
	}, nil
}

func duplicateResult(existing Vulnerability, msg string) tools.Result {
	return tools.Result{
		Output: msg,
		Metadata: map[string]any{
			"duplicate":        true,
			"existing_vuln_id": existing.ID,
		},
	}
}

func findDuplicateVulnerability(existing []Vulnerability, title, description, target, endpoint string) (Vulnerability, string, bool) {
	normalizedTitle := normalizeFindingText(title)
	normalizedTarget := normalizeEndpoint(target)
	normalizedEndpoint := normalizeEndpoint(endpoint)
	vulnType := extractVulnType(title, description)

	for _, vuln := range existing {
		existingTitle := normalizeFindingText(vuln.Title)
		existingTarget := normalizeEndpoint(vuln.Target)
		existingEndpoint := normalizeEndpoint(vuln.Endpoint)
		existingType := extractVulnType(vuln.Title, vuln.Description)
		sameTarget := normalizedTarget == existingTarget

		// Exact finding match after trimming/case normalization.
		if sameTarget && normalizedTitle != "" && normalizedTitle == existingTitle && normalizedEndpoint == existingEndpoint {
			return vuln, fmt.Sprintf("⚠️ DUPLICATE: '%s' at endpoint '%s' already reported as %s. Skipping.", title, endpoint, vuln.ID), true
		}

		// Same vulnerability class on the same normalized endpoint.
		if sameTarget && vulnType != "" && vulnType == existingType && normalizedEndpoint != "" && normalizedEndpoint == existingEndpoint {
			return vuln, fmt.Sprintf("⚠️ DUPLICATE: Same vulnerability type '%s' already reported on endpoint '%s' as %s ('%s'). Skipping.\nIf this is genuinely different, use a distinct endpoint or describe how it differs.",
				vulnType, endpoint, vuln.ID, vuln.Title), true
		}
	}

	return Vulnerability{}, "", false
}

// checkFalsePositive detects common false positive patterns and rejects them.
func checkFalsePositive(title, description, severity, proof string) string {
	lower := strings.ToLower(title + " " + description)
	isHighSev := severity == "critical" || severity == "high" || severity == "medium"

	// Pattern 1: Missing security headers reported as vulnerability
	headerKeywords := []string{"missing header", "x-frame-options", "x-content-type", "content-security-policy",
		"strict-transport", "x-xss-protection", "referrer-policy", "permissions-policy", "hsts"}
	for _, kw := range headerKeywords {
		if strings.Contains(lower, kw) && isHighSev {
			return fmt.Sprintf("❌ REJECTED: Missing security headers are INFORMATIONAL, not %s. Re-report as severity 'info' if needed.", strings.ToUpper(severity))
		}
	}

	// Pattern 2: Version/technology disclosure
	disclosureKeywords := []string{"version disclosure", "server header", "x-powered-by", "technology disclosure",
		"software version", "banner grabbing"}
	for _, kw := range disclosureKeywords {
		if strings.Contains(lower, kw) && isHighSev {
			return "❌ REJECTED: Version/technology disclosure is INFORMATIONAL unless you can exploit a specific CVE. Provide CVE + exploitation proof, or re-report as 'info'."
		}
	}

	// Pattern 3: Scanner-only findings without manual verification
	scannerKeywords := []string{"nuclei detected", "nuclei found", "scanner reported", "automated scan found",
		"wpscan found", "nmap detected"}
	for _, kw := range scannerKeywords {
		if strings.Contains(lower, kw) && proof == "" {
			return "❌ REJECTED: Scanner-only findings require MANUAL VERIFICATION. Run the scanner, then manually exploit the finding to confirm it. Paste the exploitation output as proof."
		}
	}

	// Pattern 4: CORS without exploitation proof
	if strings.Contains(lower, "cors") && isHighSev {
		corsProofKeywords := []string{"cookie", "token", "session", "steal", "extract", "hijack", "javascript", "xmlhttprequest", "fetch("}
		hasExploitProof := false
		lowerProof := strings.ToLower(proof)
		for _, kw := range corsProofKeywords {
			if strings.Contains(lowerProof, kw) {
				hasExploitProof = true
				break
			}
		}
		if !hasExploitProof {
			return "❌ REJECTED: CORS misconfiguration alone is INFORMATIONAL. To report as medium+, you must demonstrate cookie/token theft via CORS (provide PoC JavaScript that exfiltrates data). Otherwise re-report as 'info'."
		}
	}

	// Pattern 5: Open redirect without chaining
	if strings.Contains(lower, "open redirect") && isHighSev {
		chainKeywords := []string{"oauth", "token", "ssrf", "phishing", "chain", "exfiltrate", "steal"}
		hasChain := false
		lowerProof := strings.ToLower(proof + " " + description)
		for _, kw := range chainKeywords {
			if strings.Contains(lowerProof, kw) {
				hasChain = true
				break
			}
		}
		if !hasChain {
			return "❌ REJECTED: Open redirect alone is INFORMATIONAL. To report as medium+, chain it with OAuth token theft, SSRF, or demonstrate real impact. Otherwise re-report as 'info'."
		}
	}

	// Pattern 6: SSL/TLS issues (weak ciphers, old TLS versions)
	sslKeywords := []string{"ssl", "tls", "cipher", "certificate", "sweet32", "poodle", "heartbleed", "beast", "crime"}
	for _, kw := range sslKeywords {
		if strings.Contains(lower, kw) {
			return "❌ REJECTED: SSL/TLS configuration issues (weak ciphers, old versions) are OUT OF SCOPE. Do not report them."
		}
	}

	// Pattern 7: DNS configuration issues (SPF, DMARC, TXT)
	dnsKeywords := []string{"spf", "dmarc", "dkim", "domain-based message authentication", "sender policy framework", "txt record", "email spoofing"}
	for _, kw := range dnsKeywords {
		if strings.Contains(lower, kw) {
			return "❌ REJECTED: DNS and email configuration issues (SPF, DMARC, TXT, DKIM) are OUT OF SCOPE. Do not report them."
		}
	}

	// Pattern 8: CSV injection (almost always Informative on HackerOne)
	csvKeywords := []string{"csv injection", "formula injection", "spreadsheet injection", "csv formula", "dde injection", "excel injection"}
	for _, kw := range csvKeywords {
		if strings.Contains(lower, kw) && isHighSev {
			return "❌ REJECTED: CSV/formula injection is almost always marked INFORMATIVE on HackerOne. It requires victim action (opening file + enabling macros). Re-report as 'low' or 'info' at most."
		}
	}

	// Pattern 9: Clickjacking without exploitation proof
	if strings.Contains(lower, "clickjacking") || strings.Contains(lower, "click jacking") || strings.Contains(lower, "ui redressing") {
		if isHighSev {
			return "❌ REJECTED: Clickjacking is LOW severity (CVSS 2.0-3.9) per HackerOne. To report as medium+, you must demonstrate a sensitive state-changing action that can be performed via the iframe PoC (e.g., delete account, change email). Re-report as 'low'."
		}
	}

	// Pattern 10: Directory listing without sensitive file access
	if strings.Contains(lower, "directory listing") || strings.Contains(lower, "directory index") || strings.Contains(lower, "autoindex") {
		lowerProof := strings.ToLower(proof)
		sensitiveFileEvidence := []string{"password", "credential", "secret", "key", "token", "config", ".env", "database", "backup", ".sql", ".bak"}
		hasSensitive := false
		for _, kw := range sensitiveFileEvidence {
			if strings.Contains(lowerProof, kw) {
				hasSensitive = true
				break
			}
		}
		if !hasSensitive && isHighSev {
			return "❌ REJECTED: Directory listing alone is INFORMATIONAL unless sensitive files (credentials, configs, backups) are exposed AND accessed. Show the actual sensitive file contents in your proof."
		}
	}

	// Pattern 11: TRACE/OPTIONS HTTP method enabled
	traceKeywords := []string{"trace method", "trace enabled", "options method", "http method enabled", "http verb"}
	for _, kw := range traceKeywords {
		if strings.Contains(lower, kw) {
			return "❌ REJECTED: TRACE/OPTIONS methods enabled is INFORMATIONAL. Modern browsers block cross-site TRACE (XST), making this unexploitable. Do not report."
		}
	}

	// Pattern 12: Analytics API writeKey "bypass" — these are public client-side tokens by design
	analyticsKeywords := []string{"writekey", "write_key", "write key", "analytics key", "segment key", "analytics api"}
	analyticsEndpoints := []string{"/v1/i", "/v1/t", "/v1/p", "/v1/batch", "/v1/identify", "/v1/track", "/v1/page", "/v1/screen", "/v1/group", "/v1/alias"}
	isAnalyticsFP := false
	for _, kw := range analyticsKeywords {
		if strings.Contains(lower, kw) {
			isAnalyticsFP = true
			break
		}
	}
	if !isAnalyticsFP {
		for _, ep := range analyticsEndpoints {
			if strings.Contains(lower, ep) {
				isAnalyticsFP = true
				break
			}
		}
	}
	if isAnalyticsFP && (strings.Contains(lower, "analytics") || strings.Contains(lower, "validation") || strings.Contains(lower, "writekey") || strings.Contains(lower, "write_key") || strings.Contains(lower, "write key")) {
		return "❌ REJECTED: Analytics API writeKey bypass is NOT a vulnerability. writeKeys are PUBLIC client-side tokens shipped in JavaScript (Segment, Amplitude, Mixpanel, etc.). They are designed to be exposed. Bug bounty programs mark this as N/A or Informational. Do not report."
	}

	// Pattern 13: Rate limiting / brute force — informational EXCEPT on sensitive endpoints
	rateLimitKeywords := []string{"rate limit", "rate-limit", "no rate limit", "brute force", "brute-force",
		"account lockout", "missing rate limit", "unlimited requests", "no lockout", "login throttling"}
	for _, kw := range rateLimitKeywords {
		if strings.Contains(lower, kw) && isHighSev {
			// Exception: rate limiting on sensitive/auth endpoints is a real vuln
			if !isSensitiveEndpointContext(lower, strings.ToLower(proof)) {
				return "❌ REJECTED: Missing rate limiting / brute force is INFORMATIONAL on most endpoints. Re-report as 'info' — unless this is on a sensitive endpoint (login, password reset, OTP, 2FA, signup). If so, mention the sensitive endpoint clearly in the title/description."
			}
		}
	}

	// Pattern 14: Success response without actual impact — APIs returning success:true
	if strings.Contains(lower, "success") && strings.Contains(lower, "true") &&
		(strings.Contains(lower, "any value") || strings.Contains(lower, "arbitrary") || strings.Contains(lower, "without validation")) {
		// Check if proof shows actual data modification or access
		lowerProof := strings.ToLower(proof)
		hasRealImpact := false
		impactWords := []string{"admin access", "modified", "deleted", "created user", "escalat", "bypass", "account", "password", "database"}
		for _, iw := range impactWords {
			if strings.Contains(lowerProof, iw) {
				hasRealImpact = true
				break
			}
		}
		if !hasRealImpact && isHighSev {
			return "❌ REJECTED: API returning success:true without input validation is NOT automatically a vulnerability. You must demonstrate ACTUAL IMPACT — data was modified, accounts were affected, or access was gained. A success response alone proves nothing. Re-report as 'info' with real impact proof, or move on."
		}
	}

	// Pattern 15: Client-side JavaScript config disclosure — PUBLIC_ENV, Sentry DSN, etc.
	// These are intentionally public client-side configurations, not secrets.
	jsConfigKeywords := []string{"sentry dsn", "public_env", "publicenv", "public env",
		"client-side javascript", "client side javascript", "javascript source",
		"next_public_", "react_app_", "vite_", "nuxt_public_",
		"window.__singletons", "window.__next", "window.__nuxt",
		"bundled javascript", "js chunk", "js bundle", "webpack chunk",
		"/_next/static", "/_nuxt/", "/static/js/",
		"application version", "app version"}
	jsConfigHits := 0
	for _, kw := range jsConfigKeywords {
		if strings.Contains(lower, kw) {
			jsConfigHits++
		}
	}
	// If 2+ JS config keywords match AND the "proof" is just viewing source/devtools
	if jsConfigHits >= 2 && isHighSev {
		lowerProof := strings.ToLower(proof)
		realExploitKeywords := []string{"rce", "shell", "admin access", "account takeover", "database",
			"password", "credential", "private key", "secret key", "aws_secret", "payment", "credit card"}
		hasRealExploit := false
		for _, ek := range realExploitKeywords {
			if strings.Contains(lowerProof, ek) {
				hasRealExploit = true
				break
			}
		}
		if !hasRealExploit {
			return "❌ REJECTED: Client-side JavaScript configuration (Sentry DSN, PUBLIC_ENV, API endpoints, app version) is NOT a vulnerability. These are PUBLIC client-side values shipped intentionally in JS bundles. Sentry DSNs are public by design. NEXT_PUBLIC_* vars are meant to be public. Bug bounty programs mark this as Informational or N/A. Do not report."
		}
	}

	// Pattern 16: Sentry DSN specifically — always public, never a vuln
	if strings.Contains(lower, "sentry") && (strings.Contains(lower, "dsn") || strings.Contains(lower, "ingest.sentry.io")) {
		return "❌ REJECTED: Sentry DSN is a PUBLIC client-side key designed to be embedded in JavaScript. It only allows sending error reports — no read access, no data extraction. This is NOT a vulnerability. Do not report."
	}

	// Pattern 17: Generic "information found in JavaScript source" without real impact
	if (strings.Contains(lower, "javascript") || strings.Contains(lower, "js source") || strings.Contains(lower, "source code")) &&
		(strings.Contains(lower, "information disclosure") || strings.Contains(lower, "sensitive information") || strings.Contains(lower, "exposed in")) {
		lowerProof := strings.ToLower(proof)
		// Only reject if proof is just "view source" style — not actual secret leakage
		if !strings.Contains(lowerProof, "password") && !strings.Contains(lowerProof, "private key") &&
			!strings.Contains(lowerProof, "aws_secret") && !strings.Contains(lowerProof, "database_url") &&
			isHighSev {
			return "❌ REJECTED: Finding configuration in client-side JavaScript is expected behavior — frontend apps MUST include API endpoints, service URLs, and public keys to function. This is only a vulnerability if ACTUAL SECRETS (passwords, private keys, database credentials) are exposed. Sentry DSNs, API base URLs, and app versions are NOT secrets."
		}
	}

	return ""
}

// hasStrongEvidence checks if the proof actually contains meaningful exploitation evidence.
// Uses impact-based analysis rather than just keyword matching.
func hasStrongEvidence(severity, proof, description string) bool {
	if proof == "" {
		return false
	}

	lowerProof := strings.ToLower(proof)
	lowerDesc := strings.ToLower(description)
	combined := lowerProof + " " + lowerDesc

	// Severity-specific keywords
	keywords, ok := evidenceKeywords[severity]
	if !ok {
		return true // low/info don't need strong evidence
	}
	for _, kw := range keywords {
		if strings.Contains(lowerProof, kw) {
			return true
		}
	}

	// Impact-based indicators (works for all severities)
	impactIndicators := []string{
		// Data exfiltration proof
		"extracted", "leaked", "exposed", "dumped", "obtained",
		"retrieved", "exfiltrated", "downloaded", "accessed",
		// Concrete data in proof
		"root:", "uid=", "gid=", "password", "passwd", "shadow",
		"select ", "union ", "from ", "where ",
		"alert(", "<script", "onerror=", "onload=", "document.cookie",
		"etc/passwd", "etc/shadow", "proc/self",
		"internal", "metadata", "169.254", "127.0.0.1", "localhost",
		// Response/output evidence
		"response:", "output:", "result:", "HTTP/",
		"200 ok", "302 found", "401 unauthorized",
		// Auth/session indicators
		"bearer ", "jwt", "session_id", "auth_token", "access_token",
		"set-cookie", "authorization:",
		// PII evidence
		"@", "email", "phone", "address", "name:",
		"user_id", "account", "profile",
		// Timing/blind evidence
		"sleep(", "delay", "benchmark", "elapsed", "seconds",
		"time-based", "response time",
		// Callback evidence
		"callback", "dns query", "http request received", "burp collaborator",
		"interact.sh", "oast", "webhook",
	}
	for _, ind := range impactIndicators {
		if strings.Contains(lowerProof, ind) {
			return true
		}
	}

	// If proof references concrete impact in the description
	impactPhrases := []string{"account takeover", "data breach", "privilege escalation",
		"arbitrary code", "remote execution", "unauthorized access",
		"sensitive data", "personal information", "financial", "payment",
		"credential", "authentication bypass", "session hijack"}
	for _, phrase := range impactPhrases {
		if strings.Contains(combined, phrase) {
			return true
		}
	}

	// If proof is substantial (>150 chars) and contains URLs or structured data, likely real
	if len(proof) > 150 && (strings.Contains(lowerProof, "http") || strings.Contains(lowerProof, "{") || strings.Contains(lowerProof, "<")) {
		return true
	}

	return false
}

func formatValidMethods() string {
	methods := make([]string, 0, len(validVerificationMethods))
	for m := range validVerificationMethods {
		methods = append(methods, m)
	}
	return strings.Join(methods, ", ")
}

// GetVulnerabilities returns all reported vulnerabilities for the active scan context.
func GetVulnerabilities() []Vulnerability {
	store := getStore()
	store.mu.RLock()
	defer store.mu.RUnlock()
	result := make([]Vulnerability, len(store.vulns))
	copy(result, store.vulns)
	return result
}

// GetVulnerabilitiesForContext returns vulns for a specific context ID.
func GetVulnerabilitiesForContext(contextID string) []Vulnerability {
	store := getStoreForContext(contextID)
	store.mu.RLock()
	defer store.mu.RUnlock()
	result := make([]Vulnerability, len(store.vulns))
	copy(result, store.vulns)
	return result
}

// ResetVulnerabilities clears the vulnerability list for the active scan context.
func ResetVulnerabilities() {
	store := getStore()
	store.mu.Lock()
	defer store.mu.Unlock()
	store.vulns = nil
}

// ResetVulnerabilitiesForContext clears vulns for a specific context ID.
func ResetVulnerabilitiesForContext(contextID string) {
	store := getStoreForContext(contextID)
	store.mu.Lock()
	defer store.mu.Unlock()
	store.vulns = nil
}

// CleanupContext removes the store for a context that has been deactivated.
// Also removes any parent-context mapping registered for this context so the
// parentMap does not leak entries across scan lifecycles.
func CleanupContext(contextID string) {
	storesMu.Lock()
	delete(stores, contextID)
	storesMu.Unlock()

	parentMap.Lock()
	delete(parentMap.m, contextID)
	parentMap.Unlock()
}

// PromoteToParent copies a single vulnerability from the child reporting
// context into the parent's reporting context if it isn't already there.
//
// Idempotent: if the parent already contains a vuln with the same ID, this
// is a no-op. Safe to call after every successful report_vulnerability so
// the parent aggregate stays current and survives a child panic before
// the broader MergeVulnsToContext can run at session finalization.
//
// Validates: Property 4 (panic-safe persistence) of the
// findings-consistency-and-pagination spec.
func PromoteToParent(childContextID, parentContextID, vulnID string) {
	if childContextID == "" || parentContextID == "" || vulnID == "" {
		return
	}
	if childContextID == parentContextID {
		return
	}

	src := getStoreByID(childContextID)
	src.mu.RLock()
	var found *Vulnerability
	for i := range src.vulns {
		if src.vulns[i].ID == vulnID {
			v := src.vulns[i]
			found = &v
			break
		}
	}
	src.mu.RUnlock()
	if found == nil {
		return
	}

	dst := getStoreByID(parentContextID)
	dst.mu.Lock()
	defer dst.mu.Unlock()
	for _, v := range dst.vulns {
		if v.ID == vulnID {
			return // already present
		}
	}
	// Skip semantic duplicates too, mirroring MergeVulnsToContext's behavior.
	if _, _, dup := findDuplicateVulnerability(dst.vulns, found.Title, found.Description, found.Target, found.Endpoint); dup {
		return
	}
	dst.vulns = append(dst.vulns, *found)
}

// promoteIfChildOfWildcard looks up the parent context registered for the
// child via SetParentContext and forwards to PromoteToParent. No-op if no
// parent has been declared for childCtxID.
func promoteIfChildOfWildcard(childCtxID, vulnID string) {
	parent := GetParentContext(childCtxID)
	if parent == "" {
		return
	}
	PromoteToParent(childCtxID, parent, vulnID)
}

// MergeVulnsToContext copies all vulnerabilities from srcContextID into dstContextID.
// Semantic duplicates are skipped. ID collisions are renumbered because each
// child context starts its own XALG-1 sequence.
func MergeVulnsToContext(srcContextID, dstContextID string) int {
	if srcContextID == "" || dstContextID == "" || srcContextID == dstContextID {
		return 0
	}

	// Read source vulns
	srcStore := getStoreForContext(srcContextID)
	srcStore.mu.RLock()
	srcVulns := make([]Vulnerability, len(srcStore.vulns))
	copy(srcVulns, srcStore.vulns)
	srcStore.mu.RUnlock()

	if len(srcVulns) == 0 {
		return 0
	}

	// Merge into destination, skipping duplicates
	dstStore := getStoreForContext(dstContextID)
	dstStore.mu.Lock()
	defer dstStore.mu.Unlock()

	seenIDs := make(map[string]bool, len(dstStore.vulns))
	for _, v := range dstStore.vulns {
		seenIDs[v.ID] = true
	}

	added := 0
	for _, v := range srcVulns {
		if _, _, duplicate := findDuplicateVulnerability(dstStore.vulns, v.Title, v.Description, v.Target, v.Endpoint); duplicate {
			continue
		}
		if seenIDs[v.ID] {
			nextID := len(dstStore.vulns) + 1
			for {
				v.ID = fmt.Sprintf("XALG-%d", nextID)
				if !seenIDs[v.ID] {
					break
				}
				nextID++
			}
		}
		dstStore.vulns = append(dstStore.vulns, v)
		seenIDs[v.ID] = true
		added++
	}
	return added
}

// GetVulnsJSON returns vulnerabilities as JSON for the active scan context.
func GetVulnsJSON() string {
	store := getStore()
	store.mu.RLock()
	defer store.mu.RUnlock()
	data, err := json.Marshal(store.vulns)
	if err != nil {
		return fmt.Sprintf(`{"error": "failed to marshal vulnerabilities: %s"}`, err.Error())
	}
	return string(data)
}

// severityRank maps severity strings to numeric levels for comparison.
var severityRank = map[string]int{
	"none": 0, "info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4,
}

// severityFromCVSS returns the HackerOne-standard severity label for a CVSS 3.1 score.
// Critical: 9.0-10.0, High: 7.0-8.9, Medium: 4.0-6.9, Low: 0.1-3.9, None/Info: 0.0
func severityFromCVSS(cvss float64) string {
	switch {
	case cvss >= 9.0:
		return "critical"
	case cvss >= 7.0:
		return "high"
	case cvss >= 4.0:
		return "medium"
	case cvss > 0:
		return "low"
	default:
		return "info"
	}
}

// classifySeverity enforces maximum severity caps based on vulnerability type.
// Returns the (possibly capped) severity and a reason if it was changed.
func classifySeverity(title, description, severity, proof string) (string, string) {
	rank, ok := severityRank[severity]
	if !ok || rank <= 1 {
		return severity, "" // info/low — no need to cap further
	}

	lower := strings.ToLower(title + " " + description)
	lowerProof := strings.ToLower(proof)

	// Normalize to canonical vuln type for consistent classification
	// regardless of how the LLM titles the finding. This prevents
	// "Stored XSS in CRM" and "Contact Injection / Stored XSS" from
	// getting different severity caps.
	vulnType := extractVulnType(title, description)

	// ── INFO-only findings (max severity: info) ──
	infoOnlyPatterns := []struct {
		keywords []string
		reason   string
	}{
		{[]string{"missing header", "security header", "x-frame-options missing", "csp missing",
			"hsts missing", "x-content-type missing", "referrer-policy missing",
			"permissions-policy missing", "x-xss-protection missing"},
			"Missing security headers are informational — not directly exploitable"},
		{[]string{"version disclosure", "server version", "software version", "banner grabbing",
			"x-powered-by", "server header disclosure", "technology detected"},
			"Version/technology disclosure is informational unless tied to a specific exploited CVE"},
		{[]string{"directory listing", "directory index", "index of /"},
			"Directory listing is informational unless sensitive files are exposed and accessed"},
		{[]string{"self-xss", "self xss"},
			"Self-XSS only affects the user's own session — not exploitable against others"},
		{[]string{"debug mode", "debug enabled", "stack trace exposed", "verbose error"},
			"Debug/error disclosure is informational unless it leaks credentials or enables further exploitation"},
		{[]string{"robots.txt", "sitemap.xml", "crossdomain.xml"},
			"Configuration file disclosure is informational"},
		{[]string{"ssl weak", "tls weak", "weak cipher", "tls 1.0", "tls 1.1", "ssl certificate"},
			"SSL/TLS configuration issues are informational — not directly exploitable in practice"},
		{[]string{"email disclosure", "email address found", "email harvesting"},
			"Email disclosure is informational"},
		{[]string{"dns zone transfer", "zone transfer"},
			"DNS zone transfer is informational in most contexts"},
		{[]string{"writekey", "write_key", "write key", "analytics key", "segment key", "analytics api key"},
			"Analytics writeKeys are public client-side tokens — not a security vulnerability"},
		// NOTE: rate limit findings are handled separately below (low-cap with
		// sensitive-endpoint exception) instead of blanket info-only.
		{[]string{"sentry dsn", "ingest.sentry.io", "sentry.io/api"},
			"Sentry DSN is a public client-side key — not a vulnerability"},
		{[]string{"public_env", "next_public_", "react_app_", "window.__singletons"},
			"Client-side environment variables (PUBLIC_ENV, NEXT_PUBLIC_*) are public by design"},
	}

	for _, p := range infoOnlyPatterns {
		for _, kw := range p.keywords {
			if strings.Contains(lower, kw) {
				return "info", p.reason
			}
		}
	}

	// ── LOW-cap findings (max severity: low) — HackerOne standard ──
	lowCapPatterns := []struct {
		keywords  []string
		exception func() bool
		reason    string
	}{
		{[]string{"cors", "cross-origin resource sharing"},
			func() bool {
				// Exception: CORS + credential theft proof = allow higher severity
				theftKeywords := []string{"cookie", "token", "steal", "exfiltrate", "xmlhttprequest", "fetch(", "document.cookie"}
				for _, tk := range theftKeywords {
					if strings.Contains(lowerProof, tk) {
						return true
					}
				}
				return false
			},
			"CORS alone is low severity (CVSS 2.0-3.9) — needs proven cookie/token theft for higher"},
		{[]string{"clickjacking", "click jacking", "ui redressing"},
			nil,
			"Clickjacking is low severity (CVSS 2.0-3.9) per HackerOne — limited real-world impact"},
		{[]string{"cookie without httponly", "cookie missing httponly", "cookie flag", "cookie attribute", "missing secure flag"},
			nil,
			"Missing cookie flags alone are low severity (CVSS 2.0-3.9)"},
		{[]string{"path disclosure", "full path", "internal path"},
			nil,
			"Internal path disclosure is low severity (CVSS 2.0-3.9)"},
		// Open redirect: HackerOne treats standalone open redirects as LOW
		{[]string{"open redirect", "url redirect", "unvalidated redirect"},
			func() bool {
				// Exception: redirect chained with OAuth/token theft = allow higher
				chainKeywords := []string{"oauth", "token", "ssrf", "chain", "steal", "authorization_code", "code="}
				for _, ck := range chainKeywords {
					if strings.Contains(lowerProof, ck) || strings.Contains(lower, ck) {
						return true
					}
				}
				return false
			},
			"Open redirect is low severity (CVSS 2.0-3.9) per HackerOne — needs OAuth/token chain for higher"},
		// CRLF: HackerOne treats as low unless chained
		{[]string{"crlf injection", "http response splitting"},
			func() bool {
				chainKeywords := []string{"cache poison", "xss", "session fixation", "header injection"}
				for _, ck := range chainKeywords {
					if strings.Contains(lowerProof, ck) || strings.Contains(lower, ck) {
						return true
					}
				}
				return false
			},
			"CRLF injection is low severity (CVSS 2.0-3.9) per HackerOne — needs cache poisoning or XSS chain for higher"},
		// Host header injection: low unless chained
		{[]string{"host header injection", "host header"},
			func() bool {
				chainKeywords := []string{"cache poison", "password reset", "email", "inject", "redirect"}
				for _, ck := range chainKeywords {
					if strings.Contains(lowerProof, ck) {
						return true
					}
				}
				return false
			},
			"Host header injection is low severity (CVSS 2.0-3.9) per HackerOne — needs password reset poisoning or cache poisoning chain for higher"},
		// Rate limiting: low unless on sensitive auth endpoints
		{[]string{"rate limit", "rate-limit", "no rate limit", "brute force", "brute-force",
			"account lockout", "missing rate limit", "unlimited requests", "no lockout"},
			func() bool {
				return isSensitiveEndpointContext(lower, lowerProof)
			},
			"Missing rate limiting is low severity (CVSS 2.0-3.9) on non-sensitive endpoints — on login/password-reset/OTP/2FA endpoints it can be higher"},
	}

	for _, p := range lowCapPatterns {
		for _, kw := range p.keywords {
			if strings.Contains(lower, kw) {
				if p.exception != nil && p.exception() {
					continue // exception met, allow higher severity
				}
				if rank > severityRank["low"] {
					return "low", p.reason
				}
			}
		}
	}

	// ── MEDIUM-cap findings (max severity: medium) — HackerOne standard ──
	medCapPatterns := []struct {
		keywords  []string
		exception func() bool
		reason    string
	}{
		{[]string{"reflected xss"},
			func() bool {
				// Exception: Reflected XSS → session hijack/ATO = allow high
				for _, kw := range []string{"account takeover", "session hijack", "cookie stolen", "admin access", "document.cookie"} {
					if strings.Contains(lowerProof, kw) {
						return true
					}
				}
				return false
			},
			"Reflected XSS is medium (CVSS 4.0-6.9) per HackerOne — needs proven session hijack for high"},
		{[]string{"dom xss", "dom-based xss"},
			func() bool {
				for _, kw := range []string{"account takeover", "session hijack", "cookie stolen", "admin access"} {
					if strings.Contains(lowerProof, kw) {
						return true
					}
				}
				return false
			},
			"DOM XSS is medium (CVSS 4.0-6.9) per HackerOne — needs proven session hijack for high"},
		{[]string{"csrf", "cross-site request forgery"},
			func() bool {
				// Exception: CSRF on critical action = allow high
				for _, kw := range []string{"password", "admin", "delete account", "transfer", "payment", "email change", "role change"} {
					if strings.Contains(lower, kw) || strings.Contains(lowerProof, kw) {
						return true
					}
				}
				return false
			},
			"CSRF is medium (CVSS 4.0-6.9) per HackerOne — needs critical action impact (password change, payment) for high"},
		{[]string{"information disclosure", "info disclosure", "sensitive data exposure"},
			func() bool {
				// Exception: PII/credentials leaked = allow high
				for _, kw := range []string{"password", "credential", "api key", "secret", "token", "pii", "ssn", "credit card"} {
					if strings.Contains(lowerProof, kw) {
						return true
					}
				}
				return false
			},
			"Information disclosure is medium (CVSS 4.0-6.9) per HackerOne — needs PII/credential exposure for high"},
	}

	for _, p := range medCapPatterns {
		for _, kw := range p.keywords {
			if strings.Contains(lower, kw) {
				if p.exception != nil && p.exception() {
					continue // exception met, allow higher severity
				}
				if rank > severityRank["medium"] {
					return "medium", p.reason
				}
			}
		}
	}

	// ── HIGH-cap findings (max severity: high) — HackerOne standard ──
	highCapPatterns := []struct {
		keywords  []string
		exception func() bool
		reason    string
	}{
		// Stored XSS: High on HackerOne unless it leads to mass ATO/RCE
		{[]string{"stored xss", "persistent xss"},
			func() bool {
				for _, kw := range []string{"admin", "rce", "mass", "worm", "all users", "account takeover"} {
					if strings.Contains(lowerProof, kw) {
						return true
					}
				}
				return false
			},
			"Stored XSS is high (CVSS 7.0-8.9) per HackerOne — needs admin access/mass ATO/RCE chain for critical"},
		// SSRF: High on HackerOne unless full internal access/cloud metadata
		{[]string{"ssrf", "server-side request forgery", "server side request forgery"},
			func() bool {
				for _, kw := range []string{"aws", "metadata", "169.254", "cloud", "credentials", "rce", "internal network", "full access"} {
					if strings.Contains(lowerProof, kw) {
						return true
					}
				}
				return false
			},
			"SSRF is high (CVSS 7.0-8.9) per HackerOne — needs cloud metadata/credential exposure or RCE for critical"},
		// IDOR: High on HackerOne unless mass data exposure
		{[]string{"idor", "insecure direct object"},
			func() bool {
				for _, kw := range []string{"all users", "mass", "database dump", "admin access", "full", "account takeover"} {
					if strings.Contains(lowerProof, kw) {
						return true
					}
				}
				return false
			},
			"IDOR is high (CVSS 7.0-8.9) per HackerOne — needs mass data dump or admin access for critical"},
		// File Inclusion: High unless RCE demonstrated
		{[]string{"file inclusion", "lfi", "local file inclusion", "path traversal", "directory traversal"},
			func() bool {
				for _, kw := range []string{"rce", "remote code", "shell", "/etc/shadow", "proc/self", "command execution"} {
					if strings.Contains(lowerProof, kw) {
						return true
					}
				}
				return false
			},
			"File inclusion is high (CVSS 7.0-8.9) per HackerOne — needs RCE or shadow file access for critical"},
		// Auth Bypass: High unless full admin access
		{[]string{"authentication bypass", "auth bypass", "login bypass"},
			func() bool {
				for _, kw := range []string{"admin", "root", "superuser", "full access", "all accounts"} {
					if strings.Contains(lowerProof, kw) {
						return true
					}
				}
				return false
			},
			"Auth bypass is high (CVSS 7.0-8.9) per HackerOne — needs admin/root access for critical"},
	}

	for _, p := range highCapPatterns {
		for _, kw := range p.keywords {
			if strings.Contains(lower, kw) {
				if p.exception != nil && p.exception() {
					continue // exception met, allow critical
				}
				if rank > severityRank["high"] {
					return "high", p.reason
				}
			}
		}
	}

	// ── vulnType-based fallback caps ──
	// If the keyword-based caps above didn't fire (e.g., the LLM titled the
	// finding "Contact Injection" instead of "Stored XSS"), apply caps based
	// on the canonical vuln type extracted from title + description. This
	// ensures consistent classification regardless of LLM title framing.
	switch vulnType {
	case "xss":
		// Distinguish stored vs reflected/DOM
		isStored := strings.Contains(lower, "stored") || strings.Contains(lower, "persistent") ||
			strings.Contains(lower, "stores") || strings.Contains(lower, "persist") ||
			strings.Contains(lower, "permanent") || strings.Contains(lower, "saved in")
		if isStored {
			// Stored XSS → high cap (same as highCapPatterns above)
			if rank > severityRank["high"] {
				return "high", "Stored XSS is high (CVSS 7.0-8.9) per HackerOne — needs admin access/mass ATO/RCE chain for critical"
			}
		} else {
			// Reflected/DOM/generic XSS → medium cap (same as medCapPatterns above)
			if rank > severityRank["medium"] {
				return "medium", "Reflected/DOM XSS is medium (CVSS 4.0-6.9) per HackerOne — needs session hijack proof for high"
			}
		}
	case "csrf":
		if rank > severityRank["medium"] {
			return "medium", "CSRF is medium (CVSS 4.0-6.9) per HackerOne — needs critical state change for high"
		}
	case "info_disclosure":
		if rank > severityRank["medium"] {
			return "medium", "Information disclosure is medium (CVSS 4.0-6.9) per HackerOne — needs PII/credential exposure for high"
		}
	case "ssrf":
		if rank > severityRank["high"] {
			return "high", "SSRF is high (CVSS 7.0-8.9) per HackerOne — needs cloud metadata/RCE for critical"
		}
	case "idor":
		if rank > severityRank["high"] {
			return "high", "IDOR is high (CVSS 7.0-8.9) per HackerOne — needs mass data dump for critical"
		}
	case "lfi":
		if rank > severityRank["high"] {
			return "high", "File inclusion is high (CVSS 7.0-8.9) per HackerOne — needs RCE for critical"
		}
	case "auth_bypass":
		if rank > severityRank["high"] {
			return "high", "Auth bypass is high (CVSS 7.0-8.9) per HackerOne — needs admin/root access for critical"
		}
	case "cors":
		if rank > severityRank["low"] {
			return "low", "CORS alone is low severity (CVSS 2.0-3.9) — needs proven cookie/token theft for higher"
		}
	case "open_redirect":
		if rank > severityRank["low"] {
			return "low", "Open redirect is low severity (CVSS 2.0-3.9) per HackerOne — needs OAuth/token chain for higher"
		}
	case "clickjacking":
		if rank > severityRank["low"] {
			return "low", "Clickjacking is low severity (CVSS 2.0-3.9) per HackerOne"
		}
	case "crlf":
		if rank > severityRank["low"] {
			return "low", "CRLF injection is low severity (CVSS 2.0-3.9) per HackerOne"
		}
	case "missing_header", "version_disclosure":
		return "info", "Missing headers/version disclosure are informational"
	}

	return severity, "" // no cap needed
}

// isSensitiveEndpointContext returns true when the title+description or proof
// text indicates the rate-limit issue targets a security-sensitive endpoint
// (login, password reset, OTP/2FA verification, signup, account recovery, etc.).
// These are areas where missing rate limiting can lead to credential stuffing,
// brute-force attacks, or OTP bypass — making the finding genuinely impactful.
func isSensitiveEndpointContext(lowerText, lowerProof string) bool {
	combined := lowerText + " " + lowerProof
	sensitiveKeywords := []string{
		// Authentication
		"login", "signin", "sign-in", "sign in", "authenticate",
		"authentication", "credential", "credential stuffing",
		// Password reset / recovery
		"password reset", "forgot password", "reset password",
		"password recovery", "account recovery", "reset token",
		"reset link",
		// OTP / 2FA / MFA
		"otp", "one-time password", "one time password",
		"2fa", "two-factor", "two factor", "mfa", "multi-factor",
		"multi factor", "verification code", "sms code",
		"totp", "authenticator code", "magic link",
		// Signup / registration
		"signup", "sign-up", "sign up", "registration", "register",
		"create account", "new account",
		// Email / phone verification
		"email verification", "phone verification", "verify email",
		"verify phone", "confirmation code",
		// Sensitive API endpoints
		"/auth", "/login", "/signin", "/signup", "/register",
		"/reset", "/forgot", "/otp", "/verify", "/2fa", "/mfa",
		"/token", "/session",
		// Payment / financial
		"payment", "checkout", "transaction", "purchase",
		"coupon", "promo code", "discount code", "gift card",
	}
	for _, kw := range sensitiveKeywords {
		if strings.Contains(combined, kw) {
			return true
		}
	}
	return false
}

// extractVulnType extracts a canonical vulnerability type from title/description
// for deduplication purposes. Returns empty string if type can't be determined.
func extractVulnType(title, description string) string {
	lower := strings.ToLower(title + " " + description)

	vulnTypes := []struct {
		typeName string
		keywords []string
	}{
		{"xss", []string{"xss", "cross-site scripting", "cross site scripting", "reflected xss", "stored xss", "dom xss", "script injection"}},
		{"sqli", []string{"sql injection", "sqli", "sql inject", "blind sql", "union select", "error-based sql"}},
		{"ssrf", []string{"ssrf", "server-side request forgery", "server side request forgery"}},
		{"idor", []string{"idor", "insecure direct object", "broken access control", "unauthorized access"}},
		{"lfi", []string{"local file inclusion", "lfi", "file inclusion", "path traversal", "directory traversal", "path disclosure", "physical path"}},
		{"rfi", []string{"remote file inclusion", "rfi"}},
		{"rce", []string{"remote code execution", "rce", "command injection", "os command", "code execution"}},
		{"csrf", []string{"csrf", "cross-site request forgery", "cross site request forgery"}},
		{"xxe", []string{"xxe", "xml external entity"}},
		{"open_redirect", []string{"open redirect", "url redirect", "unvalidated redirect"}},
		{"auth_bypass", []string{"authentication bypass", "auth bypass", "login bypass", "auth flow"}},
		{"info_disclosure", []string{"information disclosure", "info disclosure", "sensitive data exposure", "data leak", "api key", "credential leak", "password leak", "exposed secret", "token leak", "verbose error"}},
		{"missing_header", []string{"missing header", "security header", "x-frame-options", "content-security-policy", "hsts", "x-content-type"}},
		{"version_disclosure", []string{"version disclosure", "server header", "x-powered-by", "technology disclosure", "fingerprint"}},
		{"subdomain_takeover", []string{"subdomain takeover", "dangling dns", "unclaimed subdomain"}},
		{"clickjacking", []string{"clickjacking", "ui redressing"}},
		{"cors", []string{"cors", "cross-origin resource sharing", "cross origin"}},
		{"crlf", []string{"crlf injection", "http response splitting"}},
		{"ssti", []string{"ssti", "server-side template injection", "template injection"}},
		{"deserialization", []string{"deserialization", "insecure deserialization", "object injection"}},
	}

	for _, vt := range vulnTypes {
		for _, kw := range vt.keywords {
			if strings.Contains(lower, kw) {
				return vt.typeName
			}
		}
	}
	return ""
}

// normalizeEndpoint strips query params, fragments, and trailing slashes
// so "/api/search?q=test" and "/api/search?q=foo" match as the same endpoint.
func normalizeEndpoint(endpoint string) string {
	endpoint = strings.TrimSpace(endpoint)
	if endpoint == "" {
		return ""
	}

	// Strip query parameters
	if idx := strings.Index(endpoint, "?"); idx >= 0 {
		endpoint = endpoint[:idx]
	}
	// Strip fragment
	if idx := strings.Index(endpoint, "#"); idx >= 0 {
		endpoint = endpoint[:idx]
	}
	// Strip trailing slashes
	endpoint = strings.TrimRight(endpoint, "/")
	// Lowercase for consistent comparison
	return strings.ToLower(endpoint)
}

func normalizeFindingText(value string) string {
	return strings.Join(strings.Fields(strings.ToLower(strings.TrimSpace(value))), " ")
}
