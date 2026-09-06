package reporting

import (
	"strings"
	"testing"

	"github.com/xalgord/xalgorix/v4/internal/scanctx"
)

// TestReport_SalvagesMissingDescriptionAndSeverity verifies that a proven
// finding is NOT lost when the model omits the prose `description` and/or the
// `severity` field (a common small-model omission). description is synthesized
// from the title/proof, and severity is derived from cvss.
func TestReport_SalvagesMissingDescriptionAndSeverity(t *testing.T) {
	ctxID := "salvage-test-ctx"
	sc := scanctx.New(ctxID, "")
	scanctx.Activate(sc)
	defer scanctx.Deactivate(ctxID)

	args := map[string]string{
		"title":               "SQL Injection on GET /users/v1/name1 allows extraction of all user records",
		"exploitation_proof":  "Injected ' UNION SELECT username,password,3,4 FROM users-- ; response returned all users with plaintext passwords: name1:pass1, name2:pass2, admin:pass_admin",
		"verification_method": "data_extracted",
		"cvss":                "8.6",
		"cwe_id":              "CWE-89",
		"endpoint":            "/users/v1/name1",
		"method":              "GET",
		// NOTE: no `description`, no `severity` on purpose.
	}

	res, err := reportVulnWithContextID(ctxID, args)
	if err != nil {
		t.Fatalf("reportVulnWithContextID returned error: %v", err)
	}
	if strings.Contains(strings.ToUpper(res.Output), "REJECTED") ||
		strings.Contains(res.Output, "missing required parameter") {
		t.Fatalf("finding was rejected instead of salvaged: %s", res.Output)
	}

	vulns := getStoreByID(ctxID).vulns
	if len(vulns) != 1 {
		t.Fatalf("expected 1 recorded vuln, got %d (output=%s)", len(vulns), res.Output)
	}
	v := vulns[0]
	if strings.TrimSpace(v.Description) == "" {
		t.Errorf("description was not synthesized (empty)")
	}
	if v.Severity != "high" {
		t.Errorf("severity not derived from cvss 8.6: got %q want %q", v.Severity, "high")
	}
}
