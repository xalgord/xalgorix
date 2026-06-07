package skills

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/xalgord/xalgorix/v4/internal/tools"
)

// setupTestSkills creates a temporary skills directory with test files.
func setupTestSkills(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()

	// Create category directories
	categories := []string{"vulnerabilities", "protocols", "frameworks"}
	for _, cat := range categories {
		os.MkdirAll(filepath.Join(dir, cat), 0755)
	}

	// Create test skill files in new directory/SKILL.md format
	files := map[string]string{
		"vulnerabilities/sql_injection/SKILL.md": "# SQL Injection\nTest payloads...",
		"vulnerabilities/xss/SKILL.md":           "# XSS\nReflected payloads...",
		"protocols/graphql/SKILL.md":             "# GraphQL\nIntrospection...",
		"frameworks/django/SKILL.md":             "# Django\nDebug mode...",
	}
	for path, content := range files {
		os.MkdirAll(filepath.Join(dir, filepath.Dir(path)), 0755)
		os.WriteFile(filepath.Join(dir, path), []byte(content), 0644)
	}

	return dir
}

func TestReadSkill_Basic(t *testing.T) {
	dir := setupTestSkills(t)
	reg := tools.NewRegistry()
	Register(reg, "")

	fn := makeReadSkill(os.DirFS(dir))

	// Read existing skill
	result, err := fn(map[string]string{"name": "sql_injection"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(result.Output, "SQL Injection") {
		t.Errorf("expected SQL Injection content, got: %s", result.Output)
	}
}

func TestReadSkill_WithExtension(t *testing.T) {
	dir := setupTestSkills(t)
	fn := makeReadSkill(os.DirFS(dir))

	// Should work with .md extension too
	result, err := fn(map[string]string{"name": "sql_injection.md"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(result.Output, "SQL Injection") {
		t.Errorf("expected SQL Injection content, got: %s", result.Output)
	}
}

func TestReadSkill_DifferentCategory(t *testing.T) {
	dir := setupTestSkills(t)
	fn := makeReadSkill(os.DirFS(dir))

	result, err := fn(map[string]string{"name": "graphql", "category": "protocols"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(result.Output, "GraphQL") {
		t.Errorf("expected GraphQL content, got: %s", result.Output)
	}
}

func TestReadSkill_NotFound(t *testing.T) {
	dir := setupTestSkills(t)
	fn := makeReadSkill(os.DirFS(dir))

	result, _ := fn(map[string]string{"name": "nonexistent_skill"})
	if result.Error == "" {
		t.Error("expected error for nonexistent skill")
	}
	if !strings.Contains(result.Error, "skill not found") {
		t.Errorf("expected 'skill not found' error, got: %s", result.Error)
	}
}

func TestReadSkill_EmptyName(t *testing.T) {
	dir := setupTestSkills(t)
	fn := makeReadSkill(os.DirFS(dir))

	result, _ := fn(map[string]string{"name": ""})
	if result.Error == "" {
		t.Error("expected error for empty name")
	}
}

func TestReadSkill_PathTraversal(t *testing.T) {
	dir := setupTestSkills(t)
	fn := makeReadSkill(os.DirFS(dir))

	// Attempt path traversal
	traversalInputs := []string{
		"../../etc/passwd",
		"../../../etc/shadow",
		"../secrets",
		"..%2F..%2Fetc%2Fpasswd",
	}
	for _, input := range traversalInputs {
		result, _ := fn(map[string]string{"name": input})
		if result.Output != "" && strings.Contains(result.Output, "root:") {
			t.Errorf("path traversal succeeded with input: %s", input)
		}
	}
}

func TestReadSkill_CrossCategorySearch(t *testing.T) {
	dir := setupTestSkills(t)
	fn := makeReadSkill(os.DirFS(dir))

	// Request skill from protocols category without specifying category
	// (defaults to vulnerabilities, then searches all categories)
	result, _ := fn(map[string]string{"name": "graphql"})
	if !strings.Contains(result.Output, "GraphQL") {
		t.Errorf("cross-category search should find graphql in protocols, got: %s", result.Output)
	}
}

func TestListSkills_All(t *testing.T) {
	dir := setupTestSkills(t)
	fn := makeListSkills(os.DirFS(dir))

	result, err := fn(map[string]string{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should list all skills across categories
	if !strings.Contains(result.Output, "sql_injection") {
		t.Error("expected sql_injection in output")
	}
	if !strings.Contains(result.Output, "graphql") {
		t.Error("expected graphql in output")
	}
	if !strings.Contains(result.Output, "django") {
		t.Error("expected django in output")
	}
	if !strings.Contains(result.Output, "Total: 4 skills") {
		t.Errorf("expected total of 4 skills, got: %s", result.Output)
	}
}

func TestListSkills_FilterCategory(t *testing.T) {
	dir := setupTestSkills(t)
	fn := makeListSkills(os.DirFS(dir))

	result, err := fn(map[string]string{"category": "protocols"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !strings.Contains(result.Output, "graphql") {
		t.Error("expected graphql in protocols output")
	}
	if strings.Contains(result.Output, "sql_injection") {
		t.Error("should NOT contain sql_injection when filtering protocols")
	}
}

func TestListSkills_EmptyCategory(t *testing.T) {
	dir := setupTestSkills(t)
	fn := makeListSkills(os.DirFS(dir))

	result, _ := fn(map[string]string{"category": "nonexistent"})
	if !strings.Contains(result.Output, "Total: 0 skills") {
		t.Errorf("expected 0 skills for nonexistent category, got: %s", result.Output)
	}
}

func TestResolveAlias(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"xss", "testing-for-xss-vulnerabilities"},
		{"XSS", "testing-for-xss-vulnerabilities"},
		{"sqli", "exploiting-sql-injection-vulnerabilities"},
		{"sql-injection", "exploiting-sql-injection-vulnerabilities"},
		{"ssrf", "performing-ssrf-vulnerability-exploitation"},
		{"csrf", "performing-csrf-attack-simulation"},
		{"xxe", "testing-for-xxe-injection-vulnerabilities"},
		{"idor", "exploiting-idor-vulnerabilities"},
		{"ssti", "exploiting-template-injection-vulnerabilities"},
		{"cors", "testing-cors-misconfiguration"},
		{"jwt", "exploiting-jwt-algorithm-confusion-attack"},
		{"oauth", "exploiting-oauth-misconfiguration"},
		{"nmap", "scanning-network-with-nmap-advanced"},
		{"recon", "conducting-external-reconnaissance-with-osint"},
		{"privesc", "detecting-privilege-escalation-attempts"},
		{"bloodhound", "exploiting-active-directory-with-bloodhound"},
		// Non-alias passthrough
		{"some-random-name", "some-random-name"},
		{"", ""},
	}
	for _, tc := range tests {
		got := resolveAlias(tc.input)
		if got != tc.want {
			t.Errorf("resolveAlias(%q) = %q, want %q", tc.input, got, tc.want)
		}
	}
}

// TestResolveAlias_SystemPromptHints verifies that every alias referenced
// in agent.go's system prompt (the read_skill(name="...") hints) resolves
// to a real skill. These were previously broken (16 dead references).
func TestResolveAlias_SystemPromptHints(t *testing.T) {
	hints := []struct {
		input string
		want  string
	}{
		{"2fa-mfa-bypass", "bypassing-two-factor-and-otp"},
		{"authentication-jwt", "exploiting-jwt-algorithm-confusion-attack"},
		{"cache-poisoning", "performing-web-cache-poisoning-attack"},
		{"cors-exploitation", "testing-cors-misconfiguration"},
		{"dom-xss", "testing-for-xss-vulnerabilities"},
		{"graphql-advanced", "performing-graphql-security-assessment"},
		{"host-header-attacks", "testing-for-host-header-injection"},
		{"information-disclosure", "testing-for-sensitive-data-exposure"},
		{"insecure-file-uploads", "exploiting-file-upload-vulnerabilities"},
		{"oauth2-attacks", "exploiting-oauth-misconfiguration"},
		{"path-traversal-lfi-rfi", "performing-directory-traversal-testing"},
		{"race-conditions", "exploiting-race-condition-vulnerabilities"},
		{"web-llm-attacks", "testing-llm-prompt-injection-and-jailbreaks"},
		{"websocket-hijacking", "exploiting-websocket-vulnerabilities"},
		{"zero-day-hunting", "performing-zero-day-vulnerability-discovery"},
	}
	for _, tc := range hints {
		got := resolveAlias(tc.input)
		if got != tc.want {
			t.Errorf("resolveAlias(%q) = %q, want %q", tc.input, got, tc.want)
		}
	}
}

// TestResolveAlias_UnderscoreNormalization verifies that underscore-style
// names (used in old system prompt examples) resolve via the dash-keyed
// alias map after normalization.
func TestResolveAlias_UnderscoreNormalization(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"nosql_injection", "exploiting-nosql-injection-vulnerabilities"},
		{"prototype_pollution", "exploiting-prototype-pollution-in-javascript"},
		{"http_request_smuggling", "exploiting-http-request-smuggling"},
		{"mass_assignment", "exploiting-mass-assignment-in-rest-apis"},
		{"sql_injection", "exploiting-sql-injection-vulnerabilities"},
		// Mixed case + underscores
		{"SQL_Injection", "exploiting-sql-injection-vulnerabilities"},
		{"NOSQL_INJECTION", "exploiting-nosql-injection-vulnerabilities"},
	}
	for _, tc := range tests {
		got := resolveAlias(tc.input)
		if got != tc.want {
			t.Errorf("resolveAlias(%q) = %q, want %q", tc.input, got, tc.want)
		}
	}
}

func TestReadSkill_Alias(t *testing.T) {
	// Set up a test FS that has the full canonical name the alias resolves to.
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, "vulnerabilities", "exploiting-sql-injection-vulnerabilities"), 0755)
	os.WriteFile(
		filepath.Join(dir, "vulnerabilities", "exploiting-sql-injection-vulnerabilities", "SKILL.md"),
		[]byte("# SQL Injection\nFull methodology..."),
		0644,
	)

	fn := makeReadSkill(os.DirFS(dir))

	// Use shorthand alias
	result, err := fn(map[string]string{"name": "sql-injection"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(result.Output, "SQL Injection") {
		t.Errorf("alias 'sql-injection' should resolve to full skill, got: %s", result.Output)
	}

	// Also test 'sqli' alias
	result, err = fn(map[string]string{"name": "sqli"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(result.Output, "SQL Injection") {
		t.Errorf("alias 'sqli' should resolve to full skill, got: %s", result.Output)
	}

	// Test underscore-style name resolves via normalization
	result, err = fn(map[string]string{"name": "sql_injection"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(result.Output, "SQL Injection") {
		t.Errorf("underscore alias 'sql_injection' should resolve to full skill, got: %s", result.Output)
	}
}
