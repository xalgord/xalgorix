package agent

import (
	"fmt"
	"strings"
	"testing"
)

// ── extractEndpointFromCmd tests ─────────────────────────────────────────────

func TestExtractEndpointFromCmd(t *testing.T) {
	tests := []struct {
		name string
		cmd  string
		want string
	}{
		{"curl with https", `curl -sk https://example.com/api/users`, "example.com/api/users"},
		{"curl with http", `curl http://example.com/login`, "example.com/login"},
		{"curl root path", `curl https://example.com/`, "example.com/"},
		{"curl no path", `curl https://example.com`, "example.com/"},
		{"curl with quotes", `curl https://example.com/v1/token`, "example.com/v1/token"},
		{"curl with flags", `curl -si -H "Host: evil" https://target.com/admin/panel`, "target.com/admin/panel"},
		{"httpx command", `httpx -u https://target.com/api/v2/health`, "target.com/api/v2/health"},
		{"wget command", `wget https://cdn.example.com/bundle.js`, "cdn.example.com/bundle.js"},
		{"no url", `nmap -sV target.com`, ""},
		{"sqlmap no url prefix", `sqlmap -r request.txt`, ""},
		{"strips query params", `curl https://api.example.com/search?q=test`, "api.example.com/search"},
		// New: piped commands (audit fix #1)
		{"piped curl", `echo '{"id":1}' | curl -d @- https://target.com/api/users`, "target.com/api/users"},
		{"piped with grep", `curl -sk https://target.com/api/v2/config | grep secret`, "target.com/api/v2/config"},
		// New: tools the old extractor missed (audit fix #1)
		{"sqlmap with url", `sqlmap -u https://target.com/api/search?q=test --batch`, "target.com/api/search"},
		{"nuclei with url", `nuclei -u https://target.com/api/health -t cves/`, "target.com/api/health"},
		{"dalfox", `dalfox url https://target.com/search?q=xss`, "target.com/search"},
		// Edge cases
		{"url in quotes", `curl "https://target.com/api/v1/data"`, "target.com/api/v1/data"},
		{"ncat no url", `echo "GET / HTTP/1.1" | ncat target.com 80`, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractEndpointFromCmd(tt.cmd)
			if got != tt.want {
				t.Errorf("extractEndpointFromCmd(%q) = %q, want %q", tt.cmd, got, tt.want)
			}
		})
	}
}

// ── extractHostFromCmd tests ─────────────────────────────────────────────────

func TestExtractHostFromCmd(t *testing.T) {
	tests := []struct {
		cmd  string
		want string
	}{
		{`ffuf -u https://target.com/FUZZ -w wordlist.txt`, "target.com"},
		{`gobuster dir -u https://sub.target.com/ -w list.txt`, "sub.target.com"},
		{`dirsearch -u http://10.0.0.1:8080/api`, "10.0.0.1:8080"},
		{`nmap target.com`, ""},
	}

	for _, tt := range tests {
		name := tt.cmd
		if len(name) > 30 {
			name = name[:30]
		}
		t.Run(name, func(t *testing.T) {
			got := extractHostFromCmd(tt.cmd)
			if got != tt.want {
				t.Errorf("extractHostFromCmd(%q) = %q, want %q", tt.cmd, got, tt.want)
			}
		})
	}
}

// ── hookWorkTracker tests ────────────────────────────────────────────────────

func TestWorkTracker_TracksUniqueEndpoints(t *testing.T) {
	state := NewScanState()

	// First curl — should track endpoint
	hookWorkTracker(state, map[string]string{
		"tool_name": "terminal_execute",
		"command":   `curl -sk https://example.com/api/users`,
	})
	if len(state.EndpointsTested) != 1 {
		t.Errorf("Expected 1 endpoint tracked, got %d", len(state.EndpointsTested))
	}

	// Same endpoint again — no duplicate
	hookWorkTracker(state, map[string]string{
		"tool_name": "terminal_execute",
		"command":   `curl -sk https://example.com/api/users -H "X-Test: 1"`,
	})
	if len(state.EndpointsTested) != 1 {
		t.Errorf("Expected still 1 endpoint (deduped), got %d", len(state.EndpointsTested))
	}

	// Different endpoint
	hookWorkTracker(state, map[string]string{
		"tool_name": "terminal_execute",
		"command":   `curl https://example.com/api/login`,
	})
	if len(state.EndpointsTested) != 2 {
		t.Errorf("Expected 2 endpoints, got %d", len(state.EndpointsTested))
	}
}

func TestWorkTracker_InjectionEndpoints(t *testing.T) {
	state := NewScanState()

	// SQLi on /api/users — realistic curl with injection in data flag
	hookWorkTracker(state, map[string]string{
		"tool_name": "terminal_execute",
		"command":   `curl -d "id=1' or 1=1--" https://target.com/api/users`,
	})
	if len(state.InjectionEndpoints) != 1 {
		t.Errorf("Expected 1 injection endpoint, got %d", len(state.InjectionEndpoints))
	}
	if !state.InjectionTested {
		t.Error("InjectionTested should be true")
	}

	// XSS on /search — realistic curl with script in parameter
	hookWorkTracker(state, map[string]string{
		"tool_name": "terminal_execute",
		"command":   `curl -d "q=<script>alert(1)</script>" https://target.com/search`,
	})
	if len(state.InjectionEndpoints) != 2 {
		t.Errorf("Expected 2 injection endpoints, got %d", len(state.InjectionEndpoints))
	}
}

func TestWorkTracker_AccessControlEndpoints(t *testing.T) {
	state := NewScanState()

	hookWorkTracker(state, map[string]string{
		"tool_name": "terminal_execute",
		"command":   `curl https://target.com/api/user/1`,
	})
	if len(state.AccessControlEndpoints) != 1 {
		t.Errorf("Expected 1 access control endpoint, got %d", len(state.AccessControlEndpoints))
	}

	hookWorkTracker(state, map[string]string{
		"tool_name": "terminal_execute",
		"command":   `curl -H "x-forwarded-for: 127.0.0.1" https://target.com/admin/dashboard`,
	})
	if len(state.AccessControlEndpoints) != 2 {
		t.Errorf("Expected 2 access control endpoints, got %d", len(state.AccessControlEndpoints))
	}
}

func TestWorkTracker_VulnClassTracking(t *testing.T) {
	state := NewScanState()

	// SSTI
	hookWorkTracker(state, map[string]string{
		"tool_name": "terminal_execute",
		"command":   `curl "https://target.com/search?q={{7*7}}"`,
	})
	if !state.VulnClassesTested["ssti"] {
		t.Error("SSTI should be detected from {{7*7}}")
	}

	// CRLF
	hookWorkTracker(state, map[string]string{
		"tool_name": "terminal_execute",
		"command":   `curl "https://target.com/redirect?url=%0d%0aInjected-Header:true"`,
	})
	if !state.VulnClassesTested["crlf"] {
		t.Error("CRLF should be detected from CRLF payload")
	}

	// Command injection
	hookWorkTracker(state, map[string]string{
		"tool_name": "terminal_execute",
		"command":   `curl "https://target.com/ping?host=127.0.0.1; id"`,
	})
	if !state.VulnClassesTested["cmdi"] {
		t.Error("CmdI should be detected from ; id")
	}

	// Path traversal
	hookWorkTracker(state, map[string]string{
		"tool_name": "terminal_execute",
		"command":   `curl "https://target.com/file?path=../../../etc/passwd"`,
	})
	if !state.VulnClassesTested["path_traversal"] {
		t.Error("Path traversal should be detected from ../../../etc/passwd")
	}

	// SSRF
	hookWorkTracker(state, map[string]string{
		"tool_name": "terminal_execute",
		"command":   `curl "https://target.com/proxy?url=http://169.254.169.254/latest"`,
	})
	if !state.VulnClassesTested["ssrf"] {
		t.Error("SSRF should be detected from 169.254")
	}

	// Verify SQLi and XSS not set (we didn't send those)
	if state.VulnClassesTested["sqli"] {
		t.Error("SQLi should not be detected without SQL payloads")
	}
	if state.VulnClassesTested["xss"] {
		t.Error("XSS should not be detected without XSS payloads")
	}
}

func TestWorkTracker_PythonActionVulnTracking(t *testing.T) {
	state := NewScanState()

	// Python code with SSTI and CRLF payloads
	hookWorkTracker(state, map[string]string{
		"tool_name": "python_action",
		"code":      `import requests; r = requests.get("https://target.com/search?q={{7*7}}")`,
	})
	if !state.VulnClassesTested["ssti"] {
		t.Error("SSTI should be detected from python_action code")
	}

	hookWorkTracker(state, map[string]string{
		"tool_name": "python_action",
		"code":      `r = requests.get("https://target.com/r?url=%0d%0aX-Injected:true")`,
	})
	if !state.VulnClassesTested["crlf"] {
		t.Error("CRLF should be detected from python_action code")
	}
}

func TestCurlPreference_PythonRequestsNudge(t *testing.T) {
	state := NewScanState()

	// First python HTTP call — soft nudge
	result := hookCurlPreference(state, map[string]string{
		"tool_name": "python_action",
		"code":      `import requests; r = requests.get("https://target.com/api/test")`,
	})
	if result.Nudge == "" {
		t.Error("Should nudge on first python requests.get() call")
	}

	// Non-HTTP python code — no nudge
	state2 := NewScanState()
	result2 := hookCurlPreference(state2, map[string]string{
		"tool_name": "python_action",
		"code":      `print("hello world"); x = 1 + 2`,
	})
	if result2.Nudge != "" {
		t.Error("Should NOT nudge on python code without HTTP calls")
	}
}

func TestWorkTracker_EndpointInventory(t *testing.T) {
	state := NewScanState()

	// Non-inventory note — no keywords at all
	hookWorkTracker(state, map[string]string{
		"tool_name": "add_note",
		"key":       "waf_info",
		"value":     "Target uses CloudFlare WAF",
	})
	if state.EndpointInventorySaved {
		t.Error("Should not be saved for non-inventory note")
	}

	// False positive — keyword in key but only 1 path-like token (too few)
	hookWorkTracker(state, map[string]string{
		"tool_name": "add_note",
		"key":       "discovery_notes",
		"value":     "Discovered that the WAF blocks /api calls",
	})
	if state.EndpointInventorySaved {
		t.Error("Should not be saved for note with just 1 path token")
	}

	// Real inventory note — keyword + 3 path-like tokens
	hookWorkTracker(state, map[string]string{
		"tool_name": "add_note",
		"key":       "endpoint_inventory",
		"value":     "## Discovered Endpoints\n- /api/users\n- /api/login\n- /admin/dashboard",
	})
	if !state.EndpointInventorySaved {
		t.Error("Should be saved for inventory note with keyword + 3 path tokens")
	}

	// Reset and test multi-line fallback (3+ lines)
	state2 := NewScanState()
	hookWorkTracker(state2, map[string]string{
		"tool_name": "add_note",
		"key":       "endpoints",
		"value":     "Discovered endpoints:\n/page1\n/page2\n/page3\n/page4",
	})
	if !state2.EndpointInventorySaved {
		t.Error("Should be saved for note with keyword + 3+ lines")
	}

	// Regression test: vanhack-style note the old check rejected
	state3 := NewScanState()
	hookWorkTracker(state3, map[string]string{
		"tool_name": "add_note",
		"key":       "endpoint_inventory",
		"value":     "Discovered Endpoints:\n- /api/candidates (VULNERABLE - unauthenticated access)\n- /api/jobs (public job listings)\n- /api/testimonials (public)\n- /api/candidate-stories\n- /v1/auth/refreshtoken",
	})
	if !state3.EndpointInventorySaved {
		t.Error("Should be saved for vanhack-style endpoint inventory")
	}
}

// ── hookFinishGatekeeper tests ───────────────────────────────────────────────

func TestFinishGatekeeper_BlocksLowIteration(t *testing.T) {
	state := NewScanState()
	state.Iteration = 2
	state.TerminalCalls = 10
	state.ReconDone = true

	result := hookFinishGatekeeper(state, nil)
	if !result.Block {
		t.Error("Should block at iteration < 3")
	}
}

func TestFinishGatekeeper_BlocksLowCommands(t *testing.T) {
	state := NewScanState()
	state.Iteration = 10
	state.TerminalCalls = 3

	result := hookFinishGatekeeper(state, nil)
	if !result.Block {
		t.Error("Should block with < 5 terminal commands")
	}
}

func TestFinishGatekeeper_BlocksNoRecon(t *testing.T) {
	state := NewScanState()
	state.Iteration = 10
	state.TerminalCalls = 10
	state.ReconDone = false

	result := hookFinishGatekeeper(state, nil)
	if !result.Block {
		t.Error("Should block without recon")
	}
}

func TestFinishGatekeeper_BlocksNoInventory(t *testing.T) {
	state := NewScanState()
	state.Iteration = 30
	state.TerminalCalls = 15
	state.ReconDone = true
	state.EndpointInventorySaved = false

	result := hookFinishGatekeeper(state, nil)
	if !result.Block {
		t.Error("Should block without endpoint inventory saved")
	}
}

func TestFinishGatekeeper_BlocksLowCoverage(t *testing.T) {
	state := NewScanState()
	state.Iteration = 30
	state.TerminalCalls = 15
	state.ReconDone = true
	state.EndpointInventorySaved = true
	// Only 1 injection endpoint out of 10 tested
	state.EndpointsTested["a"] = true
	state.EndpointsTested["b"] = true
	state.EndpointsTested["c"] = true
	state.EndpointsTested["d"] = true
	state.EndpointsTested["e"] = true
	state.EndpointsTested["f"] = true
	state.EndpointsTested["g"] = true
	state.EndpointsTested["h"] = true
	state.EndpointsTested["i"] = true
	state.EndpointsTested["j"] = true
	state.InjectionEndpoints["a"] = true // only 1

	result := hookFinishGatekeeper(state, nil)
	if !result.Block {
		t.Error("Should block with only 1/10 injection endpoints tested")
	}
}

func TestFinishGatekeeper_AllowsAfter50WithCoverage(t *testing.T) {
	state := NewScanState()
	state.Iteration = 55
	state.TerminalCalls = 30
	state.ReconDone = true
	state.EndpointInventorySaved = true
	state.InjectionEndpoints["a"] = true
	state.InjectionEndpoints["b"] = true
	state.InjectionEndpoints["c"] = true
	state.AccessControlEndpoints["a"] = true
	state.AccessControlEndpoints["b"] = true
	state.DirBustingHosts["target.com"] = true
	state.EndpointsTested["a"] = true
	state.EndpointsTested["b"] = true
	state.EndpointsTested["c"] = true
	state.FinishAttempts = 2 // not first attempt (already incremented in the function)

	result := hookFinishGatekeeper(state, nil)
	if result.Block {
		t.Errorf("Should allow finish after 50 iterations with good coverage, but got blocked: %s", result.BlockReason)
	}
}

func TestFinishGatekeeper_BlocksBelow50EvenWithCoverage(t *testing.T) {
	// Large surface area (> 15 endpoints): 50-iteration floor always applies
	state := NewScanState()
	state.Iteration = 40
	state.TerminalCalls = 30
	state.ReconDone = true
	state.EndpointInventorySaved = true
	// 20 endpoints — large surface, adaptive early finish doesn't apply
	for i := range 20 {
		state.EndpointsTested[fmt.Sprintf("ep%d", i)] = true
	}
	state.InjectionEndpoints["ep0"] = true
	state.InjectionEndpoints["ep1"] = true
	state.InjectionEndpoints["ep2"] = true
	state.AccessControlEndpoints["ep0"] = true
	state.AccessControlEndpoints["ep1"] = true
	state.DirBustingHosts["target.com"] = true

	result := hookFinishGatekeeper(state, nil)
	if !result.Block {
		t.Error("Large surface (20 endpoints) should block below 50 iterations even with good coverage")
	}
}

func TestFinishGatekeeper_DiscoveryModeAllowsEarly(t *testing.T) {
	state := NewScanState()
	state.DiscoveryMode = true
	state.TerminalCalls = 5
	state.Iteration = 8

	result := hookFinishGatekeeper(state, nil)
	if result.Block {
		t.Error("Discovery mode should allow finish after 3+ terminal calls")
	}
}

func TestFinishGatekeeper_DiscoveryModeBlocksTooFew(t *testing.T) {
	state := NewScanState()
	state.DiscoveryMode = true
	state.TerminalCalls = 2

	result := hookFinishGatekeeper(state, nil)
	if !result.Block {
		t.Error("Discovery mode should block with < 3 terminal calls")
	}
}

// ── minInt / maxInt tests ────────────────────────────────────────────────────

func TestMinMaxInt(t *testing.T) {
	if minInt(3, 5) != 3 {
		t.Error("minInt(3,5) should be 3")
	}
	if minInt(5, 3) != 3 {
		t.Error("minInt(5,3) should be 3")
	}
	if maxInt(3, 5) != 5 {
		t.Error("maxInt(3,5) should be 5")
	}
	if maxInt(5, 3) != 5 {
		t.Error("maxInt(5,3) should be 5")
	}
}

// ── Role temperature tests ───────────────────────────────────────────────────

func TestRoleTemperatures(t *testing.T) {
	tests := []struct {
		name string
		temp *float64
		want float64
	}{
		{"Scanner", TempScanner, 0.2},
		{"Reasoner", TempReasoner, 0.2},
		{"Validator", TempValidator, 0.0},
		{"Reporter", TempReporter, 0.3},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.temp == nil {
				t.Fatal("temperature pointer should not be nil")
			}
			if *tt.temp != tt.want {
				t.Errorf("Temp%s = %f, want %f", tt.name, *tt.temp, tt.want)
			}
		})
	}
}

func TestFloatPtr(t *testing.T) {
	p := floatPtr(0.5)
	if p == nil || *p != 0.5 {
		t.Error("floatPtr(0.5) should return pointer to 0.5")
	}

	// Zero value should work (not nil)
	p0 := floatPtr(0.0)
	if p0 == nil || *p0 != 0.0 {
		t.Error("floatPtr(0.0) should return pointer to 0.0, not nil")
	}
}

// ── testDepthRatio tests ─────────────────────────────────────────────────────

func TestTestDepthRatio(t *testing.T) {
	tests := []struct {
		name                                                  string
		total, injection, accessControl, dirbusting           int
		want                                                  float64
	}{
		{"no endpoints", 0, 0, 0, 0, 0.0},
		{"3 endpoints, full coverage", 3, 3, 3, 3, 3.0},
		{"10 endpoints, partial", 10, 3, 2, 1, 0.6},
		{"1 endpoint, all classes", 1, 1, 1, 1, 3.0},
		{"5 endpoints, shallow", 5, 1, 0, 0, 0.2},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := testDepthRatio(tt.total, tt.injection, tt.accessControl, tt.dirbusting)
			if got != tt.want {
				t.Errorf("testDepthRatio(%d,%d,%d,%d) = %f, want %f",
					tt.total, tt.injection, tt.accessControl, tt.dirbusting, got, tt.want)
			}
		})
	}
}

// ── Adaptive surface area tests ──────────────────────────────────────────────

func TestFinishGatekeeper_SmallSurfaceEarlyFinish(t *testing.T) {
	// Small target (3 endpoints), deep testing (depth 2.0+), iter 30 → allow
	state := NewScanState()
	state.Iteration = 30
	state.TerminalCalls = 12
	state.ReconDone = true
	state.EndpointInventorySaved = true
	// 3 endpoints, all tested with injection + access control + dirbusting
	state.EndpointsTested["a"] = true
	state.EndpointsTested["b"] = true
	state.EndpointsTested["c"] = true
	state.InjectionEndpoints["a"] = true
	state.InjectionEndpoints["b"] = true
	state.InjectionEndpoints["c"] = true
	state.AccessControlEndpoints["a"] = true
	state.AccessControlEndpoints["b"] = true
	state.DirBustingHosts["target.com"] = true
	// depth = (3 + 2 + 1) / 3 = 2.0

	result := hookFinishGatekeeper(state, nil)
	if result.Block {
		t.Errorf("Small surface with depth 2.0 at iter 30 should allow early finish, got blocked: %s", result.BlockReason)
	}
}

func TestFinishGatekeeper_SmallSurfaceShallowBlocked(t *testing.T) {
	// Small target (3 endpoints), shallow testing (depth 0.3), iter 30 → block
	state := NewScanState()
	state.Iteration = 30
	state.TerminalCalls = 12
	state.ReconDone = true
	state.EndpointInventorySaved = true
	state.EndpointsTested["a"] = true
	state.EndpointsTested["b"] = true
	state.EndpointsTested["c"] = true
	state.InjectionEndpoints["a"] = true // only 1 injection test
	state.DirBustingHosts["target.com"] = true
	// depth = (1 + 0 + 1) / 3 = 0.67 — too shallow

	result := hookFinishGatekeeper(state, nil)
	if !result.Block {
		t.Error("Small surface with shallow depth should still block")
	}
}

func TestFinishGatekeeper_MediumSurfaceEarlyFinish(t *testing.T) {
	// Medium target (8 endpoints), good depth (1.5+), iter 42 → allow
	state := NewScanState()
	state.Iteration = 42
	state.TerminalCalls = 20
	state.ReconDone = true
	state.EndpointInventorySaved = true
	for i := range 8 {
		state.EndpointsTested[fmt.Sprintf("ep%d", i)] = true
	}
	// 4 injection + 4 access control + 4 dirbusting hosts = 12 tests / 8 endpoints = 1.5
	for i := range 4 {
		state.InjectionEndpoints[fmt.Sprintf("ep%d", i)] = true
		state.AccessControlEndpoints[fmt.Sprintf("ep%d", i)] = true
	}
	state.DirBustingHosts["target.com"] = true
	state.DirBustingHosts["sub.target.com"] = true
	state.DirBustingHosts["api.target.com"] = true
	state.DirBustingHosts["admin.target.com"] = true
	// depth = (4 + 4 + 4) / 8 = 1.5

	result := hookFinishGatekeeper(state, nil)
	if result.Block {
		t.Errorf("Medium surface with depth 1.5 at iter 42 should allow finish, got blocked: %s", result.BlockReason)
	}
}

func TestFinishGatekeeper_LargeSurfaceNoEarlyFinish(t *testing.T) {
	// Large target (20 endpoints), good depth, iter 35 → still blocked (> 15 endpoints)
	state := NewScanState()
	state.Iteration = 35
	state.TerminalCalls = 25
	state.ReconDone = true
	state.EndpointInventorySaved = true
	for i := range 20 {
		state.EndpointsTested[fmt.Sprintf("ep%d", i)] = true
	}
	for i := range 10 {
		state.InjectionEndpoints[fmt.Sprintf("ep%d", i)] = true
		state.AccessControlEndpoints[fmt.Sprintf("ep%d", i)] = true
	}
	state.DirBustingHosts["target.com"] = true
	// depth = (10 + 10 + 1) / 20 = 1.05 — but > 15 endpoints, no early finish

	result := hookFinishGatekeeper(state, nil)
	if !result.Block {
		t.Error("Large surface (20 endpoints) should not get early finish at iter 35")
	}
}

func TestFinishGatekeeper_DirBustingOnlyGamingBlocked(t *testing.T) {
	// Audit fix: agent inflates dirbusting hosts to game depth ratio
	// 3 endpoints, 0 injection, 0 access control, 4 dirbusting hosts
	// depth = (0 + 0 + 4) / 3 = 1.33 — looks okay but only 1 category covered
	state := NewScanState()
	state.Iteration = 30
	state.TerminalCalls = 12
	state.ReconDone = true
	state.EndpointInventorySaved = true
	state.EndpointsTested["a"] = true
	state.EndpointsTested["b"] = true
	state.EndpointsTested["c"] = true
	state.DirBustingHosts["target.com"] = true
	state.DirBustingHosts["sub1.target.com"] = true
	state.DirBustingHosts["sub2.target.com"] = true
	state.DirBustingHosts["sub3.target.com"] = true
	// categoriesCovered = 1 (only dirbusting) → early finish blocked

	result := hookFinishGatekeeper(state, nil)
	if !result.Block {
		t.Error("Should block early finish when only 1 of 3 vuln categories covered (dirbusting-only gaming)")
	}
}

// ── hookCurlPreference tests ─────────────────────────────────────────────────

func TestCurlPreference_SendRequestFirstUseNudge(t *testing.T) {
	state := NewScanState()
	result := hookCurlPreference(state, map[string]string{
		"tool_name": "send_request",
		"method":    "GET",
		"headers":   "",
	})
	if result.Nudge == "" {
		t.Error("Should nudge on first send_request without auth headers")
	}
	if state.SendRequestCalls != 1 {
		t.Errorf("SendRequestCalls = %d, want 1", state.SendRequestCalls)
	}
}

func TestCurlPreference_SendRequestEscalatesAfter3(t *testing.T) {
	state := NewScanState()
	state.SendRequestCalls = 2 // already used twice

	result := hookCurlPreference(state, map[string]string{
		"tool_name": "send_request",
		"method":    "POST",
		"headers":   "Content-Type: application/json",
	})
	if result.Nudge == "" {
		t.Error("Should escalate warning after 3+ send_request calls")
	}
	if !strings.Contains(result.Nudge, "STOP") {
		t.Error("Escalated warning should contain 'STOP'")
	}
}

func TestCurlPreference_SendRequestAllowsWithAuth(t *testing.T) {
	state := NewScanState()
	state.SendRequestCalls = 4 // would normally trigger strong warning

	result := hookCurlPreference(state, map[string]string{
		"tool_name": "send_request",
		"method":    "GET",
		"headers":   "Cookie: session=abc123; Authorization: Bearer xyz",
	})
	if result.Nudge != "" {
		t.Errorf("Should NOT nudge send_request with auth headers, got: %s", result.Nudge)
	}
}

func TestCurlPreference_BrowserNudgeWithoutAuth(t *testing.T) {
	state := NewScanState()
	state.ConsecutiveBrowser = 3 // already used 3 times
	state.BrowserAuthContext = false

	result := hookCurlPreference(state, map[string]string{
		"tool_name": "browser_action",
		"action":    "navigate",
		"url":       "https://target.com/api/users",
		"text":      "",
	})
	if result.Nudge == "" {
		t.Error("Should nudge browser usage without auth context after 2+ consecutive uses")
	}
}

func TestCurlPreference_BrowserAllowsAuthContext(t *testing.T) {
	state := NewScanState()
	state.ConsecutiveBrowser = 5

	// Login page navigation sets auth context
	result := hookCurlPreference(state, map[string]string{
		"tool_name": "browser_action",
		"action":    "navigate",
		"url":       "https://target.com/login",
		"text":      "",
	})
	if !state.BrowserAuthContext {
		t.Error("Login URL should set BrowserAuthContext = true")
	}
	if result.Nudge != "" {
		t.Errorf("Should NOT nudge browser on login page, got: %s", result.Nudge)
	}
}

func TestCurlPreference_IgnoresOtherTools(t *testing.T) {
	state := NewScanState()
	result := hookCurlPreference(state, map[string]string{
		"tool_name": "terminal_execute",
		"command":   "curl https://target.com",
	})
	if result.Nudge != "" {
		t.Error("Should not nudge for terminal_execute (curl)")
	}
	if state.SendRequestCalls != 0 {
		t.Error("SendRequestCalls should remain 0 for non-send_request tools")
	}
}
