package agent

import (
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

func TestWorkTracker_EndpointInventory(t *testing.T) {
	state := NewScanState()

	// Non-inventory note
	hookWorkTracker(state, map[string]string{
		"tool_name": "add_note",
		"content":   "Target uses CloudFlare WAF",
	})
	if state.EndpointInventorySaved {
		t.Error("Should not be saved for non-inventory note")
	}

	// Inventory note
	hookWorkTracker(state, map[string]string{
		"tool_name": "add_note",
		"content":   "## Discovered Endpoints\n- /api/users\n- /api/login",
	})
	if !state.EndpointInventorySaved {
		t.Error("Should be saved for inventory note")
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
	state := NewScanState()
	state.Iteration = 40
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

	result := hookFinishGatekeeper(state, nil)
	if !result.Block {
		t.Error("Should block below 50 iterations even with good coverage (first 2 attempts)")
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
