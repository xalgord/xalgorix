// Package agent provides the core agent loop.
// hooks.go implements an extensible hooks system for agent lifecycle events.
// All behavioral policy (stuck detection, finish gating, work tracking, nudges)
// lives here rather than inline in the Run loop.
package agent

import (
	"fmt"
	"net/url"
	"strings"
	"time"
)

// ── Hook Events ──────────────────────────────────────────────────────────────

const (
	OnToolCall        = "OnToolCall"        // Before every tool execution
	OnToolResult      = "OnToolResult"      // After every tool execution
	OnFinishAttempt   = "OnFinishAttempt"   // When agent calls finish
	OnStuckCheck      = "OnStuckCheck"      // After stuck-loop counter updates (every tool call)
	OnEmptyResponse   = "OnEmptyResponse"   // When LLM returns empty
	OnNoToolResponse  = "OnNoToolResponse"  // When LLM responds without tools
	OnIterationStart  = "OnIterationStart"  // At the start of each iteration
	OnContextPrune    = "OnContextPrune"    // After message history is pruned
	OnHealthyResponse = "OnHealthyResponse" // After a non-empty response with tool calls (resets error counters)
)

// ── Scan State ───────────────────────────────────────────────────────────────

// ScanState holds all mutable state that hooks can read and write.
// It replaces the loose local variables previously scattered in Run().
type ScanState struct {
	Iteration                  int
	TerminalCalls              int
	SkillsLoaded               int
	UniqueToolsUsed            map[string]bool
	ReconDone                  bool
	ScannerUsed                bool
	FinishAttempts             int
	DiscoveryMode              bool
	ReconOnlyMode              bool
	AllowedPhases              []int
	PassiveReconGuardActive    bool
	PassiveReconPassiveLookups int
	PassiveReconBlockedActive  int

	// Coverage counters — track UNIQUE endpoints per test category.
	// These replace the old boolean flags (InjectionTested, etc.) which
	// fired after a single command, allowing the agent to finish after
	// testing only 1 out of 20 discovered endpoints.
	InjectionEndpoints     map[string]bool // unique endpoints with injection payloads
	AccessControlEndpoints map[string]bool // unique endpoints with auth/IDOR tests
	DirBustingHosts        map[string]bool // unique hosts/paths fuzzed
	EndpointsTested        map[string]bool // all unique URL paths tested with any tool
	EndpointInventorySaved bool            // add_note called (recon checklist step 5)

	// Backward-compat booleans — derived from map lengths in hookWorkTracker
	InjectionTested     bool
	DirBustingDone      bool
	AccessControlTested bool

	// Stuck-loop detection
	StuckDomain        string
	StuckIterations    int
	ConsecutiveBrowser int
	ConsecutiveSearch  int
	ConsecutiveErrors  int
	EmptyResponseCount int
	NoToolCount        int

	// CumulativeRateLimitWait tracks the total time spent parked in the
	// provider-rate-limit backoff loop across the whole scan. It bounds an
	// otherwise-indefinite stall: a persistently 429'd provider would
	// otherwise keep the scan alive forever (the idle watchdog is kept
	// alive on purpose during the wait), so we cap the total wait and fail
	// the scan cleanly once the ceiling is reached.
	CumulativeRateLimitWait time.Duration

	// New enrichment hooks
	WAFDetected          bool
	DetectedTechs        map[string]bool // e.g. "php", "nodejs", "java"
	SkillSuggestionFired bool            // prevents hookAutoSkillSuggester from firing more than once
}

// NewScanState creates a zero-value ScanState with initialized maps.
func NewScanState() *ScanState {
	return &ScanState{
		UniqueToolsUsed:        make(map[string]bool),
		DetectedTechs:          make(map[string]bool),
		InjectionEndpoints:     make(map[string]bool),
		AccessControlEndpoints: make(map[string]bool),
		DirBustingHosts:        make(map[string]bool),
		EndpointsTested:        make(map[string]bool),
	}
}

// ── Hook Result ──────────────────────────────────────────────────────────────

// HookResult is what hooks return to influence the agent loop.
// Multiple hooks fire per event; results are merged (first non-empty wins for strings,
// OR logic for bools).
type HookResult struct {
	Nudge          string // message to inject into conversation
	Block          bool   // prevent the action (e.g., block finish)
	BlockReason    string // why it was blocked
	ForceSkip      bool   // skip current tool call
	EmitMessage    string // emit to UI without injecting into conversation
	CleanupBrowser bool   // signal to force-close browser
}

// ── Hook Registry ────────────────────────────────────────────────────────────

// HookFn is the signature for all hook functions.
// args contains tool-specific data (tool name, tool args, tool output, etc.)
type HookFn func(state *ScanState, args map[string]string) HookResult

// HookRegistry maintains an ordered list of hooks per event.
type HookRegistry struct {
	hooks map[string][]HookFn
}

// NewHookRegistry creates an empty hook registry.
func NewHookRegistry() *HookRegistry {
	return &HookRegistry{
		hooks: make(map[string][]HookFn),
	}
}

// Register adds a hook function for the given event.
// Hooks fire in registration order; first blocking result wins.
//
// CONCURRENCY: Register must only be called during initialization,
// before Agent.Run() is invoked. It is NOT safe for concurrent use.
func (r *HookRegistry) Register(event string, fn HookFn) {
	r.hooks[event] = append(r.hooks[event], fn)
}

// Fire dispatches all hooks for the given event and merges results.
// First non-empty string fields win. Bool fields use OR logic.
func (r *HookRegistry) Fire(event string, state *ScanState, args map[string]string) HookResult {
	merged := HookResult{}
	for _, fn := range r.hooks[event] {
		result := fn(state, args)
		if merged.Nudge == "" && result.Nudge != "" {
			merged.Nudge = result.Nudge
		}
		if result.Block {
			merged.Block = true
			if merged.BlockReason == "" {
				merged.BlockReason = result.BlockReason
			}
		}
		if result.ForceSkip {
			merged.ForceSkip = true
		}
		if merged.EmitMessage == "" && result.EmitMessage != "" {
			merged.EmitMessage = result.EmitMessage
		}
		if result.CleanupBrowser {
			merged.CleanupBrowser = true
		}
	}
	return merged
}

// ── Thresholds ───────────────────────────────────────────────────────────────

const (
	StuckBrowserThreshold = 60 // browser actions before nudge
	StuckSearchThreshold  = 45 // web searches before nudge
	StuckHardLimit        = 80 // total stuck iterations before force-skip
)

// ── Built-in Hooks ───────────────────────────────────────────────────────────

// RegisterDefaultHooks registers all built-in behavioral hooks.
func RegisterDefaultHooks(reg *HookRegistry) {
	// Order matters: tracking → detection → policy → reset
	reg.Register(OnToolCall, hookWorkTracker)
	reg.Register(OnToolCall, hookStuckTracker)
	reg.Register(OnStuckCheck, hookStuckNudge)
	reg.Register(OnToolResult, hookWAFDetector)
	reg.Register(OnToolResult, hookTechDetector)
	reg.Register(OnFinishAttempt, hookFinishGatekeeper)
	reg.Register(OnEmptyResponse, hookEmptyResponseHandler)
	reg.Register(OnNoToolResponse, hookNoToolHandler)
	reg.Register(OnIterationStart, hookAutoSkillSuggester)
	reg.Register(OnHealthyResponse, hookResetOnSuccess)
}

// ── hookWorkTracker ──────────────────────────────────────────────────────────
// Replaces the trackWork() closure. Detects recon, injection, dirbusting,
// access control testing, scanner usage, and skill loading from tool calls.
func hookWorkTracker(state *ScanState, args map[string]string) HookResult {
	toolName := args["tool_name"]
	state.UniqueToolsUsed[toolName] = true

	if toolName == "terminal_execute" {
		state.TerminalCalls++
		cmd := strings.ToLower(args["command"])

		// Extract endpoint from curl/httpx commands for coverage tracking
		endpoint := extractEndpointFromCmd(cmd)
		if endpoint != "" {
			state.EndpointsTested[endpoint] = true
		}

		// Detect recon commands
		if strings.Contains(cmd, "nmap") || strings.Contains(cmd, "whatweb") ||
			strings.Contains(cmd, "curl -si") || strings.Contains(cmd, "curl -sk") ||
			strings.Contains(cmd, "httpx") || strings.Contains(cmd, "wappalyzer") ||
			strings.Contains(cmd, "ffuf") || strings.Contains(cmd, "gobuster") ||
			strings.Contains(cmd, "dirsearch") || strings.Contains(cmd, "katana") ||
			strings.Contains(cmd, "gospider") || strings.Contains(cmd, "wafw00f") {
			state.ReconDone = true
		}

		// Detect directory busting — track unique hosts/paths
		if strings.Contains(cmd, "ffuf") || strings.Contains(cmd, "gobuster") ||
			strings.Contains(cmd, "dirsearch") || strings.Contains(cmd, "feroxbuster") ||
			strings.Contains(cmd, "dirb ") {
			host := extractHostFromCmd(cmd)
			if host != "" {
				state.DirBustingHosts[host] = true
			}
			state.DirBustingDone = true
		}

		// Detect injection testing — track unique endpoints
		isInjection := strings.Contains(cmd, "sqlmap") || strings.Contains(cmd, "dalfox") ||
			strings.Contains(cmd, "sleep(") || strings.Contains(cmd, "alert(") ||
			strings.Contains(cmd, "<script>") || strings.Contains(cmd, "' or ") ||
			strings.Contains(cmd, "' and ") || strings.Contains(cmd, "{{7*7}}") ||
			strings.Contains(cmd, "etc/passwd") || strings.Contains(cmd, "xalg0r1x") ||
			strings.Contains(cmd, "$ne") || strings.Contains(cmd, "$gt") ||
			strings.Contains(cmd, "__proto__") || strings.Contains(cmd, "%0d%0a") ||
			(strings.Contains(cmd, "content-length") && strings.Contains(cmd, "transfer-encoding"))
		if isInjection {
			if endpoint != "" {
				state.InjectionEndpoints[endpoint] = true
			}
			state.InjectionTested = true
		}

		// Detect access control testing — track unique endpoints
		isAccessControl := strings.Contains(cmd, "/user/1") || strings.Contains(cmd, "/user/2") ||
			strings.Contains(cmd, "id=1") || strings.Contains(cmd, "id=2") ||
			strings.Contains(cmd, "role=admin") || strings.Contains(cmd, "isadmin") ||
			strings.Contains(cmd, "x-forwarded-for") || strings.Contains(cmd, "x-original-url") ||
			(strings.Contains(cmd, "admin") && strings.Contains(cmd, "curl")) ||
			strings.Contains(cmd, "authorization")
		if isAccessControl {
			if endpoint != "" {
				state.AccessControlEndpoints[endpoint] = true
			}
			state.AccessControlTested = true
		}

		// Detect scanner usage
		if strings.Contains(cmd, "nuclei") || strings.Contains(cmd, "sqlmap") ||
			strings.Contains(cmd, "dalfox") || strings.Contains(cmd, "ffuf") ||
			strings.Contains(cmd, "gobuster") ||
			strings.Contains(cmd, "wpscan") || strings.Contains(cmd, "joomscan") {
			state.ScannerUsed = true
		}
	}

	if toolName == "read_skill" {
		state.SkillsLoaded++
	}

	// Track endpoint inventory saved (mandatory recon checklist step 5)
	if toolName == "add_note" {
		noteContent := strings.ToLower(args["content"])
		if strings.Contains(noteContent, "endpoint") || strings.Contains(noteContent, "api") ||
			strings.Contains(noteContent, "subdomain") || strings.Contains(noteContent, "inventory") ||
			strings.Contains(noteContent, "discovered") {
			state.EndpointInventorySaved = true
		}
	}

	return HookResult{}
}

// extractEndpointFromCmd extracts a URL path from curl/httpx commands.
// Returns a normalized endpoint like "/api/users" or "" if not found.
func extractEndpointFromCmd(cmd string) string {
	for _, prefix := range []string{"curl ", "httpx ", "wget "} {
		if !strings.Contains(cmd, prefix) {
			continue
		}
		for _, token := range strings.Fields(cmd) {
			if strings.HasPrefix(token, "http://") || strings.HasPrefix(token, "https://") {
				token = strings.Trim(token, "\"'")
				if parsed, err := url.Parse(token); err == nil && parsed.Host != "" {
					path := parsed.Path
					if path == "" || path == "/" {
						path = "/"
					}
					return parsed.Host + path
				}
			}
		}
	}
	return ""
}

// extractHostFromCmd extracts the target host from a command for dirbusting tracking.
func extractHostFromCmd(cmd string) string {
	for _, token := range strings.Fields(cmd) {
		token = strings.Trim(token, "\"'")
		if strings.HasPrefix(token, "http://") || strings.HasPrefix(token, "https://") {
			if parsed, err := url.Parse(token); err == nil && parsed.Host != "" {
				return parsed.Host
			}
		}
	}
	return ""
}

// ── hookStuckTracker ─────────────────────────────────────────────────────────
// Tracks consecutive browser/search actions and domain stickiness.
// Updates counters on ScanState — the actual nudge/force-skip is in hookStuckNudge.
func hookStuckTracker(state *ScanState, args map[string]string) HookResult {
	toolName := args["tool_name"]

	switch toolName {
	case "browser_action":
		state.ConsecutiveBrowser++
		state.ConsecutiveSearch = 0

		// Extract domain from URL arg if present
		if u := args["url"]; u != "" {
			if parsed, parseErr := url.Parse(u); parseErr == nil && parsed.Host != "" {
				host := parsed.Hostname()
				if state.StuckDomain == "" || state.StuckDomain == host {
					state.StuckDomain = host
					state.StuckIterations++
				} else {
					// Different domain — reset
					state.StuckDomain = host
					state.StuckIterations = 1
					state.ConsecutiveBrowser = 1
				}
			}
		} else {
			// No URL arg (snapshot, click, etc.) — still on same domain
			state.StuckIterations++
		}
	case "web_search":
		state.ConsecutiveSearch++
		q := strings.ToLower(args["query"])
		// If searching for bypass/cloudflare/captcha/WAF, it's a stuck signal
		if strings.Contains(q, "bypass") || strings.Contains(q, "cloudflare") ||
			strings.Contains(q, "captcha") || strings.Contains(q, "waf") ||
			strings.Contains(q, "javascript challenge") || strings.Contains(q, "security check") ||
			strings.Contains(q, "403 forbidden") || strings.Contains(q, "access denied") {
			state.StuckIterations++
		}
	default:
		// A non-browser, non-search tool call = real progress, reset counters
		if toolName != "add_note" && toolName != "read_notes" {
			state.ConsecutiveBrowser = 0
			state.ConsecutiveSearch = 0
			state.StuckIterations = 0
			state.StuckDomain = ""
		}
	}

	return HookResult{}
}

// ── hookStuckNudge ───────────────────────────────────────────────────────────
// Fires on OnStuckCheck. Produces soft nudge or hard force-skip based on
// stuck counters accumulated by hookStuckTracker.
func hookStuckNudge(state *ScanState, args map[string]string) HookResult {
	if state.ReconOnlyMode {
		return HookResult{}
	}

	// Hard limit: force-skip after too many stuck iterations
	if state.StuckIterations >= StuckHardLimit {
		forceMsg := fmt.Sprintf(`⛔ EXHAUSTION LIMIT: You have spent %d iterations on %q. You have exhausted browser-based approaches for this target. Close the browser and:
1. Try terminal-based testing (curl with different encodings/headers)
2. If terminal also fails, document what you tried in notes and move to the next target
3. This is NOT a failure — some targets require out-of-band techniques or authenticated access

Move on now — other targets may have lower defenses.`, state.StuckIterations, state.StuckDomain)

		// Reset hard to prevent getting stuck again on the same domain
		state.StuckIterations = 0
		state.StuckDomain = ""
		state.ConsecutiveBrowser = 0
		state.ConsecutiveSearch = 0

		return HookResult{
			Nudge:          forceMsg,
			ForceSkip:      true,
			CleanupBrowser: true,
			EmitMessage:    forceMsg,
		}
	}

	// Soft nudge: encourage the agent to pivot technique
	if (state.ConsecutiveBrowser >= StuckBrowserThreshold || state.ConsecutiveSearch >= StuckSearchThreshold) && state.StuckIterations >= StuckBrowserThreshold {
		nudge := fmt.Sprintf(`⚠️ PIVOT REQUIRED: You have spent %d iterations on %q using browser/search actions. The current approach is not working — you need to change your technique, NOT give up.

MANDATORY NEXT STEPS (in order):
1. Load the relevant bypass skill: read_skill(name="xss") or read_skill(name="sql-injection") — skills contain advanced WAF bypass payloads
2. Close the browser and try curl/httpx directly with different User-Agent, encoding, and content-types
3. Try WAF bypass techniques: double-URL encoding, Unicode, null bytes, HTTP Parameter Pollution, chunked transfer encoding
4. Try different entry points: alternative endpoints, API routes, different HTTP methods (PUT, PATCH, DELETE)
5. If the WAF blocks everything after trying ALL of the above, THEN move to the next target

DO NOT give up without trying at least 3 different bypass techniques from the loaded skills.`, state.StuckIterations, state.StuckDomain)

		// Reset so the nudge doesn't fire every iteration
		state.ConsecutiveBrowser = 0
		state.ConsecutiveSearch = 0

		return HookResult{
			Nudge:       nudge,
			EmitMessage: nudge,
		}
	}

	return HookResult{}
}

// ── hookWAFDetector ──────────────────────────────────────────────────────────
// Detects WAF/Cloudflare/security middleware from tool output patterns.
func hookWAFDetector(state *ScanState, args map[string]string) HookResult {
	output := strings.ToLower(args["output"])
	errorMsg := strings.ToLower(args["error"])
	combined := output + " " + errorMsg

	wafSignals := []string{
		"cloudflare", "akamai", "incapsula", "sucuri",
		"mod_security", "modsecurity", "aws waf", "azure front door",
		"checking your browser", "please wait while we verify",
		"access denied", "403 forbidden", "request blocked",
		"your request has been blocked", "security check",
		"ray id", "cf-ray", "attention required",
	}

	for _, signal := range wafSignals {
		if strings.Contains(combined, signal) {
			if !state.WAFDetected {
				state.WAFDetected = true
				return HookResult{
					EmitMessage: fmt.Sprintf("🛡️ WAF/Security middleware detected: %q — loading bypass techniques will help", signal),
				}
			}
			return HookResult{}
		}
	}

	return HookResult{}
}

// ── hookTechDetector ─────────────────────────────────────────────────────────
// Detects technology stack from HTTP headers and response patterns.
func hookTechDetector(state *ScanState, args map[string]string) HookResult {
	output := strings.ToLower(args["output"])

	techSignals := map[string][]string{
		"php":        {"x-powered-by: php", "phpsessid", ".php", "laravel", "symfony", "wordpress", "wp-content"},
		"nodejs":     {"x-powered-by: express", "connect.sid", "node.js", "next.js", "nuxt"},
		"java":       {"x-powered-by: servlet", "jsessionid", "java", "spring", "tomcat", "thymeleaf", "struts"},
		"python":     {"x-powered-by: flask", "x-powered-by: django", "csrfmiddlewaretoken", "django", "flask", "fastapi"},
		"ruby":       {"x-powered-by: phusion", "ruby", "rails", "_rails_session"},
		"aspnet":     {"x-powered-by: asp.net", "x-aspnet-version", ".aspx", "asp.net", "__viewstate"},
		"graphql":    {"graphql", "introspectionquery", "__schema"},
		"firebase":   {"firebaseapp", "firebase", "firestore"},
		"cloudflare": {"cf-ray", "cloudflare"},
	}

	detected := false
	for tech, signals := range techSignals {
		if state.DetectedTechs[tech] {
			continue // already detected
		}
		for _, signal := range signals {
			if strings.Contains(output, signal) {
				state.DetectedTechs[tech] = true
				detected = true
				break
			}
		}
	}

	if detected {
		techs := make([]string, 0, len(state.DetectedTechs))
		for t := range state.DetectedTechs {
			techs = append(techs, t)
		}
		return HookResult{
			EmitMessage: fmt.Sprintf("🔍 Tech stack detected: %s", strings.Join(techs, ", ")),
		}
	}

	return HookResult{}
}

// ── hookFinishGatekeeper ─────────────────────────────────────────────────────
// Decides if the agent has done enough work. Uses proportional coverage
// tracking: the gate checks how many UNIQUE endpoints were tested per
// vuln class, not just "did you run sqlmap once?".
func hookFinishGatekeeper(state *ScanState, args map[string]string) HookResult {
	state.FinishAttempts++

	// Discovery mode (Phase 1 enumeration): allow finish after minimum work
	if state.DiscoveryMode {
		if state.TerminalCalls < 3 {
			if state.ReconOnlyMode {
				return HookResult{
					Block:       true,
					BlockReason: fmt.Sprintf("Recon-only scan: only %d commands executed. Run at least 3 reconnaissance tools (for example dig/nslookup, nmap/naabu, httpx/whatweb/curl -I) before finishing.", state.TerminalCalls),
				}
			}
			return HookResult{
				Block:       true,
				BlockReason: fmt.Sprintf("Discovery phase: only %d commands executed. Run at least 3 enumeration tools (subfinder, crt.sh, findomain, assetfinder) before finishing.", state.TerminalCalls),
			}
		}
		return HookResult{}
	}

	iter := state.Iteration
	totalEndpoints := len(state.EndpointsTested)
	injectionCount := len(state.InjectionEndpoints)
	accessControlCount := len(state.AccessControlEndpoints)
	dirBustingCount := len(state.DirBustingHosts)

	// Absolute minimum: at least 3 iterations (sanity floor)
	if iter < 3 {
		return HookResult{
			Block:       true,
			BlockReason: fmt.Sprintf("Only %d iterations completed. Run at least basic recon before finishing.", iter+1),
		}
	}

	// If agent has done very little (< 5 terminal commands), reject
	if state.TerminalCalls < 5 {
		return HookResult{
			Block:       true,
			BlockReason: fmt.Sprintf("Only %d commands executed. You haven't done enough testing. Run port scanning, directory brute-forcing, and parameter testing before finishing.", state.TerminalCalls),
		}
	}

	// If recon wasn't done, reject
	if !state.ReconDone {
		return HookResult{
			Block:       true,
			BlockReason: "No reconnaissance detected. You must at least run: port scanning (nmap), directory discovery (ffuf/gobuster), and technology fingerprinting (whatweb/curl -sI) before finishing.",
		}
	}

	// ── Coverage-based gating ──
	// Instead of "did you run sqlmap once?", check how many unique
	// endpoints were tested per category. This prevents shallow scans
	// that test 1 out of 20 discovered endpoints.

	// Gate: Endpoint inventory must be saved (mandatory recon step 5)
	if !state.EndpointInventorySaved && iter < 50 {
		return HookResult{
			Block:       true,
			BlockReason: "You haven't saved your endpoint inventory with add_note yet. Complete the mandatory recon checklist: save ALL discovered endpoints, subdomains, and API bases to notes before finishing.",
		}
	}

	// Gate: Proportional coverage — require testing multiple endpoints
	if iter < 50 {
		missing := []string{}

		// Injection: require at least 3 unique endpoints tested (or all if < 3 exist)
		minInjection := minInt(3, maxInt(1, totalEndpoints/3))
		if injectionCount < minInjection {
			missing = append(missing, fmt.Sprintf("injection testing on %d more endpoints (tested %d/%d — try SQLi, XSS, SSRF, SSTI on different endpoints)",
				minInjection-injectionCount, injectionCount, totalEndpoints))
		}

		// Directory busting: require at least 1 host
		if dirBustingCount < 1 {
			missing = append(missing, "directory brute-forcing (ffuf/gobuster/dirsearch on at least 1 target)")
		}

		// Access control: require at least 2 unique endpoints tested
		minAccessControl := minInt(2, maxInt(1, totalEndpoints/4))
		if accessControlCount < minAccessControl {
			missing = append(missing, fmt.Sprintf("access control testing on %d more endpoints (tested %d — try IDOR, auth bypass, privilege escalation)",
				minAccessControl-accessControlCount, accessControlCount))
		}

		if len(missing) > 0 {
			return HookResult{
				Block:       true,
				BlockReason: fmt.Sprintf("Coverage gap: you've tested %d unique endpoints total but still need: %s", totalEndpoints, strings.Join(missing, "; ")),
			}
		}
	}

	// ── Iteration floor: 50 ──
	// Matches the system prompt: "Minimum 50 iterations for a thorough assessment"
	if iter < 50 {
		if state.FinishAttempts <= 2 {
			scannerNote := ""
			if !state.ScannerUsed {
				scannerNote = "\n- You haven't used any automated scanners (nuclei/ffuf) yet — consider running them on promising endpoints"
			}
			skillNote := ""
			if state.SkillsLoaded == 0 {
				skillNote = "\n- ⚠️ You haven't loaded ANY deep knowledge skills (read_skill). Load skills for the target's tech stack to get expert-level payloads and bypass techniques!"
			}
			coverageNote := fmt.Sprintf("\n- Endpoints tested: %d (injection: %d, access control: %d, dirbusting hosts: %d)",
				totalEndpoints, injectionCount, accessControlCount, dirBustingCount)
			nudgeMsg := fmt.Sprintf(`⚠️ Only %d/50 iterations completed. You still have capacity to test more.

Before finishing, verify you have covered:
- All discovered endpoints and parameters tested MANUALLY
- Common vulnerability classes (SQLi, XSS, SSRF, IDOR, broken auth)
- Technology-specific CVEs
- API endpoints found in JavaScript files%s%s%s

Continue testing. Call finish again after iteration 50.`, iter, coverageNote, scannerNote, skillNote)

			return HookResult{
				Block:       true,
				BlockReason: nudgeMsg,
			}
		}
	}

	// After 50 iterations with coverage met: allow finish
	return HookResult{}
}

// maxInt returns the larger of two ints.
func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// minInt returns the smaller of two ints.
func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// ── hookEmptyResponseHandler ─────────────────────────────────────────────────
// Handles LLM returning empty responses. Nudges after 5, force-stops after 12.
func hookEmptyResponseHandler(state *ScanState, args map[string]string) HookResult {
	state.EmptyResponseCount++

	if state.EmptyResponseCount >= 12 {
		return HookResult{
			ForceSkip:   true,
			EmitMessage: "⛔ LLM returned 12 consecutive empty responses. Force finishing to prevent infinite loop.",
		}
	}

	if state.EmptyResponseCount >= 5 {
		return HookResult{
			Nudge: "Your last responses were empty. You MUST call a tool NOW. Use terminal_execute to run your next command, or call finish if you are truly done.",
		}
	}

	return HookResult{}
}

// ── hookNoToolHandler ────────────────────────────────────────────────────────
// Handles LLM responding without any tool calls. Nudges after 3, force-stops after 15.
func hookNoToolHandler(state *ScanState, args map[string]string) HookResult {
	state.NoToolCount++

	if state.NoToolCount >= 15 {
		return HookResult{
			ForceSkip:   true,
			EmitMessage: "⛔ LLM failed to call any tools for 15 consecutive responses. Force finishing.",
		}
	}

	if state.NoToolCount >= 3 {
		return HookResult{
			Nudge: `You MUST use tools to interact with the target. Do not just explain — take action NOW.

To execute a command, use:
<function=terminal_execute>
<parameter=command>your command here</parameter>
</function>

To finish the task, use:
<function=finish>
<parameter=summary>Your summary here</parameter>
</function>

Call a tool NOW in your next response.`,
		}
	}

	return HookResult{
		Nudge: "Please use the available tools by calling them with the XML format shown in the system prompt. Do not just describe what you would do — actually call the tools.",
	}
}

// ── hookAutoSkillSuggester ───────────────────────────────────────────────────
// On iteration start, suggests loading skills if techs have been detected
// but no skills have been loaded yet. Only fires once, at iteration 15.
func hookAutoSkillSuggester(state *ScanState, args map[string]string) HookResult {
	if state.ReconOnlyMode {
		return HookResult{}
	}

	// Fire once at iteration >= 15 — early enough to help, late enough to have tech data
	if state.Iteration < 15 || state.SkillSuggestionFired {
		return HookResult{}
	}

	if state.SkillsLoaded > 0 {
		return HookResult{} // already loading skills
	}

	if len(state.DetectedTechs) == 0 && !state.WAFDetected {
		return HookResult{} // no tech data to suggest from
	}

	suggestions := []string{}
	techSkillMap := map[string]string{
		"php":    "sql-injection",
		"nodejs": "prototype-pollution",
		"java":   "ssti",
		"python": "ssti",
		"aspnet": "sql-injection",
	}

	for tech := range state.DetectedTechs {
		if skill, ok := techSkillMap[tech]; ok {
			suggestions = append(suggestions, fmt.Sprintf("read_skill(name=%q) for %s targets", skill, tech))
		}
	}

	if state.WAFDetected {
		suggestions = append(suggestions, `read_skill(name="xss") and read_skill(name="sql-injection") for WAF bypass payloads`)
	}

	if len(suggestions) == 0 {
		return HookResult{}
	}

	state.SkillSuggestionFired = true
	return HookResult{
		Nudge: fmt.Sprintf(`💡 SKILL RECOMMENDATION: You have detected technologies but haven't loaded any deep knowledge skills yet. Consider:
%s

Skills contain expert-level payloads, WAF bypass techniques, and technology-specific attack chains that significantly improve testing depth.`, strings.Join(suggestions, "\n")),
	}
}

// ── hookResetOnSuccess ───────────────────────────────────────────────────────
// Centralizes counter resets that were previously scattered in agent.go.
// Fires on OnHealthyResponse (a non-empty response that contained tool calls).
func hookResetOnSuccess(state *ScanState, args map[string]string) HookResult {
	state.ConsecutiveErrors = 0
	state.EmptyResponseCount = 0
	state.NoToolCount = 0
	return HookResult{}
}
