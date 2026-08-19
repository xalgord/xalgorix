package agent

import (
	"errors"
	"fmt"
	"math/rand"
	"net"
	"strings"
	"testing"

	"github.com/xalgord/xalgorix/v4/internal/scopeguard"
)

// TestShouldBlockForOutOfScope_AllowsThirdPartyHost is the inverted
// successor to the original "blocks third party host" test (Bucket A
// of the scope-guard-local-only spec → Test Surface Migration). Each
// row references a Public_OOS_Host — including 159.223.74.62, a real
// public DigitalOcean address — and the post-fix guard MUST allow
// every one of them: engagement-scope policing is no longer the
// agent guard's job. Each row asserts blocked == false and that
// args are byte-identical pre- and post-call (Property 1).
//
// Validates: Requirements 2.1, 2.2, 2.3, 2.4.
func TestShouldBlockForOutOfScope_AllowsThirdPartyHost(t *testing.T) {
	a := &Agent{}
	a.SetActivityPolicy("active", "active", []string{"https://pentest-ground.com"})

	cases := []struct {
		name string
		tool string
		args map[string]string
	}{
		{
			name: "terminal_execute against unrelated IP",
			tool: "terminal_execute",
			args: map[string]string{
				"command": "curl http://159.223.74.62:9999/?title=%22%3E%3Csvg/onload=alert(1)%3E",
			},
		},
		{
			name: "report_vulnerability with unrelated target field",
			tool: "report_vulnerability",
			args: map[string]string{
				"title":    "XSS in Grafana",
				"target":   "http://159.223.74.62:9999",
				"endpoint": "http://159.223.74.62:9999/?title=%3Csvg",
				"severity": "high",
			},
		},
		{
			name: "browser_action navigating to unrelated host",
			tool: "browser_action",
			args: map[string]string{
				"action": "navigate",
				"url":    "https://attacker.example/callback",
			},
		},
		{
			name: "python_action requesting unrelated host",
			tool: "python_action",
			args: map[string]string{
				"code": "import requests; requests.get('http://example.org/admin')",
			},
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			before := cloneArgs(tc.args)
			blocked, reason := a.shouldBlockForOutOfScope(tc.tool, tc.args)
			if blocked {
				t.Fatalf("expected %s with args %v to be allowed, got blocked: %s", tc.tool, tc.args, reason)
			}
			if !argsEqual(tc.args, before) {
				t.Fatalf("args mutated: before=%v after=%v", before, tc.args)
			}
		})
	}
}

// TestShouldBlockForOutOfScope_AllowsInScope confirms the guard does
// not block legitimate tool calls against the configured target or
// its subdomains.
func TestShouldBlockForOutOfScope_AllowsInScope(t *testing.T) {
	a := &Agent{}
	a.SetActivityPolicy("active", "active", []string{"https://pentest-ground.com"})

	cases := []struct {
		name string
		tool string
		args map[string]string
	}{
		{
			name: "exact target",
			tool: "terminal_execute",
			args: map[string]string{"command": "nmap -sV pentest-ground.com"},
		},
		{
			name: "subdomain",
			tool: "terminal_execute",
			args: map[string]string{"command": "curl https://api.pentest-ground.com/v1/users"},
		},
		{
			name: "URL form with port",
			tool: "browser_action",
			args: map[string]string{"url": "https://app.pentest-ground.com:8443/admin"},
		},
		{
			name: "report_vulnerability against subdomain",
			tool: "report_vulnerability",
			args: map[string]string{
				"target":   "https://api.pentest-ground.com",
				"endpoint": "https://api.pentest-ground.com/v1/users",
				"title":    "IDOR",
				"severity": "high",
			},
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			if blocked, reason := a.shouldBlockForOutOfScope(tc.tool, tc.args); blocked {
				t.Fatalf("expected %s with args %v to be allowed, got blocked: %s", tc.tool, tc.args, reason)
			}
		})
	}
}

// TestShouldBlockForOutOfScope_AllowsHostlessCommands confirms tool
// calls that don't name any host (local artifact analysis like grep,
// awk, jq over recon output files) are allowed.
func TestShouldBlockForOutOfScope_AllowsHostlessCommands(t *testing.T) {
	a := &Agent{}
	a.SetActivityPolicy("active", "active", []string{"https://pentest-ground.com"})

	cases := []map[string]string{
		{"command": "ls -la"},
		{"command": "grep 'password' notes.json"},
		{"command": "jq '.vulns[]' scan.json"},
		{"command": "wc -l live_subdomains.txt"},
	}
	for _, args := range cases {
		if blocked, reason := a.shouldBlockForOutOfScope("terminal_execute", args); blocked {
			t.Fatalf("hostless command %v should be allowed, got blocked: %s", args, reason)
		}
	}
}

// TestShouldBlockForOutOfScope_AllowsAnywhereWhenNoScope confirms
// the gate's behavior when no activity hosts are configured. The
// guard is no longer "disabled" on empty scope; it just has no
// Public_OOS_Host rule left to fire (engagement scope is not
// consulted at all post-fix). Public_OOS_Host references therefore
// flow through. The Local_Or_Listener_Host rule, however, MUST
// remain active even with empty scope — see Requirement 3.7's
// parenthetical and design.md → "Open Question: Requirement 3.7".
//
// Validates: Requirements 2.2, 3.7.
func TestShouldBlockForOutOfScope_AllowsAnywhereWhenNoScope(t *testing.T) {
	t.Run("public OOS host allowed when scope is empty", func(t *testing.T) {
		a := &Agent{}
		// activityHosts left empty
		args := map[string]string{"command": "curl http://anywhere.example"}
		before := cloneArgs(args)
		if blocked, reason := a.shouldBlockForOutOfScope("terminal_execute", args); blocked {
			t.Fatalf("expected public OOS host to be allowed when scope is empty, got blocked: %s", reason)
		}
		if !argsEqual(args, before) {
			t.Fatalf("args mutated: before=%v after=%v", before, args)
		}
	})

	t.Run("loopback still blocks when scope is empty (Req 3.7)", func(t *testing.T) {
		a := &Agent{}
		// activityHosts left empty; localGuard is the zero Config
		// which IsLocalOrListener treats as BindAddr "127.0.0.1".
		args := map[string]string{"command": "curl http://127.0.0.1/admin"}
		before := cloneArgs(args)
		blocked, reason := a.shouldBlockForOutOfScope("terminal_execute", args)
		if !blocked {
			t.Fatalf("Requirement 3.7: loopback MUST still block when scope is empty, got allow")
		}
		if reason == "" {
			t.Fatalf("expected non-empty rejection reason")
		}
		if !argsEqual(args, before) {
			t.Fatalf("args mutated: before=%v after=%v", before, args)
		}
	})
}

// TestExtractHostFromTokenForScope tests the host-extraction primitive
// for the variety of token shapes the agent emits.
func TestExtractHostFromTokenForScope(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"https://example.com/path", "example.com"},
		{"http://example.com:8080/path", "example.com"},
		{"example.com:8080", "example.com"},
		{"example.com", "example.com"},
		{"159.223.74.62", "159.223.74.62"},
		{"159.223.74.62:9999", "159.223.74.62"},
		{"[2001:db8::1]:443", "2001:db8::1"},
		{"./script.sh", ""},
		{"/tmp/foo.txt", ""},
		{"../etc/passwd", ""},
		{"v1.2.3", ""},
		{"1.2.3", ""},
		{"--rate-limit", ""},
		{"", ""},
	}
	for _, tc := range cases {
		got := extractHostFromTokenForScope(tc.in)
		if got != tc.want {
			t.Errorf("extractHostFromTokenForScope(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// TestExtractHostsFromArgs verifies multi-token extraction.
func TestExtractHostsFromArgs(t *testing.T) {
	args := map[string]string{
		"command": `curl -H "Host: api.example.com" https://example.com/foo && nmap evil.org`,
	}
	hosts := extractHostsFromArgs(args)
	got := strings.Join(hosts, ",")
	// Order is insertion-order; the actual hosts must include the three
	// distinct ones from the command.
	for _, want := range []string{"api.example.com", "example.com", "evil.org"} {
		if !strings.Contains(got, want) {
			t.Errorf("extractHostsFromArgs(%v) = %v, missing %q", args, hosts, want)
		}
	}
}

// TestExtractHostsFromArgs_QueryParamRedirect locks in the URL-sweep
// path. URLs nested inside query parameters, fragments, or bare
// `key=value` forms must surface their embedded host alongside the
// outer in-scope host so the gate sees the full set, and a gated
// tool that names the wrapped OOS host must be rejected.
//
// Validates Requirements 1.2, 1.3, 1.5, 1.6.
func TestExtractHostsFromArgs_QueryParamRedirect(t *testing.T) {
	extractCases := []struct {
		name     string
		args     map[string]string
		wantAll  []string
		wantNone []string
	}{
		{
			name:    "redirect param surfaces both hosts",
			args:    map[string]string{"url": "https://in-scope.example/redirect?next=https://oos.example/path"},
			wantAll: []string{"in-scope.example", "oos.example"},
		},
		{
			name:    "fragment-embedded URL surfaces both hosts",
			args:    map[string]string{"url": "https://in-scope.example/page#https://oos.example/p"},
			wantAll: []string{"in-scope.example", "oos.example"},
		},
		{
			name:    "bare key=value pair splits and extracts host",
			args:    map[string]string{"url": "next=evil.example"},
			wantAll: []string{"evil.example"},
		},
		{
			// Req 1.5: in-scope host, OOS host, filename, and
			// version-like token in one value — the host-classification
			// rules must apply to each token independently.
			name:     "mix of in-scope, OOS, filename, and version",
			args:     map[string]string{"command": "scanner --version v1.2.3 --in pentest-ground.com --out notes.json target=evil.example"},
			wantAll:  []string{"pentest-ground.com", "evil.example"},
			wantNone: []string{"notes.json", "v1.2.3", "1.2.3"},
		},
		{
			// Req 1.6: the URL-sweep helper hits "https://user:pass"
			// (which url.Parse rejects with "invalid port"). The sweep
			// must drop it silently and the separator pass must still
			// recover the trailing bare host.
			name:    "malformed URL then bare host",
			args:    map[string]string{"url": "https://user:pass evil.example"},
			wantAll: []string{"evil.example"},
		},
	}
	for _, tc := range extractCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			hosts := extractHostsFromArgs(tc.args)
			joined := "," + strings.Join(hosts, ",") + ","
			for _, want := range tc.wantAll {
				if !strings.Contains(joined, ","+want+",") {
					t.Errorf("extractHostsFromArgs(%v) = %v, missing %q", tc.args, hosts, want)
				}
			}
			for _, none := range tc.wantNone {
				if strings.Contains(joined, ","+none+",") {
					t.Errorf("extractHostsFromArgs(%v) = %v, %q must not appear", tc.args, hosts, none)
				}
			}
		})
	}

	// Req 1.3 (post-fix Bucket A inversion per scope-guard-local-only
	// → Test Surface Migration): the wrapped host is `oos.example`,
	// a Public_OOS_Host. The narrowed guard does NOT consult
	// Activity_Hosts, so a redirect-style URL whose query parameter
	// wraps a Public_OOS_Host MUST be allowed. The extraction
	// sub-cases above keep — the tokenizer still surfaces every
	// embedded host — but the gating verdict on the wrapped OOS
	// host flips from "blocked" to "allowed". The Local_Or_Listener
	// behavior for wrapped local IPs is exercised separately by
	// TestProperty_LocalOrListenerInvarianceUnderTokenizationShape.
	t.Run("gated tool allowed on wrapped OOS host", func(t *testing.T) {
		a := &Agent{}
		a.SetActivityPolicy("active", "active", []string{"https://pentest-ground.com"})
		args := map[string]string{
			"url": "https://app.pentest-ground.com/redirect?next=https://oos.example/path",
		}
		before := cloneArgs(args)
		blocked, reason := a.shouldBlockForOutOfScope("browser_action", args)
		if blocked {
			t.Fatalf("expected redirect-style Public_OOS_Host wrapper to be allowed, got blocked: %s", reason)
		}
		if !argsEqual(args, before) {
			t.Fatalf("args mutated: before=%v after=%v", before, args)
		}
	})
}

// TestExtractHostsFromArgs_UserinfoForm locks in the userinfo-aware
// extraction path. Both the bare `user@host` shape (caught by the
// new `@` separator in scopeHostTokenSplit) and the
// `https://user:pass@host` shape (caught by url.Parse via the URL
// sweep) must surface the host portion case-insensitively, and a
// gated tool naming a userinfo-wrapped OOS host must be rejected.
//
// Validates Requirement 1.4.
func TestExtractHostsFromArgs_UserinfoForm(t *testing.T) {
	extractCases := []struct {
		name string
		args map[string]string
		want string
	}{
		{
			name: "bare user@host",
			args: map[string]string{"target": "user@oos.example"},
			want: "oos.example",
		},
		{
			name: "case-insensitive bare user@host",
			args: map[string]string{"target": "USER@OOS.EXAMPLE"},
			want: "oos.example",
		},
		{
			name: "userinfo URL",
			args: map[string]string{"target": "https://user:pass@oos.example"},
			want: "oos.example",
		},
		{
			name: "case-insensitive userinfo URL",
			args: map[string]string{"target": "https://USER:PASS@OOS.EXAMPLE"},
			want: "oos.example",
		},
	}
	for _, tc := range extractCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			hosts := extractHostsFromArgs(tc.args)
			found := false
			for _, h := range hosts {
				if h == tc.want {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("extractHostsFromArgs(%v) = %v, missing %q", tc.args, hosts, tc.want)
			}
		})
	}

	// Gated-tool path (post-fix Bucket A inversion per
	// scope-guard-local-only → Test Surface Migration): a userinfo-
	// wrapped OOS host inside a terminal_execute command MUST be
	// allowed, because oos.example is a Public_OOS_Host and the
	// narrowed guard no longer consults Activity_Hosts.
	t.Run("gated tool allowed on userinfo OOS host", func(t *testing.T) {
		a := &Agent{}
		a.SetActivityPolicy("active", "active", []string{"https://pentest-ground.com"})
		for _, raw := range []string{
			"user@oos.example",
			"https://user:pass@oos.example",
		} {
			args := map[string]string{"command": "curl " + raw}
			before := cloneArgs(args)
			blocked, reason := a.shouldBlockForOutOfScope("terminal_execute", args)
			if blocked {
				t.Errorf("expected userinfo Public_OOS_Host form %q to be allowed, got blocked: %s", raw, reason)
				continue
			}
			if !argsEqual(args, before) {
				t.Errorf("args mutated for %q: before=%v after=%v", raw, before, args)
			}
		}
	})
}

// TestScopeHostTokenSplit_NewSeparators pins the separator switch to
// the four runes added in Wave A — `=`, `?`, `#`, and `@` — without
// regressing the pre-existing whitespace and shell metacharacter
// boundaries.
//
// Validates Requirement 1.1.
func TestScopeHostTokenSplit_NewSeparators(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want []string
	}{
		{
			name: "equals splits",
			in:   "key=evil.example",
			want: []string{"key", "evil.example"},
		},
		{
			name: "question splits",
			in:   "host.example?id=1",
			want: []string{"host.example", "id", "1"},
		},
		{
			name: "fragment splits",
			in:   "host.example#anchor",
			want: []string{"host.example", "anchor"},
		},
		{
			name: "at splits",
			in:   "user@oos.example",
			want: []string{"user", "oos.example"},
		},
		{
			name: "all four new separators together",
			in:   "k=v?p#f@h",
			want: []string{"k", "v", "p", "f", "h"},
		},
		{
			name: "pre-existing separators still split",
			in:   "a,b;c|d&e<f>g",
			want: []string{"a", "b", "c", "d", "e", "f", "g"},
		},
		{
			name: "whitespace, brackets, and quotes still split",
			in:   "a\tb\nc \"d\" 'e' (f) [g] {h}",
			want: []string{"a", "b", "c", "d", "e", "f", "g", "h"},
		},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			got := scopeHostTokenSplit(tc.in)
			if strings.Join(got, "|") != strings.Join(tc.want, "|") {
				t.Errorf("scopeHostTokenSplit(%q) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

// runAddNoteRedaction previously mirrored the pre-gate redaction step
// the agent loop ran before shouldBlockForOutOfScope. That production
// wiring at internal/agent/agent.go:1614–1631 was removed in task 3.6
// of the scope-guard-local-only spec, so this helper is now a no-op
// pass-through: it never mutates args and always reports zero
// redactions. Kept temporarily so the bug-condition exploration test
// keeps its symbolic call site; task 3.8 deletes the redaction-era
// tests that still consume it.
func runAddNoteRedaction(a *Agent, args map[string]string) int {
	_ = a
	_ = args
	return 0
}

// TestAddNote_PassesThroughOOSHosts pins the byte-identical
// pass-through guarantee for non-gated tools. add_note is not in
// the gated tool list and the pre-gate redaction wiring was removed
// in task 3.6 of the scope-guard-local-only spec. Even when key /
// value carry Public_OOS_Host text, the args MUST reach the tool
// handler byte-identical (no redaction marker substitution, no
// mutation of any sort).
//
// Validates: Requirements 2.4, 3.9.
func TestAddNote_PassesThroughOOSHosts(t *testing.T) {
	a := &Agent{}
	a.SetActivityPolicy("active", "active", []string{"https://pentest-ground.com"})

	cases := []struct {
		name string
		args map[string]string
	}{
		{
			name: "OOS host text in key and value",
			args: map[string]string{
				"key":   "leak_oos.example",
				"value": "saw https://evil.example/dump",
			},
		},
		{
			name: "in-scope host text in key and value",
			args: map[string]string{
				"key":   "csrf_token_app",
				"value": "found at https://app.pentest-ground.com/login",
			},
		},
		{
			name: "no host tokens at all",
			args: map[string]string{
				"key":   "phase_done",
				"value": "recon complete, see notes.json",
			},
		},
		{
			name: "missing key (passthrough)",
			args: map[string]string{
				"value": "ok",
			},
		},
		{
			name: "missing value (passthrough)",
			args: map[string]string{
				"key": "phase_done",
			},
		},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			before := cloneArgs(tc.args)
			blocked, reason := a.shouldBlockForOutOfScope("add_note", tc.args)
			if blocked {
				t.Fatalf("add_note must bypass the gate, got blocked: %s", reason)
			}
			if !argsEqual(tc.args, before) {
				t.Fatalf("add_note args mutated:\n  before=%v\n  after =%v", before, tc.args)
			}
			for _, v := range tc.args {
				if strings.Contains(v, "[redacted: out-of-scope host]") {
					t.Errorf("add_note arg gained a redaction marker (wiring should be deleted): %q", v)
				}
			}
		})
	}

	// Empty activityHosts: add_note still passes through untouched
	// — no redaction wiring exists and the gate doesn't apply to
	// add_note in any case.
	t.Run("empty activityHosts pass-through", func(t *testing.T) {
		bare := &Agent{}
		args := map[string]string{
			"key":   "leak_from_oos.example",
			"value": "saw https://evil.example/dump",
		}
		before := cloneArgs(args)
		blocked, reason := bare.shouldBlockForOutOfScope("add_note", args)
		if blocked {
			t.Fatalf("add_note with empty scope must pass through, got blocked: %s", reason)
		}
		if !argsEqual(args, before) {
			t.Fatalf("scope-less add_note mutated args:\n  before=%v\n  after =%v", before, args)
		}
	})
}

// ───────────────────────────────────────────────────────────────────
// Bug condition exploration property test (spec: scope-guard-local-only,
// task 1). This test encodes Property 1 ("Public_OOS_Host pass-through
// through Agent_Scope_Guard") from design.md → "Correctness Properties"
// and bugfix.md → "Properties":
//
//   FOR ALL X WHERE isBugCondition(X) DO
//     (blocked, _) := shouldBlockForOutOfScope(X.toolName, X.toolArgs)
//     ASSERT blocked = false
//     ASSERT X.toolArgs is byte-identical pre- and post-call
//   END FOR
//
// where isBugCondition(X) is (per design.md → "Bug Condition"):
//
//   X.toolName ∈ GATED_TOOLS
//   ∧ Activity_Hosts ≠ ∅
//   ∧ extractHostsFromArgs(X.toolArgs) ≠ ∅
//   ∧ ∃ h: ¬isLocalOrListenerHost(h) ∧ ¬hostInScope(h, Activity_Hosts)
//   ∧ ¬∃ h: isLocalOrListenerHost(h)
//
// THE TEST IS EXPECTED TO FAIL ON UNFIXED CODE. The failure confirms
// the "Conflated SSRF-vs-scope" root-cause hypothesis from design.md →
// "Hypothesized Root Cause": today the agent guard rejects any
// host-shaped token outside Activity_Hosts, so a Public_OOS_Host inside
// any Gated_Tool argument trips the gate. After task 3 narrows the
// guard to Local_Or_Listener_Host this same test passes.

// scopeBugSeed is the fixed seed used by the bug-condition exploration
// PBT. Documented here so reruns reproduce the same counterexamples.
const scopeBugSeed = int64(0x53434F50455F4255) // "SCOPE_BU"

// gatedToolsForBugProperty enumerates every Gated_Tool name the agent
// guard inspects today. Mirrors the switch in shouldBlockForOutOfScope
// (internal/agent/agent.go ~line 821) so the property covers every
// gated path including report_vulnerability's belt-and-braces leg.
// Covers Requirements 2.1, 2.2, 2.3.
var gatedToolsForBugProperty = []string{
	"terminal_execute",
	"python_action",
	"browser_action",
	"page_agent",
	"pageagent",
	"report_vulnerability",
}

// genPublicOOSLabel returns a host-shaped label that:
//   - uses only ASCII letters / digits / dots / dashes (no slashes),
//   - has at least two dot-separated labels (so the tokenizer treats
//     it as a host, not a bare word),
//   - is not version-shaped (won't be filtered by isVersionLike),
//   - is not file-name-shaped (won't be filtered by looksLikeFilename),
//   - is not a reserved-IP literal (composed entirely of letters in
//     the TLD, so net.ParseIP rejects it),
//   - is not equal to or a subdomain of any string in avoid (so it
//     stays out of Activity_Hosts).
//
// extractHostFromTokenForScope returning a non-empty host on the
// generated label is asserted by the caller — that's the "tokenizer
// surfaces it" precondition for isBugCondition.
func genPublicOOSLabel(r *rand.Rand, avoid []string) string {
	const letters = "abcdefghijklmnopqrstuvwxyz"
	const lettersDigits = "abcdefghijklmnopqrstuvwxyz0123456789"
	for attempt := 0; attempt < 100; attempt++ {
		// 2 to 4 labels, each 3 to 10 runes. First/last char of each
		// label is a letter (avoids leading-digit / trailing-dash
		// shapes that some resolvers reject and that aren't useful
		// here). Final label (TLD) is letters-only, length 2 to 6.
		nLabels := 2 + r.Intn(3)
		var sb strings.Builder
		for i := 0; i < nLabels; i++ {
			if i > 0 {
				sb.WriteByte('.')
			}
			isTLD := i == nLabels-1
			labelLen := 3 + r.Intn(8)
			if isTLD {
				labelLen = 2 + r.Intn(5)
			}
			for j := 0; j < labelLen; j++ {
				switch {
				case isTLD:
					sb.WriteByte(letters[r.Intn(len(letters))])
				case j == 0 || j == labelLen-1:
					sb.WriteByte(letters[r.Intn(len(letters))])
				default:
					alphabet := lettersDigits
					// 1-in-6 chance of a dash in interior positions.
					if r.Intn(6) == 0 {
						sb.WriteByte('-')
						continue
					}
					sb.WriteByte(alphabet[r.Intn(len(alphabet))])
				}
			}
		}
		label := sb.String()

		// Reject if version-like, file-name-shaped, or IP-shaped.
		if isVersionLike(label) || looksLikeFilename(label) {
			continue
		}
		if net.ParseIP(label) != nil {
			continue
		}
		// Tokenizer must surface the label as a host.
		if extractHostFromTokenForScope(label) == "" {
			continue
		}
		// Reject if in scope (equal to, subdomain of, or contains an
		// avoid token).
		clash := false
		for _, a := range avoid {
			a = strings.ToLower(strings.TrimSpace(a))
			if a == "" {
				continue
			}
			if label == a || strings.HasSuffix(label, "."+a) || strings.Contains(label, a) {
				clash = true
				break
			}
		}
		if clash {
			continue
		}
		return label
	}
	// Fallback — astronomically unlikely. Shape obviously OOS.
	return "rare-public-oos.example"
}

// argShapeName labels each of the five argument shapes the existing
// tokenizer surfaces (per design.md → "Property-based shape"):
// bare host, full URL, userinfo wrapper, redirect query parameter,
// fragment-embedded URL.
type argShape int

const (
	shapeBareHost argShape = iota
	shapeFullURL
	shapeUserinfoURL
	shapeRedirectQuery
	shapeFragmentEmbed
)

func (s argShape) String() string {
	switch s {
	case shapeBareHost:
		return "bare-host"
	case shapeFullURL:
		return "full-url"
	case shapeUserinfoURL:
		return "userinfo-url"
	case shapeRedirectQuery:
		return "redirect-query"
	case shapeFragmentEmbed:
		return "fragment-embed"
	}
	return "unknown"
}

// embedOOSHostInArg returns a tool-argument value that embeds host
// using the requested shape. inScope is the operator's configured
// host (used as the wrapper origin in redirect/fragment shapes so
// the value also contains an in-scope reference, mirroring how
// these shapes appear in real LLM output).
func embedOOSHostInArg(shape argShape, host, inScope string) string {
	switch shape {
	case shapeBareHost:
		return host
	case shapeFullURL:
		return "https://" + host + "/admin"
	case shapeUserinfoURL:
		return "https://user:pass@" + host + "/path"
	case shapeRedirectQuery:
		return "https://" + inScope + "/redirect?next=https://" + host + "/path"
	case shapeFragmentEmbed:
		return "https://" + inScope + "/page#https://" + host + "/p"
	}
	return host
}

// argFieldForTool picks the conventional argument field the agent
// uses for each Gated_Tool. report_vulnerability also gets the OOS
// host on the explicit `target` field so the belt-and-braces leg is
// exercised.
func argFieldForTool(toolName string) string {
	switch toolName {
	case "browser_action":
		return "url"
	case "python_action":
		return "code"
	case "report_vulnerability":
		return "target"
	default:
		// terminal_execute, page_agent, pageagent
		return "command"
	}
}

// shapeIntoCommand wraps the OOS-bearing payload into a plausible
// command/code string for tools that take free-form text. Keeps the
// value byte-stable so the byte-identical assertion is meaningful.
func shapeIntoCommand(toolName, payload string) string {
	switch toolName {
	case "python_action":
		return "import requests; requests.get('" + payload + "')"
	case "terminal_execute", "page_agent", "pageagent":
		return "curl " + payload
	default:
		return payload
	}
}

// cloneArgs returns a deep copy of args so the caller can compare
// pre- and post-call maps byte-identically.
func cloneArgs(args map[string]string) map[string]string {
	out := make(map[string]string, len(args))
	for k, v := range args {
		out[k] = v
	}
	return out
}

// argsEqual reports whether a and b have identical keys and
// byte-identical values.
func argsEqual(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if bv, ok := b[k]; !ok || bv != v {
			return false
		}
	}
	return true
}

// TestBugCondition_PublicOOSHostPassThrough is the property-based
// exploration test for spec scope-guard-local-only, task 1.
//
// Property 1 (Bug Condition): for every (toolName, toolArgs) where
// isBugCondition holds — Gated_Tool, non-empty Activity_Hosts, at
// least one Public_OOS_Host token, no Local_Or_Listener_Host tokens —
// the fixed shouldBlockForOutOfScope returns (false, "") and leaves
// toolArgs byte-identical to the input.
//
// Generators (per design.md → "Property-based shape"):
//   - random Public_OOS_Host labels via genPublicOOSLabel,
//   - five argument shapes via embedOOSHostInArg,
//   - every Gated_Tool name via gatedToolsForBugProperty.
//
// Plus four scoped deterministic counterexamples (per design.md →
// "Exploratory Bug Condition Checking → Test Cases") pinned to
// anchor the property at known-failing inputs.
//
// Validates: Requirements 1.1, 1.2, 1.3, 1.4, 2.1, 2.2, 2.3, 2.4.
//
// EXPECTED OUTCOME on UNFIXED code: this test FAILS. The failure
// confirms the bug exists. After task 3's fix the same test passes.
func TestBugCondition_PublicOOSHostPassThrough(t *testing.T) {
	// ── Scoped deterministic counterexamples ────────────────────
	// These four cases are pinned per design.md → "Exploratory Bug
	// Condition Checking → Test Cases". They serve as reproducible
	// anchors for the property and survive any future change to
	// the random generator.

	t.Run("scoped/python_attribute_reference", func(t *testing.T) {
		// Case 1: python_action with `requests.get(...)` and scope
		// {pentest-ground.com}. Today rejected as
		// `"requests.get" is not in scope`. Expected: allow.
		a := &Agent{}
		a.SetActivityPolicy("active", "active", []string{"https://pentest-ground.com"})
		args := map[string]string{
			"code": "import requests; requests.get('http://example.org/admin')",
		}
		before := cloneArgs(args)
		blocked, reason := a.shouldBlockForOutOfScope("python_action", args)
		if blocked {
			t.Fatalf("BUG: python_action with `requests.get` rejected: %s", reason)
		}
		if !argsEqual(args, before) {
			t.Fatalf("BUG: python_action args mutated: before=%v after=%v", before, args)
		}
	})

	t.Run("scoped/bare_third_party_host", func(t *testing.T) {
		// Case 2: terminal_execute against pentest-ground.com with
		// scope {gov.pk, dgip.gov.pk, clientfeedback.dgip.gov.pk}.
		// Today rejected as `"pentest-ground.com" is not in scope`.
		// Expected: allow.
		a := &Agent{}
		a.SetActivityPolicy("active", "active", []string{
			"https://gov.pk",
			"https://dgip.gov.pk",
			"https://clientfeedback.dgip.gov.pk",
		})
		args := map[string]string{"command": "nmap pentest-ground.com"}
		before := cloneArgs(args)
		blocked, reason := a.shouldBlockForOutOfScope("terminal_execute", args)
		if blocked {
			t.Fatalf("BUG: terminal_execute against pentest-ground.com rejected: %s", reason)
		}
		if !argsEqual(args, before) {
			t.Fatalf("BUG: terminal_execute args mutated: before=%v after=%v", before, args)
		}
	})

	t.Run("scoped/report_vulnerability_oos_target", func(t *testing.T) {
		// Case 3: report_vulnerability with target=https://oos.example
		// and scope {pentest-ground.com}. Today rejected via the
		// explicit-target leg with the
		// `report_vulnerability target … is out of scope` reason.
		// Expected: allow.
		a := &Agent{}
		a.SetActivityPolicy("active", "active", []string{"https://pentest-ground.com"})
		args := map[string]string{
			"title":    "XSS",
			"target":   "https://oos.example",
			"endpoint": "https://oos.example/login?title=<svg>",
			"severity": "high",
		}
		before := cloneArgs(args)
		blocked, reason := a.shouldBlockForOutOfScope("report_vulnerability", args)
		if blocked {
			t.Fatalf("BUG: report_vulnerability against oos.example rejected: %s", reason)
		}
		if !argsEqual(args, before) {
			t.Fatalf("BUG: report_vulnerability args mutated: before=%v after=%v", before, args)
		}
	})

	t.Run("scoped/add_note_redaction_observation", func(t *testing.T) {
		// Case 4 (observation): add_note with OOS-host text in key
		// and value. add_note is NOT a gated tool, but the agent
		// loop currently runs a pre-gate redaction step that rewrites
		// `key` and `value` with `[redacted: out-of-scope host]`
		// markers (internal/agent/agent.go ~line 1614–1631). This
		// substitution is what task 3.6 removes. The assertion here
		// is the byte-identical guarantee from Property 1 ("toolArgs
		// is byte-identical pre- and post-call"), enforced through
		// runAddNoteRedaction (the test helper that mirrors the
		// agent loop's pre-gate path). On unfixed code the helper
		// mutates args; the assertion fails — that's the bug.
		a := &Agent{}
		a.SetActivityPolicy("active", "active", []string{"https://pentest-ground.com"})
		args := map[string]string{
			"key":   "leak_oos.example",
			"value": "saw https://evil.example/dump",
		}
		before := cloneArgs(args)
		_ = runAddNoteRedaction(a, args)
		if !argsEqual(args, before) {
			t.Fatalf("BUG: add_note args mutated by pre-gate redaction:\n  before=%v\n  after =%v", before, args)
		}
	})

	// ── Property-based generation ───────────────────────────────
	// Random Public_OOS_Hosts × 5 shapes × every Gated_Tool. Fixed
	// seed (scopeBugSeed) for reproducibility.

	r := rand.New(rand.NewSource(scopeBugSeed))
	const inScope = "pentest-ground.com"
	scope := []string{"https://" + inScope}
	avoid := []string{inScope, "pentest-ground", "ground"}

	const iterations = 60

	type counterexample struct {
		toolName string
		shape    argShape
		host     string
		args     map[string]string
		reason   string
		mutated  bool
	}
	var counterexamples []counterexample

	for i := 0; i < iterations; i++ {
		host := genPublicOOSLabel(r, avoid)
		// Sanity: tokenizer must surface this as a host, otherwise
		// the bug condition can't fire and we'd be testing nothing.
		if extractHostFromTokenForScope(host) == "" {
			t.Fatalf("generator emitted non-host-shaped label %q (seed bug)", host)
		}
		// Sanity: must not be reserved-IP literal.
		if net.ParseIP(host) != nil {
			t.Fatalf("generator emitted IP-shaped label %q (seed bug)", host)
		}

		for _, tool := range gatedToolsForBugProperty {
			for _, shape := range []argShape{
				shapeBareHost,
				shapeFullURL,
				shapeUserinfoURL,
				shapeRedirectQuery,
				shapeFragmentEmbed,
			} {
				payload := embedOOSHostInArg(shape, host, inScope)
				field := argFieldForTool(tool)

				var args map[string]string
				switch tool {
				case "report_vulnerability":
					// Put the OOS host on the explicit target field
					// so the belt-and-braces leg is exercised.
					args = map[string]string{
						"title":    "Auto-generated finding for property test",
						"target":   payload,
						"endpoint": payload,
						"severity": "medium",
					}
				default:
					value := payload
					if shape != shapeBareHost && (tool == "terminal_execute" ||
						tool == "python_action" ||
						tool == "page_agent" ||
						tool == "pageagent") {
						value = shapeIntoCommand(tool, payload)
					} else if tool == "browser_action" {
						// browser_action expects a URL on `url`; the
						// bare-host shape is fine as-is for the
						// tokenizer.
						value = payload
					}
					args = map[string]string{field: value}
				}

				// Fresh local Agent per iteration so accidental
				// state in one tool's run cannot affect another.
				a := &Agent{}
				a.SetActivityPolicy("active", "active", scope)

				before := cloneArgs(args)
				blocked, reason := a.shouldBlockForOutOfScope(tool, args)
				mutated := !argsEqual(args, before)

				if blocked || mutated {
					counterexamples = append(counterexamples, counterexample{
						toolName: tool,
						shape:    shape,
						host:     host,
						args:     before,
						reason:   reason,
						mutated:  mutated,
					})
				}
			}
		}
	}

	if len(counterexamples) > 0 {
		// Cap the dump so the failure log stays readable.
		const dumpCap = 8
		var b strings.Builder
		fmt.Fprintf(&b, "found %d Public_OOS_Host counterexamples (seed=0x%x); first %d:\n",
			len(counterexamples), uint64(scopeBugSeed), min(dumpCap, len(counterexamples)))
		for i, c := range counterexamples {
			if i >= dumpCap {
				break
			}
			fmt.Fprintf(&b, "  [%d] tool=%s shape=%s host=%s mutated=%v\n      args=%v\n      reason=%q\n",
				i, c.toolName, c.shape, c.host, c.mutated, c.args, c.reason)
		}
		t.Fatalf("BUG: Property 1 violated — Public_OOS_Hosts blocked or args mutated.\n%s", b.String())
	}
}

// ───────────────────────────────────────────────────────────────────
// Preservation property tests (spec: scope-guard-local-only, task 2).
// Property 2 from design.md → "Correctness Properties":
//
//   FOR ALL X WHERE ¬isBugCondition(X) DO
//     ASSERT oracleShouldBlockForOutOfScope(X) == shouldBlockForOutOfScope(X)
//     ASSERT toolArgs is byte-identical pre- and post-call
//   END FOR
//
// On UNFIXED code the oracle (oracleShouldBlockForOutOfScope, captured
// in scope_oracle_test.go) is byte-frozen against today's production
// implementation, so the equality assertion is tautological. After
// task 3 narrows the production guard, the same oracle is the
// ground-truth `F` against which the post-fix `F'` must match for
// every ¬C(X) input.
//
// "(blocked, reason) tuple" from the task is interpreted as: the
// `blocked` bool matches and, when blocked, both implementations
// produce a non-empty reason. The reason TEXT itself is allowed to
// change between F and F' (design.md → "Narrow shouldBlockForOutOfScope"
// rewrites the wording for Local_Or_Listener_Host rejections). What
// preservation pins is the BEHAVIOR (allow/block), not the wording.
//
// The empty-scope-+-Local_Or_Listener_Host cell is treated specially
// per design.md → "Open Question: Requirement 3.7": today the oracle
// short-circuits empty scope to allow, and the production code does
// the same; post-fix the production code keeps the local check active
// even when scope is empty (oracle = allow, fixed = block). The
// asymmetry is intentional. Rows in this cell are excluded from
// strict oracle-vs-production comparison — the property pins
// oracle = allow (unchanged across the spec) and lets task 3.11
// reconcile the production divergence post-fix.

// withOracleLookupHost swaps oracleLookupHost (the agent oracle's
// frozen resolver indirection) for the duration of a single test.
// Restoration runs via t.Cleanup so the original binding is
// preserved on every exit path.
func withOracleLookupHost(t *testing.T, stub func(string) ([]string, error)) {
	t.Helper()
	prev := oracleLookupHost
	oracleLookupHost = stub
	t.Cleanup(func() { oracleLookupHost = prev })
}

// preservationRow is one ¬C(X) input the preservation property
// exercises. cell tags which partition cell the row belongs to so
// the test output names which preservation requirement is being
// hit when a row fails post-fix.
type preservationRow struct {
	cell  string // partition cell name from task 2
	name  string
	scope []string
	tool  string
	args  map[string]string
	// excludeProductionComparison is set for the empty-scope-+-Local
	// cell where post-fix divergence is expected per Requirement 3.7.
	excludeProductionComparison bool
}

func preservationRows() []preservationRow {
	return []preservationRow{
		// ── Cell 1: Local_Or_Listener_Host ────────────────────────
		// Literal locals. Both oracle and production reject because
		// the host is a Local_Or_Listener_Host (loopback / localhost).
		{
			cell:  "local-or-listener",
			name:  "loopback literal in curl",
			scope: []string{"https://pentest-ground.com"},
			tool:  "terminal_execute",
			args:  map[string]string{"command": "curl http://127.0.0.1/admin"},
		},
		{
			cell:  "local-or-listener",
			name:  "localhost literal in curl",
			scope: []string{"https://pentest-ground.com"},
			tool:  "terminal_execute",
			args:  map[string]string{"command": "curl http://localhost/admin"},
		},

		// ── Cell 1b: Non-local private/link-local hosts ───────────
		// Under the scope-guard-local-only rule these are NOT blocked:
		// RFC1918 and link-local (including 169.254.169.254 cloud
		// metadata) are legitimate scan targets on the target's
		// network, not the operator's own machine. Both oracle and
		// production allow — the rows pin allow==allow so a future
		// regression that re-introduces blanket private-range
		// blocking fails here.
		{
			cell:  "non-local-private",
			name:  "rfc1918 ipv4 in browser_action (allowed)",
			scope: []string{"https://pentest-ground.com"},
			tool:  "browser_action",
			args:  map[string]string{"url": "http://10.0.0.1:8080/"},
		},
		{
			cell:  "non-local-private",
			name:  "rfc1918 ipv4 192.168 in python_action (allowed)",
			scope: []string{"https://pentest-ground.com"},
			tool:  "python_action",
			args:  map[string]string{"code": "import requests; requests.get('http://192.168.1.1/')"},
		},
		{
			cell:  "non-local-private",
			name:  "link-local 169.254 cloud metadata in curl (allowed)",
			scope: []string{"https://pentest-ground.com"},
			tool:  "terminal_execute",
			args:  map[string]string{"command": "curl http://169.254.169.254/latest/meta-data/"},
		},

		// ── Cell 2: Self-listener ─────────────────────────────────
		// Post-fix both oracle and production reject because the
		// host is loopback (caught by the Local_Or_Listener_Host
		// loopback fast-path regardless of port).
		{
			cell:  "self-listener",
			name:  "127.0.0.1:8080 (loopback, any port)",
			scope: []string{"https://pentest-ground.com"},
			tool:  "terminal_execute",
			args:  map[string]string{"command": "curl http://127.0.0.1:8080/admin"},
		},

		// ── Cell 3: In-scope ──────────────────────────────────────
		// Both implementations allow.
		{
			cell:  "in-scope",
			name:  "exact configured target",
			scope: []string{"https://pentest-ground.com"},
			tool:  "terminal_execute",
			args:  map[string]string{"command": "nmap -sV pentest-ground.com"},
		},
		{
			cell:  "in-scope",
			name:  "subdomain of configured target",
			scope: []string{"https://pentest-ground.com"},
			tool:  "terminal_execute",
			args:  map[string]string{"command": "curl https://api.pentest-ground.com/v1/users"},
		},
		{
			cell:  "in-scope",
			name:  "deeply-nested subdomain",
			scope: []string{"https://pentest-ground.com"},
			tool:  "browser_action",
			args:  map[string]string{"url": "https://app.api.v2.pentest-ground.com/"},
		},
		{
			cell:  "in-scope",
			name:  "www variant",
			scope: []string{"https://pentest-ground.com", "https://www.pentest-ground.com"},
			tool:  "browser_action",
			args:  map[string]string{"url": "https://www.pentest-ground.com/login"},
		},

		// ── Cell 4: Hostless ──────────────────────────────────────
		// Both implementations allow.
		{
			cell:  "hostless",
			name:  "ls",
			scope: []string{"https://pentest-ground.com"},
			tool:  "terminal_execute",
			args:  map[string]string{"command": "ls -la"},
		},
		{
			cell:  "hostless",
			name:  "grep over notes file",
			scope: []string{"https://pentest-ground.com"},
			tool:  "terminal_execute",
			args:  map[string]string{"command": "grep 'csrf' notes.json"},
		},
		{
			cell:  "hostless",
			name:  "jq over scan output",
			scope: []string{"https://pentest-ground.com"},
			tool:  "terminal_execute",
			args:  map[string]string{"command": "jq '.vulns[]' scan.json"},
		},
		{
			cell:  "hostless",
			name:  "wc over recon list",
			scope: []string{"https://pentest-ground.com"},
			tool:  "terminal_execute",
			args:  map[string]string{"command": "wc -l live_subdomains.txt"},
		},

		// ── Cell 5: Empty Activity_Hosts ──────────────────────────
		// Hostless and Public_OOS_Host inputs: both eras allow (the
		// oracle short-circuits, today's production short-circuits,
		// post-fix the rewritten guard has nothing to do with scope
		// at all on these inputs).
		{
			cell:  "empty-scope/hostless",
			name:  "empty scope, hostless",
			scope: nil,
			tool:  "terminal_execute",
			args:  map[string]string{"command": "ls"},
		},
		{
			cell:  "empty-scope/public-oos",
			name:  "empty scope, public OOS host",
			scope: nil,
			tool:  "terminal_execute",
			args:  map[string]string{"command": "curl http://anywhere.example/"},
		},
		// Empty-scope-+-Local — the documented Requirement 3.7
		// asymmetry. Oracle allows (short-circuits before any
		// local check). Production today allows (oracle == production
		// on unfixed code). Post-fix production blocks. We exclude
		// this row from the strict oracle-vs-production comparison
		// and pin the oracle verdict explicitly so reviewers can
		// see the asymmetry.
		{
			cell:                        "empty-scope/local",
			name:                        "empty scope, loopback (Requirement 3.7 asymmetry)",
			scope:                       nil,
			tool:                        "terminal_execute",
			args:                        map[string]string{"command": "curl http://127.0.0.1/"},
			excludeProductionComparison: true,
		},

		// ── Cell 6: Non-gated tools ───────────────────────────────
		// Both eras bypass the gate entirely; args byte-identical.
		{
			cell:  "non-gated",
			name:  "add_note (with OOS host text)",
			scope: []string{"https://pentest-ground.com"},
			tool:  "add_note",
			args: map[string]string{
				"key":   "leak_oos.example",
				"value": "saw https://evil.example/dump",
			},
		},
		{
			cell:  "non-gated",
			name:  "read_notes",
			scope: []string{"https://pentest-ground.com"},
			tool:  "read_notes",
			args:  map[string]string{},
		},
		{
			cell:  "non-gated",
			name:  "finish",
			scope: []string{"https://pentest-ground.com"},
			tool:  "finish",
			args:  map[string]string{"summary": "done with https://evil.example/dump"},
		},
		{
			cell:  "non-gated",
			name:  "web_search",
			scope: []string{"https://pentest-ground.com"},
			tool:  "web_search",
			args:  map[string]string{"query": "site:evil.example admin login"},
		},
		{
			cell:  "non-gated",
			name:  "list_skills",
			scope: []string{"https://pentest-ground.com"},
			tool:  "list_skills",
			args:  map[string]string{},
		},
		{
			cell:  "non-gated",
			name:  "agentmail",
			scope: []string{"https://pentest-ground.com"},
			tool:  "agentmail",
			args:  map[string]string{"to": "ops@evil.example", "subject": "x"},
		},

		// ── Cell 7: report_vulnerability on local target ──────────
		// Both eras reject. blocked bool matches.
		{
			cell:  "report-vuln-local",
			name:  "report_vulnerability against 127.0.0.1",
			scope: []string{"https://pentest-ground.com"},
			tool:  "report_vulnerability",
			args: map[string]string{
				"title":    "Local-only finding",
				"target":   "http://127.0.0.1",
				"endpoint": "http://127.0.0.1/admin",
				"severity": "high",
			},
		},
		{
			cell:  "report-vuln-local",
			name:  "report_vulnerability against [::1]:8080",
			scope: []string{"https://pentest-ground.com"},
			tool:  "report_vulnerability",
			args: map[string]string{
				"title":    "IPv6 loopback finding",
				"target":   "http://[::1]:8080/x",
				"endpoint": "http://[::1]:8080/x",
				"severity": "high",
			},
		},
	}
}

// TestPreservation_AgentGuardMatchesOracle pins Property 2 across
// the seven ¬C(X) partition cells. Asserts:
//
//  1. oracleShouldBlockForOutOfScope(X).blocked ==
//     shouldBlockForOutOfScope(X).blocked
//  2. when blocked, both produce a non-empty reason
//  3. toolArgs byte-identical pre- and post-call (no mutation under
//     preservation)
//
// The empty-scope-+-Local cell (preservationRow.excludeProductionComparison)
// is the documented Requirement 3.7 asymmetry: the oracle's
// short-circuit on empty scope returns allow, post-fix production
// returns block. On unfixed code production happens to match the
// oracle (allow); post-fix it diverges. The property pins oracle =
// allow for the row and skips the strict equality check, leaving
// task 3.11 to validate the post-fix shift.
//
// Validates: Requirements 3.1, 3.2, 3.3, 3.4, 3.5, 3.6, 3.7, 3.9.
func TestPreservation_AgentGuardMatchesOracle(t *testing.T) {
	for _, row := range preservationRows() {
		row := row
		t.Run(row.cell+"/"+row.name, func(t *testing.T) {
			a := &Agent{}
			a.SetActivityPolicy("active", "active", row.scope)

			oracleA := &Agent{}
			oracleA.SetActivityPolicy("active", "active", row.scope)

			// Snapshot args for byte-identical comparison.
			oracleArgsBefore := cloneArgs(row.args)
			oracleArgs := cloneArgs(row.args)
			oracleBlocked, oracleReason := oracleShouldBlockForOutOfScope(oracleA, row.tool, oracleArgs)
			if !argsEqual(oracleArgs, oracleArgsBefore) {
				t.Fatalf("oracle mutated args: before=%v after=%v", oracleArgsBefore, oracleArgs)
			}

			prodArgsBefore := cloneArgs(row.args)
			prodArgs := cloneArgs(row.args)
			prodBlocked, prodReason := a.shouldBlockForOutOfScope(row.tool, prodArgs)
			if !argsEqual(prodArgs, prodArgsBefore) {
				t.Fatalf("production mutated args: before=%v after=%v", prodArgsBefore, prodArgs)
			}

			// Empty-scope-+-Local cell: pin oracle = allow per Req 3.7
			// and skip the strict production comparison (post-fix
			// divergence is expected and validated by task 3.11).
			if row.excludeProductionComparison {
				if oracleBlocked {
					t.Fatalf("Requirement 3.7: oracle MUST allow on empty-scope-+-Local, got blocked: %s", oracleReason)
				}
				return
			}

			if oracleBlocked != prodBlocked {
				t.Fatalf("blocked verdicts diverge: oracle=%v (reason=%q), production=%v (reason=%q)",
					oracleBlocked, oracleReason, prodBlocked, prodReason)
			}
			if oracleBlocked && oracleReason == "" {
				t.Errorf("oracle blocked but reason empty")
			}
			if prodBlocked && prodReason == "" {
				t.Errorf("production blocked but reason empty")
			}
		})
	}
}

// TestPreservation_LocalOrListenerInvarianceUnderTokenizationShape
// pins the sub-property called out in task 2: the same
// Local_Or_Listener_Host expressed as bare host / host:port /
// http://host / http://user:pass@host / inside redirect query
// parameters MUST reject identically — pre- and post-fix.
//
// On unfixed code the agent guard rejects all five shapes via the
// OOS rule (because none of these literals appear in Activity_Hosts).
// Post-fix the agent guard rejects all five shapes via the
// Local_Or_Listener_Host rule. Either way blocked = true across
// every shape.
//
// Validates: Requirements 3.1, 3.2, 3.3, 3.4.
func TestPreservation_LocalOrListenerInvarianceUnderTokenizationShape(t *testing.T) {
	a := &Agent{}
	a.SetActivityPolicy("active", "active", []string{"https://pentest-ground.com"})

	// Only Local_Or_Listener_Hosts are exercised here. Under the
	// scope-guard-local-only rule, RFC1918/link-local literals
	// (10.0.0.1, 192.168.1.1, 169.254.169.254) are NOT local and are
	// allowed, so they no longer belong to this reject-invariance
	// property. 127.0.0.1 is the representative literal local; its
	// rejection must be invariant across every tokenization shape.
	hosts := []string{
		"127.0.0.1",
	}
	shapeBuilders := map[string]func(string) string{
		"bare host":      func(h string) string { return "curl " + h },
		"host:port":      func(h string) string { return "curl " + h + ":8080" },
		"scheme://host":  func(h string) string { return "curl http://" + h },
		"userinfo URL":   func(h string) string { return "curl http://user:pass@" + h },
		"redirect query": func(h string) string { return "curl https://app.pentest-ground.com/redir?next=http://" + h },
	}

	for _, host := range hosts {
		host := host
		for shapeName, build := range shapeBuilders {
			shapeName, build := shapeName, build
			t.Run(host+"/"+shapeName, func(t *testing.T) {
				args := map[string]string{"command": build(host)}
				before := cloneArgs(args)
				blocked, reason := a.shouldBlockForOutOfScope("terminal_execute", args)
				if !blocked {
					t.Fatalf("Local_Or_Listener_Host %s in shape %q must be blocked across the spec, got allow", host, shapeName)
				}
				if reason == "" {
					t.Errorf("blocked but reason empty for %s/%s", host, shapeName)
				}
				if !argsEqual(args, before) {
					t.Errorf("args mutated under preservation: before=%v after=%v", before, args)
				}
				// Oracle parity check: on unfixed code the oracle
				// matches production (tautological); the assertion
				// is here to lock the parity in for post-fix runs.
				oracleA := &Agent{}
				oracleA.SetActivityPolicy("active", "active", []string{"https://pentest-ground.com"})
				oracleArgs := cloneArgs(args)
				oracleBlocked, _ := oracleShouldBlockForOutOfScope(oracleA, "terminal_execute", oracleArgs)
				if !oracleBlocked {
					t.Errorf("oracle disagrees: %s in shape %q allowed by oracle", host, shapeName)
				}
			})
		}
	}
}

// TestPreservation_AgentOracleStableAcrossLookupSwap is a defensive
// sanity check on the oracle's frozen-byte property. The oracle
// declares its own oracleLookupHost var; even if a future reviewer
// accidentally rewires the oracle to call DNS, this test catches
// the regression by feeding a bomb resolver and asserting the
// oracle's verdicts on the standard preservation rows are
// unaffected (because today's oracle does no DNS).
//
// On post-fix runs the production agent guard does call DNS via
// scopeguard.LookupHost, but the oracle keeps reading from
// oracleLookupHost — so the byte-frozen pre-fix `F` stays stable
// regardless of how the production resolver is wired.
func TestPreservation_AgentOracleStableAcrossLookupSwap(t *testing.T) {
	withOracleLookupHost(t, func(host string) ([]string, error) {
		t.Errorf("oracle MUST NOT call DNS today (host=%q)", host)
		return nil, fmt.Errorf("oracle must not call DNS")
	})

	for _, row := range preservationRows() {
		oracleA := &Agent{}
		oracleA.SetActivityPolicy("active", "active", row.scope)
		args := cloneArgs(row.args)
		_, _ = oracleShouldBlockForOutOfScope(oracleA, row.tool, args)
	}
}

// ───────────────────────────────────────────────────────────────────
// Bucket D — new coverage for the narrowed Local_Or_Listener_Host
// rule. See design.md → "Test Surface Migration → Bucket D — add"
// and tasks.md → 3.8 Bucket D.

// withScopeguardLookupHost swaps scopeguard.LookupHost for the
// duration of a single test. Restoration runs via t.Cleanup so the
// original net.LookupHost binding is preserved on every exit path.
// The test functions below MUST NOT call t.Parallel() because
// scopeguard.LookupHost is package-level state.
func withScopeguardLookupHost(t *testing.T, stub func(string) ([]string, error)) {
	t.Helper()
	prev := scopeguard.SetLookupHost(stub)
	t.Cleanup(func() { scopeguard.SetLookupHost(prev) })
}

// firstLocalInterfaceIP returns the first IP address bound to one of
// this machine's interfaces. Used by the Bucket D row that asserts
// hostnames whose injected resolver returns a local-interface IP
// must reject. Returns "" if no interface address is available, in
// which case the row is skipped.
func firstLocalInterfaceIP() string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return ""
	}
	for _, a := range addrs {
		var ip net.IP
		switch v := a.(type) {
		case *net.IPNet:
			ip = v.IP
		case *net.IPAddr:
			ip = v.IP
		}
		if ip == nil || ip.IsLoopback() {
			continue
		}
		if v4 := ip.To4(); v4 != nil {
			return v4.String()
		}
	}
	return ""
}

// TestShouldBlockForOutOfScope_BlocksLocalOrListener pins the
// post-fix Local_Or_Listener_Host rule across the full classifier
// surface: literal loopback / RFC1918 / link-local, the listener
// bind:port pairing, and hostnames whose injected resolver returns
// either a private-range IP or a local-interface IP. Each row
// asserts blocked == true.
//
// Validates: Requirements 3.1, 3.2, 3.3, 3.4.
func TestShouldBlockForOutOfScope_BlocksLocalOrListener(t *testing.T) {
	const listenerPort = 9000
	const bindAddr = "127.0.0.1"

	// Build an agent with a configured listener identity. The
	// localGuard field is consulted by shouldBlockForOutOfScope via
	// scopeguard.IsLocalOrListener.
	makeAgent := func() *Agent {
		a := &Agent{
			localGuard: scopeguard.Config{BindAddr: bindAddr, Port: listenerPort},
		}
		a.SetActivityPolicy("active", "active", []string{"https://pentest-ground.com"})
		return a
	}

	type row struct {
		name       string
		command    string
		stubLookup func(string) ([]string, error)
	}

	rows := []row{
		{name: "loopback ipv4 literal", command: "curl http://127.0.0.1/admin"},
		{name: "localhost name", command: "curl http://localhost/admin"},
		// NOTE on bracketed IPv6 literals (`[::1]`, `[fe80::1]`,
		// `[fc00::1]` etc.): the agent's tokenizer (extractHostsFromArgs
		// → extractHostFromTokenForScope) cannot surface bracketed
		// IPv6 hosts from a free-form command string today. `[` / `]`
		// are token separators in scopeTokenSeparator, so `http://[::1]:8080/admin`
		// is broken into tokens {`curl`, `http://`, `::1`, `:8080/admin`}
		// and `extractHostFromTokenForScope` rejects `::1` after the
		// leading `:` is stripped by its punctuation trim. IPv6
		// literal coverage for the Local_Or_Listener_Host rule is
		// therefore exercised via:
		//   - TestShouldBlockForOutOfScope_ReportVulnerabilityLocalOrListener
		//     where the report_vulnerability belt-and-braces leg
		//     passes the raw `endpoint=http://[::1]:8080/x` directly
		//     to scopeguard.IsLocalOrListener (bypassing the tokenizer).
		//   - the "hostname resolves to ::1" stub row below.
		// The classifier itself (scopeguard.IsLocalOrListener) handles
		// every IPv6 literal shape and is independently covered by
		// internal/scopeguard/scopeguard_test.go.
		//
		// NOTE: RFC1918 (10.x, 192.168.x) and link-local (169.254.x)
		// literals are deliberately NOT in this block-list. Under the
		// scope-guard-local-only rule they are legitimate scan targets
		// and must be ALLOWED — that is asserted by the companion test
		// TestShouldBlockForOutOfScope_AllowsNonLocalPrivateHosts.
		{name: "0.0.0.0 paired with listener port", command: "curl http://0.0.0.0:9000/"},
		{name: "configured bind:port", command: "curl http://127.0.0.1:9000/"},
		{
			name:    "hostname resolves to ipv6 loopback via scopeguard.LookupHost",
			command: "curl http://lb6.example/",
			stubLookup: func(host string) ([]string, error) {
				return []string{"::1"}, nil
			},
		},
	}

	// Local-interface row only runs if the machine has a non-loopback
	// interface address available to inject through the resolver.
	if iface := firstLocalInterfaceIP(); iface != "" {
		rows = append(rows, row{
			name:    "hostname resolves to local-interface IP via scopeguard.LookupHost",
			command: "curl http://lb.example/",
			stubLookup: func(host string) ([]string, error) {
				return []string{iface}, nil
			},
		})
	}

	for _, tc := range rows {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			if tc.stubLookup != nil {
				withScopeguardLookupHost(t, tc.stubLookup)
			} else {
				// Even rows that should NOT trigger DNS still install
				// a counter-only stub. If the production code regresses
				// and starts looking up an IP literal, the assertion
				// fails loudly.
				withScopeguardLookupHost(t, func(host string) ([]string, error) {
					return nil, fmt.Errorf("DNS should not have been invoked for row %q (host=%q)", tc.name, host)
				})
			}

			a := makeAgent()
			args := map[string]string{"command": tc.command}
			before := cloneArgs(args)
			blocked, reason := a.shouldBlockForOutOfScope("terminal_execute", args)
			if !blocked {
				t.Fatalf("Local_Or_Listener_Host row %q must block, got allow", tc.name)
			}
			if reason == "" {
				t.Errorf("blocked but reason empty for %q", tc.name)
			}
			if !argsEqual(args, before) {
				t.Errorf("args mutated under preservation: before=%v after=%v", before, args)
			}
		})
	}
}

// TestShouldBlockForOutOfScope_AllowsNonLocalPrivateHosts is the
// companion to TestShouldBlockForOutOfScope_BlocksLocalOrListener. It
// pins the scope-guard-local-only rule that RFC1918, link-local
// (including the 169.254.169.254 cloud-metadata address), and
// arbitrary public OOS hostnames are NOT blocked from a Gated_Tool —
// they are legitimate targets on the scanned host's network, not the
// operator's own machine. Each row asserts blocked == false.
//
// This guards against a regression that re-introduces blanket
// private-range blocking (the behavior removed in commit b6f8f4f).
func TestShouldBlockForOutOfScope_AllowsNonLocalPrivateHosts(t *testing.T) {
	const listenerPort = 9000
	const bindAddr = "127.0.0.1"

	makeAgent := func() *Agent {
		a := &Agent{
			localGuard: scopeguard.Config{BindAddr: bindAddr, Port: listenerPort},
		}
		a.SetActivityPolicy("active", "active", []string{"https://pentest-ground.com"})
		return a
	}

	type row struct {
		name       string
		command    string
		stubLookup func(string) ([]string, error)
	}

	rows := []row{
		{name: "rfc1918 10.x literal", command: "curl http://10.0.0.1/"},
		{name: "rfc1918 192.168.x literal", command: "curl http://192.168.1.1/"},
		{name: "rfc1918 172.16.x literal", command: "curl http://172.16.5.4/"},
		{name: "link-local 169.254 cloud metadata", command: "curl http://169.254.169.254/latest/meta-data/"},
		{name: "public OOS hostname", command: "curl http://anywhere.example/"},
		{
			name:    "hostname resolves to private IP via scopeguard.LookupHost",
			command: "curl http://internal.example/",
			stubLookup: func(host string) ([]string, error) {
				return []string{"10.0.0.5"}, nil
			},
		},
	}

	for _, tc := range rows {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			if tc.stubLookup != nil {
				withScopeguardLookupHost(t, tc.stubLookup)
			}
			a := makeAgent()
			args := map[string]string{"command": tc.command}
			before := cloneArgs(args)
			blocked, reason := a.shouldBlockForOutOfScope("terminal_execute", args)
			if blocked {
				t.Fatalf("non-local host row %q must be allowed, got block (reason=%q)", tc.name, reason)
			}
			if !argsEqual(args, before) {
				t.Errorf("args mutated: before=%v after=%v", before, args)
			}
		})
	}
}

// TestShouldBlockForOutOfScope_LocalGuardActiveWithEmptyScope pins
// Requirement 3.7's parenthetical: the Local_Or_Listener_Host block
// path remains active independent of Activity_Hosts being populated.
// An agent with empty activityHosts that sees a Gated_Tool referring
// to 127.0.0.1 MUST still block.
//
// Validates: Requirement 3.7.
func TestShouldBlockForOutOfScope_LocalGuardActiveWithEmptyScope(t *testing.T) {
	a := &Agent{
		localGuard: scopeguard.Config{BindAddr: "127.0.0.1", Port: 9000},
	}
	// activityHosts intentionally left empty.

	args := map[string]string{"command": "curl http://127.0.0.1/admin"}
	before := cloneArgs(args)
	blocked, reason := a.shouldBlockForOutOfScope("terminal_execute", args)
	if !blocked {
		t.Fatalf("Requirement 3.7: loopback MUST still block when scope is empty, got allow")
	}
	if reason == "" {
		t.Errorf("expected non-empty rejection reason")
	}
	if !argsEqual(args, before) {
		t.Errorf("args mutated: before=%v after=%v", before, args)
	}
}

// TestShouldBlockForOutOfScope_AddNotePassThrough asserts the
// scoped deterministic case 4 from design.md → "Exploratory Bug
// Condition Checking → Test Cases" — an add_note call carrying
// OOS-host text in `key` and `value` reaches the gate, the gate
// recognizes add_note as non-gated, and `key` / `value` reach the
// handler byte-identical.
//
// Validates: Requirements 2.4, 3.9.
func TestShouldBlockForOutOfScope_AddNotePassThrough(t *testing.T) {
	a := &Agent{}
	a.SetActivityPolicy("active", "active", []string{"https://pentest-ground.com"})

	args := map[string]string{
		"key":   "leak_oos.example",
		"value": "saw https://evil.example/dump",
	}
	before := cloneArgs(args)
	blocked, reason := a.shouldBlockForOutOfScope("add_note", args)
	if blocked {
		t.Fatalf("add_note MUST bypass the gate, got blocked: %s", reason)
	}
	if !argsEqual(args, before) {
		t.Fatalf("add_note args mutated:\n  before=%v\n  after =%v", before, args)
	}
	if got := args["key"]; got != "leak_oos.example" {
		t.Errorf("key was rewritten: got %q", got)
	}
	if got := args["value"]; got != "saw https://evil.example/dump" {
		t.Errorf("value was rewritten: got %q", got)
	}
}

// TestShouldBlockForOutOfScope_ReportVulnerabilityLocalOrListener
// pins the report_vulnerability belt-and-braces leg flipping to
// the Local_Or_Listener_Host rule: target / endpoint pointing at
// the operator's machine reject; pointing at a Public_OOS_Host
// allow.
//
// Validates: Requirements 2.3, 3.4.
func TestShouldBlockForOutOfScope_ReportVulnerabilityLocalOrListener(t *testing.T) {
	a := &Agent{
		localGuard: scopeguard.Config{BindAddr: "127.0.0.1", Port: 9000},
	}
	a.SetActivityPolicy("active", "active", []string{"https://pentest-ground.com"})

	cases := []struct {
		name        string
		args        map[string]string
		wantBlocked bool
	}{
		{
			name: "target=http://127.0.0.1 rejects",
			args: map[string]string{
				"title":    "Local-only finding",
				"target":   "http://127.0.0.1",
				"endpoint": "http://127.0.0.1/admin",
				"severity": "high",
			},
			wantBlocked: true,
		},
		{
			name: "target=https://oos.example allows",
			args: map[string]string{
				"title":    "Public OOS finding",
				"target":   "https://oos.example",
				"endpoint": "https://oos.example/dump",
				"severity": "medium",
			},
			wantBlocked: false,
		},
		{
			name: "endpoint=http://[::1]:8080/x rejects",
			args: map[string]string{
				"title":    "IPv6 loopback finding",
				"target":   "https://pentest-ground.com",
				"endpoint": "http://[::1]:8080/x",
				"severity": "high",
			},
			wantBlocked: true,
		},
		{
			name: "endpoint=https://oos.example/x allows",
			args: map[string]string{
				"title":    "Public OOS endpoint",
				"target":   "https://pentest-ground.com",
				"endpoint": "https://oos.example/x",
				"severity": "medium",
			},
			wantBlocked: false,
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			before := cloneArgs(tc.args)
			blocked, reason := a.shouldBlockForOutOfScope("report_vulnerability", tc.args)
			if blocked != tc.wantBlocked {
				t.Fatalf("blocked = %v, want %v (reason=%q)", blocked, tc.wantBlocked, reason)
			}
			if !argsEqual(tc.args, before) {
				t.Errorf("args mutated: before=%v after=%v", before, tc.args)
			}
			if blocked && reason == "" {
				t.Errorf("blocked but reason empty")
			}
		})
	}
}

// ───────────────────────────────────────────────────────────────────
// Bucket D PBT — additional property tests called out in design.md →
// "Property-Based Tests" that aren't already implemented by Property
// 1 / Property 2.

// TestProperty_LocalOrListenerInvarianceUnderTokenizationShape pins
// the sub-property: the same Local_Or_Listener_Host expressed five
// ways (bare host / host:port / scheme://host / userinfo URL /
// inside redirect query parameters) MUST reject identically.
//
// NOTE: This is the post-fix rejection-side analog of
// TestPreservation_LocalOrListenerInvarianceUnderTokenizationShape
// (task 2). The preservation version asserts oracle-vs-production
// agreement on shape invariance; this version asserts the
// production guard alone rejects all five shapes after the
// scope-guard-local-only fix. We keep them as siblings rather than
// alias — the preservation test exercises the oracle path
// independently and would be lost as a sanity check if folded into
// this one.
//
// Validates: Requirements 3.1, 3.2, 3.3, 3.4.
func TestProperty_LocalOrListenerInvarianceUnderTokenizationShape(t *testing.T) {
	a := &Agent{
		localGuard: scopeguard.Config{BindAddr: "127.0.0.1", Port: 9000},
	}
	a.SetActivityPolicy("active", "active", []string{"https://pentest-ground.com"})

	// Only Local_Or_Listener_Hosts are exercised here. Post the
	// scope-guard-local-only fix, RFC1918/link-local literals are
	// legitimate scan targets (allowed), so the reject-invariance
	// property applies only to true locals — represented by the
	// loopback literal.
	hosts := []string{
		"127.0.0.1",
	}
	shapeBuilders := map[string]func(string) string{
		"bare host":      func(h string) string { return "curl " + h },
		"host:port":      func(h string) string { return "curl " + h + ":8080" },
		"scheme://host":  func(h string) string { return "curl http://" + h },
		"userinfo URL":   func(h string) string { return "curl http://user:pass@" + h },
		"redirect query": func(h string) string { return "curl https://app.pentest-ground.com/redir?next=http://" + h },
	}

	for _, host := range hosts {
		host := host
		for shapeName, build := range shapeBuilders {
			shapeName, build := shapeName, build
			t.Run(host+"/"+shapeName, func(t *testing.T) {
				args := map[string]string{"command": build(host)}
				before := cloneArgs(args)
				blocked, reason := a.shouldBlockForOutOfScope("terminal_execute", args)
				if !blocked {
					t.Fatalf("Local_Or_Listener_Host %s in shape %q must reject under post-fix rule, got allow", host, shapeName)
				}
				if reason == "" {
					t.Errorf("blocked but reason empty for %s/%s", host, shapeName)
				}
				if !argsEqual(args, before) {
					t.Errorf("args mutated: before=%v after=%v", before, args)
				}
			})
		}
	}
}

// TestProperty_DNSLookupCountIsOnePerHostShapedArg pins the
// single-DNS-lookup contract from design.md → "DNS Lookup Semantics":
// for every host-shaped argument that requires resolution, the guard
// invokes scopeguard.LookupHost exactly once. IP literals skip DNS
// entirely. The counter-wrapped resolver asserts the call count.
//
// Validates: Requirement 3.3, design.md → "DNS Lookup Semantics".
func TestProperty_DNSLookupCountIsOnePerHostShapedArg(t *testing.T) {
	a := &Agent{
		localGuard: scopeguard.Config{BindAddr: "127.0.0.1", Port: 9000},
	}
	a.SetActivityPolicy("active", "active", []string{"https://pentest-ground.com"})

	t.Run("hostname triggers exactly one lookup", func(t *testing.T) {
		var calls int
		perHost := map[string]int{}
		withScopeguardLookupHost(t, func(host string) ([]string, error) {
			calls++
			perHost[host]++
			// Resolve to a public IP so the gate allows the call —
			// this row is checking the lookup count contract, not
			// the verdict.
			return []string{"203.0.113.10"}, nil
		})

		args := map[string]string{"command": "curl https://oos.example/path"}
		_, _ = a.shouldBlockForOutOfScope("terminal_execute", args)

		if calls != 1 {
			t.Fatalf("expected exactly 1 LookupHost call for one host-shaped arg, got %d (per-host=%v)", calls, perHost)
		}
		if perHost["oos.example"] != 1 {
			t.Errorf("expected 1 lookup for oos.example, got %d (per-host=%v)", perHost["oos.example"], perHost)
		}
	})

	t.Run("IP literal skips DNS entirely", func(t *testing.T) {
		var calls int
		withScopeguardLookupHost(t, func(host string) ([]string, error) {
			calls++
			return nil, errors.New("DNS should not have been invoked for an IP literal")
		})

		args := map[string]string{"command": "curl http://203.0.113.10/"}
		_, _ = a.shouldBlockForOutOfScope("terminal_execute", args)

		if calls != 0 {
			t.Fatalf("expected 0 LookupHost calls for an IP literal, got %d", calls)
		}
	})

	t.Run("two distinct host-shaped args trigger two lookups", func(t *testing.T) {
		var calls int
		perHost := map[string]int{}
		withScopeguardLookupHost(t, func(host string) ([]string, error) {
			calls++
			perHost[host]++
			return []string{"203.0.113.10"}, nil
		})

		args := map[string]string{
			"command": "curl https://a.example/ && nmap b.example",
		}
		_, _ = a.shouldBlockForOutOfScope("terminal_execute", args)

		if calls != 2 {
			t.Fatalf("expected 2 LookupHost calls (one per distinct host-shaped arg), got %d (per-host=%v)", calls, perHost)
		}
		if perHost["a.example"] != 1 || perHost["b.example"] != 1 {
			t.Errorf("expected one lookup each for a.example and b.example, got per-host=%v", perHost)
		}
	})
}
