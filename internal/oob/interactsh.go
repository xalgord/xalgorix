// Interactsh (ProjectDiscovery OAST) backend for the OOB oracle.
//
// This is the ZERO-CONFIG default: when the operator has not stood up a
// self-hosted callback listener (XALGORIX_OOB_PUBLIC_URL), the agent still
// gets a working out-of-band oracle via ProjectDiscovery's public interactsh
// servers (oast.pro, oast.live, …). Unlike the built-in HTTP-only listener,
// interactsh also captures DNS and SMTP interactions — critical because many
// blind sinks (SSRF via DNS rebinding, blind RCE that only resolves a host,
// libraries that DNS-resolve before connecting) trigger a DNS lookup but no
// HTTP request. All polled interactions are RSA/AES decrypted client-side by
// the official library, so the public server never sees our correlation data
// in the clear.

package oob

import (
	"bufio"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	ishclient "github.com/projectdiscovery/interactsh/pkg/client"
	ishserver "github.com/projectdiscovery/interactsh/pkg/server"
	"github.com/xalgord/xalgorix/v4/internal/config"
)

const (
	ishPollInterval  = 5 * time.Second
	ishMaxHitsPerTok = 100
	ishMaxTokens     = 4096
)

var (
	ishOnce     sync.Once
	ishClient   *ishclient.Client
	ishInitErr  error
	ishMu       sync.Mutex
	ishHits     = map[string][]Interaction{} // full-id token -> interactions
	ishTokOrder []string                     // FIFO of registered tokens
	ishReg      = map[string]bool{}          // registered tokens (minted by us)
)

// interactshEnabled reports whether the interactsh backend may be used. It is
// on by default and only disabled explicitly via XALGORIX_OOB_DISABLE.
func interactshEnabled() bool {
	return !config.Get().OOBDisable
}

// ensureInteractsh lazily registers with an interactsh server and starts the
// background poller. Registration hits the network, so the first OOB use in a
// scan pays that cost; subsequent calls are cheap.
func ensureInteractsh() error {
	ishOnce.Do(func() {
		cfg := config.Get()
		// The client does NOT fall back to its default server list when
		// ServerURL is empty — it errors "invalid server url provided". So when
		// the operator hasn't pinned a server, pass the library's public
		// default list explicitly (oast.pro, oast.live, …).
		server := strings.TrimSpace(cfg.InteractshServer)
		if server == "" {
			server = ishclient.DefaultOptions.ServerURL
		}
		opts := &ishclient.Options{
			ServerURL:         server,
			Token:             strings.TrimSpace(cfg.InteractshToken),
			KeepAliveInterval: time.Minute, // renew the session across a long scan
		}
		c, err := ishclient.New(opts)
		if err != nil {
			ishInitErr = fmt.Errorf("interactsh registration failed: %w", err)
			return
		}
		if err := c.StartPolling(ishPollInterval, onInteraction); err != nil {
			_ = c.Close()
			ishInitErr = fmt.Errorf("interactsh polling failed to start: %w", err)
			return
		}
		ishClient = c
	})
	return ishInitErr
}

// onInteraction is the poll callback. It records an interaction under the
// token (FullId) it targeted, but only for tokens we actually minted and
// within the per-token cap — so unrelated noise can never grow the store
// without bound.
func onInteraction(i *ishserver.Interaction) {
	if i == nil {
		return
	}
	tok := strings.TrimSpace(i.FullId)
	if tok == "" {
		tok = strings.TrimSpace(i.UniqueID)
	}
	ishMu.Lock()
	defer ishMu.Unlock()
	if !ishReg[tok] {
		return // not one of ours (or already evicted)
	}
	if len(ishHits[tok]) >= ishMaxHitsPerTok {
		return
	}
	ishHits[tok] = append(ishHits[tok], ishToInteraction(tok, i))
}

// interactshGenerate mints a fresh interactsh URL and returns it plus the
// bare correlation token (the URL's leftmost label) used for polling.
func interactshGenerate() (callbackURL, token string, err error) {
	if err := ensureInteractsh(); err != nil {
		return "", "", err
	}
	host := ishClient.URL() // e.g. "c<corr><nonce>.oast.pro" (no scheme)
	if host == "" {
		return "", "", fmt.Errorf("interactsh client is closed")
	}
	token = host
	if i := strings.IndexByte(host, '.'); i > 0 {
		token = host[:i] // the FullId label that interactions report
	}
	ishMu.Lock()
	if !ishReg[token] {
		ishReg[token] = true
		ishHits[token] = []Interaction{}
		ishTokOrder = append(ishTokOrder, token)
		for len(ishTokOrder) > ishMaxTokens {
			old := ishTokOrder[0]
			ishTokOrder = ishTokOrder[1:]
			delete(ishReg, old)
			delete(ishHits, old)
		}
	}
	ishMu.Unlock()
	// interactsh serves HTTP, HTTPS, and DNS on the same host. Present https://
	// (works for SSRF/RCE HTTP egress); the bare host alone is enough for
	// DNS-only sinks.
	return "https://" + host, token, nil
}

// interactshPoll returns a copy of interactions recorded for a token.
func interactshPoll(token string) []Interaction {
	token = strings.TrimSpace(token)
	// A caller may pass the full URL/host; reduce to the leftmost label.
	token = strings.TrimPrefix(token, "https://")
	token = strings.TrimPrefix(token, "http://")
	if i := strings.IndexByte(token, '.'); i > 0 {
		token = token[:i]
	}
	ishMu.Lock()
	defer ishMu.Unlock()
	out := make([]Interaction, len(ishHits[token]))
	copy(out, ishHits[token])
	return out
}

// ishToInteraction maps an interactsh Interaction into our transport-neutral
// Interaction shape, parsing the raw HTTP request when present so the agent
// sees method/path/headers just like the self-hosted listener reports.
func ishToInteraction(token string, i *ishserver.Interaction) Interaction {
	proto := strings.ToLower(strings.TrimSpace(i.Protocol))
	out := Interaction{
		Token:      token,
		Protocol:   proto,
		RemoteAddr: i.RemoteAddress,
		Time:       i.Timestamp,
		Headers:    map[string]string{},
	}
	if out.Time.IsZero() {
		out.Time = time.Now()
	}
	switch proto {
	case "http", "https":
		if req := parseRawHTTP(i.RawRequest); req != nil {
			out.Method = req.Method
			out.Path = req.URL.Path
			out.Query = req.URL.RawQuery
			out.UserAgent = req.UserAgent()
			for k, v := range req.Header {
				out.Headers[k] = strings.Join(v, ", ")
			}
			if req.Body != nil {
				buf := make([]byte, maxOOBBody)
				n, _ := req.Body.Read(buf)
				out.Body = string(buf[:n])
			}
		} else {
			out.Method = strings.ToUpper(proto)
			out.Body = truncateRaw(i.RawRequest)
		}
	case "dns":
		// DNS source addresses normally identify a recursive resolver, not the
		// process that initiated the lookup. Preserve the lead, but attribution
		// and SSRF proof require stronger corroboration at the reporting gate.
		out.Method = "DNS"
		out.Path = i.QType
		out.Body = truncateRaw(i.RawRequest)
	default:
		out.Method = strings.ToUpper(proto)
		if i.SMTPFrom != "" {
			out.Headers["Mail-From"] = i.SMTPFrom
		}
		out.Body = truncateRaw(i.RawRequest)
	}
	return out
}

func parseRawHTTP(raw string) *http.Request {
	// Trim only leading whitespace — the trailing CRLFCRLF terminates the
	// header block and MUST be preserved or http.ReadRequest fails.
	raw = strings.TrimLeft(raw, " \t\r\n")
	if raw == "" {
		return nil
	}
	req, err := http.ReadRequest(bufio.NewReader(strings.NewReader(raw)))
	if err != nil {
		return nil
	}
	return req
}

func truncateRaw(s string) string {
	if len(s) > maxOOBBody {
		return s[:maxOOBBody]
	}
	return s
}
