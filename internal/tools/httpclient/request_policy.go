package httpclient

import (
	"context"
	"crypto/sha256"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// RequestPolicy constrains HTTP calls made by a targeted finding re-test.
// Ordinary scans have no policy and retain their existing behavior.
type RequestPolicy struct {
	AllowedHosts   []string
	AllowedMethods []string
	AffectedURL    string
	AffectedMethod string
	MaxRequests    int
	MaxTimeout     int
	MaxBytes       int
	PublicOnly     bool
}

type RequestPolicyExecution struct {
	RequestCount         int
	AffectedRequestCount int
	AffectedVariantCount int
}

type requestPolicyState struct {
	policy           RequestPolicy
	used             int
	executed         int
	affectedExecuted int
	affectedVariants map[[sha256.Size]byte]struct{}
}

var requestPolicies = struct {
	sync.Mutex
	byContext map[string]*requestPolicyState
}{byContext: make(map[string]*requestPolicyState)}

func SetRequestPolicy(contextID string, policy RequestPolicy) {
	requestPolicies.Lock()
	defer requestPolicies.Unlock()
	requestPolicies.byContext[contextID] = &requestPolicyState{
		policy:           normalizePolicy(policy),
		affectedVariants: make(map[[sha256.Size]byte]struct{}),
	}
}

func ClearRequestPolicy(contextID string) {
	requestPolicies.Lock()
	defer requestPolicies.Unlock()
	delete(requestPolicies.byContext, contextID)
}

func RequestPolicyUsage(contextID string) int {
	requestPolicies.Lock()
	defer requestPolicies.Unlock()
	if state := requestPolicies.byContext[contextID]; state != nil {
		return state.used
	}
	return 0
}

// RequestPolicyExecutionStats describes only requests that received an HTTP
// response. Connection, DNS, TLS, and timeout failures are not execution
// evidence. Affected variants are distinct method/URL/header/body combinations
// sent to the stored finding endpoint; two variants are required to support a
// baseline/control comparison for a "fixed" verdict.
func RequestPolicyExecutionStats(contextID string) RequestPolicyExecution {
	requestPolicies.Lock()
	defer requestPolicies.Unlock()
	state := requestPolicies.byContext[contextID]
	if state == nil {
		return RequestPolicyExecution{}
	}
	return RequestPolicyExecution{
		RequestCount:         state.executed,
		AffectedRequestCount: state.affectedExecuted,
		AffectedVariantCount: len(state.affectedVariants),
	}
}

func RequestPolicyExecutionCount(contextID string) int {
	return RequestPolicyExecutionStats(contextID).RequestCount
}

func markRequestPolicyExecuted(contextID string, req *http.Request, authProfile, body string) {
	requestPolicies.Lock()
	defer requestPolicies.Unlock()
	state := requestPolicies.byContext[contextID]
	if state == nil {
		return
	}
	state.executed++
	if !matchesAffectedEndpoint(state.policy, req) {
		return
	}
	state.affectedExecuted++
	state.affectedVariants[effectiveRequestSignature(req, authProfile, body)] = struct{}{}
}

// effectiveRequestSignature hashes canonical effective request data without
// retaining or exposing credential values. Header names and values are sorted,
// so semantically equivalent JSON object/array ordering produces one variant.
func effectiveRequestSignature(req *http.Request, authProfile, body string) [sha256.Size]byte {
	h := sha256.New()
	writeSignatureField := func(value string) {
		_, _ = h.Write([]byte(strconv.Itoa(len(value))))
		_, _ = h.Write([]byte{':'})
		_, _ = h.Write([]byte(value))
	}
	writeSignatureField(strings.ToUpper(req.Method))
	writeSignatureField(req.URL.String())

	canonicalHeaders := make(map[string][]string, len(req.Header))
	for name, values := range req.Header {
		name = strings.ToLower(strings.TrimSpace(name))
		canonicalHeaders[name] = append(canonicalHeaders[name], values...)
	}
	names := make([]string, 0, len(canonicalHeaders))
	for name := range canonicalHeaders {
		names = append(names, name)
	}
	sort.Strings(names)
	writeSignatureField(strconv.Itoa(len(names)))
	for _, name := range names {
		writeSignatureField(name)
		values := append([]string(nil), canonicalHeaders[name]...)
		sort.Strings(values)
		writeSignatureField(strconv.Itoa(len(values)))
		for _, value := range values {
			writeSignatureField(value)
		}
	}
	writeSignatureField(body)
	writeSignatureField(normalizeAuthProfile(authProfile))

	var signature [sha256.Size]byte
	copy(signature[:], h.Sum(nil))
	return signature
}

func matchesAffectedEndpoint(policy RequestPolicy, req *http.Request) bool {
	if req == nil || req.URL == nil || policy.AffectedURL == "" {
		return false
	}
	affected, err := url.Parse(policy.AffectedURL)
	if err != nil {
		return false
	}
	if policy.AffectedMethod != "" && !strings.EqualFold(req.Method, policy.AffectedMethod) {
		return false
	}
	requestPath := req.URL.EscapedPath()
	if requestPath == "" {
		requestPath = "/"
	}
	affectedPath := affected.EscapedPath()
	if affectedPath == "" {
		affectedPath = "/"
	}
	return strings.EqualFold(req.URL.Scheme, affected.Scheme) &&
		normalizePolicyHost(req.URL.Host) == normalizePolicyHost(affected.Host) &&
		requestPath == affectedPath
}

func normalizePolicy(policy RequestPolicy) RequestPolicy {
	for i := range policy.AllowedHosts {
		policy.AllowedHosts[i] = normalizePolicyHost(policy.AllowedHosts[i])
	}
	for i := range policy.AllowedMethods {
		policy.AllowedMethods[i] = strings.ToUpper(strings.TrimSpace(policy.AllowedMethods[i]))
	}
	policy.AffectedMethod = strings.ToUpper(strings.TrimSpace(policy.AffectedMethod))
	return policy
}

func requestPolicy(contextID string) (RequestPolicy, bool) {
	requestPolicies.Lock()
	defer requestPolicies.Unlock()
	state := requestPolicies.byContext[contextID]
	if state == nil {
		return RequestPolicy{}, false
	}
	return state.policy, true
}

func applyRequestPolicy(contextID string, parsed *url.URL, method string, args map[string]string) error {
	p, ok := requestPolicy(contextID)
	if !ok {
		return nil
	}
	if err := validatePolicyURL(p, parsed, method); err != nil {
		return err
	}

	requestPolicies.Lock()
	state := requestPolicies.byContext[contextID]
	if state == nil {
		requestPolicies.Unlock()
		return fmt.Errorf("targeted re-test request policy is no longer active")
	}
	if state.policy.MaxRequests > 0 && state.used >= state.policy.MaxRequests {
		requestPolicies.Unlock()
		return fmt.Errorf("targeted re-test request budget exhausted")
	}
	state.used++
	requestPolicies.Unlock()

	// Policy values override model-supplied values rather than merely capping
	// them, which keeps each call deterministic and prevents redirects.
	args["follow_redirects"] = "false"
	if p.MaxTimeout > 0 {
		args["timeout"] = fmt.Sprintf("%d", p.MaxTimeout)
	}
	if p.MaxBytes > 0 {
		args["max_bytes"] = fmt.Sprintf("%d", p.MaxBytes)
	}
	return nil
}

func validatePolicyURL(p RequestPolicy, parsed *url.URL, method string) error {
	if parsed == nil || (parsed.Scheme != "http" && parsed.Scheme != "https") {
		return fmt.Errorf("targeted re-test only permits HTTP(S)")
	}
	if parsed.User != nil {
		return fmt.Errorf("targeted re-test refuses embedded credentials")
	}
	host := normalizePolicyHost(parsed.Host)
	if host == "" || !policyContains(p.AllowedHosts, host) {
		return fmt.Errorf("targeted re-test refused out-of-scope host %q", host)
	}
	if !policyContains(p.AllowedMethods, strings.ToUpper(method)) {
		return fmt.Errorf("targeted re-test refused method %q", method)
	}
	if p.PublicOnly {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if _, err := resolvePublicIPs(ctx, parsed.Hostname()); err != nil {
			return err
		}
	}
	return nil
}

func policyContains(values []string, candidate string) bool {
	for _, value := range values {
		if strings.EqualFold(strings.TrimSpace(value), candidate) {
			return true
		}
	}
	return false
}

func normalizePolicyHost(host string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
}

func policyAllowsDial(allowed []string, host, port string) bool {
	authority := normalizePolicyHost(net.JoinHostPort(host, port))
	if policyContains(allowed, authority) {
		return true
	}
	// A URL without an explicit port can only dial its scheme's standard port.
	return (port == "80" || port == "443") && policyContains(allowed, normalizePolicyHost(host))
}

// ValidateRequestPolicyURL performs the same host, scheme, method, and public
// address validation used immediately before a targeted HTTP request.
func ValidateRequestPolicyURL(policy RequestPolicy, rawURL, method string) error {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("invalid targeted re-test URL: %w", err)
	}
	return validatePolicyURL(normalizePolicy(policy), parsed, strings.ToUpper(strings.TrimSpace(method)))
}

// dialContextForPolicy resolves and pins a targeted request to the public
// addresses checked here. This closes the gap between a preflight DNS lookup
// and the transport's later lookup (DNS rebinding/TOCTOU).
func dialContextForPolicy(contextID string, fallback func(context.Context, string, string) (net.Conn, error)) func(context.Context, string, string) (net.Conn, error) {
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		p, ok := requestPolicy(contextID)
		if !ok || !p.PublicOnly {
			return fallback(ctx, network, address)
		}
		host, port, err := net.SplitHostPort(address)
		if err != nil {
			return nil, fmt.Errorf("targeted re-test invalid dial address: %w", err)
		}
		host = normalizePolicyHost(host)
		if !policyAllowsDial(p.AllowedHosts, host, port) {
			return nil, fmt.Errorf("targeted re-test refused dial host %q", net.JoinHostPort(host, port))
		}
		ips, err := resolvePublicIPs(ctx, host)
		if err != nil {
			return nil, err
		}
		var lastErr error
		for _, ip := range ips {
			conn, dialErr := fallback(ctx, network, net.JoinHostPort(ip.String(), port))
			if dialErr == nil {
				return conn, nil
			}
			lastErr = dialErr
		}
		return nil, fmt.Errorf("targeted re-test connection failed: %w", lastErr)
	}
}

func resolvePublicIPs(ctx context.Context, host string) ([]net.IP, error) {
	if ip := net.ParseIP(host); ip != nil {
		if blockedRetestIP(ip) {
			return nil, fmt.Errorf("targeted re-test refuses non-public target address")
		}
		return []net.IP{ip}, nil
	}
	addrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil || len(addrs) == 0 {
		return nil, fmt.Errorf("targeted re-test could not safely resolve host")
	}
	ips := make([]net.IP, 0, len(addrs))
	for _, addr := range addrs {
		if blockedRetestIP(addr.IP) {
			return nil, fmt.Errorf("targeted re-test refuses host with non-public address")
		}
		ips = append(ips, addr.IP)
	}
	return ips, nil
}

var blockedRetestPrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("2001:db8::/32"),
}

func blockedRetestIP(ip net.IP) bool {
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return true
	}
	addr = addr.Unmap()
	if !addr.IsGlobalUnicast() || addr.IsPrivate() || addr.IsLoopback() || addr.IsLinkLocalUnicast() || addr.IsMulticast() || addr.IsUnspecified() {
		return true
	}
	for _, prefix := range blockedRetestPrefixes {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}
