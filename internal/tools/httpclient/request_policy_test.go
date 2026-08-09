package httpclient

import (
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestRequestPolicyEnforcesHostMethodAndBounds(t *testing.T) {
	const contextID = "targeted-policy-test"
	SetRequestPolicy(contextID, RequestPolicy{
		AllowedHosts: []string{"8.8.8.8"}, AllowedMethods: []string{"GET", "HEAD"},
		MaxRequests: 2, MaxTimeout: 20, MaxBytes: 64 * 1024, PublicOnly: true,
	})
	t.Cleanup(func() { ClearRequestPolicy(contextID) })

	parsed, _ := url.Parse("https://8.8.8.8/dns-query")
	args := map[string]string{"follow_redirects": "true", "timeout": "60", "max_bytes": "524288"}
	if err := applyRequestPolicy(contextID, parsed, "GET", args); err != nil {
		t.Fatalf("allowed request rejected: %v", err)
	}
	if args["follow_redirects"] != "false" || args["timeout"] != "20" || args["max_bytes"] != "65536" {
		t.Fatalf("policy bounds not forced: %#v", args)
	}
	if err := applyRequestPolicy(contextID, parsed, "POST", map[string]string{}); err == nil || !strings.Contains(err.Error(), "method") {
		t.Fatalf("POST should be rejected, got %v", err)
	}
	other, _ := url.Parse("https://8.8.4.4/")
	if err := applyRequestPolicy(contextID, other, "GET", map[string]string{}); err == nil || !strings.Contains(err.Error(), "host") {
		t.Fatalf("other host should be rejected, got %v", err)
	}
}

func TestRequestPolicyBudgetAndPublicAddresses(t *testing.T) {
	const contextID = "targeted-budget-test"
	SetRequestPolicy(contextID, RequestPolicy{
		AllowedHosts: []string{"8.8.8.8"}, AllowedMethods: []string{"GET"},
		MaxRequests: 1, PublicOnly: true,
	})
	t.Cleanup(func() { ClearRequestPolicy(contextID) })
	parsed, _ := url.Parse("https://8.8.8.8/")
	if err := applyRequestPolicy(contextID, parsed, "GET", map[string]string{}); err != nil {
		t.Fatal(err)
	}
	if err := applyRequestPolicy(contextID, parsed, "GET", map[string]string{}); err == nil || !strings.Contains(err.Error(), "budget") {
		t.Fatalf("second request should exhaust budget, got %v", err)
	}
	if got := RequestPolicyUsage(contextID); got != 1 {
		t.Fatalf("usage=%d want=1", got)
	}

	for _, raw := range []string{"127.0.0.1", "10.0.0.1", "169.254.169.254", "100.64.0.1", "192.0.2.1", "198.18.0.1", "224.0.0.1"} {
		if !blockedRetestIP(net.ParseIP(raw)) {
			t.Errorf("%s should be blocked", raw)
		}
	}
	if blockedRetestIP(net.ParseIP("8.8.8.8")) {
		t.Fatal("public address was blocked")
	}
}

func TestRequestPolicyRequiresExactPortWhenSpecified(t *testing.T) {
	policy := RequestPolicy{AllowedHosts: []string{"8.8.8.8:8443"}, AllowedMethods: []string{"GET"}, PublicOnly: true}
	if err := ValidateRequestPolicyURL(policy, "https://8.8.8.8:8443/x", "GET"); err != nil {
		t.Fatalf("exact port rejected: %v", err)
	}
	if err := ValidateRequestPolicyURL(policy, "https://8.8.8.8/x", "GET"); err == nil {
		t.Fatal("different port/authority should be rejected")
	}
}

func TestRequestPolicyTracksAffectedEndpointAndDistinctControls(t *testing.T) {
	const contextID = "targeted-evidence-test"
	SetRequestPolicy(contextID, RequestPolicy{
		AllowedHosts:   []string{"8.8.8.8"},
		AllowedMethods: []string{"GET"},
		AffectedURL:    "https://8.8.8.8/dns-query?name=stored",
		AffectedMethod: "GET",
		PublicOnly:     true,
	})
	t.Cleanup(func() { ClearRequestPolicy(contextID) })

	for _, rawURL := range []string{
		"https://8.8.8.8/",
		"https://8.8.8.8/dns-query?name=baseline",
		"https://8.8.8.8/dns-query?name=payload",
	} {
		req, err := http.NewRequest(http.MethodGet, rawURL, nil)
		if err != nil {
			t.Fatal(err)
		}
		markRequestPolicyExecuted(contextID, req, "primary", "")
	}

	stats := RequestPolicyExecutionStats(contextID)
	if stats.RequestCount != 3 || stats.AffectedRequestCount != 2 || stats.AffectedVariantCount != 2 {
		t.Fatalf("unexpected execution stats: %#v", stats)
	}
}

func TestTargetedAuthProfilesAreAuthoritativeAndOpaque(t *testing.T) {
	const contextID = "targeted-auth-application"
	const primarySecret = "primary-secret-never-expose"
	const secondarySecret = "secondary-secret-never-expose"

	var received []http.Header
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received = append(received, r.Header.Clone())
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	SetSessionAuth(contextID, map[string]string{
		"Authorization":  "Bearer " + primarySecret,
		"X-Primary-Auth": primarySecret,
	})
	SetSessionAuthSecondary(contextID, map[string]string{
		"Cookie":           "session=" + secondarySecret,
		"X-Secondary-Auth": secondarySecret,
	})
	SetRequestPolicy(contextID, RequestPolicy{
		AllowedHosts: []string{strings.TrimPrefix(server.URL, "http://")}, AllowedMethods: []string{"GET"},
		AffectedURL: server.URL, AffectedMethod: "GET", MaxRequests: 4,
	})
	t.Cleanup(func() {
		SetSessionAuth(contextID, nil)
		SetSessionAuthSecondary(contextID, nil)
		ClearRequestPolicy(contextID)
	})

	secondaryResult, err := executeWithContext(contextID, map[string]string{
		"url": server.URL, "auth_profile": "  SeConDary  ", "headers": `{"X-Control":"secondary"}`,
	})
	if err != nil {
		t.Fatalf("secondary request failed: %v", err)
	}
	noneResult, err := executeWithContext(contextID, map[string]string{
		"url": server.URL, "auth_profile": "none", "headers": `{"X-Control":"none"}`,
	})
	if err != nil {
		t.Fatalf("none request failed: %v", err)
	}
	if len(received) != 2 {
		t.Fatalf("received %d requests, want 2", len(received))
	}
	if got := received[0].Get("Cookie"); got != "session="+secondarySecret {
		t.Fatalf("secondary Cookie = %q", got)
	}
	if got := received[0].Get("X-Secondary-Auth"); got != secondarySecret {
		t.Fatalf("secondary custom auth = %q", got)
	}
	for _, name := range []string{"Authorization", "X-Primary-Auth"} {
		if got := received[0].Get(name); got != "" {
			t.Fatalf("secondary request leaked primary %s", name)
		}
	}
	for _, name := range []string{"Authorization", "Proxy-Authorization", "Cookie", "X-Api-Key", "X-Auth-Token", "X-Primary-Auth", "X-Secondary-Auth"} {
		if got := received[1].Get(name); got != "" {
			t.Fatalf("none request sent protected %s=%q", name, got)
		}
	}
	for _, output := range []string{secondaryResult.Output, noneResult.Output} {
		if strings.Contains(output, primarySecret) || strings.Contains(output, secondarySecret) {
			t.Fatal("tool output exposed server-held authentication material")
		}
	}
}

func TestTargetedAuthValidationDoesNotConsumeBudget(t *testing.T) {
	const contextID = "targeted-auth-prebudget"
	SetSessionAuth(contextID, map[string]string{"X-Primary-Auth": "primary"})
	SetSessionAuthSecondary(contextID, map[string]string{"X-Secondary-Auth": "secondary"})
	SetRequestPolicy(contextID, RequestPolicy{
		AllowedHosts: []string{"8.8.8.8"}, AllowedMethods: []string{"GET"}, MaxRequests: 1,
	})
	t.Cleanup(func() {
		SetSessionAuth(contextID, nil)
		SetSessionAuthSecondary(contextID, nil)
		ClearRequestPolicy(contextID)
	})

	cases := []map[string]string{
		{"url": "https://8.8.8.8/", "auth_profile": "invalid"},
		{"url": "https://8.8.8.8/", "headers": `{"Authorization":"attacker"}`},
		{"url": "https://8.8.8.8/", "auth_profile": "primary", "headers": `{"x-secondary-auth":"attacker"}`},
		{"url": "https://8.8.8.8/", "auth_profile": "none", "headers": `{"Cookie":""}`},
		{"url": "https://8.8.8.8/", "headers": `{"Authorization":`},
	}
	for i, args := range cases {
		if _, err := executeWithContext(contextID, args); err == nil {
			t.Fatalf("case %d should be rejected", i)
		}
		if got := RequestPolicyUsage(contextID); got != 0 {
			t.Fatalf("case %d consumed budget: usage=%d", i, got)
		}
	}

	const unavailableContext = "targeted-auth-unavailable"
	SetRequestPolicy(unavailableContext, RequestPolicy{
		AllowedHosts: []string{"8.8.8.8"}, AllowedMethods: []string{"GET"}, MaxRequests: 1,
	})
	t.Cleanup(func() { ClearRequestPolicy(unavailableContext) })
	if _, err := executeWithContext(unavailableContext, map[string]string{
		"url": "https://8.8.8.8/", "auth_profile": "secondary",
	}); err == nil || !strings.Contains(err.Error(), "unavailable") {
		t.Fatalf("unavailable secondary profile error = %v", err)
	}
	if got := RequestPolicyUsage(unavailableContext); got != 0 {
		t.Fatalf("unavailable profile consumed budget: usage=%d", got)
	}
}

func TestAuthProfileRejectedOutsideTargetedMode(t *testing.T) {
	if _, err := executeWithContext("ordinary-auth-profile", map[string]string{
		"url": "https://8.8.8.8/", "auth_profile": "none",
	}); err == nil || !strings.Contains(err.Error(), "targeted retests") {
		t.Fatalf("ordinary auth_profile error = %v", err)
	}
}

func TestAffectedVariantsUseCanonicalEffectiveRequestAndProfile(t *testing.T) {
	const contextID = "targeted-canonical-variants"
	SetRequestPolicy(contextID, RequestPolicy{
		AllowedHosts: []string{"8.8.8.8"}, AllowedMethods: []string{"POST"},
		AffectedURL: "https://8.8.8.8/affected", AffectedMethod: "POST",
	})
	t.Cleanup(func() { ClearRequestPolicy(contextID) })

	first, _ := http.NewRequest(http.MethodPost, "https://8.8.8.8/affected?id=1", nil)
	first.Header["X-Zeta"] = []string{"second", "first"}
	first.Header["X-Alpha"] = []string{"value"}
	second, _ := http.NewRequest(http.MethodPost, "https://8.8.8.8/affected?id=1", nil)
	second.Header["x-alpha"] = []string{"value"}
	second.Header["x-zeta"] = []string{"first", "second"}

	markRequestPolicyExecuted(contextID, first, " PRIMARY ", "same-body")
	markRequestPolicyExecuted(contextID, second, "primary", "same-body")
	markRequestPolicyExecuted(contextID, second, "secondary", "same-body")
	markRequestPolicyExecuted(contextID, second, "none", "same-body")

	stats := RequestPolicyExecutionStats(contextID)
	if stats.RequestCount != 4 || stats.AffectedRequestCount != 4 || stats.AffectedVariantCount != 3 {
		t.Fatalf("canonical/profile-aware execution stats = %#v", stats)
	}
}

func TestOrdinaryScanAuthOverrideBehaviorIsUnchanged(t *testing.T) {
	const contextID = "ordinary-auth-overrides"
	var received []http.Header
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received = append(received, r.Header.Clone())
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	SetSessionAuth(contextID, map[string]string{"Authorization": "Bearer server-held"})
	t.Cleanup(func() { SetSessionAuth(contextID, nil) })

	if _, err := executeWithContext(contextID, map[string]string{
		"url": server.URL, "headers": `{"Authorization":"Bearer model-override"}`,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := executeWithContext(contextID, map[string]string{
		"url": server.URL, "headers": `{"Authorization":""}`,
	}); err != nil {
		t.Fatal(err)
	}
	if got := received[0].Get("Authorization"); got != "Bearer model-override" {
		t.Fatalf("ordinary override = %q", got)
	}
	if got := received[1].Get("Authorization"); got != "" {
		t.Fatalf("ordinary blank override sent Authorization=%q", got)
	}
}
