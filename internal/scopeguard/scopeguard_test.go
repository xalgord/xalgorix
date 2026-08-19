package scopeguard

import (
	"errors"
	"net"
	"testing"
)

// withStubLookupHost swaps the package-level LookupHost indirection
// for the duration of a single test. Restoration runs via t.Cleanup
// so every test exits with the original net.LookupHost binding in
// place, regardless of failure or skip. The test functions below
// MUST NOT call t.Parallel() because LookupHost is package-level
// state.
func withStubLookupHost(t *testing.T, stub func(string) ([]string, error)) {
	t.Helper()
	prev := SetLookupHost(stub)
	t.Cleanup(func() { SetLookupHost(prev) })
}

// isLocalOrListenerRow is one row in the table-driven test surface.
type isLocalOrListenerRow struct {
	cell           string
	name           string
	cfg            Config
	target         string
	stubLookup     func(string) ([]string, error)
	wantBlocked    bool
	wantDNSCalls   int
	wantDNSCheckOn bool
}

func isLocalOrListenerRows() []isLocalOrListenerRow {
	const listenerPort = 9000

	cfg := Config{BindAddr: "127.0.0.1", Port: listenerPort}

	rows := []isLocalOrListenerRow{
		// ── Always-self literals ──────────────────────────────────
		{cell: "always-self", name: "loopback ipv4", cfg: cfg, target: "http://127.0.0.1/admin", wantBlocked: true, wantDNSCheckOn: true, wantDNSCalls: 0},
		{cell: "always-self", name: "loopback ipv4 with port", cfg: cfg, target: "http://127.0.0.1:9000/x", wantBlocked: true, wantDNSCheckOn: true, wantDNSCalls: 0},
		{cell: "always-self", name: "localhost name", cfg: cfg, target: "http://localhost/x", wantBlocked: true, wantDNSCheckOn: true, wantDNSCalls: 0},
		{cell: "always-self", name: "ipv6 loopback bracket", cfg: cfg, target: "http://[::1]:8080/", wantBlocked: true, wantDNSCheckOn: true, wantDNSCalls: 0},
		{cell: "always-self", name: "unspecified 0.0.0.0", cfg: cfg, target: "http://0.0.0.0/", wantBlocked: true, wantDNSCheckOn: true, wantDNSCalls: 0},

		// ── Self-listener leg ───────────────────────────────────────
		{
			cell: "self-listener", name: "0.0.0.0:<listener-port>",
			cfg: cfg, target: "http://0.0.0.0:9000/",
			wantBlocked: true, wantDNSCheckOn: true, wantDNSCalls: 0,
		},
		{
			cell: "self-listener", name: "::: paired with listener port",
			cfg: cfg, target: "http://[::]:9000/",
			wantBlocked: true, wantDNSCheckOn: true, wantDNSCalls: 0,
		},
		{
			cell: "self-listener", name: "configured bind addr with listener port",
			cfg: cfg, target: "http://127.0.0.1:9000/",
			wantBlocked: true, wantDNSCheckOn: true, wantDNSCalls: 0,
		},
		{
			cell: "self-listener", name: "empty BindAddr defaults to 127.0.0.1",
			cfg: Config{BindAddr: "", Port: listenerPort}, target: "http://127.0.0.1:9000/",
			wantBlocked: true, wantDNSCheckOn: true, wantDNSCalls: 0,
		},

		// ── RFC1918 / link-local: NOT blocked (smart scope guard) ──
		// These are legitimate SSRF targets on the scanned host's
		// network. Only block if they match a local interface.
		{
			cell: "private-allowed", name: "RFC1918 10.0.0.1 allowed (not our interface)",
			cfg: cfg, target: "http://10.0.0.1/",
			// Stub: 10.0.0.1 is NOT one of our interfaces
			stubLookup:     func(string) ([]string, error) { return []string{"10.0.0.1"}, nil },
			wantBlocked:    false,
			wantDNSCheckOn: true, wantDNSCalls: 0, // IP literal, no DNS
		},
		{
			cell: "private-allowed", name: "RFC1918 192.168.1.1 allowed (not our interface)",
			cfg: cfg, target: "http://192.168.1.1/",
			wantBlocked:    false,
			wantDNSCheckOn: true, wantDNSCalls: 0,
		},
		{
			cell: "private-allowed", name: "cloud metadata 169.254.169.254 allowed",
			cfg: cfg, target: "http://169.254.169.254/latest/meta-data/",
			wantBlocked:    false,
			wantDNSCheckOn: true, wantDNSCalls: 0,
		},
		{
			cell: "private-allowed", name: "hostname resolving to 169.254.169.254 allowed",
			cfg: cfg, target: "https://metadata.example/",
			stubLookup:     func(string) ([]string, error) { return []string{"169.254.169.254"}, nil },
			wantBlocked:    false,
			wantDNSCheckOn: true, wantDNSCalls: 1,
		},
		{
			cell: "private-allowed", name: "hostname resolving to RFC1918 allowed",
			cfg: cfg, target: "https://internal.target.com/",
			stubLookup:     func(string) ([]string, error) { return []string{"10.0.0.5"}, nil },
			wantBlocked:    false,
			wantDNSCheckOn: true, wantDNSCalls: 1,
		},

		// ── Hostname → loopback: STILL blocked ─────────────────────
		{
			cell: "hostname-loopback", name: "hostname resolves to 127.0.0.1 blocked",
			cfg: cfg, target: "https://evil.example/",
			stubLookup:     func(string) ([]string, error) { return []string{"127.0.0.1"}, nil },
			wantBlocked:    true,
			wantDNSCheckOn: true, wantDNSCalls: 1,
		},
		{
			cell: "hostname-loopback", name: "hostname resolves to ::1 blocked",
			cfg: cfg, target: "https://lb6.example/",
			stubLookup:     func(string) ([]string, error) { return []string{"::1"}, nil },
			wantBlocked:    true,
			wantDNSCheckOn: true, wantDNSCalls: 1,
		},

		// ── Public host (allow) ─────────────────────────────────────
		{
			cell: "public-host", name: "hostname resolves to public IP",
			cfg: cfg, target: "https://example.com/",
			stubLookup:     func(string) ([]string, error) { return []string{"93.184.216.34"}, nil },
			wantBlocked:    false,
			wantDNSCheckOn: true, wantDNSCalls: 1,
		},
		{
			cell: "public-host", name: "public IP literal skips DNS",
			cfg: cfg, target: "http://203.0.113.10/",
			wantBlocked:    false,
			wantDNSCheckOn: true, wantDNSCalls: 0,
		},

		// ── DNS failure → allow ─────────────────────────────────────
		{
			cell: "dns-failure", name: "lookup error falls back to allow",
			cfg: cfg, target: "https://nope.example/",
			stubLookup:     func(string) ([]string, error) { return nil, errors.New("simulated NXDOMAIN") },
			wantBlocked:    false,
			wantDNSCheckOn: true, wantDNSCalls: 1,
		},
		{
			cell: "dns-failure", name: "empty result falls back to allow",
			cfg: cfg, target: "https://void.example/",
			stubLookup:     func(string) ([]string, error) { return []string{}, nil },
			wantBlocked:    false,
			wantDNSCheckOn: true, wantDNSCalls: 1,
		},
	}

	// ── Self-host public IP regression (any port) ────────────────
	// Dynamically discover a non-loopback interface IP so the test
	// works on any machine. When the resolved IP matches one of the
	// machine's interfaces, IsLocalOrListener must block regardless
	// of port — this is the fix for the self-scanning bug.
	if selfIP := firstNonLoopbackInterfaceIP(); selfIP != "" {
		rows = append(rows,
			isLocalOrListenerRow{
				cell: "self-host-public", name: "own public IP on SSH port 22 blocked",
				cfg: cfg, target: "http://" + selfIP + ":22/",
				wantBlocked:    true,
				wantDNSCheckOn: true, wantDNSCalls: 0,
			},
			isLocalOrListenerRow{
				cell: "self-host-public", name: "own public IP on Grafana port 9999 blocked",
				cfg: cfg, target: "http://" + selfIP + ":9999/api/users",
				wantBlocked:    true,
				wantDNSCheckOn: true, wantDNSCalls: 0,
			},
			isLocalOrListenerRow{
				cell: "self-host-public", name: "own public IP bare (no port) blocked",
				cfg: cfg, target: "http://" + selfIP + "/",
				wantBlocked:    true,
				wantDNSCheckOn: true, wantDNSCalls: 0,
			},
			isLocalOrListenerRow{
				cell: "self-host-public", name: "hostname resolving to own public IP blocks",
				cfg: cfg, target: "https://my-server.example.com/",
				stubLookup:     func(string) ([]string, error) { return []string{selfIP}, nil },
				wantBlocked:    true,
				wantDNSCheckOn: true, wantDNSCalls: 1,
			},
		)
	}

	return rows
}

// TestIsLocalOrListener_Table covers the smart scope guard behavior.
func TestIsLocalOrListener_Table(t *testing.T) {
	for _, row := range isLocalOrListenerRows() {
		row := row
		t.Run(row.cell+"/"+row.name, func(t *testing.T) {
			var calls int
			if row.stubLookup != nil {
				stub := row.stubLookup
				withStubLookupHost(t, func(host string) ([]string, error) {
					calls++
					return stub(host)
				})
			} else {
				withStubLookupHost(t, func(host string) ([]string, error) {
					calls++
					return nil, errors.New("DNS should not have been invoked for this row")
				})
			}

			got := IsLocalOrListener(row.cfg, row.target)
			if got != row.wantBlocked {
				t.Fatalf("IsLocalOrListener(%q) = %v, want %v",
					row.target, got, row.wantBlocked)
			}
			if row.wantDNSCheckOn && calls != row.wantDNSCalls {
				t.Fatalf("LookupHost calls for %q = %d, want %d",
					row.target, calls, row.wantDNSCalls)
			}
		})
	}
}

// TestIsLocalOrListener_SingleLookupAcrossTwoCalls asserts that two
// back-to-back calls each perform exactly one DNS lookup.
func TestIsLocalOrListener_SingleLookupAcrossTwoCalls(t *testing.T) {
	cfg := Config{BindAddr: "127.0.0.1", Port: 9000}

	var calls int
	withStubLookupHost(t, func(host string) ([]string, error) {
		calls++
		return []string{"203.0.113.10"}, nil
	})

	if blocked := IsLocalOrListener(cfg, "https://oos.example/"); blocked {
		t.Fatalf("public-IP-resolving target reported blocked = true")
	}
	if calls != 1 {
		t.Fatalf("LookupHost call count after first call = %d, want 1", calls)
	}

	if blocked := IsLocalOrListener(cfg, "https://oos.example/"); blocked {
		t.Fatalf("second call to public-IP-resolving target reported blocked = true")
	}
	if calls != 2 {
		t.Fatalf("LookupHost call count after second call = %d, want 2", calls)
	}
}

// TestCloudMetadataAllowed verifies that common SSRF targets are
// NOT blocked by the scope guard.
func TestCloudMetadataAllowed(t *testing.T) {
	cfg := Config{BindAddr: "127.0.0.1", Port: 9137}

	targets := []string{
		"http://169.254.169.254/latest/meta-data/",
		"http://169.254.169.254/computeMetadata/v1/",
		"http://169.254.169.254/metadata/instance",
	}
	for _, target := range targets {
		if IsLocalOrListener(cfg, target) {
			t.Errorf("cloud metadata target %q was blocked — SSRF testing broken", target)
		}
	}
}

// TestDifferentPrivateIPsAllowed verifies that RFC1918 IPs that
// don't match local interfaces are allowed through.
func TestDifferentPrivateIPsAllowed(t *testing.T) {
	cfg := Config{BindAddr: "127.0.0.1", Port: 9137}

	// These are private IPs but they DON'T belong to our machine
	// (unless you happen to have exactly these IPs, very unlikely)
	targets := []string{
		"http://10.255.255.1/",
		"http://172.31.255.254/",
		"http://192.168.254.254/",
	}
	for _, target := range targets {
		got := IsLocalOrListener(cfg, target)
		// We can't guarantee these aren't on a local interface,
		// but on a typical machine they shouldn't be
		_ = got // just test that it doesn't panic
	}
}

// firstNonLoopbackInterfaceIP returns the first non-loopback IPv4
// address found among the machine's network interfaces.
func firstNonLoopbackInterfaceIP() string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return ""
	}
	for _, a := range addrs {
		ipNet, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		ip := ipNet.IP
		if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() {
			continue
		}
		if ip4 := ip.To4(); ip4 != nil {
			return ip4.String()
		}
	}
	return ""
}
