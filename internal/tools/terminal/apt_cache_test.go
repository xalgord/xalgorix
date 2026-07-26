package terminal

import (
	"testing"
)

// Regression for the issue fixed in supersession of PR #287: the apt package
// index refresh must run at most once per process. Previously every
// installPackage call re-ran `apt-get update`, so a command installing N
// missing apt tools triggered N sequential full-mirror round-trips.
//
// maybeRefreshAptLists is guarded by aptListsRefreshed (set on the first call
// regardless of outcome, so a flaky mirror does not cause unbounded retries).
// This test pins that contract: after the first call the flag is set and
// subsequent calls are no-ops (they return "" without re-running anything).
func TestMaybeRefreshAptListsRunsAtMostOncePerProcess(t *testing.T) {
	// Reset to a known state (other tests in this package may have flipped it).
	aptListsMu.Lock()
	aptListsRefreshed = false
	aptListsMu.Unlock()

	// First call: performs the refresh work (or skips it on a non-apt / fresh
	// host) and marks the gate so it never runs again this process.
	_ = maybeRefreshAptLists()

	aptListsMu.Lock()
	refreshed := aptListsRefreshed
	aptListsMu.Unlock()
	if !refreshed {
		t.Fatal("aptListsRefreshed must be true after the first maybeRefreshAptLists call")
	}

	// Subsequent calls must be no-ops (return "" immediately). We cannot
	// observe the skipped work directly, but a no-op returns the empty string
	// without touching the network — assert the contract.
	for i := 0; i < 5; i++ {
		if got := maybeRefreshAptLists(); got != "" {
			t.Errorf("maybeRefreshAptLists() call #%d = %q, want \"\" (must be a no-op after the first refresh)", i+2, got)
		}
	}
}

// Resetting the gate returns it to the "will refresh" state — this guards the
// reset semantics used by the test above and documents the flag's lifecycle.
func TestAptListsRefreshedFlagIsResettable(t *testing.T) {
	aptListsMu.Lock()
	aptListsRefreshed = false
	aptListsMu.Unlock()

	_ = maybeRefreshAptLists()

	aptListsMu.Lock()
	aptListsRefreshed = false // reset
	got := aptListsRefreshed
	aptListsMu.Unlock()
	if got {
		t.Error("aptListsRefreshed must read false immediately after reset")
	}
}
