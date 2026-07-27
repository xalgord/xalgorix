package web

import "testing"

// A stale in-memory instance (left after an engine restart + auto-resume) must
// NOT downgrade an already-terminal on-disk scan status back to "running", nor
// regress its phase. This is the crowdproof.id desync: the scan finished on
// disk but a leftover instance reported "running", so GET /api/scans/{id}
// showed it running forever and the SaaS never reconciled it.
func TestApplyInstanceSnapshot_KeepsTerminalOverStaleRunning(t *testing.T) {
	s := newTestServer(t, nil)

	s.instancesMu.Lock()
	s.instances["inst-crowd"] = &ScanInstance{ID: "inst-crowd", Status: "running", CurrentPhase: 11}
	s.instancesMu.Unlock()

	rec := &ScanRecord{ID: "scan-crowd", InstanceID: "inst-crowd", Status: "completed", CurrentPhase: 22}
	s.applyInstanceSnapshot(rec, false)

	if rec.Status != "completed" {
		t.Fatalf("terminal status was downgraded to %q by a stale running instance", rec.Status)
	}
	if rec.CurrentPhase != 22 {
		t.Errorf("phase regressed from 22 to %d", rec.CurrentPhase)
	}
}

// Conversely, when the record is NOT terminal, the live instance status still
// wins (an instance that just reached a terminal state must update the record).
func TestApplyInstanceSnapshot_LiveInstanceStillWinsForNonTerminal(t *testing.T) {
	s := newTestServer(t, nil)

	s.instancesMu.Lock()
	s.instances["inst-live"] = &ScanInstance{ID: "inst-live", Status: "failed", CurrentPhase: 14, StopReason: "idle_timeout"}
	s.instancesMu.Unlock()

	rec := &ScanRecord{ID: "scan-live", InstanceID: "inst-live", Status: "running", CurrentPhase: 12}
	s.applyInstanceSnapshot(rec, false)

	if rec.Status != "failed" {
		t.Fatalf("live terminal instance status not applied: rec.Status=%q", rec.Status)
	}
	if rec.CurrentPhase != 14 {
		t.Errorf("phase did not advance to 14: %d", rec.CurrentPhase)
	}
}
