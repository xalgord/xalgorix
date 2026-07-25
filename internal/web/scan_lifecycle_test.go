package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

// A deleted instance (removed from the map mid-run) must be treated as
// interrupted so the queue / subdomain loops stop scanning. Regression for
// issue #239 where deleting a scan left the pipeline running in the background.
func TestInstanceInterrupted_MissingInstanceIsInterrupted(t *testing.T) {
	s := newTestServer(t, nil)

	s.instancesMu.Lock()
	s.instances["run-1"] = &ScanInstance{ID: "run-1", Status: "running"}
	s.instances["stopped-1"] = &ScanInstance{ID: "stopped-1", Status: "stopped"}
	s.instancesMu.Unlock()

	if s.instanceInterrupted("run-1") {
		t.Error("running instance should NOT be interrupted")
	}
	if !s.instanceInterrupted("stopped-1") {
		t.Error("stopped instance should be interrupted")
	}
	if !s.instanceInterrupted("never-existed") {
		t.Error("missing/deleted instance MUST be treated as interrupted")
	}
	if s.instanceInterrupted("") {
		t.Error("empty instance id should not be interrupted")
	}
}

// Deleting a running scan must halt it: cancel the in-flight context, mark the
// instance stopped, remove it from the map, AND delete the persisted queue
// resume file so the startup auto-resume never replays it (issue #239).
func TestHandleDeleteScan_StopsInstanceAndClearsQueueState(t *testing.T) {
	s := newTestServer(t, nil)

	canceled := false
	inst := &ScanInstance{ID: "del-1", Targets: "a.com, b.com", Status: "running"}
	inst.cancel = func() { canceled = true }
	s.instancesMu.Lock()
	s.instances["del-1"] = inst
	s.instancesMu.Unlock()

	// Persist a resume file for this queue (2 targets, still at index 0).
	s.saveQueueState(0, ScanRequest{
		InstanceID: "del-1",
		Targets:    []string{"a.com", "b.com"},
		ScanMode:   "wildcard",
	})
	queuePath := s.queueStatePathForInstance("del-1")
	if _, err := os.Stat(queuePath); err != nil {
		t.Fatalf("precondition: queue state file should exist: %v", err)
	}

	rr := httptest.NewRecorder()
	s.handleGetScan(rr, httptest.NewRequest(http.MethodDelete, "/api/scans/del-1", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("delete code = %d body=%s", rr.Code, rr.Body.String())
	}

	if !canceled {
		t.Error("delete must cancel the running instance's context")
	}
	s.instancesMu.RLock()
	_, stillThere := s.instances["del-1"]
	s.instancesMu.RUnlock()
	if stillThere {
		t.Error("instance should be removed from the map after delete")
	}
	if _, err := os.Stat(queuePath); !os.IsNotExist(err) {
		t.Errorf("queue state file must be removed after delete (err=%v)", err)
	}
}

// Stopping a single instance clears its persisted resume file so the dashboard
// queue counter clears immediately and nothing is auto-resumed.
func TestHandleInstanceStop_ClearsQueueState(t *testing.T) {
	s := newTestServer(t, nil)

	inst := &ScanInstance{ID: "stop-1", Targets: "a.com", Status: "running"}
	inst.cancel = func() {}
	s.instancesMu.Lock()
	s.instances["stop-1"] = inst
	s.instancesMu.Unlock()

	s.saveQueueState(0, ScanRequest{
		InstanceID: "stop-1",
		Targets:    []string{"a.com", "b.com"},
		ScanMode:   "wildcard",
	})
	queuePath := s.queueStatePathForInstance("stop-1")
	if _, err := os.Stat(queuePath); err != nil {
		t.Fatalf("precondition: queue state file should exist: %v", err)
	}

	rr := httptest.NewRecorder()
	s.handleInstanceAction(rr, httptest.NewRequest(http.MethodPost, "/api/instances/stop-1/stop", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("stop code = %d body=%s", rr.Code, rr.Body.String())
	}

	s.instancesMu.RLock()
	got := s.instances["stop-1"]
	s.instancesMu.RUnlock()
	if got == nil || got.Status != "stopped" {
		t.Fatalf("instance should be marked stopped, got %#v", got)
	}
	if _, err := os.Stat(queuePath); !os.IsNotExist(err) {
		t.Errorf("queue state file must be removed after stop (err=%v)", err)
	}
}

// A pending scan must leave a resumable queue_state_<id>.json on disk so that,
// after a server restart, the auto-resume goroutine re-queues it instead of
// silently dropping it. Before the fix, runMultiScan only wrote queue state
// AFTER admission, so an instance parked at "pending" left no trace and was
// lost on restart. This test verifies the persistence + resume round-trip that
// change relies on: saveQueueState(0, req) produces a file that
// autoResumeQueueEntries considers resumable and scanRequestFromQueueState
// rebuilds faithfully.
func TestPendingScanQueueState_RoundTripsForResume(t *testing.T) {
	s := newTestServer(t, nil)

	req := ScanRequest{
		InstanceID: "pending-1",
		Targets:    []string{"https://pentest-ground.com:9000"},
		ScanMode:   "quick",
		Name:       "Pentest ground",
	}
	// This is exactly what runMultiScan now does on instance creation.
	s.saveQueueState(0, req)

	queuePath := s.queueStatePathForInstance("pending-1")
	if _, err := os.Stat(queuePath); err != nil {
		t.Fatalf("pending scan must persist queue state on creation: %v", err)
	}

	// The file must be picked up by the auto-resume path (not filtered out as
	// inactive/empty/corrupt/completed).
	entries := autoResumeQueueEntries(s.validQueueStateEntries(true))
	var found *QueueState
	for _, e := range entries {
		if e.state != nil && e.state.InstanceID == "pending-1" {
			found = e.state
			break
		}
	}
	if found == nil {
		t.Fatalf("pending queue state not resumable via auto-resume path (entries=%d)", len(entries))
	}
	if found.CurrentIdx != 0 {
		t.Errorf("pending scan CurrentIdx = %d, want 0 (never started)", found.CurrentIdx)
	}
	if !found.Active {
		t.Error("pending scan queue state must be Active=true")
	}

	// scanRequestFromQueueState must rebuild a request that re-enters the
	// admission loop with all original targets.
	resumed := scanRequestFromQueueState(found, queuePath)
	if len(resumed.Targets) != 1 || resumed.Targets[0] != "https://pentest-ground.com:9000" {
		t.Errorf("resumed targets = %v, want original single target", resumed.Targets)
	}
	if resumed.ScanMode != "quick" || resumed.Name != "Pentest ground" {
		t.Errorf("resumed request lost fields: mode=%q name=%q", resumed.ScanMode, resumed.Name)
	}
	if !resumed.IsResume {
		t.Error("resumed request must have IsResume=true")
	}
}

// clearQueueState must remove a pending scan's file — this is the contract the
// cancel path (user_stopped) relies on so a canceled scan is not resurrected
// on the next boot.
func TestClearQueueState_RemovesPendingScanFile(t *testing.T) {
	s := newTestServer(t, nil)

	s.saveQueueState(0, ScanRequest{
		InstanceID: "cancel-1",
		Targets:    []string{"a.com"},
	})
	queuePath := s.queueStatePathForInstance("cancel-1")
	if _, err := os.Stat(queuePath); err != nil {
		t.Fatalf("precondition: queue state should exist: %v", err)
	}

	s.clearQueueState("cancel-1")
	if _, err := os.Stat(queuePath); !os.IsNotExist(err) {
		t.Errorf("clearQueueState must remove pending scan file (err=%v)", err)
	}

	// And it must no longer appear in the auto-resume set (so a restart won't
	// resurrect it).
	for _, e := range autoResumeQueueEntries(s.validQueueStateEntries(true)) {
		if e.state != nil && e.state.InstanceID == "cancel-1" {
			t.Error("canceled pending scan must not be resumable after clearQueueState")
		}
	}
}

// Regression: a PENDING scan must NOT be marked "stopped by user" merely
// because the global stopReq flag is true. Before the fix, stopReq was a
// shared flag whose lifetime was decoupled from any one scan (set true by
// Stop All / SIGTERM, cleared only when some OTHER scan started). The
// admission loop read it directly and killed pending scans that observed a
// stale-true value — producing "stopped by user" with no user action against
// that scan. The fix made stop signaling per-instance: the admission/target
// loops now consult instanceInterrupted / instance.Status only, never the
// global flag. This test pins that contract: a stale stopReq MUST NOT
// interrupt a pending instance; only the instance's own status change does.
func TestStopReqGlobalFlagDoesNotInterruptPendingScan(t *testing.T) {
	s := newTestServer(t, nil)

	inst := &ScanInstance{ID: "pend-1", Status: "pending"}
	s.instancesMu.Lock()
	s.instances["pend-1"] = inst
	s.instancesMu.Unlock()

	// Simulate the exact cause of the bug: a stale/Stop-All/SIGTERM global
	// stopReq left true while this scan is parked pending.
	s.stopReq.Store(true)

	// instanceInterrupted is what the loops now consult. A pending scan must
	// NOT be considered interrupted just because stopReq is true.
	if s.instanceInterrupted("pend-1") {
		t.Error("a pending scan must NOT be interrupted by a stale global stopReq (per-instance signal only)")
	}

	// And the instance's status must be untouched.
	inst.mu.RLock()
	if inst.Status != "pending" {
		t.Errorf("pending scan status changed to %q with no per-instance stop", inst.Status)
	}
	inst.mu.RUnlock()

	// The correct stop channel: flip the instance's OWN status. Now it IS
	// interrupted, and stopReq is irrelevant.
	inst.mu.Lock()
	inst.Status = "stopped"
	inst.mu.Unlock()
	if !s.instanceInterrupted("pend-1") {
		t.Error("a stopped instance must be reported interrupted via its own status")
	}

	// And a deleted instance (removed from the map) is interrupted regardless.
	s.instancesMu.Lock()
	delete(s.instances, "pend-1")
	s.instancesMu.Unlock()
	if !s.instanceInterrupted("pend-1") {
		t.Error("a deleted instance must be reported interrupted")
	}
}

// Regression: the /api/scan dispatch ack must report the scan's actual local
// state ("pending" — queued until the admission gate grants a slot), not
// "started". The old "started" ack was read by external callers (e.g. a SaaS
// control plane) as "running", producing a SaaS=running / worker=pending
// desync whenever the worker was at its concurrency cap.
func TestHandleScanAckIsPendingNotStarted(t *testing.T) {
	s := newTestServer(t, nil)

	body := `{"targets":["https://example.com"],"scan_mode":"quick"}`
	req := httptest.NewRequest(http.MethodPost, "/api/scan", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	s.handleScan(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status code = %d, want 200", rr.Code)
	}
	var resp map[string]string
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("invalid JSON response: %v body=%q", err, rr.Body.String())
	}
	if resp["status"] != "pending" {
		t.Errorf("ack status = %q, want \"pending\" (must reflect queued state, not \"started\")", resp["status"])
	}
	if resp["instance_id"] == "" {
		t.Error("ack must include an instance_id")
	}
}
