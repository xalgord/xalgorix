package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// Per-instance actions may resolve either a live instance id or an exact,
// persisted scan record id used by dashboard navigation. They must never infer
// an unrelated run from a recent short alias.
func TestResolveInstanceForAction(t *testing.T) {
	s := newTestServer(t, nil)

	// Live instance keyed by its instance id.
	s.instancesMu.Lock()
	s.instances["inst-xyz"] = &ScanInstance{ID: "inst-xyz", Targets: "att.com", Status: "running"}
	s.instancesMu.Unlock()

	// A persisted scan record whose directory-slug ID differs from the instance
	// id but points back to it via InstanceID (the wildcard-parent shape).
	writeScanRecord(t, s.dataDir, "att.com/2026-07-20/att.com_slug", ScanRecord{
		ID:         "att.com_slug",
		InstanceID: "inst-xyz",
		Target:     "att.com",
		StartedAt:  "2026-07-20T10:00:00Z",
		Status:     "running",
	})

	t.Run("exact instance id", func(t *testing.T) {
		inst, ok := s.resolveInstanceForAction("inst-xyz")
		if !ok || inst == nil || inst.ID != "inst-xyz" {
			t.Fatalf("exact id did not resolve: ok=%v inst=%#v", ok, inst)
		}
	})

	t.Run("scan record id resolves to instance", func(t *testing.T) {
		inst, ok := s.resolveInstanceForAction("att.com_slug")
		if !ok || inst == nil || inst.ID != "inst-xyz" {
			t.Fatalf("record id did not resolve to instance: ok=%v inst=%#v", ok, inst)
		}
	})

	t.Run("unknown id", func(t *testing.T) {
		if _, ok := s.resolveInstanceForAction("does-not-exist"); ok {
			t.Fatal("unknown id should not resolve")
		}
	})

	t.Run("empty id", func(t *testing.T) {
		if _, ok := s.resolveInstanceForAction(""); ok {
			t.Fatal("empty id should not resolve")
		}
	})
}

func TestRestartRebuildPreservesExactInstanceSnapshot(t *testing.T) {
	s := newTestServer(t, nil)
	writeScanRecord(t, s.dataDir, "example/2026-08-12/canonical-record", ScanRecord{
		ID: "canonical-record", InstanceID: "a52be226", Target: "https://example.test",
		StartedAt: "2026-08-12T10:00:00Z", FinishedAt: "2026-08-12T10:10:00Z", Status: "finished",
		Events: []WSEvent{{Type: "message", Content: "final event"}},
	})

	s.rebuildInstancesFromDisk()
	if s.instances["a52be226"] == nil {
		t.Fatal("persisted external instance id was not reconstructed")
	}
	if s.instances["canonical-record"] != nil {
		t.Fatal("canonical record id replaced persisted external instance ownership")
	}

	assertSnapshot := func(wantID string) {
		t.Helper()
		rr := httptest.NewRecorder()
		s.handleInstanceAction(rr, httptest.NewRequest(http.MethodGet, "/api/instances/a52be226/snapshot", nil))
		if rr.Code != http.StatusOK {
			t.Fatalf("snapshot code=%d body=%s", rr.Code, rr.Body.String())
		}
		var got ScanRecord
		if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
			t.Fatalf("decode snapshot: %v", err)
		}
		if got.ID != wantID || got.InstanceID != "a52be226" || len(got.Events) != 1 {
			t.Fatalf("snapshot identity/events mismatch: %#v", got)
		}
	}
	assertSnapshot("a52be226")

	// Simulate terminal instance eviction: the exact persisted fallback keeps
	// the canonical record provenance and external run identity independently.
	s.instancesMu.Lock()
	delete(s.instances, "a52be226")
	s.instancesMu.Unlock()
	assertSnapshot("canonical-record")
}

func TestUnknownShortIDCannotReadOrMutateAnotherScan(t *testing.T) {
	s := newTestServer(t, nil)
	writeScanRecord(t, s.dataDir, "example/2026-08-12/owned-record", ScanRecord{
		ID: "owned-record", InstanceID: "a52be226", Target: "https://example.test",
		StartedAt: "2026-08-12T10:00:00Z", Status: "finished",
		Vulns: []VulnSummary{{ID: "v1", Title: "kept"}},
	})
	s.rebuildInstancesFromDisk()

	for _, tc := range []struct{ method, path string }{
		{http.MethodGet, "/api/instances/deadbeef"},
		{http.MethodGet, "/api/instances/deadbeef/snapshot"},
		{http.MethodPost, "/api/instances/deadbeef/stop"},
		{http.MethodPost, "/api/instances/deadbeef/restart"},
	} {
		rr := httptest.NewRecorder()
		s.handleInstanceAction(rr, httptest.NewRequest(tc.method, tc.path, nil))
		if rr.Code != http.StatusNotFound {
			t.Fatalf("%s %s code=%d body=%s", tc.method, tc.path, rr.Code, rr.Body.String())
		}
	}

	rr := httptest.NewRecorder()
	s.handleDeleteVuln(rr, httptest.NewRequest(http.MethodDelete, "/api/scans/deadbeef/vulns/v1", nil))
	if rr.Code != http.StatusNotFound {
		t.Fatalf("unknown alias deleted vulnerability: code=%d body=%s", rr.Code, rr.Body.String())
	}
	_, rec := s.findScanByInstanceID("a52be226")
	if rec == nil || len(rec.Vulns) != 1 {
		t.Fatalf("owned record was mutated through unknown alias: %#v", rec)
	}
}

func TestExactSnapshotWaitsForFinalEventPublication(t *testing.T) {
	s := newTestServer(t, nil)
	inst := &ScanInstance{
		ID:                 "exact-run",
		Targets:            "https://example.test",
		Status:             "finished",
		FinishedAt:         "2026-08-12T10:10:00Z",
		snapshotFinalizing: true,
		events:             []WSEvent{{Type: "message", Content: "persisted finding"}},
	}
	s.instancesMu.Lock()
	s.instances[inst.ID] = inst
	s.instancesMu.Unlock()

	requestSnapshot := func() *httptest.ResponseRecorder {
		t.Helper()
		rr := httptest.NewRecorder()
		s.handleInstanceAction(rr, httptest.NewRequest(http.MethodGet, "/api/instances/exact-run/snapshot", nil))
		return rr
	}
	if rr := requestSnapshot(); rr.Code != http.StatusConflict {
		t.Fatalf("finalizing snapshot code=%d body=%s", rr.Code, rr.Body.String())
	}

	inst.mu.Lock()
	inst.events = append(inst.events, WSEvent{Type: "queue_finished", Content: "Scan queue ended"})
	inst.snapshotFinalizing = false
	inst.mu.Unlock()

	rr := requestSnapshot()
	if rr.Code != http.StatusOK {
		t.Fatalf("published snapshot code=%d body=%s", rr.Code, rr.Body.String())
	}
	var got struct {
		InstanceID string    `json:"instance_id"`
		Events     []WSEvent `json:"events"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode snapshot: %v", err)
	}
	if got.InstanceID != "exact-run" || len(got.Events) != 2 || got.Events[1].Type != "queue_finished" {
		t.Fatalf("snapshot published without exact final event: %#v", got)
	}
}

func TestDuplicatePersistedInstanceIDIsNeverAuthoritative(t *testing.T) {
	s := newTestServer(t, nil)
	for _, item := range []struct{ path, id, target string }{
		{"one/2026-08-12/record-one", "record-one", "https://one.test"},
		{"two/2026-08-12/record-two", "record-two", "https://two.test"},
	} {
		writeScanRecord(t, s.dataDir, item.path, ScanRecord{
			ID: item.id, InstanceID: "duplicate-run", Target: item.target,
			StartedAt: "2026-08-12T10:00:00Z", FinishedAt: "2026-08-12T10:10:00Z", Status: "finished",
		})
	}

	s.rebuildInstancesFromDisk()
	if s.instances["duplicate-run"] != nil {
		t.Fatal("ambiguous persisted ownership was rebuilt as a live exact instance")
	}
	if _, rec := s.findScanByInstanceID("duplicate-run"); rec != nil {
		t.Fatalf("ambiguous persisted ownership resolved to %#v", rec)
	}
	if status, reserved := s.reserveDispatchID("duplicate-run"); reserved || status != "conflict" {
		t.Fatalf("ambiguous persisted ID was reusable: status=%q reserved=%v", status, reserved)
	}
	rr := httptest.NewRecorder()
	s.handleInstanceAction(rr, httptest.NewRequest(http.MethodGet, "/api/instances/duplicate-run/snapshot", nil))
	if rr.Code != http.StatusNotFound {
		t.Fatalf("ambiguous exact snapshot code=%d body=%s", rr.Code, rr.Body.String())
	}
}

func TestExactStopHeaderNeverResolvesCanonicalRecordAlias(t *testing.T) {
	s := newTestServer(t, nil)
	writeScanRecord(t, s.dataDir, "example/2026-08-12/canonical-record", ScanRecord{
		ID: "canonical-record", InstanceID: "exact-external-instance", Target: "https://example.test", Status: "running",
	})
	inst := &ScanInstance{ID: "exact-external-instance", Status: "running", Targets: "https://example.test"}
	s.instances[inst.ID] = inst

	req := httptest.NewRequest(http.MethodPost, "/api/instances/canonical-record/stop", nil)
	req.Header.Set("X-Xalgorix-Exact-Instance", "1")
	rr := httptest.NewRecorder()
	s.handleInstanceAction(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("exact stop accepted canonical alias: code=%d body=%s", rr.Code, rr.Body.String())
	}
	if inst.Status != "running" {
		t.Fatalf("exact stop mutated aliased instance: status=%q", inst.Status)
	}
}
