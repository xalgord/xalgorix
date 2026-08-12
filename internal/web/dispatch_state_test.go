package web

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/xalgord/xalgorix/v4/internal/agent"
	"github.com/xalgord/xalgorix/v4/internal/scanctx"
	"github.com/xalgord/xalgorix/v4/internal/scopeguard"
)

func TestExactStopTombstonePreventsDelayedDispatch(t *testing.T) {
	s := newTestServer(t, nil)
	id := "550e8400-e29b-41d4-a716-446655440000"

	stopReq := httptest.NewRequest(http.MethodPost, "/api/instances/"+id+"/stop", nil)
	stopReq.Header.Set("X-Xalgorix-Exact-Instance", "1")
	stopRR := httptest.NewRecorder()
	s.handleInstanceAction(stopRR, stopReq)
	if stopRR.Code != http.StatusOK {
		t.Fatalf("pre-dispatch exact stop code=%d body=%s", stopRR.Code, stopRR.Body.String())
	}
	var stopSnapshot struct {
		InstanceID  string `json:"instance_id"`
		Status      string `json:"status"`
		WorkStarted bool   `json:"work_started"`
	}
	if err := json.Unmarshal(stopRR.Body.Bytes(), &stopSnapshot); err != nil {
		t.Fatalf("decode pre-dispatch stop snapshot: %v", err)
	}
	if stopSnapshot.InstanceID != id || stopSnapshot.Status != "stopped" || stopSnapshot.WorkStarted {
		t.Fatalf("pre-dispatch stop returned invalid work evidence: %#v", stopSnapshot)
	}

	body := strings.NewReader(`{"targets":["https://example.test"],"scan_mode":"single","dispatch_id":"` + id + `"}`)
	startRR := httptest.NewRecorder()
	s.handleScan(startRR, httptest.NewRequest(http.MethodPost, "/api/scan", body))
	var ack map[string]string
	if err := json.Unmarshal(startRR.Body.Bytes(), &ack); err != nil {
		t.Fatalf("decode delayed dispatch ack: %v", err)
	}
	if ack["instance_id"] != id || ack["status"] != "stopped" {
		t.Fatalf("delayed dispatch bypassed tombstone: %#v", ack)
	}
	if s.instances[id] != nil {
		t.Fatal("delayed dispatch registered an instance after exact stop")
	}
}

func TestDurableExactSnapshotOwnsMultiTargetDispatch(t *testing.T) {
	s := newTestServer(t, nil)
	id := "550e8400-e29b-41d4-a716-446655440001"
	for _, item := range []struct{ path, recordID, target string }{
		{"one/2026-08-12/record-one", "record-one", "https://one.test"},
		{"two/2026-08-12/record-two", "record-two", "https://two.test"},
	} {
		writeScanRecord(t, s.dataDir, item.path, ScanRecord{
			ID: item.recordID, InstanceID: id, Target: item.target,
			StartedAt: "2026-08-12T10:00:00Z", FinishedAt: "2026-08-12T10:10:00Z", Status: "finished",
		})
	}
	inst := &ScanInstance{
		ID: id, Targets: "https://one.test, https://two.test", Status: "finished",
		StartedAt: "2026-08-12T10:00:00Z", FinishedAt: "2026-08-12T10:10:00Z",
		WorkStarted: true, SubScans: []SubScanSummary{},
		events: []WSEvent{{Type: "queue_finished", Content: "both targets complete"}},
	}
	if err := s.persistExactInstanceSnapshot(inst); err != nil {
		t.Fatalf("persist exact aggregate: %v", err)
	}

	_, rec := s.findScanByInstanceID(id)
	if rec == nil || rec.ID != id || rec.Target != inst.Targets || !rec.WorkStarted {
		t.Fatalf("exact aggregate did not own duplicated target records: %#v", rec)
	}
	rr := httptest.NewRecorder()
	s.handleInstanceAction(rr, httptest.NewRequest(http.MethodGet, "/api/instances/"+id+"/snapshot", nil))
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), "both targets complete") {
		t.Fatalf("exact aggregate snapshot code=%d body=%s", rr.Code, rr.Body.String())
	}
}

func TestDuplicateDispatchDuringFinalizationIsNonterminal(t *testing.T) {
	s := newTestServer(t, nil)
	id := "550e8400-e29b-41d4-a716-446655440002"
	s.instances[id] = &ScanInstance{ID: id, Status: "finished", snapshotFinalizing: true}
	if status, reserved := s.reserveDispatchID(id); reserved || status != "pending" {
		t.Fatalf("finalizing duplicate = (%q,%v), want pending acknowledgement", status, reserved)
	}
}

func TestSessionAdmissionSerializesWithExactStop(t *testing.T) {
	s := newTestServer(t, nil)
	id := "550e8400-e29b-41d4-a716-446655440003"
	inst := &ScanInstance{ID: id, Status: "running", SubScans: []SubScanSummary{}}
	s.instances[id] = inst

	newSessionAgent := func(name string) (*scanSession, *scanctx.ScanContext, *agent.Agent) {
		t.Helper()
		sctx := scanctx.New(name, t.TempDir())
		agnt := agent.NewAgent(s.cfg, name, make(chan agent.Event, 1), scopeguard.Config{}, sctx)
		sess := &scanSession{id: name, instanceID: id, scanDir: t.TempDir(), parentCtx: context.Background()}
		t.Cleanup(func() { agnt.Stop(); sctx.Close() })
		return sess, sctx, agnt
	}

	sess, sctx, agnt := newSessionAgent("admitted")
	if !s.registerSessionAgent(sess, sctx, agnt) || !inst.WorkStarted {
		t.Fatal("running session was not atomically admitted")
	}
	persisted, err := s.loadExactDispatchSnapshot(id)
	if err != nil || persisted.Status != "running" || !persisted.WorkStarted {
		t.Fatalf("work admission was not durable before Agent.Run: rec=%#v err=%v", persisted, err)
	}
	stopReq := httptest.NewRequest(http.MethodPost, "/api/instances/"+id+"/stop", nil)
	stopReq.Header.Set("X-Xalgorix-Exact-Instance", "1")
	stopRR := httptest.NewRecorder()
	s.handleInstanceAction(stopRR, stopReq)
	if stopRR.Code != http.StatusOK {
		t.Fatalf("exact stop code=%d body=%s", stopRR.Code, stopRR.Body.String())
	}
	var stopSnapshot struct {
		Status      string `json:"status"`
		WorkStarted bool   `json:"work_started"`
	}
	if err := json.Unmarshal(stopRR.Body.Bytes(), &stopSnapshot); err != nil {
		t.Fatalf("decode admitted stop snapshot: %v", err)
	}
	if stopSnapshot.Status != "stopped" || !stopSnapshot.WorkStarted {
		t.Fatalf("admitted stop lost positive work evidence: %#v", stopSnapshot)
	}
	if _, err := agnt.SendMessage("must be stopped"); err == nil {
		t.Fatal("admitted agent remained startable after exact stop")
	}

	lateSess, lateCtx, lateAgent := newSessionAgent("late")
	if s.registerSessionAgent(lateSess, lateCtx, lateAgent) {
		t.Fatal("session registered after exact stop")
	}
}

func TestWildcardChildStopRejectsLaterSessionAdmission(t *testing.T) {
	s := newTestServer(t, nil)
	id := "550e8400-e29b-41d4-a716-446655440004"
	inst := &ScanInstance{
		ID: id, Status: "running", ScanMode: "wildcard",
		SubScans:     []SubScanSummary{{Target: "child.example", Status: "pending"}},
		SubScanTotal: 1, SubScanRemaining: 1,
	}
	s.instances[id] = inst

	if !s.beginWildcardSubScan(id, 0, "child.example", "child-session") {
		t.Fatal("wildcard child was not admitted before stop")
	}

	stopReq := httptest.NewRequest(http.MethodPost, "/api/instances/"+id+"/stop", nil)
	stopReq.Header.Set("X-Xalgorix-Exact-Instance", "1")
	stopRR := httptest.NewRecorder()
	s.handleInstanceAction(stopRR, stopReq)
	if stopRR.Code != http.StatusOK {
		t.Fatalf("exact wildcard stop code=%d body=%s", stopRR.Code, stopRR.Body.String())
	}

	sctx := scanctx.New("child-session", t.TempDir())
	agnt := agent.NewAgent(s.cfg, "child-session", make(chan agent.Event, 1), scopeguard.Config{}, sctx)
	sess := &scanSession{
		id: "child-session", instanceID: id, scanDir: t.TempDir(), parentCtx: context.Background(),
	}
	t.Cleanup(func() { agnt.Stop(); sctx.Close() })
	if s.registerSessionAgent(sess, sctx, agnt) {
		t.Fatal("wildcard child session registered after exact stop")
	}

	inst.mu.RLock()
	defer inst.mu.RUnlock()
	if inst.Status != "stopped" || inst.WorkStarted {
		t.Fatalf("stopped wildcard gained false work evidence: status=%q work_started=%v", inst.Status, inst.WorkStarted)
	}
	if got := inst.SubScans[0].Status; got != "stopped" {
		t.Fatalf("dispatched wildcard child status=%q, want stopped", got)
	}
}

func TestExactStopWaitsForDurableFinalSnapshot(t *testing.T) {
	s := newTestServer(t, nil)
	id := "550e8400-e29b-41d4-a716-446655440005"
	inst := &ScanInstance{
		ID: id, Targets: "https://example.test", Status: "running", ScanMode: "single",
		WorkStarted: true, snapshotFinalizing: true,
		events: []WSEvent{{Type: "tool_result", Content: "final evidence"}},
	}
	s.instances[id] = inst

	stop := func() *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequest(http.MethodPost, "/api/instances/"+id+"/stop", nil)
		req.Header.Set("X-Xalgorix-Exact-Instance", "1")
		rr := httptest.NewRecorder()
		s.handleInstanceAction(rr, req)
		return rr
	}
	if rr := stop(); rr.Code != http.StatusConflict {
		t.Fatalf("finalizing exact stop code=%d body=%s", rr.Code, rr.Body.String())
	}
	stopping, err := s.loadExactDispatchSnapshot(id)
	if err != nil || stopping.Status != "stopping" || !stopping.WorkStarted {
		t.Fatalf("durable stop intent missing: rec=%#v err=%v", stopping, err)
	}

	inst.mu.Lock()
	inst.events = append(inst.events, WSEvent{Type: "queue_finished", Content: "Scan queue stopped"})
	inst.Vulns = append(inst.Vulns, VulnSummary{ID: "v-final", Title: "Final finding", Severity: "high"})
	inst.mu.Unlock()
	if err := s.persistExactInstanceSnapshot(inst); err != nil {
		t.Fatalf("persist coherent stopped snapshot: %v", err)
	}
	inst.mu.Lock()
	inst.snapshotFinalizing = false
	inst.mu.Unlock()

	rr := stop()
	if rr.Code != http.StatusOK {
		t.Fatalf("coherent exact stop code=%d body=%s", rr.Code, rr.Body.String())
	}
	var got ScanRecord
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode coherent stop: %v", err)
	}
	if got.Status != "stopped" || len(got.Events) < 2 || len(got.Vulns) != 1 || !got.WorkStarted {
		t.Fatalf("exact stop omitted final durable data: %#v", got)
	}
}

func TestExactStopReconstructsStoppingSnapshotAfterRestart(t *testing.T) {
	s := newTestServer(t, nil)
	id := "550e8400-e29b-41d4-a716-446655440006"
	if err := s.saveExactDispatchSnapshot(&ScanRecord{
		ID: id, InstanceID: id, Target: "https://example.test", Status: "stopping",
		Events: []WSEvent{}, Vulns: []VulnSummary{}, SubScans: []SubScanSummary{},
	}); err != nil {
		t.Fatalf("persist stopping intent: %v", err)
	}
	writeScanRecord(t, s.dataDir, "example/2026-08-12/physical-record", ScanRecord{
		ID: "physical-record", InstanceID: id, Target: "https://example.test", Status: "stopped",
		ToolCalls: 1, Events: []WSEvent{{Type: "tool_result", Content: "persisted before crash"}},
		Vulns: []VulnSummary{{ID: "v-crash", Title: "Crash-safe finding", Severity: "high"}},
	})

	req := httptest.NewRequest(http.MethodPost, "/api/instances/"+id+"/stop", nil)
	req.Header.Set("X-Xalgorix-Exact-Instance", "1")
	rr := httptest.NewRecorder()
	s.handleInstanceAction(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("restart recovery stop code=%d body=%s", rr.Code, rr.Body.String())
	}
	var got ScanRecord
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode restart recovery: %v", err)
	}
	if got.Status != "stopped" || got.StopReason != "exact_stop_recovered_after_restart" ||
		len(got.Events) != 2 || got.Events[0].Content != "persisted before crash" ||
		got.Events[1].Content != exactStopEventContent || len(got.Vulns) != 1 || !got.WorkStarted {
		t.Fatalf("restart stop did not reconstruct exact durable records: %#v", got)
	}
}

func TestQueuePersistenceFailureTerminalizesPendingDispatch(t *testing.T) {
	s := newTestServer(t, nil)
	id := "550e8400-e29b-41d4-a716-446655440007"
	req := ScanRequest{Targets: []string{"https://example.test"}, ScanMode: "single", InstanceID: id}
	if _, accepted, err := s.persistPendingDispatchSnapshot(req, id); err != nil || !accepted {
		t.Fatalf("persist pending dispatch: accepted=%v err=%v", accepted, err)
	}
	if err := s.abortPendingDispatchSnapshot(id, "queue_state_persist_failed"); err != nil {
		t.Fatalf("abort orphanable pending dispatch: %v", err)
	}
	rec, err := s.loadExactDispatchSnapshot(id)
	if err != nil || rec.Status != "failed" || rec.StopReason != "queue_state_persist_failed" {
		t.Fatalf("pending dispatch remained retryable without queue state: rec=%#v err=%v", rec, err)
	}
}

func TestResumeReplacementRequiresExactInertPlaceholder(t *testing.T) {
	placeholder := &ScanInstance{Status: "pending", StopReason: "server_restart_resuming"}
	if !isReplaceableResumePlaceholder(placeholder) {
		t.Fatal("exact inert restart placeholder was not replaceable")
	}
	for name, inst := range map[string]*ScanInstance{
		"new reservation": {Status: "pending"},
		"live generation": {Status: "running", StopReason: "server_restart_resuming"},
		"active placeholder": {
			Status: "pending", StopReason: "server_restart_resuming", cancel: func() {},
		},
	} {
		if isReplaceableResumePlaceholder(inst) {
			t.Fatalf("resume could overwrite %s: %#v", name, inst)
		}
	}
}

func TestSnapshotGETRetriesReadyTerminalPersistence(t *testing.T) {
	s := newTestServer(t, nil)
	id := "550e8400-e29b-41d4-a716-446655440008"
	req := ScanRequest{
		InstanceID: id,
		Targets:    []string{"https://example.test"},
		ScanMode:   "single",
	}
	if err := s.saveQueueStateDurable(0, req); err != nil {
		t.Fatalf("save resumable queue state: %v", err)
	}
	inst := &ScanInstance{
		ID: id, Targets: "https://example.test", Status: "finished", ScanMode: "single",
		FinishedAt: time.Now().Format(time.RFC3339Nano), WorkStarted: true,
		snapshotFinalizing: true, snapshotReady: true,
		events: []WSEvent{{Type: "queue_finished", Content: "Scan queue ended"}},
	}
	s.instances[id] = inst

	rr := httptest.NewRecorder()
	s.handleInstanceAction(rr, httptest.NewRequest(http.MethodGet, "/api/instances/"+id+"/snapshot", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("ready terminal snapshot GET code=%d body=%s", rr.Code, rr.Body.String())
	}
	inst.mu.RLock()
	finalizing := inst.snapshotFinalizing
	inst.mu.RUnlock()
	if finalizing {
		t.Fatal("GET did not clear finalization after durable exact snapshot retry")
	}
	persisted, err := s.loadExactDispatchSnapshot(id)
	if err != nil || persisted.Status != "finished" || len(persisted.Events) != 1 {
		t.Fatalf("GET did not persist coherent terminal snapshot: rec=%#v err=%v", persisted, err)
	}
	if _, err := os.Stat(s.queueStatePathForInstance(id)); !os.IsNotExist(err) {
		t.Fatalf("queue state remained after durable terminal retry: %v", err)
	}
}
