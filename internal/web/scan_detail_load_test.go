package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func makeEvents(n int) []WSEvent {
	events := make([]WSEvent, n)
	for i := 0; i < n; i++ {
		events[i] = WSEvent{
			Type:      "log",
			Content:   "event-" + itoa(i),
			Timestamp: "2026-08-15T00:00:00Z",
		}
	}
	return events
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	neg := i < 0
	if neg {
		i = -i
	}
	var b [20]byte
	pos := len(b)
	for i > 0 {
		pos--
		b[pos] = byte('0' + i%10)
		i /= 10
	}
	if neg {
		pos--
		b[pos] = '-'
	}
	return string(b[pos:])
}

func TestLoadScanRecordForDetail_TailsEventsAndCountsTotal(t *testing.T) {
	s := newTestServer(t, nil)
	total := 950
	writeScanRecord(t, s.dataDir, "example.com/2026-08-15/example.com_detail1", ScanRecord{
		ID:          "example.com_detail1",
		Target:      "example.com",
		Status:      "finished",
		Events:      makeEvents(total),
		TotalTokens: 123,
	})

	dir, ok := s.resolveScanDirByID("example.com_detail1")
	if !ok {
		t.Fatal("could not resolve scan dir")
	}
	rec, ok := s.loadScanRecordForDetail(dir, detailEventTail)
	if !ok || rec == nil {
		t.Fatal("loadScanRecordForDetail failed")
	}
	if rec.EventsTotal != total {
		t.Fatalf("EventsTotal = %d, want %d", rec.EventsTotal, total)
	}
	if !rec.EventsTruncated {
		t.Fatal("EventsTruncated should be true when total exceeds the tail")
	}
	if len(rec.Events) != detailEventTail {
		t.Fatalf("inline events = %d, want tail %d", len(rec.Events), detailEventTail)
	}
	// The tail must be the LAST detailEventTail events, in order.
	wantFirst := "event-" + itoa(total-detailEventTail)
	if rec.Events[0].Content != wantFirst {
		t.Fatalf("tail first = %q, want %q", rec.Events[0].Content, wantFirst)
	}
	if rec.Events[len(rec.Events)-1].Content != "event-"+itoa(total-1) {
		t.Fatalf("tail last = %q, want last event", rec.Events[len(rec.Events)-1].Content)
	}
	// Metadata must survive the streaming decode.
	if rec.Target != "example.com" || rec.TotalTokens != 123 || rec.Status != "finished" {
		t.Fatalf("metadata not preserved: %+v", rec)
	}
}

func TestLoadScanRecordForDetail_SmallScanNotTruncated(t *testing.T) {
	s := newTestServer(t, nil)
	writeScanRecord(t, s.dataDir, "small.com/2026-08-15/small.com_x", ScanRecord{
		ID:     "small.com_x",
		Target: "small.com",
		Status: "finished",
		Events: makeEvents(5),
	})
	dir, _ := s.resolveScanDirByID("small.com_x")
	rec, ok := s.loadScanRecordForDetail(dir, detailEventTail)
	if !ok {
		t.Fatal("load failed")
	}
	if rec.EventsTruncated {
		t.Fatal("small scan must not be truncated")
	}
	if rec.EventsTotal != 5 || len(rec.Events) != 5 {
		t.Fatalf("want 5 events total+inline, got total=%d inline=%d", rec.EventsTotal, len(rec.Events))
	}
}

func TestLoadScanEventsWindow(t *testing.T) {
	s := newTestServer(t, nil)
	total := 500
	writeScanRecord(t, s.dataDir, "win.com/2026-08-15/win.com_w", ScanRecord{
		ID:     "win.com_w",
		Target: "win.com",
		Status: "finished",
		Events: makeEvents(total),
	})
	dir, _ := s.resolveScanDirByID("win.com_w")

	events, got, ok := loadScanEventsWindow(dir, 100, 50)
	if !ok {
		t.Fatal("window load failed")
	}
	if got != total {
		t.Fatalf("total = %d, want %d", got, total)
	}
	if len(events) != 50 {
		t.Fatalf("window len = %d, want 50", len(events))
	}
	if events[0].Content != "event-100" || events[49].Content != "event-149" {
		t.Fatalf("window bounds wrong: first=%q last=%q", events[0].Content, events[49].Content)
	}

	// Window past the end clamps to whatever remains.
	tailEvents, _, _ := loadScanEventsWindow(dir, 480, 100)
	if len(tailEvents) != 20 {
		t.Fatalf("tail window len = %d, want 20", len(tailEvents))
	}
}

func TestHandleScanEvents_Endpoint(t *testing.T) {
	s := newTestServer(t, nil)
	writeScanRecord(t, s.dataDir, "ep.com/2026-08-15/ep.com_e", ScanRecord{
		ID:     "ep.com_e",
		Target: "ep.com",
		Status: "finished",
		Events: makeEvents(120),
	})

	rr := httptest.NewRecorder()
	s.handleScanEvents(rr, httptest.NewRequest(http.MethodGet, "/api/scans/ep.com_e/events?offset=10&limit=25", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("code = %d body=%s", rr.Code, rr.Body.String())
	}
	var resp struct {
		Events []WSEvent `json:"events"`
		Total  int       `json:"total"`
		Offset int       `json:"offset"`
		Limit  int       `json:"limit"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp.Total != 120 || resp.Offset != 10 || resp.Limit != 25 {
		t.Fatalf("meta wrong: %+v", resp)
	}
	if len(resp.Events) != 25 || resp.Events[0].Content != "event-10" {
		t.Fatalf("events window wrong: len=%d first=%q", len(resp.Events), resp.Events[0].Content)
	}
}

func TestReadScanSummary_SkipsEventsKeepsMetadata(t *testing.T) {
	s := newTestServer(t, nil)
	writeScanRecord(t, s.dataDir, "sum.com/2026-08-15/sum.com_s", ScanRecord{
		ID:          "sum.com_s",
		Target:      "sum.com",
		Status:      "finished",
		TotalTokens: 4242,
		Iterations:  7,
		Vulns:       []VulnSummary{{ID: "v1", Title: "x", Severity: "high"}},
		Events:      makeEvents(400),
	})
	dir, _ := s.resolveScanDirByID("sum.com_s")

	rec, ok := readScanSummary(dir + "/scan.json")
	if !ok {
		t.Fatal("readScanSummary failed")
	}
	if rec.Events != nil {
		t.Fatalf("summary must not carry events, got %d", len(rec.Events))
	}
	if rec.Target != "sum.com" || rec.TotalTokens != 4242 || rec.Iterations != 7 {
		t.Fatalf("metadata not preserved: %+v", rec)
	}
	if len(rec.Vulns) != 1 || rec.Vulns[0].ID != "v1" {
		t.Fatalf("vulns (a field AFTER events in the JSON) not preserved: %+v", rec.Vulns)
	}
}

func TestSaveScanRecordTo_WritesDetailSidecar(t *testing.T) {
	s := newTestServer(t, nil)
	dir := filepath.Join(s.dataDir, "side.com", "2026-08-16", "side.com_a")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	rec := &ScanRecord{ID: "side.com_a", Target: "side.com", Status: "finished", Events: makeEvents(800)}
	s.saveScanRecordTo(rec, dir)

	if _, err := os.Stat(filepath.Join(dir, scanMetaFile)); err != nil {
		t.Fatalf("sidecar not written: %v", err)
	}
	meta, ok := readScanDetailMeta(dir)
	if !ok {
		t.Fatal("readScanDetailMeta failed")
	}
	if meta.EventsTotal != 800 || !meta.EventsTruncated || len(meta.Events) != detailEventTail {
		t.Fatalf("sidecar contents wrong: total=%d trunc=%v inline=%d", meta.EventsTotal, meta.EventsTruncated, len(meta.Events))
	}
	// scan.json remains the full source of truth.
	full, ok := loadScanRecordFromDir(dir)
	if !ok || len(full.Events) != 800 {
		t.Fatalf("scan.json must keep all events, got ok=%v n=%d", ok, len(full.Events))
	}
}

func TestLoadScanRecordForDetail_UsesSidecarFastPath(t *testing.T) {
	s := newTestServer(t, nil)
	dir := filepath.Join(s.dataDir, "fp.com", "2026-08-16", "fp.com_a")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	// scan.json says 10 events; a sidecar (fresher) says something different so
	// we can prove the reader served the sidecar, not scan.json.
	writeScanRecord(t, dir, ".", ScanRecord{ID: "fp.com_a", Target: "fp.com", Status: "finished", Events: makeEvents(10)})
	// Rename the written file into place (writeScanRecord wrote scan.json here).
	sentinel := &ScanRecord{ID: "fp.com_a", Target: "fp.com", Status: "finished", Events: makeEvents(3)}
	sentinel.EventsTotal = 999
	sentinel.EventsTruncated = true
	writeScanDetailMetaLight(dir, sentinel)
	// Make the sidecar newer than scan.json.
	now := time.Now().Add(2 * time.Second)
	_ = os.Chtimes(filepath.Join(dir, scanMetaFile), now, now)

	rec, ok := s.loadScanRecordForDetail(dir, detailEventTail)
	if !ok {
		t.Fatal("load failed")
	}
	if rec.EventsTotal != 999 {
		t.Fatalf("expected sidecar to be served (total=999), got %d", rec.EventsTotal)
	}
}

func TestReadScanDetailMeta_IgnoresStaleSidecar(t *testing.T) {
	s := newTestServer(t, nil)
	dir := filepath.Join(s.dataDir, "stale.com", "2026-08-16", "stale.com_a")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	// Old sidecar first.
	writeScanDetailMetaLight(dir, &ScanRecord{ID: "stale.com_a", EventsTotal: 5})
	old := time.Now().Add(-1 * time.Hour)
	_ = os.Chtimes(filepath.Join(dir, scanMetaFile), old, old)
	// Newer scan.json (as if a later write skipped the sidecar).
	writeScanRecord(t, dir, ".", ScanRecord{ID: "stale.com_a", Target: "stale.com", Status: "finished", Events: makeEvents(50)})

	if _, ok := readScanDetailMeta(dir); ok {
		t.Fatal("stale sidecar (older than scan.json) must be ignored")
	}
	// The detail loader should then rebuild from scan.json and refresh the sidecar.
	rec, ok := s.loadScanRecordForDetail(dir, detailEventTail)
	if !ok || rec.EventsTotal != 50 {
		t.Fatalf("rebuild from scan.json failed: ok=%v total=%d", ok, rec.EventsTotal)
	}
	if meta, ok := readScanDetailMeta(dir); !ok || meta.EventsTotal != 50 {
		t.Fatalf("sidecar not refreshed after rebuild: ok=%v", ok)
	}
}

func TestHandleGetScan_ReturnsTailAndTruncatedFlag(t *testing.T) {
	s := newTestServer(t, nil)
	total := 700
	writeScanRecord(t, s.dataDir, "big.com/2026-08-15/big.com_g", ScanRecord{
		ID:     "big.com_g",
		Target: "big.com",
		Status: "finished",
		Events: makeEvents(total),
	})

	rr := httptest.NewRecorder()
	s.handleGetScan(rr, httptest.NewRequest(http.MethodGet, "/api/scans/big.com_g", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("code = %d body=%s", rr.Code, rr.Body.String())
	}
	var rec ScanRecord
	if err := json.Unmarshal(rr.Body.Bytes(), &rec); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if rec.EventsTotal != total || !rec.EventsTruncated {
		t.Fatalf("expected total=%d truncated=true, got total=%d truncated=%v", total, rec.EventsTotal, rec.EventsTruncated)
	}
	if len(rec.Events) != detailEventTail {
		t.Fatalf("detail inline events = %d, want %d", len(rec.Events), detailEventTail)
	}
}
