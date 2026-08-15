// Package web — streaming loaders for the scan-detail read path.
//
// A finished scan's scan.json embeds the entire event log (every LLM message
// and raw tool stdout), which for a high-token scan can be hundreds of MB. The
// old GET /api/scans/{id} path json.Unmarshalled that whole file into
// ScanRecord (decoding millions of WSEvent struct fields) and then re-marshaled
// it — so opening one big scan could hang the handler for minutes.
//
// These loaders walk scan.json ONCE with a streaming decoder, decode only the
// small metadata fields, count the events, and materialize just the slice of
// events the caller needs (a tail for the detail view, or an offset/limit
// window for lazy paging). Event elements outside the requested slice are never
// decoded into structs and never held in memory.
package web

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
)

// detailEventTail is how many of the most recent events GET /api/scans/{id}
// returns inline. Enough to render a useful activity tail immediately; older
// events are paged on demand via GET /api/scans/{id}/events.
const detailEventTail = 300

// maxEventsWindow bounds a single lazy events page so a caller can't ask the
// server to materialize an unbounded slice.
const maxEventsWindow = 1000

// walkScanJSON streams the scan.json object at path. Non-"events" top-level
// fields are captured (undecoded) into meta; every element of the "events"
// array is passed to onEvent by index. It returns the total event count. The
// whole file is read but only metadata + whatever onEvent retains stays live.
func walkScanJSON(path string, onEvent func(idx int, raw json.RawMessage)) (map[string]json.RawMessage, int, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, 0, err
	}
	defer f.Close()

	dec := json.NewDecoder(bufio.NewReaderSize(f, 1<<20))
	meta := make(map[string]json.RawMessage, 32)
	total := 0

	// Opening '{'.
	if _, err := dec.Token(); err != nil {
		return nil, 0, err
	}
	for dec.More() {
		keyTok, err := dec.Token()
		if err != nil {
			return nil, 0, err
		}
		key, _ := keyTok.(string)
		if key == "events" {
			// The value is either an array or null.
			t, err := dec.Token()
			if err != nil {
				return nil, 0, err
			}
			if d, ok := t.(json.Delim); ok && d == '[' {
				if onEvent == nil {
					// Summary mode: skip the events array by token depth without
					// materializing any element. Critically this avoids copying a
					// multi-hundred-MB events blob into memory (the old
					// ReadFile + scanRecordLite path did exactly that on every
					// cache-cold walk, thrashing GC near GOMEMLIMIT). Element
					// strings are tokenized transiently and GC'd one at a time.
					depth := 1
					for depth > 0 {
						tok, err := dec.Token()
						if err != nil {
							return nil, 0, err
						}
						if delim, ok := tok.(json.Delim); ok {
							switch delim {
							case '[', '{':
								depth++
							case ']', '}':
								depth--
							}
						}
					}
				} else {
					for dec.More() {
						var raw json.RawMessage
						if err := dec.Decode(&raw); err != nil {
							return nil, 0, err
						}
						onEvent(total, raw)
						total++
					}
					// Closing ']'.
					if _, err := dec.Token(); err != nil {
						return nil, 0, err
					}
				}
			}
			// else: null (or unexpected) → no events.
			continue
		}
		var raw json.RawMessage
		if err := dec.Decode(&raw); err != nil {
			return nil, 0, err
		}
		meta[key] = raw
	}
	return meta, total, nil
}

// recordFromMeta rebuilds a ScanRecord from the captured non-event fields.
func recordFromMeta(meta map[string]json.RawMessage) (*ScanRecord, error) {
	metaBytes, err := json.Marshal(meta)
	if err != nil {
		return nil, err
	}
	var rec ScanRecord
	if err := json.Unmarshal(metaBytes, &rec); err != nil {
		return nil, err
	}
	return &rec, nil
}

func decodeEvents(raws []json.RawMessage) []WSEvent {
	events := make([]WSEvent, 0, len(raws))
	for _, r := range raws {
		var e WSEvent
		if json.Unmarshal(r, &e) == nil {
			events = append(events, e)
		}
	}
	return events
}

// readScanSummary parses a scan.json into a ScanRecord WITHOUT its event log,
// streaming past the events array so a huge log is never read into memory. This
// is the events-free parse behind the summary cache; it replaces the old
// os.ReadFile + Unmarshal(scanRecordLite) path that copied the entire events
// blob into a RawMessage only to discard it.
func readScanSummary(path string) (*ScanRecord, bool) {
	meta, _, err := walkScanJSON(path, nil)
	if err != nil {
		return nil, false
	}
	rec, err := recordFromMeta(meta)
	if err != nil {
		return nil, false
	}
	rec.Events = nil
	return rec, true
}

// loadScanRecordForDetail loads a scan record for the detail response with only
// the last `tail` events inline. It sets EventsTotal and, when older events
// were dropped, EventsTruncated. Falls back to a full load on any streaming
// error so callers still get a correct (if slower) response for odd records.
func (s *Server) loadScanRecordForDetail(dir string, tail int) (*ScanRecord, bool) {
	if dir == "" {
		return nil, false
	}
	if tail < 0 {
		tail = 0
	}
	path := filepath.Join(dir, "scan.json")

	// Ring buffer keeping only the last `tail` raw events.
	ring := make([]json.RawMessage, 0, tail)
	meta, total, err := walkScanJSON(path, func(_ int, raw json.RawMessage) {
		if tail == 0 {
			return
		}
		if len(ring) < tail {
			ring = append(ring, raw)
			return
		}
		copy(ring, ring[1:])
		ring[tail-1] = raw
	})
	if err != nil {
		// Fallback: legacy/edge records that don't stream cleanly.
		return loadScanRecordFromDir(dir)
	}
	rec, err := recordFromMeta(meta)
	if err != nil {
		return loadScanRecordFromDir(dir)
	}
	rec.Events = decodeEvents(ring)
	rec.EventsTotal = total
	rec.EventsTruncated = total > len(rec.Events)
	return rec, true
}

// loadScanEventsWindow returns the events in [offset, offset+limit) in original
// order, plus the total event count. Used by the lazy-paging endpoint.
func loadScanEventsWindow(dir string, offset, limit int) ([]WSEvent, int, bool) {
	if dir == "" || limit <= 0 {
		return nil, 0, false
	}
	if offset < 0 {
		offset = 0
	}
	if limit > maxEventsWindow {
		limit = maxEventsWindow
	}
	path := filepath.Join(dir, "scan.json")
	end := offset + limit
	window := make([]json.RawMessage, 0, limit)
	_, total, err := walkScanJSON(path, func(idx int, raw json.RawMessage) {
		if idx >= offset && idx < end {
			window = append(window, raw)
		}
	})
	if err != nil {
		return nil, 0, false
	}
	return decodeEvents(window), total, true
}
