package web

import (
	"encoding/json"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/xalgord/xalgorix/v4/internal/tools/reporting"
)

// vulnToSummary converts a reporting.Vulnerability to a VulnSummary with all fields.
func vulnToSummary(v reporting.Vulnerability) VulnSummary {
	return VulnSummary{
		ID:                 v.ID,
		Title:              v.Title,
		Severity:           v.Severity,
		Target:             v.Target,
		Endpoint:           v.Endpoint,
		CVSS:               v.CVSS,
		CVSSVector:         v.CVSSVector,
		Description:        v.Description,
		Impact:             v.Impact,
		Method:             v.Method,
		CVE:                v.CVE,
		CWE:                v.CWE,
		OWASP:              v.OWASP,
		TechnicalAnalysis:  v.TechnicalAnalysis,
		PoCDescription:     v.PoCDescription,
		PoCScript:          v.PoCScript,
		Remediation:        v.Remediation,
		Fix:                v.Fix,
		ExploitationProof:  v.ExploitationProof,
		VerificationMethod: v.VerificationMethod,
		Verified:           v.Verified,
		Tags:               v.Tags,
	}
}

func metadataString(metadata map[string]any, key string) (string, bool) {
	if metadata == nil {
		return "", false
	}
	value, ok := metadata[key]
	if !ok {
		return "", false
	}
	text, ok := value.(string)
	if !ok {
		return "", false
	}
	text = strings.TrimSpace(text)
	return text, text != ""
}

func findReportedVulnerabilityByID(vulns []reporting.Vulnerability, id string) (reporting.Vulnerability, bool) {
	for _, vuln := range vulns {
		if vuln.ID == id {
			return vuln, true
		}
	}
	return reporting.Vulnerability{}, false
}

func appendVulnSummaryUnique(vulns *[]VulnSummary, vuln VulnSummary) bool {
	key := vulnSummaryKey(vuln)
	for i := range *vulns {
		existing := &(*vulns)[i]
		if vulnSummaryKey(*existing) == key {
			// A live parent snapshot can arrive before the persisted wildcard
			// child. Preserve the row while enriching it with authoritative
			// physical provenance once the child copy is attached.
			if existing.SourceScanID == "" && vuln.SourceScanID != "" {
				existing.SourceScanID = vuln.SourceScanID
			}
			return false
		}
	}
	*vulns = append(*vulns, vuln)
	return true
}

func vulnSummaryKey(v VulnSummary) string {
	return strings.Join([]string{
		normalizeSummaryPart(v.Title),
		normalizeSummaryPart(v.Target),
		normalizeSummaryPart(v.Endpoint),
		normalizeSummaryPart(v.Method),
		normalizeSummaryPart(v.CVE),
	}, "|")
}

func normalizeSummaryPart(value string) string {
	return strings.Join(strings.Fields(strings.ToLower(strings.TrimSpace(value))), " ")
}

// generateReportAt generates a PDF report, saving it to a specific directory.
func (s *Server) generateReportAt(scan *ScanRecord, scanDir string) (string, error) {
	// Temporarily set currentScanDir for the report generator,
	// then restore it. The report.go generateReport method reads s.currentScanDir.
	s.mu.Lock()
	prevDir := s.currentScanDir
	s.currentScanDir = scanDir
	s.mu.Unlock()

	reportPath, err := s.generateReport(scan)

	s.mu.Lock()
	s.currentScanDir = prevDir
	s.mu.Unlock()

	return reportPath, err
}

// scanEntry holds a discovered scan.json path and its parsed record.
type scanEntry struct {
	dir string     // directory containing scan.json
	rec ScanRecord // parsed record
}

// findAllScans recursively walks dataDir to find all scan.json files.
// Structure: dataDir/target/date/slug/scan.json
func (s *Server) findAllScans() []scanEntry {
	var results []scanEntry
	_ = filepath.WalkDir(s.dataDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			name := d.Name()
			if name == "scratch" || name == "reports" || name == "logs" || name == "artifacts" || name == "tools" || name == "snapshots" || name == "notes" || name == ".git" {
				return filepath.SkipDir
			}
			return nil
		}
		if d.Name() != "scan.json" {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		var rec ScanRecord
		if json.Unmarshal(data, &rec) != nil {
			return nil
		}
		results = append(results, scanEntry{dir: filepath.Dir(path), rec: rec})
		return nil
	})
	return results
}

// scanSummaryCacheEntry is one memoized, events-free scan record plus the file
// stat used to detect staleness.
type scanSummaryCacheEntry struct {
	modNano int64
	size    int64
	rec     ScanRecord
}

// scanRecordLite parses a scan.json while skipping the heavy events array.
// The embedded ScanRecord carries every field; the shadow Events field — a
// json.RawMessage at depth 0 — captures the "events" key so encoding/json
// routes it here instead of unmarshaling thousands of WSEvent structs into the
// embedded slice (encoding/json picks the shallowest field on a tag conflict).
// The captured bytes are discarded: list, findings, and summary views never
// read events, and skipping the per-event struct decode is the bulk of the
// parse-cost saving.
type scanRecordLite struct {
	ScanRecord
	Events json.RawMessage `json:"events"`
}

// findAllScanSummaries is the events-free, cached counterpart to findAllScans.
// It walks the data dir, parses each scan.json without decoding its event log,
// and memoizes the result per file keyed by (modtime, size). Subsequent walks
// only stat each file and re-parse the few that changed, so warm rebuilds are
// effectively free. Callers that need the event log (report generation,
// scan-detail) must use findAllScans instead.
func (s *Server) findAllScanSummaries() []scanEntry {
	var results []scanEntry

	s.scanSummaryCacheMu.Lock()
	defer s.scanSummaryCacheMu.Unlock()
	if s.scanSummaryCache == nil {
		s.scanSummaryCache = make(map[string]scanSummaryCacheEntry)
	}
	seen := make(map[string]struct{})

	_ = filepath.WalkDir(s.dataDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			name := d.Name()
			if name == "scratch" || name == "reports" || name == "logs" || name == "artifacts" || name == "tools" || name == "snapshots" || name == "notes" || name == ".git" {
				return filepath.SkipDir
			}
			return nil
		}
		if d.Name() != "scan.json" {
			return nil
		}
		info, ierr := d.Info()
		if ierr != nil {
			return nil
		}
		seen[path] = struct{}{}
		modNano := info.ModTime().UnixNano()
		size := info.Size()
		if c, ok := s.scanSummaryCache[path]; ok && c.modNano == modNano && c.size == size {
			results = append(results, scanEntry{dir: filepath.Dir(path), rec: c.rec})
			return nil
		}
		data, rerr := os.ReadFile(path)
		if rerr != nil {
			return nil
		}
		var lite scanRecordLite
		if json.Unmarshal(data, &lite) != nil {
			return nil
		}
		rec := lite.ScanRecord
		rec.Events = nil
		s.scanSummaryCache[path] = scanSummaryCacheEntry{modNano: modNano, size: size, rec: rec}
		results = append(results, scanEntry{dir: filepath.Dir(path), rec: rec})
		return nil
	})

	// Drop cache entries for files that no longer exist so deleted scans
	// don't leak memory across the process lifetime.
	if len(s.scanSummaryCache) > len(seen) {
		for p := range s.scanSummaryCache {
			if _, ok := seen[p]; !ok {
				delete(s.scanSummaryCache, p)
			}
		}
	}

	return results
}

// findScanByID searches for a scan by its AgentID (the slug dir name).
func (s *Server) findScanByID(scanID string) (string, *ScanRecord) {
	// Sanitize: prevent path traversal via ../
	scanID = filepath.Base(scanID)
	if scanID == "" || scanID == "." || scanID == ".." {
		return "", nil
	}

	// First: prefer top-level scans. Multiple wildcard child records share the
	// same instance id; returning a child here makes the UI route land on one
	// subdomain instead of the parent wildcard scan.
	entries := s.findAllScans()
	for _, entry := range entries {
		if entry.rec.ParentTarget != "" {
			continue
		}
		if entry.rec.ID == scanID || entry.rec.InstanceID == scanID || filepath.Base(entry.dir) == scanID {
			return entry.dir, &entry.rec
		}
	}
	// Second: allow direct child lookup when the caller explicitly uses a child
	// scan id, for report generation and historical compatibility.
	for _, entry := range entries {
		if entry.rec.ID == scanID || entry.rec.InstanceID == scanID || filepath.Base(entry.dir) == scanID {
			return entry.dir, &entry.rec
		}
	}
	// Second: try legacy flat path as fallback (dataDir/scanID/scan.json)
	direct := filepath.Join(s.dataDir, scanID, "scan.json")
	if data, err := os.ReadFile(direct); err == nil {
		var rec ScanRecord
		if json.Unmarshal(data, &rec) == nil {
			return filepath.Join(s.dataDir, scanID), &rec
		}
	}
	return "", nil
}

var shortHexIDPattern = regexp.MustCompile(`^[a-f0-9]{8}$`)

func (s *Server) findRecentScanForShortAlias(scanID string) (string, *ScanRecord) {
	if !shortHexIDPattern.MatchString(scanID) {
		return "", nil
	}

	entries := s.findAllScans()
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].rec.StartedAt > entries[j].rec.StartedAt
	})

	for _, entry := range entries {
		if entry.rec.ParentTarget != "" {
			continue
		}
		startedAt, err := time.Parse(time.RFC3339Nano, entry.rec.StartedAt)
		if err != nil {
			continue
		}
		if time.Since(startedAt) > 24*time.Hour {
			continue
		}
		log.Printf("[web] Resolving short scan route %s to recent scan %s", scanID, entry.rec.ID)
		return entry.dir, &entry.rec
	}
	return "", nil
}

func (s *Server) markDiscordWebhookConfigured(rec *ScanRecord) {
	if rec == nil {
		return
	}
	rec.DiscordWebhookConfigured = rec.DiscordWebhookConfigured ||
		rec.DiscordWebhook != "" ||
		s.discordWebhook != ""
}

// markTelegramConfigured sets the TelegramConfigured flag on a scan
// record when global Telegram notifications are enabled. Telegram is
// global-only in v1 (no per-scan override), so the flag reflects the
// server-wide configuration rather than any per-scan field. The bot
// token itself is never written to the record (only the boolean).
func (s *Server) markTelegramConfigured(rec *ScanRecord) {
	if rec == nil {
		return
	}
	rec.TelegramConfigured = s.telegramConfigured()
}

func (s *Server) scanRecordFromInstance(inst *ScanInstance) *ScanRecord {
	if inst == nil {
		return nil
	}
	inst.mu.RLock()
	defer inst.mu.RUnlock()

	events := make([]WSEvent, len(inst.events))
	copy(events, inst.events)
	vulns := make([]VulnSummary, len(inst.Vulns))
	copy(vulns, inst.Vulns)
	phases := append([]int(nil), inst.Phases...)
	severityFilter := append([]string(nil), inst.SeverityFilter...)

	return &ScanRecord{
		ID:                       inst.ID,
		InstanceID:               inst.ID,
		Name:                     inst.Name,
		Target:                   inst.Targets,
		ParentTarget:             inst.ParentTarget,
		StartedAt:                inst.StartedAt,
		FinishedAt:               inst.FinishedAt,
		Status:                   inst.Status,
		StopReason:               inst.StopReason,
		ScanMode:                 inst.ScanMode,
		Instruction:              inst.Instruction,
		SeverityFilter:           severityFilter,
		DiscordWebhook:           inst.DiscordWebhook,
		DiscordWebhookConfigured: inst.DiscordWebhook != "",
		TelegramConfigured:       s.telegramConfigured(),
		ReconMode:                inst.ReconMode,
		ScanIntensity:            inst.ScanIntensity,
		Events:                   events,
		Vulns:                    vulns,
		TotalTokens:              inst.TotalTokens,
		Iterations:               inst.Iterations,
		ToolCalls:                inst.ToolCalls,
		CompanyName:              inst.CompanyName,
		LogoPath:                 inst.LogoPath,
		Phases:                   phases,
		CurrentPhase:             inst.CurrentPhase,
	}
}

func normalizeScanTarget(target string) string {
	target = strings.ToLower(strings.TrimSpace(target))
	target = strings.TrimPrefix(target, "https://")
	target = strings.TrimPrefix(target, "http://")
	target = strings.TrimRight(target, "/")
	return target
}

func isFinishedSubScanStatus(status string) bool {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "finished", "completed", "stopped", "failed":
		return true
	default:
		return false
	}
}

func isCompletedScanStatus(status string) bool {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "finished", "completed":
		return true
	default:
		return false
	}
}

func isFinalScanStatus(status string) bool {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "finished", "completed", "failed":
		return true
	default:
		return false
	}
}

func isTerminalScanStatus(status string) bool {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "finished", "completed", "stopped", "failed":
		return true
	default:
		return false
	}
}

func isUnresolvedSubScanStatus(status string) bool {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "", "pending", "running":
		return true
	default:
		return false
	}
}

func terminalSubScanStatus(parentStatus string) string {
	if strings.EqualFold(strings.TrimSpace(parentStatus), "failed") {
		return "failed"
	}
	return "stopped"
}

func isChildOfScan(parent, child *ScanRecord) bool {
	if parent == nil || child == nil || child.ParentTarget == "" {
		return false
	}
	// Instance-aware matching: when the parent has an InstanceID (all
	// multi-instance scans do), the child must belong to the same
	// instance. Without this gate a new yahoo.com scan would absorb
	// every subdomain record from *previous* yahoo.com scans on disk,
	// instantly showing stale vulns and inflated subdomain counts.
	if parent.InstanceID != "" {
		return child.InstanceID == parent.InstanceID
	}
	// Legacy fallback for scans created before multi-instance mode:
	// match by target name only.
	return normalizeScanTarget(child.ParentTarget) == normalizeScanTarget(parent.Target)
}

func (s *Server) instanceForRecord(rec *ScanRecord) *ScanInstance {
	if rec == nil {
		return nil
	}
	s.instancesMu.RLock()
	defer s.instancesMu.RUnlock()
	if rec.InstanceID != "" {
		if inst := s.instances[rec.InstanceID]; inst != nil {
			return inst
		}
	}
	return s.instances[rec.ID]
}

func (s *Server) applyInstanceSnapshot(rec *ScanRecord, includeEvents bool) {
	inst := s.instanceForRecord(rec)
	if inst == nil {
		return
	}
	snapshot := s.scanRecordFromInstance(inst)
	if snapshot == nil {
		return
	}
	if rec.InstanceID == "" {
		rec.InstanceID = snapshot.InstanceID
	}
	// Terminal states are FINAL. A stale in-memory instance — e.g. one left in
	// the map after an engine restart + auto-resume, or an orphaned pre-resume
	// instance — can report "running" for a scan that already reached a
	// terminal state on disk. Overwriting the persisted terminal status with
	// that live "running" made GET /api/scans/{id} report the scan as running
	// forever, so a poller (the SaaS reaper) never reconciled it (the
	// crowdproof.id desync). Only adopt the snapshot's status when we are NOT
	// downgrading an already-terminal persisted status to a non-terminal one.
	// Only guard genuinely-FINAL states (completed/finished). "stopped" is
	// resumable and "failed" is re-runnable, so a live "running" instance must
	// still win for those (see TestApplyInstanceSnapshotDoesNotErasePersistedResumeData).
	// But a completed scan is done forever: a stale in-memory instance left
	// after a restart/auto-resume must not downgrade it back to "running".
	if isFinalScanStatus(rec.Status) && !isFinalScanStatus(snapshot.Status) {
		log.Printf("[scan] %s (instance %s): kept final disk status %q over stale in-memory instance status %q — not downgrading a final scan to running",
			rec.ID, rec.InstanceID, rec.Status, snapshot.Status)
	} else {
		rec.Status = snapshot.Status
		rec.FinishedAt = snapshot.FinishedAt
		rec.StopReason = snapshot.StopReason
	}
	if snapshot.Iterations > rec.Iterations {
		rec.Iterations = snapshot.Iterations
	}
	if snapshot.ToolCalls > rec.ToolCalls {
		rec.ToolCalls = snapshot.ToolCalls
	}
	if snapshot.TotalTokens > rec.TotalTokens {
		rec.TotalTokens = snapshot.TotalTokens
	}
	for _, vuln := range snapshot.Vulns {
		appendVulnSummaryUnique(&rec.Vulns, vuln)
	}
	// Phase is monotonic progress — only ever advance it. A stale in-memory
	// instance (post-restart/resume) could otherwise drag a finished scan's
	// phase back down (e.g. 22 → 11), same root cause as the status downgrade.
	if snapshot.CurrentPhase > rec.CurrentPhase {
		rec.CurrentPhase = snapshot.CurrentPhase
	}
	if includeEvents && len(snapshot.Events) >= len(rec.Events) {
		rec.Events = snapshot.Events
	}
}

// attachWildcardSubScans resolves a wildcard parent scan's child sub-scans by
// walking the data dir. It is a thin wrapper around attachWildcardSubScansFrom
// for callers that do not already hold a walked entry slice.
func (s *Server) attachWildcardSubScans(rec *ScanRecord) {
	if rec == nil || rec.ParentTarget != "" {
		return
	}
	s.attachWildcardSubScansFrom(rec, s.findAllScans())
}

// attachWildcardSubScansFrom is the same as attachWildcardSubScans but reuses
// a pre-walked slice of scan entries instead of calling findAllScans() itself.
// This lets bulk callers (e.g. cachedScanList) walk the data dir ONCE and
// resolve children for every parent from the same slice, instead of triggering
// a full disk walk + parse per parent scan (previously O(parents × allScans)).
func (s *Server) attachWildcardSubScansFrom(rec *ScanRecord, entries []scanEntry) {
	if rec == nil || rec.ParentTarget != "" {
		return
	}

	children := make(map[string]*SubScanSummary)
	order := []string{}
	add := func(key string, summary SubScanSummary) *SubScanSummary {
		key = normalizeScanTarget(key)
		if key == "" {
			key = normalizeScanTarget(summary.Target)
		}
		if key == "" {
			return nil
		}
		if existing := children[key]; existing != nil {
			if summary.ID != "" {
				existing.ID = summary.ID
			}
			if summary.Target != "" {
				existing.Target = summary.Target
			}
			if summary.StartedAt != "" {
				existing.StartedAt = summary.StartedAt
			}
			if summary.FinishedAt != "" {
				existing.FinishedAt = summary.FinishedAt
			}
			if summary.Status != "" && (!isFinishedSubScanStatus(existing.Status) || !strings.EqualFold(summary.Status, "running")) {
				existing.Status = summary.Status
			}
			if summary.VulnCount > 0 {
				existing.VulnCount = summary.VulnCount
			}
			if summary.TotalTokens > 0 {
				existing.TotalTokens = summary.TotalTokens
			}
			return existing
		}
		if summary.Status == "" {
			summary.Status = "running"
		}
		children[key] = &summary
		order = append(order, key)
		return children[key]
	}

	total := 0
	if rec.SubScanTotal > total {
		total = rec.SubScanTotal
	}
	for _, child := range rec.SubScans {
		add(child.Target, child)
	}

	for _, entry := range entries {
		child := entry.rec
		if !isChildOfScan(rec, &child) {
			continue
		}
		for _, vuln := range child.Vulns {
			// Reconstruct provenance for historical records and override stale
			// promoted metadata with the physical child that owns the finding.
			vuln.SourceScanID = child.ID
			appendVulnSummaryUnique(&rec.Vulns, vuln)
		}
		add(child.Target, SubScanSummary{
			ID:          child.ID,
			Target:      child.Target,
			StartedAt:   child.StartedAt,
			FinishedAt:  child.FinishedAt,
			Status:      child.Status,
			VulnCount:   len(child.Vulns),
			TotalTokens: child.TotalTokens,
		})
	}

	for _, evt := range rec.Events {
		if evt.SubTargetTotal > total {
			total = evt.SubTargetTotal
		}
		if evt.ParentTarget == "" && evt.SubTargetTotal == 0 {
			continue
		}
		target := strings.TrimSpace(evt.Target)
		if target == "" {
			continue
		}
		status := ""
		startedAt := ""
		finishedAt := ""
		switch evt.Type {
		case "target_started":
			status = "running"
			startedAt = evt.Timestamp
		case "target_completed":
			status = "finished"
			finishedAt = evt.Timestamp
		case "subdomains_discovered":
			for _, line := range strings.Split(evt.Output, "\n") {
				target := strings.TrimSpace(line)
				if target == "" {
					continue
				}
				add(target, SubScanSummary{Target: target, Status: "pending"})
			}
			continue
		default:
			continue
		}
		summary := add(target, SubScanSummary{
			ID:         evt.AgentID,
			Target:     target,
			StartedAt:  startedAt,
			FinishedAt: finishedAt,
			Status:     status,
		})
		_ = summary
	}

	if total < len(children) {
		total = len(children)
	}
	if total == 0 {
		return
	}

	summaries := make([]SubScanSummary, 0, len(order))
	for _, key := range order {
		child := *children[key]
		summaries = append(summaries, child)
	}
	sort.SliceStable(summaries, func(i, j int) bool {
		if summaries[i].StartedAt == "" || summaries[j].StartedAt == "" {
			return summaries[i].Target < summaries[j].Target
		}
		return summaries[i].StartedAt < summaries[j].StartedAt
	})

	danglingActive := false
	if isTerminalScanStatus(rec.Status) {
		fallbackStatus := terminalSubScanStatus(rec.Status)
		finishedAt := rec.FinishedAt
		if finishedAt == "" {
			finishedAt = time.Now().Format(time.RFC3339)
		}
		for i := range summaries {
			if !isUnresolvedSubScanStatus(summaries[i].Status) {
				continue
			}
			danglingActive = true
			summaries[i].Status = fallbackStatus
			if summaries[i].FinishedAt == "" {
				summaries[i].FinishedAt = finishedAt
			}
		}
	}

	completed := 0
	running := 0
	for _, child := range summaries {
		if isFinishedSubScanStatus(child.Status) {
			completed++
		} else if strings.EqualFold(child.Status, "running") {
			running++
		}
	}
	remaining := total - completed - running
	if remaining < 0 {
		remaining = 0
	}
	if isCompletedScanStatus(rec.Status) && (danglingActive || running > 0 || remaining > 0) {
		rec.Status = "stopped"
		if rec.StopReason == "" {
			rec.StopReason = "incomplete_wildcard_subscans"
		}
		if rec.FinishedAt == "" {
			rec.FinishedAt = time.Now().Format(time.RFC3339)
		}
	}
	rec.SubScans = summaries
	rec.SubScanTotal = total
	rec.SubScanCompleted = completed
	rec.SubScanRunning = running
	rec.SubScanRemaining = remaining
}

func finalizeScanRecordForResponse(rec *ScanRecord) {
	if rec == nil {
		return
	}
	// Native and historical findings may predate provenance metadata. Any
	// child/live finding with known provenance has already retained it through
	// aggregation, so only unresolved rows fall back to the displayed record.
	for i := range rec.Vulns {
		if rec.Vulns[i].SourceScanID == "" {
			rec.Vulns[i].SourceScanID = rec.ID
		}
	}
	if isCompletedScanStatus(rec.Status) && phaseAllowed(rec.Phases, 22) {
		rec.CurrentPhase = 22
	}
}

// rebuildInstancesFromDisk populates s.instances from all saved scan.json files on disk.
// This ensures the dashboard shows historical scans immediately after server restart.
// Skips subdomain scans (those with ParentTarget set) — those are shown under their parent.
// Running scans from a previous server instance are marked as "stopped" since the agent process is gone.
func (s *Server) rebuildInstancesFromDisk() {
	queueEntries := s.validQueueStateEntries(false)
	qMap := make(map[string]string)
	for _, qe := range queueEntries {
		if qe.state != nil && qe.state.InstanceID != "" {
			if qe.state.ActiveScanDir != "" {
				qMap[filepath.Clean(qe.state.ActiveScanDir)] = qe.state.InstanceID
			}
			if qe.state.ActiveScanID != "" {
				qMap[qe.state.ActiveScanID] = qe.state.InstanceID
			}
			if len(qe.state.Targets) > 0 {
				qMap[normalizeScanTarget(qe.state.Targets[0])] = qe.state.InstanceID
			}
		}
	}

	for _, entry := range s.findAllScans() {
		// If scan was "running" from a previous server instance, transition it to "pending" / "resuming"
		// so the startup queue resumer can pick it back up without marking it as stopped or failed.
		if entry.rec.Status == "running" {
			entry.rec.Status = "pending"
			entry.rec.StopReason = "server_restart_resuming"
			s.saveScanRecordTo(&entry.rec, entry.dir)
		}

		// Skip subdomain scans — they belong to their parent wildcard scan
		if entry.rec.ParentTarget != "" {
			continue
		}

		instID := entry.rec.ID
		if mappedID, ok := qMap[filepath.Clean(entry.dir)]; ok {
			instID = mappedID
		} else if mappedID, ok := qMap[entry.rec.ID]; ok {
			instID = mappedID
		} else if mappedID, ok := qMap[normalizeScanTarget(entry.rec.Target)]; ok {
			instID = mappedID
		}

		inst := &ScanInstance{
			ID:             instID,
			Name:           entry.rec.Name,
			Targets:        entry.rec.Target,
			ParentTarget:   entry.rec.ParentTarget,
			Status:         entry.rec.Status,
			StartedAt:      entry.rec.StartedAt,
			FinishedAt:     entry.rec.FinishedAt,
			StopReason:     entry.rec.StopReason,
			Iterations:     entry.rec.Iterations,
			ToolCalls:      entry.rec.ToolCalls,
			VulnCount:      len(entry.rec.Vulns),
			TotalTokens:    entry.rec.TotalTokens,
			ScanMode:       entry.rec.ScanMode,
			Instruction:    entry.rec.Instruction,
			SeverityFilter: entry.rec.SeverityFilter,
			Phases:         entry.rec.Phases,
			ReconMode:      entry.rec.ReconMode,
			ScanIntensity:  entry.rec.ScanIntensity,
			CompanyName:    entry.rec.CompanyName,
			LogoPath:       entry.rec.LogoPath,
			DiscordWebhook: entry.rec.DiscordWebhook,
			Vulns:          entry.rec.Vulns,
			CurrentPhase:   entry.rec.CurrentPhase,
			events:         append([]WSEvent(nil), entry.rec.Events...),
		}
		if inst.CurrentPhase == 0 {
			inst.CurrentPhase = firstSelectedPhase(inst.Phases)
		}
		inst.ReconMode = normalizeActivityMode(inst.ReconMode)
		inst.ScanIntensity = normalizeActivityMode(inst.ScanIntensity)
		chatCfg := *s.cfg
		inst.chatCfg = &chatCfg
		s.instances[instID] = inst
	}
	// Statuses may have been rewritten on disk above (running → stopped), so
	// drop any memoized scan list built before recovery.
	s.invalidateScanListCache()
}
