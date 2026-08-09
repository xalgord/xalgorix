package web

import (
	"context"
	cryptorand "crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/xalgord/xalgorix/v4/internal/agent"
	"github.com/xalgord/xalgorix/v4/internal/llm"
	"github.com/xalgord/xalgorix/v4/internal/scanctx"
	"github.com/xalgord/xalgorix/v4/internal/scopeguard"
	"github.com/xalgord/xalgorix/v4/internal/tools/httpclient"
	"github.com/xalgord/xalgorix/v4/internal/tools/reporting"
)

const (
	maxConcurrentRetests = 4
	maxRetestJobs        = 256
	retestJobTTL         = time.Hour
	maxRetestRequestBody = 256 * 1024
)

const (
	retestQueued      = "queued"
	retestRunning     = "running"
	retestCompleted   = "completed"
	retestFailed      = "failed"
	retestUnsupported = "unsupported"
)

type retestFindingInput struct {
	Title              string `json:"title"`
	Severity           string `json:"severity,omitempty"`
	CWE                string `json:"cwe_id,omitempty"`
	VerificationMethod string `json:"verification_method,omitempty"`
	CVSSVector         string `json:"cvss_vector,omitempty"`
	Target             string `json:"target"`
	Endpoint           string `json:"endpoint"`
	Method             string `json:"method"`
	Description        string `json:"description,omitempty"`
	Proof              string `json:"exploitation_proof,omitempty"`
}

type retestStartRequest struct {
	Finding      retestFindingInput `json:"finding"`
	TargetAuth   string             `json:"target_auth,omitempty"`
	TargetAuthB  string             `json:"target_auth_b,omitempty"`
	verification reporting.VerificationRequest
	policy       httpclient.RequestPolicy
}

// localRetestStartInput is the scanner dashboard's strict wire contract. The
// browser sends identifiers only; finding content, target, authentication, and
// provider configuration remain server-derived.
type localRetestStartInput struct {
	ScanID       string `json:"scan_id"`
	SourceScanID string `json:"source_scan_id,omitempty"`
	FindingID    string `json:"finding_id"`
}

type retestResult struct {
	Verdict  string `json:"verdict"`
	Reason   string `json:"reason,omitempty"`
	Evidence string `json:"evidence,omitempty"`
}

type retestJob struct {
	ID                   string        `json:"id"`
	Status               string        `json:"status"`
	CreatedAt            string        `json:"created_at"`
	StartedAt            string        `json:"started_at,omitempty"`
	FinishedAt           string        `json:"finished_at,omitempty"`
	Result               *retestResult `json:"result,omitempty"`
	ErrorCode            string        `json:"error_code,omitempty"`
	Error                string        `json:"error,omitempty"`
	MeaningfulAttempt    bool          `json:"meaningful_attempt"`
	RequestCount         int           `json:"request_count"`
	AffectedRequestCount int           `json:"affected_request_count"`
	AffectedVariantCount int           `json:"affected_variant_count"`
}

type retestOutcome struct {
	status               string
	result               *retestResult
	errorCode            string
	err                  string
	meaningfulAttempt    bool
	requestCount         int
	affectedRequestCount int
	affectedVariantCount int
}

func (s *Server) handleStartFindingRetest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeRetestError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
		return
	}

	var req retestStartRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxRetestRequestBody))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeRetestError(w, http.StatusBadRequest, "validation_failed", "invalid request body")
		return
	}
	if err := ensureJSONEOF(dec); err != nil {
		writeRetestError(w, http.StatusBadRequest, "validation_failed", "request body must contain one JSON object")
		return
	}
	s.enqueueFindingRetest(w, req)
}

// handleStartLocalFindingRetest is the scanner dashboard entry point. Unlike
// the server-to-server SaaS endpoint above, it accepts identifiers only and
// resolves every executable value from the scanner's own record/private state.
func (s *Server) handleStartLocalFindingRetest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeRetestError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
		return
	}

	var input localRetestStartInput
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4*1024))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&input); err != nil {
		writeRetestError(w, http.StatusBadRequest, "validation_failed", "invalid request body")
		return
	}
	if err := ensureJSONEOF(dec); err != nil {
		writeRetestError(w, http.StatusBadRequest, "validation_failed", "request body must contain one JSON object")
		return
	}
	input.ScanID = strings.TrimSpace(input.ScanID)
	input.SourceScanID = strings.TrimSpace(input.SourceScanID)
	input.FindingID = strings.TrimSpace(input.FindingID)
	if !validLocalRetestID(input.ScanID) || !validLocalRetestID(input.FindingID) ||
		(input.SourceScanID != "" && !validLocalRetestID(input.SourceScanID)) {
		writeRetestError(w, http.StatusBadRequest, "validation_failed", "scan_id, source_scan_id, and finding_id must be valid identifiers")
		return
	}

	_, displayedRecord := s.findScanByID(input.ScanID)
	if displayedRecord == nil {
		writeRetestError(w, http.StatusNotFound, "not_found", "scan or finding not found")
		return
	}

	sourceRecord := displayedRecord
	if input.SourceScanID != "" {
		// Build the same effective view returned by GET /api/scans/{id}. This
		// includes live findings that may be visible before their child record
		// has been flushed to disk.
		effectiveRecord := *displayedRecord
		effectiveRecord.Vulns = append([]VulnSummary(nil), displayedRecord.Vulns...)
		effectiveRecord.Events = append([]WSEvent(nil), displayedRecord.Events...)
		effectiveRecord.SubScans = append([]SubScanSummary(nil), displayedRecord.SubScans...)
		s.applyInstanceSnapshot(&effectiveRecord, true)
		s.attachWildcardSubScans(&effectiveRecord)
		finalizeScanRecordForResponse(&effectiveRecord)

		var status int
		sourceRecord, status = s.findLocalRetestSource(displayedRecord, &effectiveRecord, input.SourceScanID)
		if sourceRecord == nil {
			if status == http.StatusConflict {
				writeRetestError(w, status, "ambiguous_finding", "source scan identifier is not unique within this scan")
			} else {
				writeRetestError(w, http.StatusNotFound, "not_found", "scan or finding not found")
			}
			return
		}
	}

	var finding *VulnSummary
	for i := range sourceRecord.Vulns {
		if sourceRecord.Vulns[i].ID != input.FindingID {
			continue
		}
		if finding != nil {
			writeRetestError(w, http.StatusConflict, "ambiguous_finding", "finding identifier is not unique within its source scan")
			return
		}
		finding = &sourceRecord.Vulns[i]
	}
	if finding == nil {
		writeRetestError(w, http.StatusNotFound, "not_found", "scan or finding not found")
		return
	}

	target := strings.TrimSpace(finding.Target)
	if target == "" {
		target = strings.TrimSpace(sourceRecord.Target)
	}
	target = normalizeLocalRetestTarget(target, sourceRecord.Target)
	method := strings.ToUpper(strings.TrimSpace(finding.Method))
	if method == "" {
		method = http.MethodGet
	}
	endpoint := normalizeLocalRetestEndpoint(finding.Endpoint, method)
	primaryAuth, secondaryAuth := s.snapshotRetestAuth(displayedRecord, sourceRecord, input.ScanID)
	req := retestStartRequest{
		Finding: retestFindingInput{
			Title: finding.Title, Severity: finding.Severity, CWE: finding.CWE,
			VerificationMethod: finding.VerificationMethod, CVSSVector: finding.CVSSVector,
			Target: target, Endpoint: endpoint, Method: method,
			Description: finding.Description, Proof: finding.ExploitationProof,
		},
		TargetAuth: primaryAuth, TargetAuthB: secondaryAuth,
	}
	s.enqueueFindingRetest(w, req)
}

// findLocalRetestSource resolves an exact physical source record and accepts it
// only when it is the displayed parent or one of that parent's wildcard
// children. Instance-ID aliases are intentionally not used here: siblings can
// share an instance ID, and choosing one by walk order could retest the wrong
// target. Duplicate exact IDs are rejected rather than selected arbitrarily.
func (s *Server) findLocalRetestSource(displayed, effective *ScanRecord, sourceScanID string) (*ScanRecord, int) {
	var matched *ScanRecord
	matches := 0
	for _, entry := range s.findAllScans() {
		candidate := entry.rec
		if candidate.ID != sourceScanID {
			continue
		}
		if candidate.ID != displayed.ID && !isChildOfScan(displayed, &candidate) {
			continue
		}
		matches++
		copy := candidate
		matched = &copy
	}
	if matches > 1 {
		return nil, http.StatusConflict
	}

	// Merge live promoted copies from the effective response view into the
	// physical record. This closes the short window where the UI already shows
	// a finding but the child scan.json has not persisted it yet.
	if matched != nil {
		for _, vuln := range effective.Vulns {
			if vuln.SourceScanID == sourceScanID {
				appendVulnSummaryUnique(&matched.Vulns, vuln)
			}
		}
		return matched, http.StatusOK
	}

	// A live wildcard child may not have a physical record yet. Validate its
	// source ID against the server-built sub-scan view, reject reused child IDs,
	// and construct an in-memory source record from findings carrying that same
	// server-assigned provenance.
	var child *SubScanSummary
	for i := range effective.SubScans {
		if effective.SubScans[i].ID != sourceScanID {
			continue
		}
		if child != nil {
			return nil, http.StatusConflict
		}
		copy := effective.SubScans[i]
		child = &copy
	}
	if child == nil {
		return nil, http.StatusNotFound
	}
	live := &ScanRecord{
		ID:           sourceScanID,
		InstanceID:   displayed.InstanceID,
		Target:       child.Target,
		ParentTarget: displayed.Target,
		Vulns:        []VulnSummary{},
	}
	for _, vuln := range effective.Vulns {
		if vuln.SourceScanID == sourceScanID {
			appendVulnSummaryUnique(&live.Vulns, vuln)
		}
	}
	if len(live.Vulns) == 0 {
		return nil, http.StatusNotFound
	}
	return live, http.StatusOK
}

func validLocalRetestID(value string) bool {
	return value != "" && len(value) <= 512 && value != "." && value != ".." && !strings.ContainsAny(value, `/\\`)
}

// normalizeLocalRetestTarget makes historical host-only finding targets usable
// by the dashboard without relaxing the strict server-to-server API contract.
// Only a bare authority is upgraded; malformed URLs, credentials, paths, and
// alternate schemes remain unchanged so validateRetestRequest rejects them.
func normalizeLocalRetestTarget(target, recordTarget string) string {
	target = strings.TrimSpace(target)
	if _, err := parseRetestURL(target); err == nil {
		return target
	}
	if target == "" || strings.Contains(target, "://") || strings.ContainsAny(target, `/\\?#@%`) ||
		strings.IndexFunc(target, func(r rune) bool { return r <= ' ' }) >= 0 {
		return target
	}

	authority, err := url.Parse("//" + target)
	if err != nil || authority.Host == "" || authority.Hostname() == "" || authority.User != nil ||
		authority.Path != "" || authority.RawQuery != "" || authority.Fragment != "" {
		return target
	}

	if recorded, err := parseRetestURL(strings.TrimSpace(recordTarget)); err == nil &&
		strings.EqualFold(recorded.Host, authority.Host) {
		return recorded.Scheme + "://" + authority.Host
	}
	return "https://" + authority.Host
}

// normalizeLocalRetestEndpoint removes a duplicated method token from legacy
// records such as "POST /v1/register" when the method is already stored in its
// dedicated field. The resulting URL is still checked by the strict validator.
func normalizeLocalRetestEndpoint(endpoint, method string) string {
	endpoint = strings.TrimSpace(endpoint)
	fields := strings.Fields(endpoint)
	if len(fields) >= 2 && strings.EqualFold(fields[0], method) {
		return strings.TrimSpace(endpoint[len(fields[0]):])
	}
	return endpoint
}

func (s *Server) snapshotRetestAuth(displayedRecord, sourceRecord *ScanRecord, requestedScanID string) (string, string) {
	candidates := uniqueStrings(
		displayedRecord.InstanceID,
		sourceRecord.InstanceID,
		displayedRecord.ID,
		requestedScanID,
		sourceRecord.ID,
	)
	s.instancesMu.RLock()
	var inst *ScanInstance
	for _, id := range candidates {
		if candidate := s.instances[id]; candidate != nil {
			inst = candidate
			break
		}
	}
	s.instancesMu.RUnlock()
	if inst == nil {
		return "", ""
	}
	inst.mu.RLock()
	defer inst.mu.RUnlock()
	return inst.TargetAuth, inst.TargetAuthSecondary
}

func (s *Server) enqueueFindingRetest(w http.ResponseWriter, req retestStartRequest) {
	if err := validateRetestRequest(&req); err != nil {
		writeRetestError(w, http.StatusBadRequest, "validation_failed", err.Error())
		return
	}

	select {
	case s.retestSlots <- struct{}{}:
	default:
		writeRetestError(w, http.StatusTooManyRequests, "capacity_exhausted", "too many targeted re-tests are already running")
		return
	}

	id, err := newRetestID()
	if err != nil {
		<-s.retestSlots
		writeRetestError(w, http.StatusInternalServerError, "start_failed", "could not start targeted re-test")
		return
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	job := retestJob{ID: id, Status: retestQueued, CreatedAt: now}
	if !s.storeRetestJob(job) {
		<-s.retestSlots
		writeRetestError(w, http.StatusTooManyRequests, "capacity_exhausted", "targeted re-test history is at capacity")
		return
	}

	go s.runRetestWorker(id, req)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusAccepted)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"id": id, "status": retestQueued, "created_at": now,
		"poll_url": "/api/findings/retest/" + id,
	})
}

func (s *Server) handleGetFindingRetest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeRetestError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
		return
	}
	id := strings.TrimPrefix(r.URL.Path, "/api/findings/retest/")
	if id == "" || strings.Contains(id, "/") {
		writeRetestError(w, http.StatusNotFound, "not_found", "targeted re-test job not found")
		return
	}
	job, ok := s.getRetestJob(id)
	if !ok {
		writeRetestError(w, http.StatusNotFound, "not_found", "targeted re-test job not found")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(job)
}

func writeRetestError(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error_code": code, "error": message})
}

func ensureJSONEOF(dec *json.Decoder) error {
	var extra any
	if err := dec.Decode(&extra); errors.Is(err, io.EOF) {
		return nil
	} else if err != nil {
		return err
	}
	return fmt.Errorf("extra JSON value")
}

func validateRetestRequest(req *retestStartRequest) error {
	f := &req.Finding
	f.Title = strings.TrimSpace(f.Title)
	f.Target = strings.TrimSpace(f.Target)
	f.Endpoint = strings.TrimSpace(f.Endpoint)
	f.Method = strings.ToUpper(strings.TrimSpace(f.Method))
	if f.Title == "" || f.Target == "" || f.Endpoint == "" || f.Method == "" {
		return fmt.Errorf("finding.title, finding.target, finding.endpoint, and finding.method are required")
	}
	for name, value := range map[string]string{
		"finding.title": f.Title, "finding.severity": f.Severity,
		"finding.cwe_id": f.CWE, "finding.verification_method": f.VerificationMethod,
		"finding.cvss_vector": f.CVSSVector, "finding.description": f.Description,
		"finding.exploitation_proof": f.Proof,
	} {
		if len(value) > 12000 {
			return fmt.Errorf("%s is too long", name)
		}
	}
	if len(f.Target) > 2048 || len(f.Endpoint) > 2048 {
		return fmt.Errorf("finding target or endpoint is too long")
	}
	if len(req.TargetAuth) > 64*1024 || len(req.TargetAuthB) > 64*1024 {
		return fmt.Errorf("target authentication material is too long")
	}

	targetURL, err := parseRetestURL(f.Target)
	if err != nil {
		return fmt.Errorf("invalid finding.target: %w", err)
	}
	endpointRef, err := url.Parse(f.Endpoint)
	if err != nil {
		return fmt.Errorf("invalid finding.endpoint")
	}
	endpointURL := targetURL.ResolveReference(endpointRef)
	if endpointURL.Scheme != "http" && endpointURL.Scheme != "https" || endpointURL.Hostname() == "" || endpointURL.User != nil {
		return fmt.Errorf("finding.endpoint must resolve to an HTTP(S) URL without embedded credentials")
	}

	hosts := uniqueStrings(targetURL.Host, endpointURL.Host)
	methods := []string{http.MethodGet, http.MethodHead}
	if f.Method == http.MethodPost {
		methods = append(methods, http.MethodPost)
	}
	policy := httpclient.RequestPolicy{
		AllowedHosts: hosts, AllowedMethods: methods,
		AffectedURL: endpointURL.String(), AffectedMethod: f.Method,
		MaxRequests: 8, MaxTimeout: 20, MaxBytes: 64 * 1024, PublicOnly: true,
	}
	if err := httpclient.ValidateRequestPolicyURL(policy, targetURL.String(), http.MethodGet); err != nil {
		return fmt.Errorf("finding.target is not an allowed public HTTP(S) target")
	}
	if err := httpclient.ValidateRequestPolicyURL(policy, endpointURL.String(), http.MethodGet); err != nil {
		return fmt.Errorf("finding.endpoint is not an allowed public HTTP(S) target")
	}

	f.Target = targetURL.String()
	f.Endpoint = endpointURL.String()
	req.policy = policy
	req.verification = reporting.VerificationRequest{
		Title: f.Title, Severity: strings.TrimSpace(f.Severity), CWE: strings.TrimSpace(f.CWE),
		VerificationMethod: strings.TrimSpace(f.VerificationMethod), CVSSVector: strings.TrimSpace(f.CVSSVector),
		Target: f.Target, Endpoint: f.Endpoint, HTTPMethod: f.Method,
		Description: strings.TrimSpace(f.Description), Proof: strings.TrimSpace(f.Proof),
	}
	return nil
}

func parseRetestURL(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil {
		return nil, fmt.Errorf("must be an absolute HTTP(S) URL without embedded credentials")
	}
	u.Fragment = ""
	return u, nil
}

func uniqueStrings(values ...string) []string {
	seen := make(map[string]bool, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.ToLower(strings.TrimSpace(value))
		if value != "" && !seen[value] {
			seen[value] = true
			out = append(out, value)
		}
	}
	return out
}

func newRetestID() (string, error) {
	buf := make([]byte, 16)
	if _, err := cryptorand.Read(buf); err != nil {
		return "", err
	}
	return "rt_" + hex.EncodeToString(buf), nil
}

func (s *Server) storeRetestJob(job retestJob) bool {
	s.retestMu.Lock()
	defer s.retestMu.Unlock()
	s.cleanupRetestJobsLocked(time.Now())
	if len(s.retestJobs) >= maxRetestJobs {
		return false
	}
	s.retestJobs[job.ID] = job
	return true
}

func (s *Server) getRetestJob(id string) (retestJob, bool) {
	s.retestMu.Lock()
	defer s.retestMu.Unlock()
	s.cleanupRetestJobsLocked(time.Now())
	job, ok := s.retestJobs[id]
	return job, ok
}

func (s *Server) updateRetestJob(id string, update func(*retestJob)) {
	s.retestMu.Lock()
	defer s.retestMu.Unlock()
	job, ok := s.retestJobs[id]
	if !ok {
		return
	}
	update(&job)
	s.retestJobs[id] = job
}

func (s *Server) cleanupRetestJobsLocked(now time.Time) {
	for id, job := range s.retestJobs {
		if job.Status == retestQueued || job.Status == retestRunning {
			continue
		}
		finished, err := time.Parse(time.RFC3339Nano, job.FinishedAt)
		if err != nil || now.Sub(finished) > retestJobTTL {
			delete(s.retestJobs, id)
		}
	}
}

func (s *Server) runRetestWorker(id string, req retestStartRequest) {
	defer func() { <-s.retestSlots }()
	s.updateRetestJob(id, func(job *retestJob) {
		job.Status = retestRunning
		job.StartedAt = time.Now().UTC().Format(time.RFC3339Nano)
	})

	outcome := retestOutcome{}
	func() {
		defer func() {
			if recover() != nil {
				outcome = retestOutcome{status: retestFailed, errorCode: "start_failed", err: "targeted re-test failed to start"}
			}
		}()
		if s.retestRunner != nil {
			outcome = s.retestRunner(req)
		} else {
			outcome = s.executeRetest(req)
		}
	}()
	if outcome.status == "" {
		outcome = retestOutcome{status: retestFailed, errorCode: "start_failed", err: "targeted re-test did not produce a result"}
	}

	s.updateRetestJob(id, func(job *retestJob) {
		job.Status = outcome.status
		job.Result = outcome.result
		job.ErrorCode = outcome.errorCode
		job.Error = outcome.err
		job.MeaningfulAttempt = outcome.meaningfulAttempt
		job.RequestCount = outcome.requestCount
		job.AffectedRequestCount = outcome.affectedRequestCount
		job.AffectedVariantCount = outcome.affectedVariantCount
		job.FinishedAt = time.Now().UTC().Format(time.RFC3339Nano)
	})
}

func (s *Server) executeRetest(req retestStartRequest) retestOutcome {
	cfg := *s.cfg
	cfg.TargetAuth = ""
	cfg.TargetAuthSecondary = ""

	ep, err := s.resolveScanCredentials(context.Background(), ScanRequest{}, &cfg)
	if errors.Is(err, errUnknownProviderProfile) {
		return retestOutcome{status: retestUnsupported, errorCode: "provider_unsupported", err: "requested provider profile is unavailable"}
	}
	if err != nil {
		return retestOutcome{status: retestFailed, errorCode: "provider_failed", err: "provider configuration could not be loaded"}
	}
	if isZeroEndpoint(ep) {
		return retestOutcome{status: retestUnsupported, errorCode: "provider_unsupported", err: "no supported LLM provider is configured"}
	}

	client := llm.NewClient(&cfg, llm.WithResolver(llm.NewFixedResolver(ep)))
	id, err := newRetestID()
	if err != nil {
		return retestOutcome{status: retestFailed, errorCode: "start_failed", err: "could not allocate targeted re-test context"}
	}
	contextID := "retest-" + strings.TrimPrefix(id, "rt_")
	sctx := scanctx.New(contextID, "")
	scanctx.Activate(sctx)
	var verifier *agent.Agent
	defer func() {
		httpclient.SetSessionAuth(contextID, nil)
		httpclient.SetSessionAuthSecondary(contextID, nil)
		httpclient.ClearRequestPolicy(contextID)
		if verifier != nil {
			verifier.Stop()
		}
		reporting.CleanupContext(contextID)
		scanctx.Deactivate(contextID)
		sctx.Close()
	}()

	httpclient.SetRequestPolicy(contextID, req.policy)
	verifier = agent.NewAgent(&cfg, "targeted-retest", nil,
		scopeguard.Config{BindAddr: s.cfg.BindAddr, Port: s.port}, sctx, agent.WithLLMClient(client))
	verifier.ConfigureRetestAuth(req.TargetAuth, req.TargetAuthB)
	verdict := verifier.RetestFinding(req.verification)
	execution := httpclient.RequestPolicyExecutionStats(contextID)
	attempts := httpclient.RequestPolicyUsage(contextID)
	if shouldRetryZeroAttemptBudgetExhaustion(verdict, execution, attempts) {
		// A model that spent every turn without even attempting an HTTP request
		// has not retested the finding. Retry once in the same bounded context.
		// Reusing the policy preserves the original request cap, and requiring
		// zero attempts prevents replaying a request that may have side effects.
		verdict = verifier.RetestFinding(req.verification)
		execution = httpclient.RequestPolicyExecutionStats(contextID)
		attempts = httpclient.RequestPolicyUsage(contextID)
	}
	if shouldRetryZeroAttemptBudgetExhaustion(verdict, execution, attempts) {
		return retestOutcome{
			status:    retestFailed,
			errorCode: "no_attempt",
			err:       "the verifier could not execute the targeted retest; no vulnerability status was inferred",
		}
	}
	verdict.Reason = verifier.RedactRetestEvidence(verdict.Reason)
	verdict.Evidence = verifier.RedactRetestEvidence(verdict.Evidence)
	outcome := retestOutcome{
		meaningfulAttempt:    execution.RequestCount > 0,
		requestCount:         execution.RequestCount,
		affectedRequestCount: execution.AffectedRequestCount,
		affectedVariantCount: execution.AffectedVariantCount,
	}

	if strings.HasPrefix(strings.ToLower(verdict.Reason), "verifier llm error:") {
		outcome.status = retestFailed
		outcome.errorCode = "provider_failed"
		outcome.err = "LLM provider failed during targeted re-test"
		return outcome
	}
	outcome.status = retestCompleted
	outcome.result = mapRetestVerdict(verdict, execution)
	return outcome
}

func shouldRetryZeroAttemptBudgetExhaustion(
	verdict reporting.VerificationVerdict,
	execution httpclient.RequestPolicyExecution,
	attempts int,
) bool {
	return verdict.Inconclusive &&
		verdict.Reason == agent.RetestTurnBudgetExhaustedReason &&
		attempts == 0 &&
		execution.RequestCount == 0 &&
		execution.AffectedRequestCount == 0 &&
		execution.AffectedVariantCount == 0
}

func mapRetestVerdict(verdict reporting.VerificationVerdict, execution httpclient.RequestPolicyExecution) *retestResult {
	result := &retestResult{
		Reason:   trimRetestOutput(verdict.Reason),
		Evidence: trimRetestOutput(verdict.Evidence),
	}
	affectedExecuted := execution.AffectedRequestCount > 0
	controlledAffectedExecution := affectedExecuted && execution.AffectedVariantCount >= 2
	switch {
	case verdict.Confirmed && affectedExecuted:
		result.Verdict = "still_vulnerable"
	case verdict.Inconclusive:
		result.Verdict = "inconclusive"
	case !verdict.Confirmed && controlledAffectedExecution:
		result.Verdict = "fixed"
	default:
		result.Verdict = "inconclusive"
		if verdict.Confirmed {
			result.Reason = "the reported impact was not reproduced through the stored affected endpoint"
		} else {
			result.Reason = "rejection lacked two distinct affected-endpoint requests needed for a baseline/control comparison"
		}
	}
	return result
}

func trimRetestOutput(value string) string {
	value = strings.TrimSpace(value)
	if len(value) > 64*1024 {
		return value[:64*1024] + "…"
	}
	return value
}
