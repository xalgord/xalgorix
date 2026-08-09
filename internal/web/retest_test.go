package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/xalgord/xalgorix/v4/internal/tools/httpclient"
	"github.com/xalgord/xalgorix/v4/internal/tools/reporting"
)

func TestFindingRetestRouteMethodsAndValidation(t *testing.T) {
	s := newTestServer(t, nil)

	for _, tc := range []struct {
		name, method, path, body string
		want                     int
	}{
		{"start method", http.MethodGet, "/api/findings/retest", "", http.StatusMethodNotAllowed},
		{"detail method", http.MethodPost, "/api/findings/retest/rt_x", "", http.StatusMethodNotAllowed},
		{"missing fields", http.MethodPost, "/api/findings/retest", `{}`, http.StatusBadRequest},
		{"unknown field", http.MethodPost, "/api/findings/retest", `{"unknown":true}`, http.StatusBadRequest},
		{"private target", http.MethodPost, "/api/findings/retest", `{"finding":{"title":"x","target":"http://127.0.0.1","endpoint":"/x","method":"GET"}}`, http.StatusBadRequest},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rr := httptest.NewRecorder()
			r := httptest.NewRequest(tc.method, tc.path, strings.NewReader(tc.body))
			if strings.Contains(tc.path, "/rt_") {
				s.handleGetFindingRetest(rr, r)
			} else {
				s.handleStartFindingRetest(rr, r)
			}
			if rr.Code != tc.want {
				t.Fatalf("status=%d want=%d body=%s", rr.Code, tc.want, rr.Body.String())
			}
		})
	}
}

func TestFindingRetestAsyncContractDoesNotExposeAuth(t *testing.T) {
	s := newTestServer(t, nil)
	const secret = "retest-secret-value"
	called := make(chan struct{}, 1)
	s.retestRunner = func(req retestStartRequest) retestOutcome {
		if !strings.Contains(req.TargetAuth, secret) {
			t.Error("worker did not receive server-side target auth")
		}
		called <- struct{}{}
		return retestOutcome{
			status: retestCompleted, result: &retestResult{Verdict: "inconclusive", Reason: "manual review"},
			meaningfulAttempt: true, requestCount: 3, affectedRequestCount: 2, affectedVariantCount: 2,
		}
	}

	body := `{"finding":{"title":"DNS endpoint issue","target":"https://8.8.8.8","endpoint":"/dns-query","method":"GET","description":"stored finding"},"target_auth":"Authorization: Bearer ` + secret + `"}`
	rr := httptest.NewRecorder()
	s.handleStartFindingRetest(rr, httptest.NewRequest(http.MethodPost, "/api/findings/retest", strings.NewReader(body)))
	if rr.Code != http.StatusAccepted {
		t.Fatalf("start status=%d body=%s", rr.Code, rr.Body.String())
	}
	if strings.Contains(rr.Body.String(), secret) {
		t.Fatal("start response exposed target auth")
	}
	var started struct {
		ID, Status, PollURL string
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &started); err != nil {
		t.Fatal(err)
	}
	if started.ID == "" || started.Status != retestQueued {
		t.Fatalf("unexpected start response: %s", rr.Body.String())
	}

	select {
	case <-called:
	case <-time.After(time.Second):
		t.Fatal("asynchronous worker did not run")
	}
	deadline := time.Now().Add(time.Second)
	for {
		rr = httptest.NewRecorder()
		s.handleGetFindingRetest(rr, httptest.NewRequest(http.MethodGet, "/api/findings/retest/"+started.ID, nil))
		if strings.Contains(rr.Body.String(), secret) {
			t.Fatal("poll response exposed target auth")
		}
		var job retestJob
		if err := json.Unmarshal(rr.Body.Bytes(), &job); err != nil {
			t.Fatal(err)
		}
		if job.Status == retestCompleted {
			if !job.MeaningfulAttempt || job.RequestCount != 3 || job.AffectedRequestCount != 2 || job.AffectedVariantCount != 2 {
				t.Fatalf("terminal execution counts were not populated: %#v", job)
			}
			if !strings.Contains(rr.Body.String(), `"affected_variant_count":2`) {
				t.Fatalf("terminal JSON omitted affected_variant_count: %s", rr.Body.String())
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("job did not complete: %s", rr.Body.String())
		}
		time.Sleep(time.Millisecond)
	}
	if s.running.Load() {
		t.Fatal("targeted retest started full scan state")
	}
}

func TestMapRetestVerdictRequiresAffectedEndpointEvidence(t *testing.T) {
	cases := []struct {
		name      string
		verdict   reporting.VerificationVerdict
		execution httpclient.RequestPolicyExecution
		want      string
	}{
		{"confirmed on affected endpoint", reporting.VerificationVerdict{Confirmed: true}, httpclient.RequestPolicyExecution{RequestCount: 1, AffectedRequestCount: 1, AffectedVariantCount: 1}, "still_vulnerable"},
		{"confirmed only on target root", reporting.VerificationVerdict{Confirmed: true}, httpclient.RequestPolicyExecution{RequestCount: 1}, "inconclusive"},
		{"rejected after controlled affected requests", reporting.VerificationVerdict{Reason: "control disproved behavior"}, httpclient.RequestPolicyExecution{RequestCount: 2, AffectedRequestCount: 2, AffectedVariantCount: 2}, "fixed"},
		{"rejected after one affected request", reporting.VerificationVerdict{Reason: "model guessed"}, httpclient.RequestPolicyExecution{RequestCount: 1, AffectedRequestCount: 1, AffectedVariantCount: 1}, "inconclusive"},
		{"rejected after unrelated requests", reporting.VerificationVerdict{Reason: "model guessed"}, httpclient.RequestPolicyExecution{RequestCount: 2}, "inconclusive"},
		{"inconclusive", reporting.VerificationVerdict{Inconclusive: true}, httpclient.RequestPolicyExecution{RequestCount: 2, AffectedRequestCount: 2, AffectedVariantCount: 2}, "inconclusive"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := mapRetestVerdict(tc.verdict, tc.execution).Verdict; got != tc.want {
				t.Fatalf("verdict=%s want=%s", got, tc.want)
			}
		})
	}
}

func TestFindingRetestRoutesRegistered(t *testing.T) {
	for _, want := range []string{"/api/findings/retest", "/api/findings/retest/"} {
		found := false
		for _, route := range dashboardRoutes {
			found = found || route == want
		}
		if !found {
			t.Errorf("dashboardRoutes missing %q", want)
		}
	}
}

func TestFindingRetestRouteRequiresDashboardAuthentication(t *testing.T) {
	resetAuthSessionsForTest()
	called := false
	handler := authMiddleware(minimalCfgForCSRF())(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusAccepted)
	}))
	req := httptest.NewRequest(http.MethodPost, "/api/findings/retest", strings.NewReader(`{}`))
	req.Host = "scanner.local"
	req.Header.Set("Origin", "http://scanner.local")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized || called {
		t.Fatalf("status=%d called=%v want unauthenticated 401", rr.Code, called)
	}
}

func TestFindingRetestRejectsModelRoutingFieldsWithoutRunnerInvocation(t *testing.T) {
	validFinding := `"finding":{"title":"DNS endpoint issue","target":"https://8.8.8.8","endpoint":"/dns-query","method":"GET"}`
	cases := []struct {
		name string
		body string
	}{
		{"top-level model", `{` + validFinding + `,"model":"attacker-model"}`},
		{"top-level provider_profile", `{` + validFinding + `,"provider_profile":"attacker-profile"}`},
		{"nested model", `{"finding":{"title":"DNS endpoint issue","target":"https://8.8.8.8","endpoint":"/dns-query","method":"GET","model":"attacker-model"}}`},
		{"nested provider_profile", `{"finding":{"title":"DNS endpoint issue","target":"https://8.8.8.8","endpoint":"/dns-query","method":"GET","provider_profile":"attacker-profile"}}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := newTestServer(t, nil)
			called := make(chan struct{}, 1)
			s.retestRunner = func(req retestStartRequest) retestOutcome {
				called <- struct{}{}
				return retestOutcome{status: retestCompleted}
			}

			rr := httptest.NewRecorder()
			s.handleStartFindingRetest(rr, httptest.NewRequest(http.MethodPost, "/api/findings/retest", strings.NewReader(tc.body)))
			if rr.Code != http.StatusBadRequest {
				t.Fatalf("status=%d want=%d body=%s", rr.Code, http.StatusBadRequest, rr.Body.String())
			}
			select {
			case <-called:
				t.Fatal("runner was invoked for a request with unknown routing fields")
			default:
			}
		})
	}
}
