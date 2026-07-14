package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/xalgord/xalgorix/v4/internal/auth"
)

func TestWriteProfileErrorUsesProviderSpecificCredentialMessage(t *testing.T) {
	tests := []struct {
		name    string
		err     error
		message string
	}{
		{name: "codex", err: auth.ErrCodexCredentialsNotFound, message: "codex cli credentials not found"},
		{name: "claude", err: auth.ErrNotFound, message: "claude cli credentials not found"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rr := httptest.NewRecorder()
			writeProfileError(rr, tt.err)

			if rr.Code != http.StatusNotFound {
				t.Fatalf("status = %d, want %d", rr.Code, http.StatusNotFound)
			}
			var body map[string]string
			if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
				t.Fatalf("decode response: %v", err)
			}
			if body["error"] != tt.message {
				t.Fatalf("error = %q, want %q", body["error"], tt.message)
			}
		})
	}
}
