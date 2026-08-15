package web

import "testing"

func TestIsInterruptedRecoverableRecord(t *testing.T) {
	cases := []struct {
		status     string
		stopReason string
		want       bool
		note       string
	}{
		{"running", "", true, "crash/SIGKILL mid-run"},
		{"pending", "", true, "queued when process died"},
		{"stopped", "signal_terminated", true, "graceful SIGTERM restart"},
		{"stopped", "signal_interrupt", true, "graceful SIGINT restart"},
		{"stopped", "panic_recovered", true, "recovered panic"},
		{"stopped", "server_restart_resuming", true, "already flagged for resume"},
		{"stopped", "server_shutdown", true, "queued (pending) at graceful shutdown must resume"},
		{"Stopped", "SERVER_SHUTDOWN", true, "case-insensitive server_shutdown"},
		{"stopped", "user_stopped", false, "explicit user stop must NOT resume"},
		{"stopped", "", false, "plain stop with no resume reason"},
		{"stopped", "server_restart_no_resume_state", false, "already terminalized, no resume"},
		{"finished", "", false, "completed scans never resume"},
		{"completed", "", false, "completed scans never resume"},
		{"failed", "", false, "failed scans never resume"},
		{"paused", "user_paused", false, "paused handled by its own path"},
		{"RUNNING", "", true, "case-insensitive status"},
		{"Stopped", "SIGNAL_terminated", true, "case-insensitive prefix"},
	}
	for _, c := range cases {
		if got := isInterruptedRecoverableRecord(c.status, c.stopReason); got != c.want {
			t.Errorf("isInterruptedRecoverableRecord(%q,%q)=%v want %v (%s)",
				c.status, c.stopReason, got, c.want, c.note)
		}
	}
}
