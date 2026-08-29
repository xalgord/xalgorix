//go:build !linux

package terminal

import (
	"log"
	"runtime"
	"sync"
)

var unsupportedProcessLimitWarning sync.Once

// setProcessLimitsForPID is intentionally best-effort outside Linux. The hard
// address-space limit is disabled by default, and macOS has no prlimit(2)
// equivalent for changing another process after launch. Process-group cleanup
// remains active through the shared terminal execution path.
func setProcessLimitsForPID(pid int, memoryLimited bool, memLimitBytes int64) {
	if pid <= 0 || !memoryLimited || memLimitBytes <= 0 {
		return
	}
	unsupportedProcessLimitWarning.Do(func() {
		log.Printf("[RESOURCES] Per-tool hard memory limits are not supported on %s; continuing without RLIMIT_AS", runtime.GOOS)
	})
}
