//go:build linux

package terminal

import (
	"fmt"
	"log"
	"os"

	"golang.org/x/sys/unix"
)

// setProcessLimitsForPID applies Linux OOM and address-space constraints to an
// already-running child. Keeping this in a Linux-only file prevents Darwin and
// other Unix builds from compiling Linux syscall numbers or relying on procfs.
func setProcessLimitsForPID(pid int, memoryLimited bool, memLimitBytes int64) {
	if pid <= 0 {
		return
	}

	// Score 500 = "kill me before most things, but not before 1000". This is
	// best effort because unprivileged processes may not be allowed to change it.
	oomPath := fmt.Sprintf("/proc/%d/oom_score_adj", pid)
	if err := os.WriteFile(oomPath, []byte("500"), 0o644); err != nil { //nolint:gosec // G306: procfs ignores the file mode
		log.Printf("[RESOURCES] Cannot set OOM score for PID %d: %v", pid, err)
	}

	if memoryLimited && memLimitBytes > 0 {
		newLimit := unix.Rlimit{
			Cur: uint64(memLimitBytes),
			Max: uint64(memLimitBytes),
		}
		if err := unix.Prlimit(pid, unix.RLIMIT_AS, &newLimit, nil); err != nil {
			log.Printf("[RESOURCES] Cannot set RLIMIT_AS for PID %d: %v", pid, err)
		} else {
			log.Printf("[RESOURCES] Tool PID %d: OOM score=500, mem limit=%d MB",
				pid, memLimitBytes/(1024*1024))
		}
	} else {
		log.Printf("[RESOURCES] PID %d: OOM score set to 500", pid)
	}
}
