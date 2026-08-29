package resources

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestLevelStringAndMaxLevel(t *testing.T) {
	if LevelOK.String() != "OK" || LevelCaution.String() != "CAUTION" || LevelCritical.String() != "CRITICAL" {
		t.Fatalf("unexpected level strings: %s %s %s", LevelOK, LevelCaution, LevelCritical)
	}
	if Level(99).String() != "UNKNOWN" {
		t.Fatalf("unknown level string = %s", Level(99))
	}
	if got := maxLevel(LevelCaution, LevelCritical); got != LevelCritical {
		t.Fatalf("maxLevel = %s, want CRITICAL", got)
	}
	if got := maxLevel(LevelCaution, LevelOK); got != LevelCaution {
		t.Fatalf("maxLevel = %s, want CAUTION", got)
	}
}

func TestLiveHostMetricsAreUsable(t *testing.T) {
	stats := GetStats()
	if stats.CPUCores < 1 {
		t.Fatalf("CPU cores = %d, want at least one", stats.CPUCores)
	}
	if stats.MemTotalMB <= 0 {
		t.Fatalf("total memory = %d MB, want a positive host reading", stats.MemTotalMB)
	}
	if stats.MemAvailableMB <= 0 {
		t.Fatalf("available memory = %d MB, want a positive host reading", stats.MemAvailableMB)
	}
	if stats.DiskFreeMB <= 0 {
		t.Fatalf("free disk = %d MB, want a positive filesystem reading", stats.DiskFreeMB)
	}
}

func TestEnvHelpers(t *testing.T) {
	t.Setenv("XALGORIX_TEST_FLOAT", "")
	if got := envFloat("XALGORIX_TEST_FLOAT", 1.5); got != 1.5 {
		t.Fatalf("envFloat default = %v", got)
	}
	t.Setenv("XALGORIX_TEST_FLOAT", "2.25")
	if got := envFloat("XALGORIX_TEST_FLOAT", 1.5); got != 2.25 {
		t.Fatalf("envFloat parsed = %v", got)
	}
	t.Setenv("XALGORIX_TEST_FLOAT", "bad")
	if got := envFloat("XALGORIX_TEST_FLOAT", 1.5); got != 1.5 {
		t.Fatalf("envFloat invalid default = %v", got)
	}

	t.Setenv("XALGORIX_TEST_INT", "7")
	if got := envInt64("XALGORIX_TEST_INT", 3); got != 7 {
		t.Fatalf("envInt64 parsed = %v", got)
	}
	t.Setenv("XALGORIX_TEST_INT", "bad")
	if got := envInt64("XALGORIX_TEST_INT", 3); got != 3 {
		t.Fatalf("envInt64 invalid default = %v", got)
	}

	t.Setenv("XALGORIX_OPTIONAL_INT", "")
	if got := envOptionalInt("XALGORIX_OPTIONAL_INT"); got != 0 {
		t.Fatalf("envOptionalInt empty = %v", got)
	}
	t.Setenv("XALGORIX_OPTIONAL_INT", "4")
	if got := envOptionalInt("XALGORIX_OPTIONAL_INT"); got != 4 {
		t.Fatalf("envOptionalInt parsed = %v", got)
	}
	t.Setenv("XALGORIX_OPTIONAL_INT", "0")
	if got := envOptionalInt("XALGORIX_OPTIONAL_INT"); got != 0 {
		t.Fatalf("envOptionalInt invalid cap = %v", got)
	}
}

func TestPerInstanceMemoryBudgetIncludesToolAndOverhead(t *testing.T) {
	oldLimit := HeavyToolMemLimitBytes
	oldOverhead := scanOverheadMB
	oldBudget := scanMemoryBudgetMB
	t.Cleanup(func() {
		HeavyToolMemLimitBytes = oldLimit
		scanOverheadMB = oldOverhead
		scanMemoryBudgetMB = oldBudget
	})

	HeavyToolMemLimitBytes = 1500 * 1024 * 1024
	scanOverheadMB = 700
	scanMemoryBudgetMB = 2048
	if got := perInstanceMemoryBudgetMB(); got != 2200 {
		t.Fatalf("perInstanceMemoryBudgetMB expands to fit explicit tool limit = %d, want 2200", got)
	}

	HeavyToolMemLimitBytes = 0
	scanOverheadMB = 128
	scanMemoryBudgetMB = 2048
	if got := perInstanceMemoryBudgetMB(); got != 2048 {
		t.Fatalf("perInstanceMemoryBudgetMB default budget = %d, want 2048", got)
	}

	scanMemoryBudgetMB = 512
	if got := perInstanceMemoryBudgetMB(); got != 1024 {
		t.Fatalf("perInstanceMemoryBudgetMB floor = %d, want 1024", got)
	}
}

func TestAutoHeavyToolLimitFitsInsideScanBudget(t *testing.T) {
	oldOverhead := scanOverheadMB
	oldBudget := scanMemoryBudgetMB
	t.Cleanup(func() {
		scanOverheadMB = oldOverhead
		scanMemoryBudgetMB = oldBudget
	})

	scanMemoryBudgetMB = 2048
	scanOverheadMB = 384
	if got := autoHeavyToolMemLimitMB(8192); got != 1664 {
		t.Fatalf("autoHeavyToolMemLimitMB(8GB) = %d, want 1664", got)
	}

	if got := autoHeavyToolMemLimitMB(4096); got != 1024 {
		t.Fatalf("autoHeavyToolMemLimitMB(4GB) = %d, want 1024", got)
	}
}

func TestEffectiveMaxInstancesUsesDynamicResourceCapacity(t *testing.T) {
	oldLimit := HeavyToolMemLimitBytes
	oldOverhead := scanOverheadMB
	oldBudget := scanMemoryBudgetMB
	oldCriticalRAM := ramCriticalMB
	oldManualCap := manualMaxInstances
	t.Cleanup(func() {
		HeavyToolMemLimitBytes = oldLimit
		scanOverheadMB = oldOverhead
		scanMemoryBudgetMB = oldBudget
		ramCriticalMB = oldCriticalRAM
		manualMaxInstances = oldManualCap
	})

	HeavyToolMemLimitBytes = 1500 * 1024 * 1024
	scanOverheadMB = 500
	scanMemoryBudgetMB = 2048
	ramCriticalMB = 1000
	manualMaxInstances = 0

	stats := SystemStats{
		CPUCores:       8,
		LoadAvg1m:      1.0,
		MemAvailableMB: 11000,
	}
	got, _ := effectiveMaxInstancesForStats(stats, "OK")
	if got != 4 {
		t.Fatalf("dynamic instances = %d, want 4 from RAM capacity", got)
	}

	manualMaxInstances = 3
	got, _ = effectiveMaxInstancesForStats(stats, "OK")
	if got != 3 {
		t.Fatalf("manual cap dynamic instances = %d, want 3", got)
	}

	manualMaxInstances = 0
	stats.MemAvailableMB = 500
	got, _ = effectiveMaxInstancesForStats(stats, "RAM critical")
	if got != 0 {
		t.Fatalf("critical dynamic instances = %d, want 0", got)
	}
}

func TestToolCapacityHonorsCPUAndMemoryHeadroom(t *testing.T) {
	oldLimit := HeavyToolMemLimitBytes
	oldCriticalRAM := ramCriticalMB
	oldCPUCritical := cpuCriticalPct
	oldHeavyCPU := heavyToolCPULoad
	oldBudget := scanMemoryBudgetMB
	oldOverhead := scanOverheadMB
	t.Cleanup(func() {
		HeavyToolMemLimitBytes = oldLimit
		ramCriticalMB = oldCriticalRAM
		cpuCriticalPct = oldCPUCritical
		heavyToolCPULoad = oldHeavyCPU
		scanMemoryBudgetMB = oldBudget
		scanOverheadMB = oldOverhead
	})
	// Pin scanMemoryBudgetMB / scanOverheadMB so autoHeavyToolMemLimitMB
	// returns a deterministic value regardless of the test host's RAM.
	scanMemoryBudgetMB = 4096
	scanOverheadMB = 512

	HeavyToolMemLimitBytes = 1024 * 1024 * 1024
	ramCriticalMB = 512
	cpuCriticalPct = 90
	heavyToolCPULoad = 0.85

	stats := SystemStats{CPUCores: 1, LoadAvg1m: 0.05, MemTotalMB: 4096, MemAvailableMB: 3500}
	capacity := toolCapacityForStats(stats, LevelOK, "OK", 0, 0)
	if capacity.HeavyToolSlots != 1 {
		t.Fatalf("single-core heavy slots = %d, want 1", capacity.HeavyToolSlots)
	}

	stats.LoadAvg1m = 0.95
	capacity = toolCapacityForStats(stats, LevelCritical, "CPU critical", 0, 0)
	if capacity.HeavyToolSlots != 1 || capacity.LightToolSlots != 1 {
		t.Fatalf("critical CPU slots = heavy %d light %d, want 1/1", capacity.HeavyToolSlots, capacity.LightToolSlots)
	}

	stats = SystemStats{CPUCores: 4, LoadAvg1m: 0.1, MemTotalMB: 8192, MemAvailableMB: 1800}
	capacity = toolCapacityForStats(stats, LevelOK, "OK", 0, 0)
	if capacity.HeavyToolSlots != 1 {
		t.Fatalf("memory-limited heavy slots = %d, want 1", capacity.HeavyToolSlots)
	}
}

func TestCPUPressureScalesButDoesNotZeroToolCapacity(t *testing.T) {
	oldCriticalRAM := ramCriticalMB
	t.Cleanup(func() {
		ramCriticalMB = oldCriticalRAM
	})

	ramCriticalMB = 1985
	stats := SystemStats{CPUCores: 4, LoadAvg1m: 4.6, MemTotalMB: 7938, MemAvailableMB: 2500}
	capacity := toolCapacityForStats(stats, LevelCritical, "critical", 0, 0)
	if capacity.HeavyToolSlots < 1 {
		t.Fatalf("critical CPU heavy slots = %d, want at least one when RAM headroom exists", capacity.HeavyToolSlots)
	}
	if capacity.LightToolSlots < capacity.HeavyToolSlots {
		t.Fatalf("light slots = %d, want >= heavy slots %d", capacity.LightToolSlots, capacity.HeavyToolSlots)
	}
	if ok, reason := toolSlotAdmission(false, capacity, 0, 0); !ok {
		t.Fatalf("light tool should be admitted with RAM headroom: %s", reason)
	}
	if ok, reason := toolSlotAdmission(true, capacity, 0, 0); !ok {
		t.Fatalf("heavy tool should be admitted with RAM headroom: %s", reason)
	}
}

func TestAcquireToolLeaseContextAllowsLightToolUnderHighCPUPressure(t *testing.T) {
	oldCPUCritical := cpuCriticalPct
	oldTotal := activeToolLeases
	oldHeavy := activeHeavyToolLeases
	t.Cleanup(func() {
		cpuCriticalPct = oldCPUCritical
		resourceMu.Lock()
		activeToolLeases = oldTotal
		activeHeavyToolLeases = oldHeavy
		resourceMu.Unlock()
	})

	cpuCriticalPct = 0
	resourceMu.Lock()
	activeToolLeases = 0
	activeHeavyToolLeases = 0
	resourceMu.Unlock()

	lease, err := acquireToolLeaseWithContext(context.Background(), false, "curl", time.Millisecond)
	if err != nil {
		t.Fatalf("light pressure-slot acquisition failed: %v", err)
	}
	if lease == nil {
		t.Fatal("expected lease")
	}
	lease.Release()
}

func TestAcquireToolLeaseContextCancelsInsteadOfRefusing(t *testing.T) {
	oldCPUCritical := cpuCriticalPct
	oldTotal := activeToolLeases
	oldHeavy := activeHeavyToolLeases
	t.Cleanup(func() {
		cpuCriticalPct = oldCPUCritical
		resourceMu.Lock()
		activeToolLeases = oldTotal
		activeHeavyToolLeases = oldHeavy
		resourceMu.Unlock()
	})

	resourceMu.Lock()
	activeToolLeases = 1 << 20
	activeHeavyToolLeases = 1 << 20
	resourceMu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Millisecond)
	defer cancel()
	lease, err := acquireToolLeaseWithContext(ctx, true, "nuclei", time.Millisecond)
	if lease != nil {
		lease.Release()
		t.Fatal("unexpected heavy-tool lease under critical pressure")
	}
	if err == nil {
		t.Fatal("expected context cancellation while waiting for heavy-tool capacity")
	}
	if strings.Contains(strings.ToLower(err.Error()), "refus") {
		t.Fatalf("resource wait should cancel, not refuse: %v", err)
	}
}

func TestHardToolMemoryLimitDisabledWhenUnset(t *testing.T) {
	oldLimit := HeavyToolMemLimitBytes
	t.Cleanup(func() {
		HeavyToolMemLimitBytes = oldLimit
	})

	HeavyToolMemLimitBytes = 0
	stats := SystemStats{CPUCores: 4, MemTotalMB: 8192, MemAvailableMB: 4096}
	if got := toolMemoryLimitMBForStats(stats, true, 1, 1, LevelOK); got != 0 {
		t.Fatalf("default hard tool memory limit = %dMB, want disabled", got)
	}
	if got := toolMemoryLimitLabel(); got != "disabled" {
		t.Fatalf("toolMemoryLimitLabel = %q, want disabled", got)
	}
}

func TestToolMemoryLimitShrinksWithProjectedParallelTools(t *testing.T) {
	oldLimit := HeavyToolMemLimitBytes
	oldCriticalRAM := ramCriticalMB
	t.Cleanup(func() {
		HeavyToolMemLimitBytes = oldLimit
		ramCriticalMB = oldCriticalRAM
	})

	HeavyToolMemLimitBytes = 2048 * 1024 * 1024
	ramCriticalMB = 512
	stats := SystemStats{CPUCores: 4, MemTotalMB: 8192, MemAvailableMB: 4608}

	first := toolMemoryLimitMBForStats(stats, true, 1, 1, LevelOK)
	second := toolMemoryLimitMBForStats(stats, true, 2, 2, LevelOK)
	if first != 2048 {
		t.Fatalf("first heavy tool mem limit = %d, want 2048", first)
	}
	if second != 2048 {
		t.Fatalf("second heavy tool still fits at max = %d, want 2048", second)
	}

	stats.MemAvailableMB = 3000
	second = toolMemoryLimitMBForStats(stats, true, 2, 2, LevelOK)
	if second >= first {
		t.Fatalf("parallel heavy limit = %d, want below first limit %d", second, first)
	}
}

func TestToolLogLabelSanitizesCommands(t *testing.T) {
	cases := map[string]string{
		`curl -H "Authorization: Bearer secret" https://example.com/login`: "curl",
		`API_KEY=secret /usr/bin/nuclei -u https://example.com`:            "nuclei",
		`bash -c 'curl https://example.com?token=secret'`:                  "shell",
		`browser_action launch`:                                            "browser_action",
		``:                                                                 "tool",
	}
	for input, want := range cases {
		if got := ToolLogLabel(input); got != want {
			t.Fatalf("ToolLogLabel(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestHeavyToolAdmissionHonorsTotalToolSlots(t *testing.T) {
	capacity := toolCapacity{
		HeavyToolSlots: 1,
		LightToolSlots: 4,
		Reason:         "test capacity",
	}

	ok, reason := toolSlotAdmission(true, capacity, 4, 0)
	if ok {
		t.Fatalf("heavy tool admitted when total slots are full: %s", reason)
	}
	if !strings.Contains(reason, "tool slots full: 4/4") {
		t.Fatalf("heavy tool rejection reason = %q, want total-slot rejection", reason)
	}

	ok, reason = toolSlotAdmission(true, capacity, 3, 1)
	if ok {
		t.Fatalf("heavy tool admitted when heavy slots are full: %s", reason)
	}
	if !strings.Contains(reason, "heavy tool slots full: 1/1") {
		t.Fatalf("heavy tool rejection reason = %q, want heavy-slot rejection", reason)
	}
}

func TestLeaseReleaseUpdatesActiveCounters(t *testing.T) {
	resourceMu.Lock()
	oldTotal := activeToolLeases
	oldHeavy := activeHeavyToolLeases
	activeToolLeases = 1
	activeHeavyToolLeases = 1
	resourceMu.Unlock()
	t.Cleanup(func() {
		resourceMu.Lock()
		activeToolLeases = oldTotal
		activeHeavyToolLeases = oldHeavy
		resourceMu.Unlock()
	})

	lease := &ToolLease{id: 99, toolName: "test", heavy: true}
	lease.Release()
	resourceMu.Lock()
	gotTotal := activeToolLeases
	gotHeavy := activeHeavyToolLeases
	resourceMu.Unlock()
	if gotTotal != 0 || gotHeavy != 0 {
		t.Fatalf("active counters after release = %d/%d, want 0/0", gotTotal, gotHeavy)
	}

	lease.Release()
	resourceMu.Lock()
	gotTotal = activeToolLeases
	gotHeavy = activeHeavyToolLeases
	resourceMu.Unlock()
	if gotTotal != 0 || gotHeavy != 0 {
		t.Fatalf("double release changed counters = %d/%d, want 0/0", gotTotal, gotHeavy)
	}
}
