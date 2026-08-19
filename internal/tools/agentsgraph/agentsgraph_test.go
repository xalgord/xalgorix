package agentsgraph

import (
	"strings"
	"sync"
	"testing"
)

func agentIDFromResult(t *testing.T, res any) string {
	t.Helper()
	result, ok := res.(map[string]any)
	if !ok {
		t.Fatalf("metadata type = %T, want map[string]any", res)
	}
	agentID, ok := result["agent_id"].(string)
	if !ok || agentID == "" {
		t.Fatalf("missing agent_id in metadata: %#v", result)
	}
	return agentID
}

func TestSpawnCheckWaitAgentSnapshots(t *testing.T) {
	Reset()
	t.Cleanup(Reset)

	release := make(chan struct{})
	setRunner(func(name string, targets []string, task string) (string, error) {
		<-release
		return "completed " + name + " on " + strings.Join(targets, ","), nil
	})

	res, err := spawnAgent(map[string]string{
		"name":   "worker",
		"task":   "scan target",
		"target": "https://example.test",
	})
	if err != nil {
		t.Fatalf("spawnAgent: %v", err)
	}
	agentID := agentIDFromResult(t, res.Metadata)

	AddPartialResult(agentID, "partial finding")
	checked, err := checkAgent(map[string]string{"agent_id": agentID})
	if err != nil {
		t.Fatalf("checkAgent: %v", err)
	}
	if !strings.Contains(checked.Output, "RUNNING") || !strings.Contains(checked.Output, "partial finding") {
		t.Fatalf("unexpected check output:\n%s", checked.Output)
	}

	close(release)
	waited, err := waitAgent(map[string]string{"agent_id": agentID, "timeout": "5"})
	if err != nil {
		t.Fatalf("waitAgent: %v", err)
	}
	if !strings.Contains(waited.Output, "COMPLETED") || !strings.Contains(waited.Output, "completed worker") {
		t.Fatalf("unexpected wait output:\n%s", waited.Output)
	}
}

func TestResetWhileAgentRunsIsRaceFree(t *testing.T) {
	Reset()
	t.Cleanup(Reset)

	started := make(chan struct{})
	release := make(chan struct{})
	done := make(chan struct{})
	setRunner(func(name string, targets []string, task string) (string, error) {
		defer close(done)
		close(started)
		<-release
		return "late result", nil
	})

	res, err := spawnAgent(map[string]string{"name": "slow", "task": "wait"})
	if err != nil {
		t.Fatalf("spawnAgent: %v", err)
	}
	agentID := agentIDFromResult(t, res.Metadata)
	<-started

	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			AddPartialResult(agentID, "still running")
			_, _ = checkAgent(map[string]string{"agent_id": agentID})
		}()
	}

	Reset()
	close(release)
	wg.Wait()
	<-done

	if got := GetRunningCount(); got != 0 {
		t.Fatalf("running count after reset = %d, want 0", got)
	}
}
