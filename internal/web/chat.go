package web

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/xalgord/xalgorix/v4/internal/config"
	"github.com/xalgord/xalgorix/v4/internal/llm"
)

// ChatRequest is the payload for sending a message to a running scan's
// agent via the chat endpoint.
type ChatRequest struct {
	Message    string `json:"message"`
	InstanceID string `json:"instance_id,omitempty"`
}

func (s *Server) handleChat(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req ChatRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}

	req.Message = strings.TrimSpace(req.Message)
	if req.Message == "" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "message is required"})
		return
	}

	response, err := s.routeChatMessage(strings.TrimSpace(req.InstanceID), req.Message)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{
		"response": response,
	})
}

func (s *Server) routeChatMessage(instanceID, message string) (string, error) {
	if instanceID != "" {
		s.instancesMu.RLock()
		inst := s.instances[instanceID]
		s.instancesMu.RUnlock()
		if inst == nil {
			return "", fmt.Errorf("instance not found")
		}

		inst.mu.RLock()
		status := inst.Status
		agnt := inst.agent
		inst.mu.RUnlock()

		if agnt != nil && status == "running" {
			return agnt.SendMessage(message)
		}
		if status == "saved" || status == "pending" {
			return "", fmt.Errorf("scan is not active yet")
		}
		return s.postScanChat(inst, message)
	}

	// Fallback for the older single-scan UI path, where chat messages did not
	// include an instance_id and the currently running session was global.
	s.mu.RLock()
	targetID := s.currentScanID
	agnt := s.currentAgents[targetID]
	s.mu.RUnlock()
	if agnt != nil && s.running.Load() {
		return agnt.SendMessage(message)
	}

	if inst := s.latestChatInstance(); inst != nil {
		return s.postScanChat(inst, message)
	}

	return "", fmt.Errorf("no active or completed scan to chat with")
}

func (s *Server) latestChatInstance() *ScanInstance {
	s.instancesMu.RLock()
	defer s.instancesMu.RUnlock()

	var best *ScanInstance
	var bestTime time.Time
	for _, inst := range s.instances {
		inst.mu.RLock()
		status := inst.Status
		finishedAt := inst.FinishedAt
		startedAt := inst.StartedAt
		inst.mu.RUnlock()

		switch status {
		case "finished", "stopped", "paused":
		default:
			continue
		}

		t := parseInstanceTime(finishedAt)
		if t.IsZero() {
			t = parseInstanceTime(startedAt)
		}
		if best == nil || t.After(bestTime) {
			best = inst
			bestTime = t
		}
	}
	return best
}

func parseInstanceTime(value string) time.Time {
	if value == "" {
		return time.Time{}
	}
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339} {
		if parsed, err := time.Parse(layout, value); err == nil {
			return parsed
		}
	}
	return time.Time{}
}

func (s *Server) postScanChat(inst *ScanInstance, message string) (string, error) {
	inst.mu.Lock()
	if inst.chatCfg == nil {
		chatCfg := *s.cfg
		inst.chatCfg = &chatCfg
	}
	chatCfg := *inst.chatCfg
	if len(inst.chatMessages) == 0 {
		lang := ""
		if s.cfg != nil {
			lang = s.cfg.Language
		}
		inst.chatMessages = []llm.Message{{
			Role:    "system",
			Content: buildPostScanChatPrompt(inst, lang),
		}}
	}
	messages := append([]llm.Message(nil), inst.chatMessages...)
	messages = append(messages, llm.Message{Role: "user", Content: message})
	inst.mu.Unlock()

	response, err := s.postScanChatFn(&chatCfg, messages)
	if err != nil {
		return "", err
	}
	response = strings.TrimSpace(llm.CleanContent(response))
	if response == "" {
		response = "I do not have enough scan context to answer that."
	}

	inst.mu.Lock()
	inst.chatMessages = append(messages, llm.Message{Role: "assistant", Content: response})
	inst.chatMessages = trimPostScanChatHistory(inst.chatMessages)
	inst.mu.Unlock()

	return response, nil
}

func buildPostScanChatPrompt(inst *ScanInstance, language string) string {
	var b strings.Builder
	if directive := config.OutputLanguageDirective(language); directive != "" {
		b.WriteString(directive)
		b.WriteString("\n\n")
	}
	if inst.Status == "paused" {
		b.WriteString("You are Xalgorix in paused-scan chat mode. The scan is paused, so answer follow-up questions using only the scan context captured so far. Do not claim that you are still scanning or that you can run tools in this chat. If the user asks for new testing, explain what the current results show and suggest resuming the scan.\n\n")
	} else {
		b.WriteString("You are Xalgorix in post-scan chat mode. The scan has already finished, so answer follow-up questions using only the completed scan context below. Do not claim that you are still scanning or that you can run tools in this chat. If the user asks for new testing, first summarize what the completed scan already found for that topic, then explain that additional live testing requires resuming, restarting, or starting a new scan.\n\n")
	}

	b.WriteString("## Scan\n")
	fmt.Fprintf(&b, "Instance ID: %s\n", inst.ID)
	fmt.Fprintf(&b, "Targets: %s\n", inst.Targets)
	fmt.Fprintf(&b, "Status: %s\n", inst.Status)
	if inst.ScanMode != "" {
		fmt.Fprintf(&b, "Mode: %s\n", inst.ScanMode)
	}
	if inst.StartedAt != "" {
		fmt.Fprintf(&b, "Started: %s\n", inst.StartedAt)
	}
	if inst.FinishedAt != "" {
		fmt.Fprintf(&b, "Finished: %s\n", inst.FinishedAt)
	}
	fmt.Fprintf(&b, "Iterations: %d\nTool calls: %d\nVulnerabilities: %d\nTotal tokens: %d\n", inst.Iterations, inst.ToolCalls, inst.VulnCount, inst.TotalTokens)
	if strings.TrimSpace(inst.Instruction) != "" {
		fmt.Fprintf(&b, "User instructions: %s\n", truncStr(inst.Instruction, 1200))
	}

	if len(inst.Vulns) > 0 {
		b.WriteString("\n## Vulnerabilities\n")
		for i, v := range inst.Vulns {
			if i >= 40 {
				fmt.Fprintf(&b, "- ... %d additional vulnerabilities omitted from prompt context\n", len(inst.Vulns)-i)
				break
			}
			fmt.Fprintf(&b, "- [%s] %s", strings.ToUpper(v.Severity), v.Title)
			if v.Endpoint != "" {
				fmt.Fprintf(&b, " at %s", v.Endpoint)
			}
			if v.CVSS > 0 {
				fmt.Fprintf(&b, " (CVSS %.1f)", v.CVSS)
			}
			if v.Description != "" {
				fmt.Fprintf(&b, " - %s", truncStr(v.Description, 500))
			}
			b.WriteByte('\n')
		}
	}

	if len(inst.events) > 0 {
		b.WriteString("\n## Recent Scan Events\n")
		start := 0
		if len(inst.events) > 80 {
			start = len(inst.events) - 80
		}
		for _, evt := range inst.events[start:] {
			line := summarizeChatEvent(evt)
			if line != "" {
				b.WriteString("- ")
				b.WriteString(line)
				b.WriteByte('\n')
			}
		}
	}

	return b.String()
}

func summarizeChatEvent(evt WSEvent) string {
	switch evt.Type {
	case "thinking":
		return fmt.Sprintf("thinking: %s", truncStr(evt.Content, 160))
	case "message":
		return fmt.Sprintf("message: %s", truncStr(evt.Content, 300))
	case "error":
		return fmt.Sprintf("error: %s", truncStr(evt.Content, 300))
	case "tool_call":
		return fmt.Sprintf("tool_call: %s", evt.ToolName)
	case "tool_result":
		body := evt.Output
		if body == "" {
			body = evt.Error
		}
		if evt.ToolName != "" {
			return fmt.Sprintf("tool_result: %s: %s", evt.ToolName, truncStr(body, 300))
		}
		return fmt.Sprintf("tool_result: %s", truncStr(body, 300))
	case "finished":
		return fmt.Sprintf("finished: %s", truncStr(evt.Content, 300))
	case "target_started", "target_completed", "queue_started", "queue_finished", "report_ready":
		if evt.Target != "" {
			return fmt.Sprintf("%s: %s (%s)", evt.Type, truncStr(evt.Content, 220), evt.Target)
		}
		return fmt.Sprintf("%s: %s", evt.Type, truncStr(evt.Content, 220))
	default:
		return ""
	}
}

func trimPostScanChatHistory(messages []llm.Message) []llm.Message {
	const keepRecent = 40
	if len(messages) <= keepRecent+1 {
		return messages
	}
	trimmed := make([]llm.Message, 0, keepRecent+1)
	trimmed = append(trimmed, messages[0])
	trimmed = append(trimmed, messages[len(messages)-keepRecent:]...)
	return trimmed
}

func truncStr(s string, max int) string {
	if max <= 0 || len(s) <= max {
		return s
	}
	if max <= 3 {
		return s[:max]
	}
	return s[:max-3] + "..."
}
