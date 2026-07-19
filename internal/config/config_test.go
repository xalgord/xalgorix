package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestEnvOr(t *testing.T) {
	// Unset env var should return fallback
	os.Unsetenv("TEST_XALGORIX_ENVVAR")
	if got := envOr("TEST_XALGORIX_ENVVAR", "default_val"); got != "default_val" {
		t.Errorf("expected 'default_val', got '%s'", got)
	}

	// Set env var should return it
	os.Setenv("TEST_XALGORIX_ENVVAR", "custom_val")
	defer os.Unsetenv("TEST_XALGORIX_ENVVAR")
	if got := envOr("TEST_XALGORIX_ENVVAR", "default_val"); got != "custom_val" {
		t.Errorf("expected 'custom_val', got '%s'", got)
	}
}

func TestEnvOrInt(t *testing.T) {
	os.Unsetenv("TEST_XALGORIX_INT")
	if got := envOrInt("TEST_XALGORIX_INT", 42); got != 42 {
		t.Errorf("expected 42, got %d", got)
	}

	os.Setenv("TEST_XALGORIX_INT", "99")
	defer os.Unsetenv("TEST_XALGORIX_INT")
	if got := envOrInt("TEST_XALGORIX_INT", 42); got != 99 {
		t.Errorf("expected 99, got %d", got)
	}

	// Invalid int should return fallback
	os.Setenv("TEST_XALGORIX_INT", "not_a_number")
	if got := envOrInt("TEST_XALGORIX_INT", 42); got != 42 {
		t.Errorf("expected fallback 42 for invalid int, got %d", got)
	}
}

func TestEnvOrBool(t *testing.T) {
	os.Unsetenv("TEST_XALGORIX_BOOL")
	if got := envOrBool("TEST_XALGORIX_BOOL", false); got != false {
		t.Error("expected false for unset env")
	}

	trueValues := []string{"1", "true", "TRUE", "True", "yes", "YES", "Yes"}
	for _, v := range trueValues {
		os.Setenv("TEST_XALGORIX_BOOL", v)
		if got := envOrBool("TEST_XALGORIX_BOOL", false); got != true {
			t.Errorf("expected true for %q, got false", v)
		}
	}

	falseValues := []string{"0", "false", "no", "anything"}
	for _, v := range falseValues {
		os.Setenv("TEST_XALGORIX_BOOL", v)
		if got := envOrBool("TEST_XALGORIX_BOOL", false); got != false {
			t.Errorf("expected false for %q, got true", v)
		}
	}

	os.Unsetenv("TEST_XALGORIX_BOOL")
}

func TestLoadEnvFile(t *testing.T) {
	// Create temp env file
	dir := t.TempDir()
	envFile := filepath.Join(dir, "test.env")

	content := `# Comment line
XALGORIX_TEST_KEY1=value1
export XALGORIX_TEST_KEY2=value2
XALGORIX_TEST_KEY3="quoted_value"
XALGORIX_TEST_KEY4='single_quoted'

# Another comment
XALGORIX_TEST_KEY5=with=equals=signs
`
	os.WriteFile(envFile, []byte(content), 0644)

	// Clean up env vars
	defer func() {
		for i := 1; i <= 5; i++ {
			os.Unsetenv("XALGORIX_TEST_KEY" + string(rune('0'+i)))
		}
	}()

	loadEnvFile(envFile)

	tests := []struct {
		key  string
		want string
	}{
		{"XALGORIX_TEST_KEY1", "value1"},
		{"XALGORIX_TEST_KEY2", "value2"},
		{"XALGORIX_TEST_KEY3", "quoted_value"},
		{"XALGORIX_TEST_KEY4", "single_quoted"},
		{"XALGORIX_TEST_KEY5", "with=equals=signs"},
	}

	for _, tt := range tests {
		if got := os.Getenv(tt.key); got != tt.want {
			t.Errorf("%s: expected %q, got %q", tt.key, tt.want, got)
		}
	}
}

func TestLoadEnvFile_NonExistent(t *testing.T) {
	// Should not panic on missing file
	loadEnvFile("/nonexistent/path/.env")
}

func TestLoad_ReadsDashboardProviderProxyAndAgentMailSettings(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("SUDO_USER", "")
	t.Setenv("XALGORIX_DEBUG_CONFIG", "")

	envFile := filepath.Join(home, ".xalgorix.env")
	content := strings.Join([]string{
		"XALGORIX_LLM=google/gemini-3.1-pro-preview",
		"XALGORIX_API_BASE=https://generativelanguage.googleapis.com/v1",
		"XALGORIX_API_KEY=gemini-key",
		"XALGORIX_REASONING_EFFORT=medium",
		"XALGORIX_OLLAMA_COMPATIBLE=true",
		"XALGORIX_LLM_MAX_RETRIES=2",
		"XALGORIX_MEMORY_COMPRESSOR_TIMEOUT=45",
		"XALGORIX_WORKSPACE=/tmp/xalgorix-workspace",
		"XALGORIX_DISABLE_BROWSER=true",
		"XALGORIX_MAX_ITERATIONS=12",
		"XALGORIX_RATE_LIMIT_REQUESTS=7",
		"XALGORIX_RATE_LIMIT_WINDOW=11",
		"XALGORIX_RATE_RPS=2.5",
		"XALGORIX_RATE_BURST=9",
		"XALGORIX_TLS_SKIP_VERIFY=true",
		"CAIDO_PORT=9090",
		"CAIDO_API_TOKEN=caido-token",
		"XALGORIX_TELEMETRY=false",
		"XALGORIX_OTEL_ENDPOINT=http://otel.test",
		"GEMINI_API_KEY=search-key",
		"AGENTMAIL_API_KEY=agentmail-key",
		"AGENTMAIL_POD=am_test_pod",
		"XALGORIX_DISCORD_WEBHOOK=https://discord.example/webhook",
		"XALGORIX_DISCORD_MIN_SEVERITY=high",
		"XALGORIX_TELEGRAM_BOT_TOKEN=123456:ABC-DEF",
		"XALGORIX_TELEGRAM_CHAT_ID=-1001234567890",
		"XALGORIX_TELEGRAM_MIN_SEVERITY=critical",
		"XALGORIX_USERNAME=admin",
		"XALGORIX_PASSWORD=password",
		"XALGORIX_BROWSER_PATH=/opt/chrome",
	}, "\n")
	if err := os.WriteFile(envFile, []byte(content), 0o600); err != nil {
		t.Fatalf("write env file: %v", err)
	}

	cfg := load()
	if cfg.LLM != "google/gemini-3.1-pro-preview" || cfg.APIBase != "https://generativelanguage.googleapis.com/v1" || cfg.APIKey != "gemini-key" {
		t.Fatalf("LLM config not loaded: %#v", cfg)
	}
	if cfg.ReasoningEffort != "medium" || !cfg.OllamaCompatible || cfg.LLMMaxRetries != 2 || cfg.MemCompTimeout != 45 {
		t.Fatalf("retry/memory settings not loaded: %#v", cfg)
	}
	if cfg.Workspace != "/tmp/xalgorix-workspace" || !cfg.DisableBrowser || cfg.MaxIterations != 12 {
		t.Fatalf("runtime settings not loaded: %#v", cfg)
	}
	if cfg.RateLimitRequests != 7 || cfg.RateLimitWindow != 11 {
		t.Fatalf("rate limit settings not loaded: %#v", cfg)
	}
	if cfg.RateLimitRPS != 2.5 || cfg.RateLimitBurst != 9 || !cfg.TLSSkipVerify {
		t.Fatalf("request throttle/TLS settings not loaded: %#v", cfg)
	}
	if cfg.CaidoPort != 9090 || cfg.CaidoAPIToken != "caido-token" {
		t.Fatalf("Caido settings not loaded: %#v", cfg)
	}
	if cfg.Telemetry || cfg.OTelEndpoint != "http://otel.test" {
		t.Fatalf("telemetry settings not loaded: %#v", cfg)
	}
	if cfg.GeminiAPIKey != "search-key" || cfg.AgentMailAPIKey != "agentmail-key" || cfg.AgentMailPod != "am_test_pod" {
		t.Fatalf("integration settings not loaded: %#v", cfg)
	}
	if cfg.DiscordWebhook != "https://discord.example/webhook" || cfg.DiscordMinSeverity != "high" {
		t.Fatalf("discord settings not loaded: %#v", cfg)
	}
	if cfg.TelegramBotToken != "123456:ABC-DEF" || cfg.TelegramChatID != "-1001234567890" || cfg.TelegramMinSeverity != "critical" {
		t.Fatalf("telegram settings not loaded: %#v", cfg)
	}
	if cfg.Username != "admin" || cfg.Password != "password" || cfg.BrowserPath != "/opt/chrome" {
		t.Fatalf("dashboard/browser settings not loaded: %#v", cfg)
	}
	if cfg.HomeDir != filepath.Join(home, ".xalgorix") || cfg.SkillsDir != filepath.Join(home, ".xalgorix", "skills") {
		t.Fatalf("home paths not derived from HOME: %#v", cfg)
	}
}

func TestConfig_Validate(t *testing.T) {
	cfg := &Config{}
	// First failure mode: empty DataDir (R6.5 guard runs before the LLM/API checks).
	if err := cfg.Validate(); err == nil {
		t.Error("expected error for empty DataDir")
	}

	// With DataDir resolved, we fall through to the LLM check.
	cfg.DataDir = "/tmp/xalgorix-validate-test"
	if err := cfg.Validate(); err == nil {
		t.Error("expected error for empty LLM")
	}

	// LLM alone is no longer enough — the validator also requires an API key.
	cfg.LLM = "openai/gpt-5.4"
	if err := cfg.Validate(); err == nil {
		t.Error("expected error when LLM is set but APIKey is empty")
	}

	cfg.APIKey = "test-key"
	if err := cfg.Validate(); err != nil {
		t.Errorf("expected no error with DataDir, LLM, and APIKey set, got: %v", err)
	}
}

func TestConfig_WorkspacePath(t *testing.T) {
	// WorkspacePath now resolves through WorkspaceRoot (R6.4/R6.6). In the
	// real load path WorkspaceRoot equals DataDir which equals Workspace,
	// but the fixture only needs WorkspaceRoot for the join behavior.
	cfg := &Config{
		Workspace:     "/home/user/project",
		DataDir:       "/home/user/project",
		WorkspaceRoot: "/home/user/project",
	}

	// Relative path should be joined with the workspace root
	if got := cfg.WorkspacePath("subdir/file.txt"); got != "/home/user/project/subdir/file.txt" {
		t.Errorf("expected joined path, got: %s", got)
	}

	// Absolute path should be returned as-is
	if got := cfg.WorkspacePath("/absolute/path"); got != "/absolute/path" {
		t.Errorf("expected absolute path as-is, got: %s", got)
	}

	// Drift guard: if Workspace ever diverges from WorkspaceRoot the helper
	// must follow WorkspaceRoot, not Workspace.
	drift := &Config{
		Workspace:     "/legacy/cwd",
		DataDir:       "/home/user/.xalgorix/data",
		WorkspaceRoot: "/home/user/.xalgorix/data",
	}
	if got := drift.WorkspacePath("subdir/file.txt"); got != "/home/user/.xalgorix/data/subdir/file.txt" {
		t.Errorf("expected resolution against WorkspaceRoot, got: %s", got)
	}
}

func TestConfig_ResolveModel(t *testing.T) {
	cfg := &Config{LLM: "openai/gpt-5.4"}
	if api := cfg.ResolveModel(); api != "openai/gpt-5.4" {
		t.Errorf("expected 'openai/gpt-5.4', got %q", api)
	}

	cfg.LLM = ""
	if api := cfg.ResolveModel(); api != "" {
		t.Errorf("expected empty for empty LLM, got %q", api)
	}
}
