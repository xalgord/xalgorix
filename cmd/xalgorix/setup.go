package main

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"github.com/xalgord/xalgorix/v4/internal/config"
	"github.com/xalgord/xalgorix/v4/internal/providers"
	"golang.org/x/term"
)

type setupProvider struct {
	id           string
	name         string
	defaultModel string
	needsAPIKey  bool
}

var setupProviders = []setupProvider{
	{id: "minimax", name: "MiniMax (recommended)", defaultModel: "MiniMax-M3", needsAPIKey: true},
	{id: "openai", name: "OpenAI", defaultModel: "gpt-5.4", needsAPIKey: true},
	{id: "anthropic", name: "Anthropic (Claude)", defaultModel: "claude-sonnet-4-20250514", needsAPIKey: true},
	{id: "google", name: "Google Gemini", defaultModel: "gemini-3.1-pro-preview", needsAPIKey: true},
	{id: "ollama", name: "Ollama (local, no API key)", defaultModel: "llama3.3"},
	{id: "custom", name: "Custom OpenAI-compatible endpoint", needsAPIKey: true},
}

type setupPrompter struct {
	in  io.Reader
	buf *bufio.Reader
	out io.Writer
}

func runSetup(in io.Reader, out io.Writer) (bool, error) {
	path := config.EnvFilePath()
	existing, err := config.ReadEnvFile(path)
	if err != nil {
		return false, err
	}
	p := &setupPrompter{in: in, buf: bufio.NewReader(in), out: out}

	fmt.Fprintln(out, "\nWelcome to Xalgorix setup")
	fmt.Fprintln(out, "Configure an LLM in a few steps. You can change advanced options later in Settings.")
	fmt.Fprintf(out, "Configuration: %s (saved with mode 0600)\n\n", path)

	for i, provider := range setupProviders {
		fmt.Fprintf(out, "  %d. %s\n", i+1, provider.name)
	}
	defaultChoice := setupProviderIndex(existingProvider(existing)) + 1
	choice, err := p.choice("Choose your LLM provider", defaultChoice, len(setupProviders))
	if err != nil {
		return false, err
	}
	selected := setupProviders[choice-1]
	entry, _ := providers.LookupBuiltin(selected.id)

	sameProvider := existingProvider(existing) == selected.id
	modelDefault := selected.defaultModel
	if sameProvider {
		if current := bareSetupModel(existing["XALGORIX_LLM"], selected.id); current != "" {
			modelDefault = current
		}
	}
	model, err := p.required("Model", modelDefault)
	if err != nil {
		return false, err
	}

	apiBase := strings.TrimSpace(entry.BaseURL)
	if sameProvider && strings.TrimSpace(existing["XALGORIX_API_BASE"]) != "" {
		apiBase = strings.TrimSpace(existing["XALGORIX_API_BASE"])
	}
	if selected.id == "custom" || selected.id == "ollama" {
		label := "API base URL"
		if selected.id == "ollama" {
			label = "Ollama URL"
		}
		apiBase, err = p.required(label, apiBase)
		if err != nil {
			return false, err
		}
	}

	apiKey := ""
	if selected.needsAPIKey {
		currentKey := ""
		if sameProvider {
			currentKey = strings.TrimSpace(existing["XALGORIX_API_KEY"])
		}
		apiKey, err = p.secret("API key", currentKey)
		if err != nil {
			return false, err
		}
		if apiKey == "" {
			return false, fmt.Errorf("an API key is required for %s", selected.name)
		}
	}

	updates := map[string]string{
		"XALGORIX_LLM_PROVIDER": selected.id,
		"XALGORIX_LLM":          model,
		"XALGORIX_API_BASE":     apiBase,
		"XALGORIX_API_KEY":      apiKey,
		"XALGORIX_LLM_PROFILE":  "",
	}
	if err := config.UpdateEnvFile(path, updates); err != nil {
		return false, err
	}
	// config.Get may already have been initialized by a transitive package init.
	// Keep the process environment and singleton synchronized so choosing
	// "launch now" uses the values that were just saved without a restart.
	for key, value := range updates {
		if value == "" {
			_ = os.Unsetenv(key)
		} else {
			_ = os.Setenv(key, value)
		}
	}
	cfg := config.Get()
	cfg.LLMProvider = selected.id
	cfg.LLM = model
	cfg.APIBase = apiBase
	cfg.APIKey = apiKey
	cfg.LLMProfile = ""

	fmt.Fprintf(out, "\n✓ Saved %s with provider %s and model %s.\n", path, selected.name, model)
	fmt.Fprintln(out, "  Your API key was not displayed and the file is readable only by your user.")
	launch, err := p.yesNo("Start the Web UI now?", true)
	if err != nil {
		return false, err
	}
	if !launch {
		fmt.Fprintln(out, "\nSetup complete. Start later with: xalgorix --web")
	}
	return launch, nil
}

func setupProviderIndex(id string) int {
	for i, provider := range setupProviders {
		if provider.id == id {
			return i
		}
	}
	return 0
}

func existingProvider(values map[string]string) string {
	if provider := strings.ToLower(strings.TrimSpace(values["XALGORIX_LLM_PROVIDER"])); provider != "" {
		return provider
	}
	model := strings.ToLower(strings.TrimSpace(values["XALGORIX_LLM"]))
	if slash := strings.IndexByte(model, '/'); slash > 0 {
		candidate := model[:slash]
		if _, ok := providers.LookupBuiltin(candidate); ok {
			return candidate
		}
	}
	return ""
}

func bareSetupModel(model, provider string) string {
	model = strings.TrimSpace(model)
	prefix := provider + "/"
	if strings.HasPrefix(strings.ToLower(model), strings.ToLower(prefix)) {
		return model[len(prefix):]
	}
	return model
}

func (p *setupPrompter) line(label, defaultValue string) (string, error) {
	if defaultValue != "" {
		fmt.Fprintf(p.out, "%s [%s]: ", label, defaultValue)
	} else {
		fmt.Fprintf(p.out, "%s: ", label)
	}
	line, err := p.buf.ReadString('\n')
	if err != nil && err != io.EOF {
		return "", err
	}
	value := strings.TrimSpace(line)
	if value == "" {
		value = defaultValue
	}
	if err == io.EOF && strings.TrimSpace(line) == "" {
		return "", io.ErrUnexpectedEOF
	}
	return value, nil
}

func (p *setupPrompter) required(label, defaultValue string) (string, error) {
	for {
		value, err := p.line(label, defaultValue)
		if err != nil {
			return "", err
		}
		if value != "" {
			return value, nil
		}
		fmt.Fprintln(p.out, "  A value is required.")
	}
}

func (p *setupPrompter) choice(label string, defaultValue, max int) (int, error) {
	for {
		value, err := p.line(label, strconv.Itoa(defaultValue))
		if err != nil {
			return 0, err
		}
		n, convErr := strconv.Atoi(value)
		if convErr == nil && n >= 1 && n <= max {
			return n, nil
		}
		fmt.Fprintf(p.out, "  Enter a number from 1 to %d.\n", max)
	}
}

func (p *setupPrompter) secret(label, existing string) (string, error) {
	if existing != "" {
		fmt.Fprintf(p.out, "%s [press Enter to keep the saved key]: ", label)
	} else {
		fmt.Fprintf(p.out, "%s (input hidden): ", label)
	}

	var value string
	if file, ok := p.in.(*os.File); ok && term.IsTerminal(int(file.Fd())) {
		secret, err := term.ReadPassword(int(file.Fd()))
		fmt.Fprintln(p.out)
		if err != nil {
			return "", err
		}
		value = strings.TrimSpace(string(secret))
	} else {
		line, err := p.buf.ReadString('\n')
		if err != nil && err != io.EOF {
			return "", err
		}
		value = strings.TrimSpace(line)
		if err == io.EOF && value == "" && existing == "" {
			return "", io.ErrUnexpectedEOF
		}
	}
	if value == "" {
		return existing, nil
	}
	return value, nil
}

func (p *setupPrompter) yesNo(label string, defaultYes bool) (bool, error) {
	hint := "Y/n"
	if !defaultYes {
		hint = "y/N"
	}
	for {
		fmt.Fprintf(p.out, "%s [%s]: ", label, hint)
		line, err := p.buf.ReadString('\n')
		if err != nil && err != io.EOF {
			return false, err
		}
		value := strings.ToLower(strings.TrimSpace(line))
		if value == "" {
			if err == io.EOF {
				return false, io.ErrUnexpectedEOF
			}
			return defaultYes, nil
		}
		switch value {
		case "y", "yes":
			return true, nil
		case "n", "no":
			return false, nil
		default:
			fmt.Fprintln(p.out, "  Enter y or n.")
		}
	}
}
