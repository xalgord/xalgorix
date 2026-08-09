package config

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

var envFileKeyPattern = regexp.MustCompile(`^[A-Z_][A-Z0-9_]*$`)

// EnvFilePath returns the per-user configuration file used by both the CLI
// setup wizard and the dashboard settings page.
func EnvFilePath() string {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		home = "/root"
	}
	return filepath.Join(home, ".xalgorix.env")
}

// ReadEnvFile parses a dotenv-style file without changing the process
// environment. Missing files are treated as empty configuration.
func ReadEnvFile(path string) (map[string]string, error) {
	values := map[string]string{}
	f, err := os.Open(path)
	if os.IsNotExist(err) {
		return values, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read env file: %w", err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		key, value, ok := parseEnvLine(scanner.Text())
		if ok {
			values[key] = value
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read env file: %w", err)
	}
	return values, nil
}

// UpdateEnvFile preserves unrelated settings and comments while applying the
// supplied values. An empty value removes that key. The replacement is atomic
// and the resulting file is always private to the current user.
func UpdateEnvFile(path string, updates map[string]string) error {
	for key, value := range updates {
		if !envFileKeyPattern.MatchString(key) {
			return fmt.Errorf("invalid environment variable name %q", key)
		}
		if strings.ContainsAny(value, "\r\n") {
			return fmt.Errorf("%s cannot contain newlines", key)
		}
	}

	existing, err := os.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("read env file: %w", err)
	}
	var lines []string
	if len(existing) > 0 {
		lines = strings.Split(strings.TrimRight(string(existing), "\n"), "\n")
	}

	seen := make(map[string]bool, len(updates))
	newLines := make([]string, 0, len(lines)+len(updates)+1)
	for _, line := range lines {
		key, _, ok := parseEnvLine(line)
		if !ok {
			newLines = append(newLines, line)
			continue
		}
		value, shouldUpdate := updates[key]
		if !shouldUpdate {
			newLines = append(newLines, line)
			continue
		}
		seen[key] = true
		if value != "" {
			newLines = append(newLines, formatEnvLine(key, value))
		}
	}

	missing := make([]string, 0, len(updates))
	for key, value := range updates {
		if !seen[key] && value != "" {
			missing = append(missing, key)
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 && len(newLines) > 0 && strings.TrimSpace(newLines[len(newLines)-1]) != "" {
		newLines = append(newLines, "")
	}
	for _, key := range missing {
		newLines = append(newLines, formatEnvLine(key, updates[key]))
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("create env dir: %w", err)
	}
	out := strings.TrimRight(strings.Join(newLines, "\n"), "\n")
	if out != "" {
		out += "\n"
	}
	return writePrivateFileAtomically(path, []byte(out))
}

func parseEnvLine(line string) (string, string, bool) {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" || strings.HasPrefix(trimmed, "#") {
		return "", "", false
	}
	trimmed = strings.TrimPrefix(trimmed, "export ")
	parts := strings.SplitN(trimmed, "=", 2)
	if len(parts) != 2 {
		return "", "", false
	}
	key := strings.TrimSpace(parts[0])
	if !envFileKeyPattern.MatchString(key) {
		return "", "", false
	}
	value := strings.TrimSpace(parts[1])
	if len(value) >= 2 {
		if (value[0] == '"' && value[len(value)-1] == '"') ||
			(value[0] == '\'' && value[len(value)-1] == '\'') {
			value = value[1 : len(value)-1]
		}
	}
	return key, value, true
}

func formatEnvLine(key, value string) string {
	return key + "=" + value
}

func writePrivateFileAtomically(path string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".xalgorix.env-*")
	if err != nil {
		return fmt.Errorf("create temporary env file: %w", err)
	}
	tmpPath := tmp.Name()
	defer func() {
		_ = os.Remove(tmpPath)
	}()

	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return fmt.Errorf("secure temporary env file: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("write env file: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("sync env file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close env file: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("replace env file: %w", err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		return fmt.Errorf("chmod env file: %w", err)
	}
	return nil
}
