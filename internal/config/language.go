package config

import "strings"

// DefaultLanguage is the fallback output language used when the operator has
// not selected one (or selected an unsupported code). English stays the
// default so existing installs are unaffected.
const DefaultLanguage = "en"

// languageDisplayNames maps a supported BCP-47-ish language code to a
// human-readable name shown in the dashboard and setup flows. Keys are the
// canonical (normalized) form returned by NormalizeLanguage.
var languageDisplayNames = map[string]string{
	"en":    "English",
	"zh-CN": "简体中文 (Simplified Chinese)",
}

// languageAliases maps common alternate spellings to a canonical code so that
// values like "zh", "zh_cn", or "zh-hans" all resolve to "zh-CN".
var languageAliases = map[string]string{
	"en":                 "en",
	"en-us":              "en",
	"english":            "en",
	"zh":                 "zh-CN",
	"zh-cn":              "zh-CN",
	"zh_cn":              "zh-CN",
	"zh-hans":            "zh-CN",
	"zh-hans-cn":         "zh-CN",
	"chinese":            "zh-CN",
	"simplified chinese": "zh-CN",
}

// SupportedLanguages returns the canonical codes of every language Xalgorix can
// localize output into. English is always first so callers can present it as
// the default choice.
func SupportedLanguages() []string {
	return []string{"en", "zh-CN"}
}

// NormalizeLanguage canonicalizes a raw language code/name (case-insensitive,
// alias-aware). Unknown or empty values fall back to DefaultLanguage so the
// rest of the system never has to defend against arbitrary strings.
func NormalizeLanguage(raw string) string {
	key := strings.ToLower(strings.TrimSpace(raw))
	if key == "" {
		return DefaultLanguage
	}
	if canonical, ok := languageAliases[key]; ok {
		return canonical
	}
	// Accept an exact canonical match regardless of casing (e.g. "ZH-CN").
	for _, code := range SupportedLanguages() {
		if strings.EqualFold(code, key) {
			return code
		}
	}
	return DefaultLanguage
}

// LanguageDisplayName returns the human-readable name for a language code.
// Unknown codes fall back to the code itself so nothing renders blank.
func LanguageDisplayName(code string) string {
	canonical := NormalizeLanguage(code)
	if name, ok := languageDisplayNames[canonical]; ok {
		return name
	}
	return code
}

// OutputLanguageDirective returns the system-prompt instruction that tells the
// LLM which language to write its human-readable output in. It returns an empty
// string for English (the model's default), so English scans are byte-for-byte
// unchanged. For other languages it returns a directive that localizes prose
// while preserving technical tokens (payloads, commands, code, URLs, headers,
// CVE/CWE IDs) verbatim so exploitation output stays correct.
func OutputLanguageDirective(code string) string {
	canonical := NormalizeLanguage(code)
	if canonical == DefaultLanguage {
		return ""
	}
	name := LanguageDisplayName(canonical)
	return "## OUTPUT LANGUAGE — MANDATORY\n\n" +
		"Write ALL human-readable prose you produce in " + name + ". This includes: " +
		"your reasoning/thinking messages, notes (add_note), vulnerability titles, descriptions, " +
		"impact, technical analysis, remediation/fix text, proof-of-concept explanations, " +
		"status messages, and every reply in post-scan chat.\n\n" +
		"Do NOT translate or alter these — keep them exactly as-is in their original form:\n" +
		"- Tool call XML, parameter names, and tool names.\n" +
		"- Shell commands, code, scripts, and payloads.\n" +
		"- URLs, hostnames, HTTP headers, parameter names, and raw request/response bodies.\n" +
		"- Identifiers such as CVE-IDs, CWE-IDs, CVSS vector strings, and the severity keywords " +
		"(critical/high/medium/low/info) required by the report_vulnerability tool.\n\n" +
		"In short: the STRUCTURE and TECHNICAL TOKENS stay in English/ASCII exactly as required by the " +
		"tools, but everything a human reads is written in " + name + "."
}
