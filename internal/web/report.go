package web

import (
	"fmt"
	"image"
	_ "image/jpeg" // register JPEG decoder for image.Decode on uploaded logos
	_ "image/png"  // register PNG decoder for image.Decode on uploaded logos
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

func supportedReportLogoExt(path string) bool {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".png", ".jpg", ".jpeg":
		return true
	default:
		return false
	}
}

func validReportLogo(path string) bool {
	if !supportedReportLogoExt(path) {
		return false
	}
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() {
		return false
	}
	file, err := os.Open(path)
	if err != nil {
		return false
	}
	defer file.Close()
	_, _, err = image.DecodeConfig(file)
	return err == nil
}

func (s *Server) resolveReportLogoPath(logoPath string) (string, bool) {
	logoPath = strings.TrimSpace(logoPath)
	if logoPath == "" {
		return "", false
	}
	var candidates []string
	if strings.HasPrefix(logoPath, "/uploads/logos/") {
		candidates = append(candidates, filepath.Join(s.dataDir, "logos", filepath.Base(logoPath)))
	} else if filepath.IsAbs(logoPath) {
		candidates = append(candidates, logoPath)
	} else {
		candidates = append(candidates,
			filepath.Join(s.currentScanDir, logoPath),
			filepath.Join(s.dataDir, "logos", filepath.Base(logoPath)),
			logoPath,
		)
	}
	for _, candidate := range candidates {
		if validReportLogo(candidate) {
			return candidate, true
		}
	}
	return "", false
}

type reconReportSummary struct {
	DNSRecords   []string
	IPAddresses  []string
	Ports        []string
	Technologies []string
	URLs         []string
}

func (s reconReportSummary) hasData() bool {
	return len(s.DNSRecords)+len(s.IPAddresses)+len(s.Ports)+len(s.Technologies)+len(s.URLs) > 0
}

var (
	ipv4Re      = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)
	dnsRecordRe = regexp.MustCompile(`(?i)\b([a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)+\.?)\s+(?:\d+\s+)?(?:in\s+)?(a|aaaa|cname|mx|ns|txt|soa)\s+(\S[^\r\n]{0,159})`)
	openPortRe  = regexp.MustCompile(`(?im)\b([0-9]{1,5})/(tcp|udp)\s+open\s+([^\s]+)?([^\r\n]{0,100})`)
)

// agentProseTypes are event types that contain natural language from the agent
// rather than structured tool output. These are skipped during recon extraction
// to avoid false positives (e.g., "the site uses WordPress" matching as a tech
// detection, or "check the A record" matching as a DNS record).
var agentProseTypes = map[string]bool{
	"agent":    true,
	"thought":  true,
	"decision": true,
	"message":  true,
	"llm":      true,
	"phase":    true,
}

func collectReconReportSummary(events []WSEvent) reconReportSummary {
	var summary reconReportSummary
	seenDNS := map[string]bool{}
	seenIP := map[string]bool{}
	seenPort := map[string]bool{}
	seenTech := map[string]bool{}
	seenURL := map[string]bool{}

	techSignals := map[string][]string{
		"Cloudflare": {"cloudflare", "cf-ray"},
		"Nginx":      {"nginx"},
		"Apache":     {"apache"},
		"IIS":        {"microsoft-iis", "iis/"},
		"WordPress":  {"wordpress", "wp-content"},
		"Laravel":    {"laravel"},
		"PHP":        {"x-powered-by: php", "phpsessid", ".php"},
		"Node.js":    {"node.js", "express", "x-powered-by: express"},
		"Next.js":    {"next.js", "_next/"},
		"React":      {"react", "react-dom"},
		"jQuery":     {"jquery"},
		"Django":     {"django", "csrftoken"},
		"Flask":      {"flask"},
		"Spring":     {"spring", "jsessionid"},
		"Tomcat":     {"tomcat"},
		"GraphQL":    {"graphql"},
	}

	for _, evt := range events {
		// Skip agent prose — only parse structured tool output to avoid
		// false positives from natural language descriptions.
		if agentProseTypes[evt.Type] {
			continue
		}

		text := evt.Output + "\n" + evt.Error
		for _, value := range evt.ToolArgs {
			text += "\n" + value
		}
		// Include Content only for non-prose events (e.g., tool_call Content
		// may contain a command summary). Agent messages are already filtered.
		if evt.Content != "" {
			text += "\n" + evt.Content
		}
		lower := strings.ToLower(text)

		for _, ip := range ipv4Re.FindAllString(text, -1) {
			if validIPv4(ip) {
				addUnique(&summary.IPAddresses, seenIP, ip, 40)
			}
		}

		for _, match := range dnsRecordRe.FindAllStringSubmatch(text, -1) {
			if len(match) == 4 {
				record := fmt.Sprintf("%s %s %s", strings.TrimSpace(match[1]), strings.ToUpper(match[2]), strings.TrimSpace(match[3]))
				addUnique(&summary.DNSRecords, seenDNS, record, 40)
			}
		}

		for _, match := range openPortRe.FindAllStringSubmatch(text, -1) {
			if len(match) >= 4 {
				port := strings.TrimSpace(match[1])
				service := strings.TrimSpace(match[3] + match[4])
				if service == "" {
					service = "unknown"
				}
				addUnique(&summary.Ports, seenPort, fmt.Sprintf("%s/%s %s", port, strings.ToLower(match[2]), service), 40)
			}
		}

		for tech, signals := range techSignals {
			for _, signal := range signals {
				if strings.Contains(lower, signal) {
					addUnique(&summary.Technologies, seenTech, tech, 30)
					break
				}
			}
		}

		for _, word := range strings.Fields(text) {
			if strings.Contains(word, "http://") || strings.Contains(word, "https://") {
				if u := extractURL(word); u != "" {
					addUnique(&summary.URLs, seenURL, u, 50)
				}
			}
		}
	}

	sort.Strings(summary.DNSRecords)
	sort.Strings(summary.IPAddresses)
	sort.Strings(summary.Ports)
	sort.Strings(summary.Technologies)
	sort.Strings(summary.URLs)
	return summary
}

func addUnique(values *[]string, seen map[string]bool, value string, max int) {
	value = strings.TrimSpace(value)
	if value == "" || seen[value] || len(*values) >= max {
		return
	}
	seen[value] = true
	*values = append(*values, value)
}

func validIPv4(ip string) bool {
	parts := strings.Split(ip, ".")
	if len(parts) != 4 {
		return false
	}
	for _, part := range parts {
		if part == "" {
			return false
		}
		var n int
		if _, err := fmt.Sscanf(part, "%d", &n); err != nil || n < 0 || n > 255 {
			return false
		}
	}
	return true
}

// methodologyPhaseNames maps phase number to name for report display.
var methodologyPhaseNames = map[int]string{
	1:  "Deep Reconnaissance & Attack Surface Mapping",
	2:  "Manual Vulnerability Discovery",
	3:  "Directory & File Discovery",
	4:  "CORS & Cookie Analysis",
	5:  "Authentication & Session Testing",
	6:  "Injection Testing",
	7:  "SSRF Testing",
	8:  "IDOR & Broken Access Control",
	9:  "API & GraphQL Testing",
	10: "File Upload Testing",
	11: "Deserialization & RCE",
	12: "Race Conditions & Business Logic",
	13: "Subdomain Takeover",
	14: "Open Redirect Testing",
	15: "Email Security Testing",
	16: "Cloud & Infrastructure",
	17: "WebSocket Testing",
	18: "CMS-Specific Testing",
	19: "Broken Link Hijacking & Content Spoofing",
	20: "Exploit Verification",
	21: "Novel Vulnerability Discovery",
	22: "Final Report",
}

// extractURL extracts a clean URL from a string
func extractURL(s string) string {
	start := strings.Index(s, "http")
	if start == -1 {
		return ""
	}
	end := len(s)
	delimiters := []string{" ", "\"", "'", ">", "<", "|", "\n", "\r"}
	for _, d := range delimiters {
		if idx := strings.Index(s[start:], d); idx != -1 && start+idx < end {
			end = start + idx
		}
	}
	url := s[start:end]
	url = strings.TrimSpace(url)
	url = strings.TrimRight(url, ".,;:!)]}>")
	return url
}
