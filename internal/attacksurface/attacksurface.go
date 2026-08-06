// Package attacksurface turns operator-supplied context artifacts — OpenAPI /
// Swagger specs, HAR captures, and Postman collections — into a normalized,
// deduplicated attack surface (endpoints + params + example bodies) plus any
// authentication material found in real requests.
//
// This is the "informed black-box" lever: instead of blindly crawling, the
// agent starts from the target's REAL endpoint/parameter surface and, when a
// HAR/Postman capture includes a live session, an authenticated one. It mirrors
// the "attach security context" capability of mature autonomous pentest
// platforms and is the single biggest force-multiplier for black-box coverage.
package attacksurface

import (
	"archive/zip"
	"bytes"
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// Endpoint is one normalized, testable request surface.
type Endpoint struct {
	Method string   // GET, POST, … ("" when unknown)
	Path   string   // path or full URL
	Params []string // query/path/body parameter names
	Body   string   // truncated example body, when available
	Source string   // "openapi" | "har" | "postman"
}

func (e Endpoint) key() string {
	return strings.ToUpper(e.Method) + " " + e.Path
}

// Result is the merged surface plus extracted auth + metadata.
type Result struct {
	Endpoints   []Endpoint
	AuthHeaders map[string]string // Authorization / Cookie / X-Api-Key … from real requests
	BaseURLs    []string
	Formats     []string // which artifact formats were parsed
	Notes       []string // security schemes, warnings, etc.
}

const (
	maxEndpoints = 500
	maxBodyChars = 400
)

// authHeaderNames are request headers we treat as authentication material worth
// reusing for the scan (case-insensitive match, exact or by suffix/keyword).
var authHeaderKeywords = []string{
	"authorization", "cookie", "x-api-key", "api-key", "apikey",
	"x-auth-token", "auth-token", "x-access-token", "access-token",
	"x-csrf-token", "csrf-token", "x-xsrf-token", "token", "x-session",
	"x-amz-security-token", "x-forwarded-authorization",
}

func isAuthHeader(name string) bool {
	n := strings.ToLower(strings.TrimSpace(name))
	for _, k := range authHeaderKeywords {
		if n == k || strings.HasSuffix(n, k) {
			return true
		}
	}
	return false
}

// isAndroidArchive reports whether a path names a ZIP-based Android artifact:
// a plain APK, a split-APK bundle (.apks/.xapk) or an app bundle (.aab).
func isAndroidArchive(p string) bool {
	switch strings.ToLower(filepath.Ext(p)) {
	case ".apk", ".apks", ".xapk", ".aab":
		return true
	}
	return false
}

// LoadFromPath parses a single artifact file or every file in a directory,
// merging the results. Unparseable files are skipped (best-effort).
func LoadFromPath(path string) (*Result, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, nil
	}
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("scan context path: %w", err)
	}

	merged := &Result{AuthHeaders: map[string]string{}}
	parseInto := func(p string) {
		// ZIP-based Android artifacts are streamed from disk: reading a
		// multi-hundred-MB APK into memory just to hand it to a zip reader
		// caused a large allocation spike (and, on constrained hosts, an
		// OOM kill that dropped in-memory dashboard sessions).
		if isAndroidArchive(p) {
			if zrc, err := zip.OpenReader(p); err == nil {
				defer zrc.Close()
				if r := parseAPKZip(&zrc.Reader, 0); r != nil {
					merged.merge(r)
				}
				return
			}
			// Fall through: a mislabelled extension is still worth sniffing.
		}
		data, err := os.ReadFile(p)
		if err != nil || len(data) == 0 {
			return
		}
		if r := ParseBytes(data, filepath.Base(p)); r != nil {
			merged.merge(r)
		}
	}

	if info.IsDir() {
		entries, _ := os.ReadDir(path)
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			parseInto(filepath.Join(path, e.Name()))
		}
	} else {
		parseInto(path)
	}

	merged.finalize()
	// BaseURLs count as usable context: an artifact can yield backend hosts
	// without concrete paths (common for APKs that build request paths at
	// runtime), and those hosts still seed the attack surface. Only fail when
	// nothing at all was recovered.
	if len(merged.Endpoints) == 0 && len(merged.AuthHeaders) == 0 && len(merged.BaseURLs) == 0 {
		return merged, fmt.Errorf("no usable endpoints or auth found in %q", path)
	}
	return merged, nil
}

// ParseBytes autodetects the artifact format and parses it. Returns nil when
// the format is unrecognized or the content is unusable.
func ParseBytes(data []byte, name string) *Result {
	trimmed := strings.TrimSpace(string(data))
	if trimmed == "" {
		return nil
	}
	// APK (Android app) — a ZIP archive. Detect by the ZIP local-file magic.
	if len(data) >= 4 && data[0] == 'P' && data[1] == 'K' && (data[2] == 0x03 || data[2] == 0x05 || data[2] == 0x07) {
		return parseAPK(data)
	}
	// JSON artifacts: HAR, Postman, or OpenAPI/Swagger in JSON.
	if strings.HasPrefix(trimmed, "{") {
		var probe map[string]json.RawMessage
		if err := json.Unmarshal(data, &probe); err == nil {
			switch {
			case hasKey(probe, "swagger") || hasKey(probe, "openapi"):
				return parseOpenAPIJSON(data)
			case hasKey(probe, "log"):
				return parseHAR(data)
			case hasKey(probe, "item") && hasKey(probe, "info"):
				return parsePostman(data)
			case hasKey(probe, "paths"):
				return parseOpenAPIJSON(data)
			}
		}
	}
	// XML artifacts: Burp Suite proxy-history / site-map export.
	if strings.HasPrefix(trimmed, "<") {
		lower := strings.ToLower(trimmed)
		if strings.Contains(lower, "<items") || strings.Contains(lower, "burp") {
			return parseBurp(data)
		}
	}
	// Otherwise assume an OpenAPI/Swagger YAML spec.
	if strings.Contains(trimmed, "openapi") || strings.Contains(trimmed, "swagger") || strings.Contains(trimmed, "paths:") {
		return parseOpenAPIYAML(data)
	}
	return nil
}

func hasKey(m map[string]json.RawMessage, k string) bool {
	_, ok := m[k]
	return ok
}

// ── OpenAPI / Swagger ──────────────────────────────────────────────────────

type oasParam struct {
	Name string `json:"name" yaml:"name"`
	In   string `json:"in" yaml:"in"`
}

type oasOperation struct {
	Parameters []oasParam `json:"parameters" yaml:"parameters"`
}

type oasSpec struct {
	Swagger  string `json:"swagger" yaml:"swagger"`
	OpenAPI  string `json:"openapi" yaml:"openapi"`
	Host     string `json:"host" yaml:"host"`         // swagger 2.0
	BasePath string `json:"basePath" yaml:"basePath"` // swagger 2.0
	Servers  []struct {
		URL string `json:"url" yaml:"url"`
	} `json:"servers" yaml:"servers"`
	Paths           map[string]map[string]oasOperation `json:"paths" yaml:"paths"`
	SecuritySchemes map[string]struct {
		Type string `json:"type" yaml:"type"`
	} `json:"securityDefinitions" yaml:"securityDefinitions"`
	Components struct {
		SecuritySchemes map[string]struct {
			Type   string `json:"type" yaml:"type"`
			Scheme string `json:"scheme" yaml:"scheme"`
		} `json:"securitySchemes" yaml:"securitySchemes"`
	} `json:"components" yaml:"components"`
}

func parseOpenAPIJSON(data []byte) *Result {
	var spec oasSpec
	if err := json.Unmarshal(data, &spec); err != nil {
		return nil
	}
	return specToResult(&spec)
}

func parseOpenAPIYAML(data []byte) *Result {
	var spec oasSpec
	if err := yaml.Unmarshal(data, &spec); err != nil {
		return nil
	}
	return specToResult(&spec)
}

var httpMethods = map[string]bool{
	"get": true, "post": true, "put": true, "delete": true,
	"patch": true, "options": true, "head": true,
}

func specToResult(spec *oasSpec) *Result {
	if len(spec.Paths) == 0 {
		return nil
	}
	res := &Result{AuthHeaders: map[string]string{}, Formats: []string{"openapi"}}

	// Base URL (openapi 3 servers, else swagger 2 host+basePath).
	for _, s := range spec.Servers {
		if u := strings.TrimSpace(s.URL); u != "" {
			res.BaseURLs = append(res.BaseURLs, u)
		}
	}
	if len(res.BaseURLs) == 0 && spec.Host != "" {
		res.BaseURLs = append(res.BaseURLs, strings.TrimRight(spec.Host+spec.BasePath, "/"))
	}
	base := ""
	if len(res.BaseURLs) > 0 {
		base = strings.TrimRight(res.BaseURLs[0], "/")
	}

	for rawPath, ops := range spec.Paths {
		for method, op := range ops {
			if !httpMethods[strings.ToLower(method)] {
				continue
			}
			var params []string
			for _, p := range op.Parameters {
				if p.Name != "" {
					params = append(params, p.Name)
				}
			}
			full := rawPath
			if base != "" {
				full = base + rawPath
			}
			res.Endpoints = append(res.Endpoints, Endpoint{
				Method: strings.ToUpper(method),
				Path:   full,
				Params: params,
				Source: "openapi",
			})
		}
	}

	if n := len(spec.SecuritySchemes) + len(spec.Components.SecuritySchemes); n > 0 {
		res.Notes = append(res.Notes, fmt.Sprintf("spec declares %d security scheme(s) — endpoints likely require auth; use the attached/target credentials", n))
	}
	return res
}

// ── HAR ────────────────────────────────────────────────────────────────────

type harFile struct {
	Log struct {
		Entries []struct {
			Request struct {
				Method  string `json:"method"`
				URL     string `json:"url"`
				Headers []struct {
					Name  string `json:"name"`
					Value string `json:"value"`
				} `json:"headers"`
				QueryString []struct {
					Name string `json:"name"`
				} `json:"queryString"`
				PostData struct {
					Text   string `json:"text"`
					Params []struct {
						Name string `json:"name"`
					} `json:"params"`
				} `json:"postData"`
			} `json:"request"`
		} `json:"entries"`
	} `json:"log"`
}

func parseHAR(data []byte) *Result {
	var har harFile
	if err := json.Unmarshal(data, &har); err != nil {
		return nil
	}
	res := &Result{AuthHeaders: map[string]string{}, Formats: []string{"har"}}
	for _, e := range har.Log.Entries {
		r := e.Request
		if r.URL == "" {
			continue
		}
		var params []string
		for _, q := range r.QueryString {
			if q.Name != "" {
				params = append(params, q.Name)
			}
		}
		for _, p := range r.PostData.Params {
			if p.Name != "" {
				params = append(params, p.Name)
			}
		}
		res.Endpoints = append(res.Endpoints, Endpoint{
			Method: strings.ToUpper(r.Method),
			Path:   stripQuery(r.URL),
			Params: params,
			Body:   truncate(r.PostData.Text, maxBodyChars),
			Source: "har",
		})
		// Harvest real auth material from the captured request headers.
		for _, h := range r.Headers {
			if isAuthHeader(h.Name) && strings.TrimSpace(h.Value) != "" {
				res.AuthHeaders[canonicalHeader(h.Name)] = h.Value
			}
		}
	}
	return res
}

// ── Postman collection (v2.x) ───────────────────────────────────────────────

type postmanColl struct {
	Item []postmanItem `json:"item"`
}

type postmanItem struct {
	Name    string          `json:"name"`
	Item    []postmanItem   `json:"item"` // folders nest items
	Request *postmanRequest `json:"request"`
}

type postmanRequest struct {
	Method string `json:"method"`
	Header []struct {
		Key   string `json:"key"`
		Value string `json:"value"`
	} `json:"header"`
	URL  json.RawMessage `json:"url"` // string OR object
	Body struct {
		Raw string `json:"raw"`
	} `json:"body"`
}

func parsePostman(data []byte) *Result {
	var coll postmanColl
	if err := json.Unmarshal(data, &coll); err != nil {
		return nil
	}
	res := &Result{AuthHeaders: map[string]string{}, Formats: []string{"postman"}}
	var walk func(items []postmanItem)
	walk = func(items []postmanItem) {
		for _, it := range items {
			if len(it.Item) > 0 {
				walk(it.Item)
			}
			if it.Request == nil {
				continue
			}
			url := postmanURL(it.Request.URL)
			if url == "" {
				continue
			}
			res.Endpoints = append(res.Endpoints, Endpoint{
				Method: strings.ToUpper(it.Request.Method),
				Path:   stripQuery(url),
				Body:   truncate(it.Request.Body.Raw, maxBodyChars),
				Source: "postman",
			})
			for _, h := range it.Request.Header {
				if isAuthHeader(h.Key) && strings.TrimSpace(h.Value) != "" {
					res.AuthHeaders[canonicalHeader(h.Key)] = h.Value
				}
			}
		}
	}
	walk(coll.Item)
	return res
}

func postmanURL(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	// URL can be a bare string.
	var s string
	if json.Unmarshal(raw, &s) == nil && s != "" {
		return s
	}
	// Or an object with a "raw" field.
	var obj struct {
		Raw string `json:"raw"`
	}
	if json.Unmarshal(raw, &obj) == nil {
		return obj.Raw
	}
	return ""
}

// ── Burp Suite export (proxy history / site map XML) ────────────────────────

type burpItems struct {
	Items []burpItem `xml:"item"`
}

type burpItem struct {
	URL     string   `xml:"url"`
	Method  string   `xml:"method"`
	Path    string   `xml:"path"`
	Request burpBlob `xml:"request"`
}

type burpBlob struct {
	Base64 string `xml:"base64,attr"`
	Data   string `xml:",chardata"`
}

func parseBurp(data []byte) *Result {
	var items burpItems
	if err := xml.Unmarshal(data, &items); err != nil || len(items.Items) == 0 {
		return nil
	}
	res := &Result{AuthHeaders: map[string]string{}, Formats: []string{"burp"}}
	for _, it := range items.Items {
		raw := strings.TrimSpace(it.URL)
		if raw == "" {
			continue
		}
		var params []string
		if u, err := url.Parse(raw); err == nil {
			for k := range u.Query() {
				params = append(params, k)
			}
		}
		res.Endpoints = append(res.Endpoints, Endpoint{
			Method: strings.ToUpper(strings.TrimSpace(it.Method)),
			Path:   stripQuery(raw),
			Params: params,
			Source: "burp",
		})
		// Decode the raw request and harvest real auth headers.
		reqText := it.Request.Data
		if strings.EqualFold(strings.TrimSpace(it.Request.Base64), "true") {
			if dec, err := base64.StdEncoding.DecodeString(strings.TrimSpace(it.Request.Data)); err == nil {
				reqText = string(dec)
			}
		}
		for name, val := range headersFromRawRequest(reqText) {
			if isAuthHeader(name) && strings.TrimSpace(val) != "" {
				res.AuthHeaders[canonicalHeader(name)] = val
			}
		}
	}
	return res
}

// headersFromRawRequest parses "Header: value" lines from a raw HTTP request
// (request line, then headers, terminated by a blank line).
func headersFromRawRequest(raw string) map[string]string {
	out := map[string]string{}
	lines := strings.Split(strings.ReplaceAll(raw, "\r\n", "\n"), "\n")
	for i, line := range lines {
		if i == 0 {
			continue // request line
		}
		if strings.TrimSpace(line) == "" {
			break // end of headers
		}
		if idx := strings.IndexByte(line, ':'); idx > 0 {
			out[strings.TrimSpace(line[:idx])] = strings.TrimSpace(line[idx+1:])
		}
	}
	return out
}

// ── APK (Android app) ────────────────────────────────────────────────────────

var (
	apkURLRe  = regexp.MustCompile(`https?://[a-zA-Z0-9._~-]+(?::\d+)?(?:/[a-zA-Z0-9._~:/?#\[\]@!$&'()*+,;=%{}.-]*)?`)
	apkPathRe = regexp.MustCompile(`(?:^|["'` + "`" + ` ])(/(?:api|rest|graphql|v\d+|internal|oauth|auth|admin)/[a-zA-Z0-9._~:/{}.-]{1,120})`)
)

// apkNoiseHosts are framework/namespace/CDN hosts that appear in every APK and
// are never the app's backend — dropped so the seeded surface stays signal.
var apkNoiseHosts = []string{
	"schemas.android.com", "schemas.xmlsoap.org", "www.w3.org", "ns.adobe.com",
	"xmlpull.org", "java.sun.com", "apache.org", "json-schema.org",
	"fonts.googleapis.com", "fonts.gstatic.com", "www.googleapis.com/auth",
	"goo.gl", "developer.android.com", "developers.google.com", "github.com",
	"gnu.org", "opensource.org", "creativecommons.org", "example.com",
	"schema.org", "w3.org", "bouncycastle.org", "slf4j.org",
}

func isNoiseHost(host string) bool {
	h := strings.ToLower(host)
	for _, n := range apkNoiseHosts {
		if h == n || strings.HasSuffix(h, "."+n) || strings.HasPrefix(n, h) {
			return true
		}
	}
	return false
}

// parseAPK scans an Android APK (a ZIP of DEX/resources/manifest/assets) for
// backend URLs and API paths, yielding the app's server-side attack surface.
func parseAPK(data []byte) *Result {
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return nil
	}
	return parseAPKZip(zr, 0)
}

// maxAPKNesting bounds descent into nested APKs so a hostile or accidentally
// self-referential bundle can't drive unbounded recursion. One level covers
// real-world layouts: .apks/.xapk/.aab hold plain .apk members.
const maxAPKNesting = 1

// maxNestedAPKBytes caps how much of an inner APK we buffer. zip readers need
// random access, so a nested member has to be materialized — this bounds that
// cost rather than trusting the declared size.
const maxNestedAPKBytes = 300 << 20 // 300MB

// parseNestedAPK reads one inner APK member and parses it. Errors are swallowed
// (best-effort, consistent with the rest of the package): a single unreadable
// split shouldn't discard the whole bundle.
func parseNestedAPK(f *zip.File, depth int) *Result {
	if f.UncompressedSize64 > maxNestedAPKBytes {
		return nil
	}
	rc, err := f.Open()
	if err != nil {
		return nil
	}
	defer rc.Close()
	inner, err := io.ReadAll(io.LimitReader(rc, maxNestedAPKBytes))
	if err != nil || len(inner) == 0 {
		return nil
	}
	zr, err := zip.NewReader(bytes.NewReader(inner), int64(len(inner)))
	if err != nil {
		return nil
	}
	return parseAPKZip(zr, depth)
}

// parseAPKZip walks an already-open APK (or split-APK bundle) archive. Taking a
// *zip.Reader rather than a []byte lets callers stream large files straight from
// disk instead of holding the whole archive in memory.
func parseAPKZip(zr *zip.Reader, depth int) *Result {
	res := &Result{AuthHeaders: map[string]string{}, Formats: []string{"apk"}}
	urlSet := map[string]bool{}
	hostSet := map[string]bool{}

	const perFileCap = 12 << 20 // 12MB scanned per entry
	scanBytes := func(b []byte) {
		for _, m := range apkURLRe.FindAll(b, -1) {
			u := strings.Trim(string(m), `"'`+"` ")
			pu, err := url.Parse(u)
			if err != nil || pu.Host == "" || isNoiseHost(pu.Host) {
				continue
			}
			urlSet[stripQuery(u)] = true
			hostSet[pu.Scheme+"://"+pu.Host] = true
		}
		for _, m := range apkPathRe.FindAllSubmatch(b, -1) {
			if len(m) > 1 {
				urlSet[string(m[1])] = true
			}
		}
	}

	for _, f := range zr.File {
		name := strings.ToLower(f.Name)

		// Split-APK bundles (.apks/.xapk) and app bundles (.aab) are ZIPs whose
		// members are themselves APKs, so descend into them. Without this the
		// entry filter below matches nothing and the bundle looks empty.
		if depth < maxAPKNesting && (strings.HasSuffix(name, ".apk") ||
			strings.HasSuffix(name, ".apks") || strings.HasSuffix(name, ".xapk")) {
			if inner := parseNestedAPK(f, depth+1); inner != nil {
				res.merge(inner)
			}
			continue
		}

		// Scan the code + resources + config; skip large media/binaries.
		// lib/**.so is included because React Native and Flutter builds keep
		// their endpoints in native libraries (Dart AOT snapshots, JSI
		// bundles) rather than in classes.dex.
		relevant := strings.HasSuffix(name, ".dex") ||
			strings.HasSuffix(name, ".arsc") ||
			strings.HasSuffix(name, ".xml") ||
			strings.HasSuffix(name, ".json") ||
			strings.HasSuffix(name, ".so") ||
			strings.HasPrefix(name, "assets/") ||
			strings.Contains(name, "androidmanifest")
		if !relevant {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			continue
		}
		// Size the buffer to the entry instead of always allocating the cap:
		// an APK has many small entries, and a flat 12MB alloc per entry was a
		// large, needless memory spike.
		bufSize := perFileCap
		if size := f.UncompressedSize64; size > 0 && size < uint64(perFileCap) {
			bufSize = int(size)
		}
		buf := make([]byte, bufSize)
		n, _ := readFull(rc, buf)
		rc.Close()
		scanBytes(buf[:n])
	}

	for u := range urlSet {
		res.Endpoints = append(res.Endpoints, Endpoint{Path: u, Source: "apk"})
	}
	for h := range hostSet {
		res.BaseURLs = append(res.BaseURLs, h)
	}
	if len(res.Endpoints) == 0 {
		res.Notes = append(res.Notes, "APK parsed but no backend URLs/paths found — the app may obfuscate endpoints or build them at runtime")
	}
	return res
}

// readFull reads up to len(buf) bytes, tolerating short reads until EOF.
func readFull(r interface{ Read([]byte) (int, error) }, buf []byte) (int, error) {
	total := 0
	for total < len(buf) {
		n, err := r.Read(buf[total:])
		total += n
		if err != nil {
			return total, err
		}
	}
	return total, nil
}

// ── merge / finalize / render ───────────────────────────────────────────────

func (r *Result) merge(other *Result) {
	if other == nil {
		return
	}
	r.Endpoints = append(r.Endpoints, other.Endpoints...)
	for k, v := range other.AuthHeaders {
		if _, ok := r.AuthHeaders[k]; !ok {
			r.AuthHeaders[k] = v
		}
	}
	r.BaseURLs = append(r.BaseURLs, other.BaseURLs...)
	r.Formats = append(r.Formats, other.Formats...)
	r.Notes = append(r.Notes, other.Notes...)
}

func (r *Result) finalize() {
	// Dedup endpoints by "METHOD path", merging params.
	seen := map[string][]string{}
	order := []string{}
	bodies := map[string]string{}
	srcs := map[string]string{}
	for _, e := range r.Endpoints {
		k := e.key()
		if _, ok := seen[k]; !ok {
			order = append(order, k)
			srcs[k] = e.Source
		}
		seen[k] = mergeUnique(seen[k], e.Params)
		if bodies[k] == "" && e.Body != "" {
			bodies[k] = e.Body
		}
	}
	out := make([]Endpoint, 0, len(order))
	for _, k := range order {
		method, path := splitKey(k)
		out = append(out, Endpoint{Method: method, Path: path, Params: seen[k], Body: bodies[k], Source: srcs[k]})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Path != out[j].Path {
			return out[i].Path < out[j].Path
		}
		return out[i].Method < out[j].Method
	})
	if len(out) > maxEndpoints {
		out = out[:maxEndpoints]
	}
	r.Endpoints = out
	r.BaseURLs = dedupStrings(r.BaseURLs)
	r.Formats = dedupStrings(r.Formats)
	r.Notes = dedupStrings(r.Notes)
}

// Briefing renders a compact, agent-facing attack-surface briefing. Returns ""
// when there is nothing useful.
func (r *Result) Briefing() string {
	if r == nil || len(r.Endpoints) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString("## ATTACK SURFACE (operator-supplied context — ")
	b.WriteString(strings.Join(r.Formats, ", "))
	b.WriteString(")\n")
	b.WriteString(fmt.Sprintf("You were given the target's REAL endpoint surface (%d endpoints). Do NOT rely on blind crawling — systematically test THESE endpoints for injection (SQLi/NoSQLi/cmdi/SSTI), broken access control (IDOR/BOLA/BFLA — swap ids, drop/downgrade auth), SSRF, and business-logic flaws. Diff authenticated vs unauthenticated on every one.\n", len(r.Endpoints)))
	if len(r.BaseURLs) > 0 {
		b.WriteString("Base URL(s): " + strings.Join(r.BaseURLs, ", ") + "\n")
	}
	if len(r.AuthHeaders) > 0 {
		names := make([]string, 0, len(r.AuthHeaders))
		for k := range r.AuthHeaders {
			names = append(names, k)
		}
		sort.Strings(names)
		b.WriteString("Authenticated session captured (headers: " + strings.Join(names, ", ") + ") — applied automatically to http_request. ALWAYS also replay each request WITHOUT it to find broken access control.\n")
	}
	for _, n := range r.Notes {
		b.WriteString("- " + n + "\n")
	}
	b.WriteString("\nEndpoints:\n")
	for _, e := range r.Endpoints {
		line := "- " + e.Method + " " + e.Path
		if len(e.Params) > 0 {
			line += "  params: " + strings.Join(e.Params, ",")
		}
		b.WriteString(line + "\n")
	}
	return b.String()
}

// ── small helpers ────────────────────────────────────────────────────────────

func stripQuery(u string) string {
	if i := strings.IndexByte(u, '?'); i >= 0 {
		return u[:i]
	}
	return u
}

func canonicalHeader(name string) string {
	name = strings.TrimSpace(name)
	if strings.EqualFold(name, "cookie") {
		return "Cookie"
	}
	if strings.EqualFold(name, "authorization") {
		return "Authorization"
	}
	return name
}

func truncate(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}

func mergeUnique(dst, src []string) []string {
	seen := map[string]bool{}
	for _, s := range dst {
		seen[s] = true
	}
	for _, s := range src {
		if s != "" && !seen[s] {
			dst = append(dst, s)
			seen[s] = true
		}
	}
	return dst
}

func dedupStrings(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if s != "" && !seen[s] {
			out = append(out, s)
			seen[s] = true
		}
	}
	return out
}

func splitKey(k string) (method, path string) {
	if i := strings.IndexByte(k, ' '); i >= 0 {
		return k[:i], k[i+1:]
	}
	return "", k
}
