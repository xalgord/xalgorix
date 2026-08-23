package web

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/xalgord/xalgorix/v4/internal/attacksurface"
)

// handleUploadTargets parses a text file with one target per line.
func (s *Server) handleUploadTargets(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}

	if err := r.ParseMultipartForm(10 << 20); err != nil {
		http.Error(w, "failed to parse multipart form: "+err.Error(), http.StatusBadRequest)
		return
	} // 10MB max
	file, _, err := r.FormFile("file")
	if err != nil {
		http.Error(w, "file required", http.StatusBadRequest)
		return
	}
	defer file.Close()

	var targets []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			targets = append(targets, line)
		}
	}
	if err := scanner.Err(); err != nil {
		log.Printf("[ERROR] Failed to read uploaded targets file: %v", err)
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"targets": targets,
		"count":   len(targets),
	})
}

// handleUploadInstructions reads a text file and returns its content.
func (s *Server) handleUploadInstructions(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}

	if err := r.ParseMultipartForm(5 << 20); err != nil {
		http.Error(w, "failed to parse multipart form: "+err.Error(), http.StatusBadRequest)
		return
	} // 5MB max
	file, _, err := r.FormFile("file")
	if err != nil {
		http.Error(w, "file required", http.StatusBadRequest)
		return
	}
	defer file.Close()

	data, err := io.ReadAll(file)
	if err != nil {
		http.Error(w, "read error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{
		"content": string(data),
	})
}

// handleUploadLogo accepts an image file upload and saves it to the logos directory.
func (s *Server) handleUploadLogo(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}

	if err := r.ParseMultipartForm(5 << 20); err != nil { // 5MB max
		http.Error(w, "failed to parse multipart form: "+err.Error(), http.StatusBadRequest)
		return
	}
	file, header, err := r.FormFile("file")
	if err != nil {
		http.Error(w, "file required", http.StatusBadRequest)
		return
	}
	defer file.Close()

	// Validate file extension. PDF reports can embed PNG/JPEG reliably; keep
	// uploads constrained to formats the report renderer can use.
	originalName := filepath.Base(header.Filename)
	ext := strings.ToLower(filepath.Ext(originalName))
	allowedExts := map[string]bool{".png": true, ".jpg": true, ".jpeg": true}
	if !allowedExts[ext] {
		http.Error(w, "unsupported image format: "+ext+" (allowed: png, jpg, jpeg)", http.StatusBadRequest)
		return
	}

	// Create logos directory
	logosDir := filepath.Join(s.dataDir, "logos")
	if err := os.MkdirAll(logosDir, 0700); err != nil {
		log.Printf("[ERROR] Failed to create logos directory: %v", err)
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}

	// Generate unique filename: timestamp_sanitizedname.ext
	nameOnly := strings.TrimSuffix(originalName, filepath.Ext(originalName))
	safeName := regexp.MustCompile(`[^a-zA-Z0-9._-]+`).ReplaceAllString(nameOnly, "_")
	safeName = strings.Trim(safeName, "._-")
	if safeName == "" {
		safeName = "logo"
	}
	fileName := fmt.Sprintf("%d_%s%s", time.Now().UnixMilli(), safeName, ext)
	dstPath := filepath.Join(logosDir, fileName)

	dst, err := os.Create(dstPath)
	if err != nil {
		log.Printf("[ERROR] Failed to create logo file: %v", err)
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}
	defer dst.Close()

	if _, err := io.Copy(dst, file); err != nil {
		log.Printf("[ERROR] Failed to write logo file: %v", err)
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}

	// Return the serving path
	servingPath := "/uploads/logos/" + fileName
	log.Printf("Logo uploaded: %s → %s", header.Filename, servingPath)

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{
		"path":     servingPath,
		"filename": originalName,
	})
}

// handleUploadContext accepts one or more scan-context artifacts (OpenAPI/
// Swagger spec, HAR capture, Postman collection + environment, Burp export, or
// an Android app) and saves them into a per-upload directory under the data
// dir. It returns that directory path, which the caller passes back as
// ScanRequest.scan_context; the engine parses every file in it and merges them
// into a seeded attack surface at scan start — resolving Postman {{variables}}
// and captured auth across the collection and its environment.
func (s *Server) handleUploadContext(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	// Hard-cap the TOTAL request body before parsing. ParseMultipartForm's
	// argument only bounds in-memory buffering (the rest spools to disk), so
	// without MaxBytesReader a client could stream an arbitrarily large upload
	// that gets written to dataDir and read back — exhausting disk/memory.
	const maxContextUpload = 160 << 20 // 160MB (allows a ~150MB APK + overhead)
	r.Body = http.MaxBytesReader(w, r.Body, maxContextUpload)
	if err := r.ParseMultipartForm(32 << 20); err != nil { // 32MB in memory, rest to disk
		http.Error(w, "failed to parse multipart form (max 160MB): "+err.Error(), http.StatusBadRequest)
		return
	}
	// Multiple artifacts can be uploaded together under the "file" field — most
	// importantly a Postman collection plus its environment file, so the engine
	// resolves {{variables}} and captured auth across them. A single file (the
	// common case) is just a list of length one.
	files := r.MultipartForm.File["file"]
	if len(files) == 0 {
		http.Error(w, "file required", http.StatusBadRequest)
		return
	}
	const maxFiles = 20
	if len(files) > maxFiles {
		http.Error(w, fmt.Sprintf("too many files (max %d)", maxFiles), http.StatusBadRequest)
		return
	}
	// .apks/.xapk are split-APK bundles and .aab is an app bundle — all ZIP
	// containers holding one or more inner .apk files, which the parser
	// descends into.
	allowedExts := map[string]bool{".json": true, ".yaml": true, ".yml": true, ".har": true, ".xml": true, ".apk": true, ".apks": true, ".xapk": true, ".aab": true, ".txt": true}
	for _, fh := range files {
		ext := strings.ToLower(filepath.Ext(filepath.Base(fh.Filename)))
		if !allowedExts[ext] {
			http.Error(w, "unsupported context format: "+ext+" (allowed: json, yaml, yml, har, xml, apk, apks, xapk, aab, txt — OpenAPI/Swagger, HAR, Postman, Burp, or an Android app)", http.StatusBadRequest)
			return
		}
	}

	contextRoot := filepath.Join(s.dataDir, "context")
	if err := os.MkdirAll(contextRoot, 0700); err != nil {
		log.Printf("[ERROR] Failed to create context directory: %v", err)
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}
	// Each upload gets its own directory: LoadFromPath parses every file in it
	// and merges the results, and a unique dir keeps concurrent uploads from
	// colliding. MkdirTemp appends a random suffix to guarantee uniqueness.
	uploadDir, err := os.MkdirTemp(contextRoot, fmt.Sprintf("%d_", time.Now().UnixMilli()))
	if err != nil {
		log.Printf("[ERROR] Failed to create context upload dir: %v", err)
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}

	sanitize := regexp.MustCompile(`[^a-zA-Z0-9._-]+`)
	usedNames := map[string]bool{}
	savedNames := make([]string, 0, len(files))
	for _, fh := range files {
		originalName := filepath.Base(fh.Filename)
		ext := strings.ToLower(filepath.Ext(originalName))
		nameOnly := strings.TrimSuffix(originalName, filepath.Ext(originalName))
		safeName := strings.Trim(sanitize.ReplaceAllString(nameOnly, "_"), "._-")
		if safeName == "" {
			safeName = "context"
		}
		fileName := safeName + ext
		for i := 1; usedNames[strings.ToLower(fileName)]; i++ {
			fileName = fmt.Sprintf("%s_%d%s", safeName, i, ext)
		}
		usedNames[strings.ToLower(fileName)] = true

		// Scoped closure so each file's handles are closed before the next.
		save := func() error {
			src, err := fh.Open()
			if err != nil {
				return err
			}
			defer src.Close()
			dst, err := os.Create(filepath.Join(uploadDir, fileName))
			if err != nil {
				return err
			}
			defer dst.Close()
			_, err = io.Copy(dst, src)
			return err
		}
		if err := save(); err != nil {
			_ = os.RemoveAll(uploadDir)
			log.Printf("[ERROR] Failed to write context file: %v", err)
			http.Error(w, "server error", http.StatusInternalServerError)
			return
		}
		savedNames = append(savedNames, originalName)
	}

	// Best-effort parse so we can report how many endpoints were seeded and
	// reject an unusable upload early with a clear message.
	res, perr := attacksurface.LoadFromPath(uploadDir)
	if perr != nil {
		_ = os.RemoveAll(uploadDir)
		http.Error(w, "could not parse context: "+perr.Error(), http.StatusBadRequest)
		return
	}
	log.Printf("Scan context uploaded: %d file(s) [%s] → %s (%d endpoints)", len(savedNames), strings.Join(savedNames, ", "), uploadDir, len(res.Endpoints))

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"path":      uploadDir,
		"filename":  strings.Join(savedNames, ", "),
		"files":     len(savedNames),
		"endpoints": len(res.Endpoints),
		"formats":   res.Formats,
		"has_auth":  len(res.AuthHeaders) > 0,
		// Surfaced so a sparse-but-valid parse (e.g. an APK yielding only
		// hosts, or one that builds paths at runtime) can be explained in the
		// UI instead of failing the upload.
		"base_urls": len(res.BaseURLs),
		"notes":     res.Notes,
	})
}
