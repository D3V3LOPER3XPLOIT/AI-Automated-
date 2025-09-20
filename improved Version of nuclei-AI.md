# Nuclei-AI-Prompts

**Purpose:** A professional, reusable collection of `nuclei -ai` prompt templates and usage guidance you can publish to GitHub. Replace `http://example.com` with your target when running; prompts are intentionally generic and responsibly worded.

---

## Quick overview
This repository-style document provides:

- Pre-scan checklist and legal guidance
- Ready-to-paste `nuclei -ai` prompt templates (Active, Authenticated, and Passive)
- High-severity focused prompts and defensive prompts
- Usage examples and recommended flags
- Contribution notes and license

All active prompts are written to be **non-destructive by default**. Always obtain written authorization and follow the pre-scan checklist before running active scans.

---

## Pre-scan checklist (must-read)
1. **Authorization:** Written permission covering scope and time window.
2. **Scope:** Define hosts/IPs, subdomains, and allowed tests. Example: `http://example.com` and `*.example.com`.
3. **Notification:** Inform/whitelist your source IP(s) with the owner.
4. **Backups & Monitoring:** Ensure backups and monitoring are in place for the scoped systems.
5. **Logging:** Enable request/response logging on your end and keep scan artifacts.
6. **Rate & Concurrency:** Start conservative and increase only if safe.

---

## How to use
- Single-host example (replace placeholder):
  ```bash
  nuclei -ai "<PROMPT>" -u http://example.com
  ```
- Targets file example (`targets.txt`):
  ```
  https://sub.example.com
  http://example.com
  ```
- Recommended flags to add where appropriate: `-severity critical,high`, `-rate-limit 10`, `-c 50`, `-json`, `-o output.json`.

---

## Active prompts (General / OWASP)
> Use only when you have explicit authorization. Replace target with `http://example.com` or adjust scope as required.

1. **OWASP Top-10 (High focus)**

```
nuclei -ai "Perform an OWASP Top-10 focused scan against http://example.com and return only high or critical findings (SQLi, RCE indicators, auth bypass, critical misconfigurations). For each finding include affected endpoint, non-destructive proof-of-concept request/response snippet, severity, and remediation guidance." -u http://example.com
```

2. **High-severity CVE fingerprinting**

```
nuclei -ai "Fingerprint server, frameworks, and components on http://example.com and map identified versions to known critical CVEs (CVSS>=7). Provide CVE IDs, evidence, and mitigation steps (no exploit attempts)." -u http://example.com
```

3. **SQL Injection (safe PoC)**

```
nuclei -ai "Scan http://example.com for SQL injection patterns (error-based, boolean, time-based) across GET/POST parameters. Provide non-destructive PoC, vulnerable parameter names, and mitigation guidance." -u http://example.com
```

4. **Remote Code Execution indicators**

```
nuclei -ai "Check http://example.com for indicators of remote code execution or dangerous deserialization: unsafe upload handlers, exec/eval patterns, and outdated components known for RCE. Provide evidence and CVE references (do not exploit)." -u http://example.com
```

5. **IDOR & Auth bypass**

```
nuclei -ai "Test authentication and access control on http://example.com for missing authorization, IDORs, and privilege escalation. Provide affected endpoints, evidence, and recommended fixes." -u http://example.com
```

---

## Active prompts (Specific checks)

- **Open Redirects**
```
nuclei -ai "Check http://example.com for open-redirect vectors and unsafe URL redirect parameters. Provide the redirect parameter name and safe PoC URL evidence." -u http://example.com
```

- **SSRF (read-only indicators)**
```
nuclei -ai "Scan http://example.com for potential SSRF sinks (URL fetcher parameters, image fetchers). Provide non-abusive PoC and affected endpoints." -u http://example.com
```

- **File Upload Handling**
```
nuclei -ai "Discover file upload endpoints on http://example.com and check for unsafe handling: missing content-type checks, direct execution, or public access to uploads. Provide endpoints and safe evidence (no malicious uploads)." -u http://example.com
```

- **Directory Traversal (safe examples)**
```
nuclei -ai "Identify endpoints on http://example.com that may be vulnerable to directory traversal (read-only checks and non-destructive PoC examples)." -u http://example.com
```

- **Exposed VCS / Backup files**
```
nuclei -ai "Scan http://example.com for exposed .git, .svn, backup files, and common VCS artifacts. Report paths and filenames only." -u http://example.com
```

---

## Authenticated scan prompts
> For authenticated scans provide session cookies or `Authorization` header in a safe manner. Example: `-H 'Cookie: session=REDACTED'` (do not commit secrets to git).

- **Authenticated OWASP checks**
```
nuclei -ai "Perform authenticated OWASP Top-10 checks for http://example.com and include endpoints accessible only after login. Provide PoC and mitigation steps." -u http://example.com -H 'Cookie: SESSION=REDACTED'
```

- **Privilege escalation / role testing**
```
nuclei -ai "Within authenticated context on http://example.com, test for privilege escalation and improper role enforcement. Report endpoints and reproduction steps." -u http://example.com -H 'Authorization: Bearer REDACTED'
```

**Important:** Keep authentication tokens out of the repository. Use environment variables or runtime injection when running scans.

---

## Passive / Defensive prompts (Safe without auth)
- **DNS & subdomain enumeration**
```
nuclei -ai "Enumerate public DNS records and subdomains for example.com (A, AAAA, CNAME, TXT, MX, SOA). Highlight stale or suspicious records." -u http://example.com
```

- **Headers & TLS fingerprint**
```
nuclei -ai "Fingerprint HTTP headers and TLS configuration for http://example.com and list missing security headers and TLS weaknesses." -u http://example.com
```

- **Public code search heuristics**
```
nuclei -ai "Search public code repositories for mentions of example.com and flag potential leaked secrets or internal URLs. Provide file references and suggested remediation." -u http://example.com
```

- **Crawl-only discovery**
```
nuclei -ai "Crawl http://example.com for public URLs, sitemap, and robots.txt entries. List discovered pages only (no fuzzing)." -u http://example.com
```

---

## Recommended flags & examples
- Add `-severity critical,high` to limit templates to higher-severity findings. Example:
```
nuclei -ai "<PROMPT>" -u http://example.com -severity critical,high
```
- Use `-rate-limit` and `-c` to tune traffic: `-rate-limit 10 -c 50`.
- For machine-readable output add `-json -o output.json`.

---

## Combining prompts: sample script
Below is an example script snippet to run a selected set sequentially (edit as needed):

```bash
#!/bin/bash
TARGET=http://example.com
nuclei -ai "Perform an OWASP Top-10 focused scan against ${TARGET} and return only high or critical findings..." -u ${TARGET} -severity critical,high -json -o owasp_high.json
nuclei -ai "Fingerprint server, frameworks, and components on ${TARGET} and map to critical CVEs..." -u ${TARGET} -json -o cve_map.json
# add more commands as required
```

---

## Reporting & remediation tips
- Prioritize Critical -> High -> Medium -> Low. Focus on RCE, auth bypass, SQLi, and data-exposure first.
- Provide redacted evidence, reproduction steps, and suggested fixes.
- Use a verification plan: after fixes run targeted re-checks.

---

## Contribution & maintenance
- Keep prompts concise and avoid destructive phrasing.
- Do not store secrets in repo. Use `.env` or CI secrets for auth tokens.
- When updating prompts, test on a safe staging host first.

---

## License
MIT License — include attribution if you reuse these prompts.

---

*End of document.*

---

## Improved Template: Directory Listing & Sensitive Paths (Professional)

> Non-destructive, multi-path check for directory listing and exposed artifacts. Replace `http://example.com` with your target when running.

```
id: improved-directory-listing-check
info:
  name: Improved Directory Listing & Sensitive Paths Check
  author: ProjectDiscoveryAI
  severity: high
  description: |
    Non-destructive check that probes multiple common paths for directory listing and exposed artifacts. Extracts page title and sample snippets for triage.

requests:
  - method: GET
    path:
      - "{{BaseURL}}/"
      - "{{BaseURL}}/backup/"
      - "{{BaseURL}}/backups/"
      - "{{BaseURL}}/backup-old/"
      - "{{BaseURL}}/uploads/"
      - "{{BaseURL}}/upload/"
      - "{{BaseURL}}/files/"
      - "{{BaseURL}}/logs/"
      - "{{BaseURL}}/old/"
      - "{{BaseURL}}/admin/"

    matchers:
      - type: status
        status:
          - 200
      - type: word
        part: body
        words:
          - "Index of /"
          - "Parent Directory"
          - "Directory listing for"
      - type: regex
        part: body
        regex:
          - "<title>(.*?)<\/title>"

    extractors:
      - type: regex
        part: body
        regex:
          - "<title>(.*?)<\/title>"
      - type: regex
        part: body
        regex:
          - "(Index of \/[\w\-\/]*)"

  - method: GET
    path:
      - "{{BaseURL}}/.git/HEAD"
      - "{{BaseURL}}/.env"
      - "{{BaseURL}}/config.php"
      - "{{BaseURL}}/wp-config.php"

    matchers:
      - type: status
        status:
          - 200
      - type: word
        part: body
        words:
          - "ref:"
          - "DB_PASSWORD"
          - "DB_USER"

    extractors:
      - type: regex
        part: body
        regex:
          - "ref:\s*(.*)"

tags:
  - discovery
  - disclosure-safe
  - non-destructive

```

**Notes:**
- This template probes many common paths; it remains non-destructive (no uploads or destructive payloads).
- Keep sensitive extractors in the scan output redacted when sharing; do not commit raw findings to public repos.
- To run against a host, replace `{{BaseURL}}` with the target (e.g., `http://example.com`) or use `-u` / `-l` flags.

---

