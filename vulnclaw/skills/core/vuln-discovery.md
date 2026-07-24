---
name: vuln-discovery
description: Vulnerability discovery workflow — scan for vulnerabilities based on reconnaissance results
---

# Vulnerability Discovery Skill

Systematically discover security vulnerabilities in the target based on information gathering results.

## Execution Steps

### 1. Known CVE Matching
- Search corresponding CVEs based on identified service versions
- Prioritize Critical/High severity
- Record CVE ID, affected versions, exploitation conditions

### 2. Web Vulnerability Scanning
- SQL Injection detection
- XSS detection (Reflected/Stored/DOM-based)
- SSRF detection
- LFI/RFI detection
- Command Injection detection
- File Upload vulnerability detection

### 3. Configuration Defect Detection
- Default credential testing
- Information disclosure detection
- Unauthorized access detection
- CORS misconfiguration detection
- HTTPS configuration detection

### 4. Output
- Vulnerability list (type, severity, URL, parameter, verification method)
