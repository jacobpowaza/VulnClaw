---
name: web-security-advanced
description: Advanced Web Security Testing — injection attack families, protocol security, authentication & logic vulnerabilities, file & deployment security, modern web attack surface, with complete playbooks
routing:
  target_types: [web, api]
  phases: [vuln_discovery, exploitation]
  task_types: [pentest, audit]
  vulnerability_classes:
    - sqli
    - xss
    - ssrf
    - ssti
    - xxe
    - rce
    - deserialization
    - idor
    - csrf
    - cors
    - file_upload
    - path_traversal
    - auth_bypass
    - jwt
    - oauth
    - graphql
    - websocket
    - request_smuggling
    - prototype_pollution
    - business_logic
  exclude_signals: ["unreplayable", "signature_blocked", "replay_blocked"]
---

# Advanced Web Security Testing Skill

Use this Skill when target is a web application, API, gateway, or browser-facing service requiring systematic vulnerability testing.

**Prerequisites**: If request is still client-controlled and replay is unstable, use `client-reverse` Skill first.

## CTF Scenario Routing

> When target is a CTF challenge (known flag, need to bypass specific filters), prefer `ctf-web` Skill for specific bypass values and payloads:

| CTF Scenario | Route to ctf-web | Reference |
|-------------|------------------|-----------|
| PHP weak comparison/type bypass | `ctf-web` | `references/php-bypass-cheatsheet.md` |
| Command injection space bypass | `ctf-web` | `references/command-injection-bypass.md` |
| eval echo/blind | `ctf-web` | `references/eval-and-rce-techniques.md` |
| PHP code audit | `ctf-web` | `references/php-code-audit-checklist.md` |
| SSTI injection chains | `ctf-web` | `references/ssti-injection-chains.md` |
| Deserialization exploit chains | `ctf-web` | `references/deserialization-playbook.md` |
| File upload → RCE | This Skill | `references/web-playbook-08-file-vulnerabilities.md` |

**This Skill focuses on penetration testing methodology**; CTF practical bypass values and payload templates refer to `ctf-web`.

## Scenario Routing

| Attack Surface Type | Primary Reference |
|---------------------|-------------------|
| Parameter injection (SQLi/XSS/CMD/SSTI/XXE) | `references/web-injection.md` |
| Protocol security (CORS/GraphQL/WebSocket/OAuth/Request Smuggling) | `references/web-modern-protocols.md` |
| Authentication & logic (IDOR/privilege escalation/payment/password reset/auth bypass) | `references/web-logic-auth.md` |
| File & infrastructure (upload/traversal/include/deployment/cache/CDN/cloud) | `references/web-file-infra.md` |
| Deployment security | `references/web-deployment-security.md` |

## Testing Workflow

### 1. Input Validation Testing
- SQL Injection: Boolean/Time-based/Error/Union/Stacked
- XSS: Reflected/Stored/DOM/CSP bypass
- Command Injection: Separator bypass, encoding bypass
- SSTI: Template engine identification + RCE chains
- XXE: Entity injection, OOB data exfiltration
- Deserialization: Java/PHP/Python chains

### 2. Authentication & Session Testing
- Default credentials, brute force
- Session management flaws (fixation/hijacking/insecure cookies)
- JWT security (algorithm confusion/key cracking/none algorithm)
- OAuth/OIDC misconfigurations
- MFA bypass

### 3. Logic Vulnerability Testing
- Privilege escalation (horizontal/vertical)
- Business logic bypass (payment/coupon/voting)
- Race conditions
- IDOR (Insecure Direct Object References)

### 4. Protocol Security Testing
- CORS misconfiguration
- GraphQL introspection/injection
- WebSocket authentication & injection
- HTTP Request Smuggling
- SSRF (internal reconnaissance/cloud metadata)

### 5. File & Deployment Security
- File upload bypass
- Path traversal
- LFI/RFI
- CDN/Cache poisoning
- Supply chain attacks
- Cloud security misconfiguration

## Reference Documents

- `references/web-injection.md` — Injection attack detailed reference
- `references/web-modern-protocols.md` — Modern protocol security
- `references/web-logic-auth.md` — Authentication & logic vulnerabilities
- `references/web-file-infra.md` — File & infrastructure security
- `references/web-deployment-security.md` — Deployment security
- `references/web-ai-attack-map.md` — Web & AI attack mapping
- `references/web-playbook-*.md` — Specialized playbooks (23 total)
