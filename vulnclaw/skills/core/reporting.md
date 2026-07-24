---
name: reporting
description: Report generation workflow — generate structured penetration test reports and PoCs
routing:
  phases: [reporting]
  task_types: [report]
---

# Report Generation Skill

Compile penetration test results into structured reports with detailed findings, PoC scripts, and remediation recommendations.

## Report Structure

### 1. Project Overview
- Test target
- Test time
- Test scope
- Test methodology

### 2. Executive Summary
- High-risk findings overview
- Risk level distribution
- Key recommendations

### 3. Detailed Findings
For each vulnerability:
- Vulnerability name and severity
- Vulnerability type
- Impact scope
- Verification steps
- Key evidence (request/response/screenshots)
- PoC script
- Remediation recommendations

### 4. Attack Paths
- Complete attack chain diagram
- Path from initial access to final objective

### 5. Appendices
- PoC scripts
- Traffic captures
- Screenshot evidence
