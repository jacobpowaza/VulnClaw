---
name: recon
description: Reconnaissance workflow — passive + active intelligence gathering
routing:
  phases: [recon]
  task_types: [recon]
---

# Reconnaissance Skill

Execute passive and active intelligence gathering to build target profile and attack surface map.

## Execution Steps

### 1. Passive Reconnaissance
- Use fetch tool to access target, collect HTTP response headers
- Identify server type, version, WAF
- Analyze HTML source for technology stack indicators

### 2. Active Reconnaissance
- Probe common web ports
- Enumerate directories and paths
- Check sensitive files (robots.txt, .env, .git)
- Discover API endpoints

### 3. Technology Stack Identification
- Frontend frameworks (React/Vue/Angular/jQuery)
- Backend frameworks (Express/Django/Flask/Spring)
- CMS systems (WordPress/Joomla/custom)
- Database types

### 4. Output
- Target profile (IP/domain/ports/services/tech stack)
- Attack surface map (accessible paths, APIs, admin portals)
