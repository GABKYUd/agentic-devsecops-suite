# DevSecOps Threat & Defense Knowledge Base — Index

This is the entry point across the full reference set. Read this first to
route to the right file rather than loading everything at once.

## Files in this set

| File | Type | Contains | Antigravity placement |
|---|---|---|---|
| `skills/bug-hunting-orchestrator/` | Agent Skill | Master 5-phase vulnerability hunting orchestrator (Surface map → Hunt → 7-Q Gate → Dual-Output → Validate) | `.agents/skills/bug-hunting-orchestrator/` |
| `skills/bug-hunting-recon-surface/` | Agent Skill | Attack surface discovery, AST route extraction, middleware hierarchy, and IP/header spoofing audits | `.agents/skills/bug-hunting-recon-surface/` |
| `skills/vuln-hunting-injection-rce/` | Agent Skill | Deep inspection heuristics for SQLi, NoSQLi, Command Injection, SSTI, Deserialization, XXE | `.agents/skills/vuln-hunting-injection-rce/` |
| `skills/vuln-hunting-auth-access-control/` | Agent Skill | Deep inspection heuristics for IDOR/BOLA, JWT flaws, OAuth 2.0, Mass Assignment (BOPLA), ATO | `.agents/skills/vuln-hunting-auth-access-control/` |
| `skills/vuln-hunting-network-ssrf-logic/` | Agent Skill | Deep inspection heuristics for SSRF, Path Traversal, CORS, TOCTOU Race Conditions, GraphQL, CI/CD injection | `.agents/skills/vuln-hunting-network-ssrf-logic/` |
| `skills/threat-intel-skills-distiller/` | Agent Skill | Ingests CVEs and disclosures to auto-generate Semgrep rules, regression tests, and Sigma signatures | `.agents/skills/threat-intel-skills-distiller/` |
| `skills/bug-bounty-validator-gate/` | Agent Skill | The 7-Question Gate triage filter; produces dual-sided triage reports **and writes a machine-readable `findings-manifest.json` entry** for the SAST→DAST pipeline bridge | `.agents/skills/bug-bounty-validator-gate/` |
| `skills/incident-response-playbooks/` | Agent Skill | Step-by-step 6-phase response checklists for 7 critical incident scenarios | `.agents/skills/incident-response-playbooks/` |
| `skills/devsecops-mcp-kb/` | Agent Skill | Interactive workflow and instructions for calling the DevSecOps Knowledge Base MCP server | `.agents/skills/devsecops-mcp-kb/` |
| `mcp/server.js` | MCP Server | Zero-dependency JSON-RPC 2.0 stdio MCP server exposing 7 security tools (matrix, gate, playbooks, rules) | `.agents/mcp/server.js` & `.agents/mcp_config.json` |
| `purple-team-vuln-class-matrix.md` | Companion reference | 20+ Web/API/Cloud/Pipeline vuln classes mapped to CWE, ATT&CK, SAST (Semgrep), DAST, 7-Question Gate, Sigma, D3FEND | `.agents/references/` or `docs/security/`, load on demand |
| `purple-team-automation-methodology.md` | Methodology & Framework | 5-phase purple team orchestration engine: Recon → Hunt → 7-Question Gate → Dual-Output → Continuous Validation | same as above |
| `devsecops-pipeline-automation.md` | Pipeline & CI/CD Guide | Reusable GitHub Actions workflow, automated 7-Question Gate SARIF triage script, DevSecOps pipeline controls | `.github/workflows/` and `.agents/` |
| `devsecops-threat-knowledge.md` | Rule | Metasploit Framework deep-dive + index of all tool categories | `.agents/rules/`, Model Decision activation |
| `devsecops-pentest-tools-reference.md` | Companion reference | 11 tool categories (recon, web, exploitation/C2, credential attacks, AD, wireless, MITM, cloud/container, mobile, social engineering), each mapped tool → technique → defense | `.agents/references/` or `docs/security/`, load on demand / `@mention` |
| `devsecops-defense-playbooks.md` | Companion reference | Published frameworks to adopt (NIST 800-61r3, CISA playbooks, CIS Controls v8.1, StopRansomware, AWS/Microsoft cloud IR, K8s hardening, OWASP, AD tier model) + detection engineering trio (ATT&CK/D3FEND, Sigma, Atomic Red Team) | same as above |
| `detection-rules-starter-reference.md` | Companion reference | Illustrative Sigma-style starter rules for host, AD, web application, cloud metadata, and CI/CD techniques | same as above |
| `playbook-phishing-response.md` | Workflow | Phishing/suspicious email IR steps | `.agents/workflows/`, invoke via `/playbook-phishing-response` |
| `playbook-ransomware-response.md` | Workflow | Ransomware/mass encryption IR steps | same |
| `playbook-ad-compromise-response.md` | Workflow | Active Directory / credential theft IR steps | same |
| `playbook-c2-beacon-response.md` | Workflow | C2 beacon detected IR steps | same |
| `playbook-cloud-credential-compromise.md` | Workflow | Cloud account/API credential compromise IR steps | same |
| `playbook-web-app-exploitation.md` | Workflow | SQLi/RCE/webshell IR steps | same |
| `playbook-container-kubernetes-compromise.md` | Workflow | Container/K8s compromise IR steps | same |

## How the pieces relate

```
Tool/Technique Knowledge          Purple Team & Defensive Frameworks       DevSecOps & Operational Response
─────────────────────────         ───────────────────────────────────       ────────────────────────────────
devsecops-threat-knowledge.md  →  purple-team-vuln-class-matrix.md      →  devsecops-pipeline-automation.md
devsecops-pentest-tools-       →  purple-team-automation-methodology.md →  playbook-*.md
  reference.md                 →  detection-rules-starter-reference.md  →  (invoked live in CI/CD or IR)
```

- The **vuln class matrix** details code patterns, SAST/DAST verification probes, and detection signatures for 20+ major application/cloud risks.
- The **purple team methodology** guides automated vulnerability hunting and false-positive eradication via the 7-Question Gate.
- The **pipeline automation doc** provides copy-paste CI/CD workflows and triage scripts to enforce these security gates in code pushes.
- The **detection rules reference** gives ready-to-tune Sigma rules for SIEM/EDR detection engineering.
- The **playbook workflows** are operational response checklists executed when active intrusions or alerts occur.

## Playbook coverage so far

Covered: phishing, ransomware, AD/credential compromise, C2 beacon, cloud
credential compromise, web app exploitation, container/Kubernetes compromise,
20+ purple team application/pipeline vulnerability classes.

Not yet covered (reasonable next additions if useful): insider threat/data
exfiltration, DDoS, wireless/rogue AP, mobile app compromise.

## Pipeline Data Contract — Finding Manifest

The `findings-manifest.json` file is the **contract between SAST (Stage 3) and DAST (Stage 5)**.

- **Written by:** `bug-bounty-validator-gate` after every 7-Question Gate run.
- **Consumed by:** Stage 5 (targeted DAST probing at the exact endpoint/payload listed) and Stage 6 (SIEM query against the `sigma_rule_id`).
- **Probe fields** (`probe_payload`, `setup`, `expected_vulnerable_signal`, `expected_safe_signal`, `teardown`) are sourced directly from the matching `Benign Staging Validation Probe` section in the relevant `vuln-hunting-*` skill — not invented ad hoc per run.

Each entry carries **two independent result axes** — do not collapse into one pass/fail:

| Field | Owner | Values | Build effect |
|---|---|---|---|
| `code_status` | Dev / App-Sec | `FIXED \| BLOCKING \| DISMISSED` | `BLOCKING` fails the build |
| `detection_status` | SOC / Detection-Eng | `DETECTED \| MISSED \| SKIPPED` | `MISSED` opens a `detection-gap:<sigma_rule_id>` ticket (non-blocking by default; configurable) |

A finding can be `code_status: FIXED` and `detection_status: MISSED` simultaneously — that surfaces a **detection gap**, not a code gap, owned by a different team.

## Usage guidance for this assistant

- Start here, load only the specific companion file(s) relevant to the
  current task rather than the whole set.
- When asked about a specific tool, technique, or incident type, check
  whether a playbook or reference file already covers it before generating
  new guidance from scratch.
- Keep new additions consistent with the existing structure (tool tables in
  the reference docs, Detect→Analyze→Contain→Eradicate→Recover→Post-incident
  in the playbooks) so the whole set stays navigable as it grows.

