---
name: devsecops-mcp-kb
description: >-
  Interactive skill and reference for using the DevSecOps Knowledge Base MCP server tools.
  Use when querying vulnerability matrices, running 7-Question Gate evaluations, fetching incident playbooks, or querying Sigma rules via MCP.
---

# DevSecOps Knowledge Base MCP Server

The DevSecOps Knowledge Base MCP Server exposes the security knowledge base, 21 vulnerability classes, 7-Question Gate evaluation engine, and incident response playbooks as callable Model Context Protocol (MCP) tools.

---

## 1. Server Configuration & Status

- **Server Location:** `.agents/mcp/server.js`
- **Config File:** `.agents/mcp_config.json`
- **Runtime:** Node.js (zero external dependencies)
- **Transport:** Standard JSON-RPC 2.0 over `stdio`

---

## 2. Available MCP Tools

### `lookup_vulnerability_class`
Retrieves full specifications for any of the 21 vulnerability classes:
- **Parameters:** `vuln_name` (e.g. `sqli`, `nosqli`, `command_injection`, `ssti`, `deserialization`, `idor`, `broken_auth`, `oauth`, `jwt`, `mass_assignment`, `ssrf`, `path_traversal`, `open_redirect`, `cors`, `xss`, `csrf`, `race_condition`, `graphql`, `hardcoded_secrets`, `cicd_injection`, `xxe`)
- **Returns:** CWE, MITRE ATT&CK, mechanics, Semgrep SAST rule, benign staging DAST probe, 7-Q checklist, Sigma detection rule, and remediation.

### `list_vulnerability_classes`
Lists all 21 classes with their category and IDs.
- **Parameters:** `category` (optional filter).

### `evaluate_7_question_gate`
Runs the automated 7-Question triage filter on any candidate vulnerability finding.
- **Parameters:**
  - `finding_id`: Unique identifier (e.g. `"FINDING-001"`)
  - `vuln_class`: Identifier (`"sqli"`, `"idor"`, `"ssrf"`, etc.)
  - `source_to_sink_evidence`: String showing dataflow trace
  - `access_prerequisites`: `"unauthenticated"`, `"standard_user"`, `"admin"`, `"internal_network"`, or `"physical"`
  - `business_impact`: Impact statement
  - `is_unique`: Boolean
  - `is_in_scope`: Boolean
  - `empirical_repro_steps`: Concrete reproduction string demonstrating differential behavior (or `deterministic_repro_steps` alias)
  - `target_endpoint`: Affected route/file
- **Returns:** Gate verdict (`PASSED_GATE` / `REJECTED_OR_DOWNGRADED`), cryptographic `approval_token` (required for probe generation), 7 criteria evaluations, differential testing guidance, Developer PR patch requirements, Blue Team Sigma rule requirements, and formatted `findings-manifest.json` pipeline contract entry.

### `get_incident_playbook`
Retrieves step-by-step 6-phase response checklists for critical incident types.
- **Parameters:** `incident_type` (`phishing`, `ransomware`, `ad_compromise`, `c2_beacon`, `cloud_credential`, `web_app_exploitation`, `container_k8s`).

### `list_incident_playbooks`
Lists all 7 playbooks and their trigger conditions.

### `get_detection_rule`
Retrieves illustrative Sigma detection rules for high-frequency attack techniques.
- **Parameters:** `technique` (e.g. `"lsass"`, `"kerberoasting"`, `"sqli"`, `"ssrf"`, `"cicd"`).

### `search_security_kb`
Performs full-text search across all markdown reference documents in `.agents/`.
- **Parameters:** `query` (search term), `max_results` (optional, default 5).

### `get_pipeline_automation`
Retrieves CI/CD automation templates:
- **Parameters:** `asset` (`"github_actions_workflow"`, `"sarif_triage_script"`, `"manifest_contract"`).

### `get_wsl_validation_probe`
Generates non-destructive Kali Linux DAST probe commands (runnable via WSL2, Docker containers, or dedicated VMs using `curl`, `ffuf`, `nuclei`, etc.) to validate code findings against local/staging environments and eliminate false positives.
- **Enforcement & Guard:** Requires a valid `approval_token` issued by `evaluate_7_question_gate` and strictly enforces target perimeter boundaries (localhost, private subnets, *.local/*.internal, or `DEVSECOPS_ALLOWED_HOSTS`).
- **Parameters:**
  - `approval_token`: Mandatory cryptographic token issued by `evaluate_7_question_gate`.
  - `vuln_class`: `"sqli"`, `"nosqli"`, `"idor"`, `"ssrf"`, `"path_traversal"`, `"cors"`, `"command_injection"`, `"jwt"`, etc.
  - `target_url`: e.g. `"http://localhost:3000/api/orders/1"` (strictly guarded)
  - `method`: HTTP method (`GET`, `POST`, etc.)
  - `param_name`: Parameter name (optional)
  - `auth_header`: Authorization header (optional)
- **Returns:** Synthesized commands for `wsl_command`, `docker_command`, `vm_ssh_command`, expected vulnerable signal, and expected safe/neutralized signal.

### `list_available_skills`
Lists all available audit and purple-team skills in `.agents/skills/` with descriptions and paths.
- **Parameters:** None.

### `explain_and_request_skill_approval`
Enforces the **Human-in-the-Loop Skill Gate**. Synthesizes a structured transparency brief explaining the skill's purpose, target files, and planned actions, and generates an approval prompt that must be confirmed by the developer before execution.
- **Parameters:**
  - `skill_name`: e.g. `"vuln-hunting-injection-rce"`, `"bug-hunting-recon-surface"`, `"vuln-hunting-auth-access-control"`.
  - `target_scope`: Target files or routes to be inspected.
  - `reasoning`: Clear developer justification for why this skill is needed.
  - `planned_actions`: Summary of AST checks or benign probes.
- **Returns:** Structured proposal, safety contract assertions, and developer prompt string.

---

## 3. Example MCP Tool Calls

### Checking an IDOR vulnerability:
```json
{
  "name": "lookup_vulnerability_class",
  "arguments": {
    "vuln_name": "idor"
  }
}
```

### Running the 7-Question Gate on a finding:
```json
{
  "name": "evaluate_7_question_gate",
  "arguments": {
    "finding_id": "SEC-IDOR-01",
    "vuln_class": "idor",
    "source_to_sink_evidence": "Order.findByPk(req.params.id) does not filter by req.user.id in /api/orders/:id",
    "access_prerequisites": "standard_user",
    "business_impact": "Standard user can view another user's order containing personal data and financial totals",
    "is_unique": true,
    "is_in_scope": true,
    "empirical_repro_steps": "GET /api/orders/456 with User 123 bearer token returns HTTP 200 with order data",
    "target_endpoint": "/api/orders/:id"
  }
}
```
