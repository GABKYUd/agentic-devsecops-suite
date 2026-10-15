---
name: bug-bounty-validator-gate
description: >-
  The 7-Question Gate triage filter; produces dual-sided triage reports and writes a machine-readable findings-manifest.json entry for the SAST->DAST pipeline bridge.
  Use when validating potential vulnerability findings to eliminate hallucinations, noise, and false positives.
---

# Bug Bounty & Vulnerability Validator: The 7-Question Gate

The 7-Question Gate is the central quality and veracity filter in the purple team workflow. Every vulnerability finding MUST pass all seven criteria before generating alerts, opening tickets, or failing pipeline builds.

---

## 1. The 7-Question Checklist

Evaluate each candidate finding against the following template:

```markdown
### 7-Question Gate Evaluation Template

1. [ ] DIRECT EXPLOITABILITY:
   Can user-controlled input realistically reach the vulnerable sink and alter program execution, or does a framework/sanitization layer neutralize it?
   - Evidence: [Trace code path from Source -> Sink]

2. [ ] ACCESS PREREQUISITES:
   What privilege tier is required? (Unauthenticated / Standard User / Admin / Physical Host Access)?
   - Required Context: [Tier Level]

3. [ ] DEMONSTRABLE BUSINESS IMPACT:
   Does this cause real confidentiality breach (data leak), integrity loss (data modification/privilege escalation), or availability loss (DoS)?
   - Impact Assessment: [Confidentiality / Integrity / Availability]

4. [ ] NOVELTY & DEDUPLICATION:
   Is this an independent root cause, or a duplicate manifestation of an already identified shared middleware flaw?
   - Finding Hash: [Unique identification]

5. [ ] SCOPE VERIFICATION:
   Is the affected asset and repository strictly within our first-party authorized scope?
   - Target Asset: [First-Party In-Scope Repository / Endpoint]

6. [ ] EMPIRICAL REPRODUCIBILITY:
   Is there an empirically validated HTTP request, unit test, or probe sequence that reliably reproduces the condition without non-deterministic flakiness? (For authorization flaws like IDOR, differential testing is required: verify that unauthorized tenants access private records rather than public data).
   - Reproduction Steps: [Exact Payload / Request]

7. [ ] SEVERITY CLASSIFICATION:
   Is the severity rating calibrated honestly according to realistic threat modeling rather than theoretical worst-case inflation?
   - Calibrated Severity: [Critical / High / Medium / Low]
```

---

## 2. Decision Tree & Gate Verdicts

- **PASSED_GATE:** If all 7 criteria are verified with concrete evidence:
  1. Produce the **Dual-Sided Output** (Developer Remediation + Blue Team Detection Rule).
  2. Append an entry to `findings-manifest.json` with `code_status: BLOCKING`.
- **REJECTED_OR_DOWNGRADED:** If any of the following occur:
  - Input cannot reach the sink due to framework defaults (e.g., React JSX auto-escaping, ORM query parameter binding) -> **DISMISSED (False Positive)**.
  - Requires physical access or root server access to exploit -> **DOWNGRADED (Informational)**.
  - Duplicate manifestation of shared router middleware -> **DEDUPLICATED**.

---

## 3. WSL Kali Linux Live Validation Probes (Eliminating False Positives)

Do not trust static AST code patterns alone. Framework protections (e.g. React JSX auto-escaping, ORMs with parameterization, CSP headers, or Cloudflare worker JWT defaults) often neutralize theoretical findings in practice.

Whenever validating findings against local or staging environments, run non-destructive verification probes via **WSL Kali Linux**:

### Standard WSL Probe Patterns:
- **SQLi Staging Probe:**
  `wsl -d kali-linux -e curl -s -o /dev/null -w "%{http_code}" "http://localhost:3000/api/items?id=1%27%20OR%201=1--"`
  - *Vulnerable:* HTTP 200 with all records OR HTTP 500 with SQL trace.
  - *Safe (False Positive):* HTTP 400 or parameterized clean response.
- **NoSQLi Staging Probe:**
  `wsl -d kali-linux -e curl -s -X POST -H "Content-Type: application/json" -d '{"username":{"$ne":null}}' "http://localhost:3000/api/auth/login"`
- **IDOR Staging Probe:**
  `wsl -d kali-linux -e curl -i -s -H "Authorization: Bearer <USER_B_TOKEN>" "http://localhost:3000/api/documents/<USER_A_ID>"`
  - *Vulnerable:* HTTP 200 with User A's data.
  - *Safe (False Positive):* HTTP 403 Forbidden or HTTP 404 Not Found.
- **CORS Misconfiguration:**
  `wsl -d kali-linux -e curl -s -I -H "Origin: https://evil.attacker.com" "http://localhost:3000/api/user"`
- **Nuclei Staging Template Validation:**
  `wsl -d kali-linux -e nuclei -u "http://localhost:3000" -tags cve,misconfig -severity critical,high`

You can also generate tailored commands automatically by calling the MCP tool `get_wsl_validation_probe` (which enforces gate compliance via `approval_token` and validates target boundaries):
```json
{
  "name": "get_wsl_validation_probe",
  "arguments": {
    "approval_token": "<TOKEN_FROM_evaluate_7_question_gate>",
    "vuln_class": "idor",
    "target_url": "http://localhost:3000/api/documents/1"
  }
}
```

---

## 4. Pipeline Data Contract: `findings-manifest.json`

When a finding passes the gate, record it in `findings-manifest.json` to bridge SAST (Stage 3) and DAST (Stage 5):

```json
{
  "finding_id": "FINDING-2026-001",
  "target_endpoint": "/api/documents/:id",
  "vuln_class": "idor",
  "cwe": "CWE-639",
  "code_status": "BLOCKING",
  "detection_status": "UNTESTED",
  "sigma_rule_id": "sigma-idor-document-access"
}
```

Two independent result axes:
- `code_status`: `FIXED | BLOCKING | DISMISSED` (Owned by Dev / AppSec; `BLOCKING` fails build).
- `detection_status`: `DETECTED | MISSED | SKIPPED` (Owned by SOC / Detection Engineering; `MISSED` opens a detection gap ticket).

---

## 5. MCP Server Automation

To evaluate findings programmatically, call the MCP tool:
```json
{
  "name": "evaluate_7_question_gate",
  "arguments": {
    "finding_id": "SEC-01",
    "vuln_class": "sqli",
    "source_to_sink_evidence": "Raw string concatenation in db.query without parameter array",
    "access_prerequisites": "unauthenticated",
    "business_impact": "Full database records exfiltration",
    "is_unique": true,
    "is_in_scope": true,
    "empirical_repro_steps": "GET /api/items?id=1%27%20OR%201=1--",
    "target_endpoint": "/api/items"
  }
}
```

---

## 6. Mandatory Validation & GitHub Push Approval Policy

### Mandatory Validation Enforcement
- **No Theoretical Unverified Findings:** No vulnerability finding may be reported, escalated, or marked as remediated without empirical, reproducible live validation.
- All candidate findings must be validated against a live instance or isolated test environment using:
  1. Non-destructive live probes (WSL2 Kali Linux curl, python probes, ffuf, nuclei).
  2. Concrete automated test scripts verifying the exact state transition and flaw.
- A remediation is only considered complete once the exact same validation probe confirms the flaw is neutralized and returns expected safe status codes (e.g., HTTP 400, 403, 409, or 429).

### GitHub Push Approval Gate
- **`git push` Strictly Requires Prior Approval:**
  - Code patches, tests, and documentation updates may be committed locally to git.
  - The assistant MUST NEVER push to GitHub or any remote repository automatically or autonomously.
  - The assistant must always present the local commit details and explicitly ask for user approval before executing any `git push` command.

