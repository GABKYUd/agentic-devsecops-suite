---
name: bug-hunting-orchestrator
description: >-
  Master 5-phase vulnerability hunting orchestrator (Surface map -> Hunt -> 7-Q Gate -> Dual-Output -> Validate).
  Use when conducting a complete autonomous defensive security audit across a codebase, feature, or API.
---

# Master Bug Hunting Orchestrator

The Master Bug Hunting Orchestrator executes a closed-loop defensive audit across 5 sequential phases:
1. **Attack Surface Discovery** (Recon & AST Mapping)
2. **Autonomous Vulnerability Hunting** (Dataflow & Logic Tracing across 20+ classes)
3. **The Strict 7-Question Gate** (False-Positive Eradication)
4. **Dual-Sided Output Synthesis** (Developer PR Patch + Blue Team Detection Rule)
5. **Continuous Purple Team Validation** (Atomic Verification & CI/CD Telemetry)

---

## The 5-Phase Workflow

### Phase 1: Attack Surface Discovery
Activate the specialized skill [bug-hunting-recon-surface](../bug-hunting-recon-surface/SKILL.md) to discover:
- All route definitions (Express, Fastify, Next.js, Django, Flask, etc.).
- Authentication tiers (Tier 0: Public, Tier 1: User, Tier 2: Admin).
- Sensitive sinks: Database drivers (`db.query`), system execution (`child_process`), file writes (`fs`), outbound HTTP (`fetch`, `axios`).

### Phase 2: Vulnerability Hunting
Dispatch specialized inspection skills based on the identified components:
- **Injection & RCE:** [vuln-hunting-injection-rce](../vuln-hunting-injection-rce/SKILL.md) for SQLi, NoSQLi, Command Injection, SSTI, Deserialization, XXE.
- **Access Control & Auth:** [vuln-hunting-auth-access-control](../vuln-hunting-auth-access-control/SKILL.md) for IDOR/BOLA, JWT, OAuth, Mass Assignment (BOPLA).
- **Network, Boundaries & Logic:** [vuln-hunting-network-ssrf-logic](../vuln-hunting-network-ssrf-logic/SKILL.md) for SSRF, Path Traversal, CORS, TOCTOU Race Conditions, GraphQL.

### Phase 3: The 7-Question Gate Triage
Before any finding is reported or escalated, pass it through [bug-bounty-validator-gate](../bug-bounty-validator-gate/SKILL.md) or invoke the MCP tool `evaluate_7_question_gate`.
All 7 criteria must be satisfied:
1. **Direct Exploitability:** Concrete source-to-sink data path without framework neutralization.
2. **Access Prerequisites:** Explicit tier requirement identified.
3. **Demonstrable Business Impact:** Real Confidentiality, Integrity, or Availability loss.
4. **Novelty & Deduplication:** Independent root cause, not duplicate middleware symptom.
5. **Scope Verification:** Verified within first-party target boundary.
6. **Empirical Reproducibility:** Exact test sequence documented with differential verification.
7. **Severity Classification:** Aligned with business risk (CVSS/CWE).

### Phase 4: Dual-Sided Outputs
For every validated finding, produce two distinct outputs:
1. **Developer Remediation Package:**
   - Architectural root-cause fix (parameterization, authorization check at data layer).
   - Automated regression unit/integration test.
2. **Blue Team Detection Rule:**
   - Sigma rule for SIEM/EDR detection.
   - WAF virtual patch rule or log alert query.
   - Entry appended to `findings-manifest.json` for CI/CD tracking.

### Phase 5: Continuous Purple Team Validation (Mandatory Validation Policy)
- **Zero-Unverified-Findings Rule:** Every security test, vulnerability candidate, and bug hunting finding MUST be actively validated in practice.
- Execute non-destructive live probes (using WSL Kali Linux DAST tools such as curl, ffuf, nuclei, or automated reproduction scripts) to prove exploitability pre-fix and verify mitigation post-fix.
- Validate that the staging SIEM/WAF triggers telemetry against the generated Sigma rule.
- Verify pipeline enforcement via [devsecops-pipeline-automation.md](../../devsecops-pipeline-automation.md).

---

## 🔒 Mandatory Operational Policies

### 1. Mandatory Security Test & Finding Validation
- Every security finding or bug candidate **must be empirically validated** before reporting or remediation (for authorization flaws like IDOR, ensure differential verification across tenants).
- Never rely on static AST patterns alone. Confirm that framework defenses (e.g., ORM parameter binding, JSX auto-escaping, CSP, middleware locks) do not neutralize the issue.
- Run live validation probes from WSL Kali Linux or an isolated reproduction harness to verify both:
  1. The flaw triggers under controlled conditions.
  2. The defensive patch completely closes the vulnerability without regressions.

### 2. Strict GitHub Push Approval Gate
- **NO AUTONOMOUS REMOTE PUSHES:** `git push` (or pushing to any remote branch/origin) is **strictly prohibited without prior, explicit user approval**.
- All code fixes, test additions, and documentation updates may be staged and committed **locally**.
- Before pushing to GitHub, you MUST:
  1. Present the validated findings and remediation summary to the user.
  2. Show the local commit hash and diff summary.
  3. Explicitly ask for user approval before running `git push`.

### 3. Strict Skill Activation & Developer Approval Gate
- **NO SILENT SKILL DISPATCH:** The assistant MUST NOT autonomously activate or switch between specialized audit skills (e.g. `vuln-hunting-injection-rce`, `vuln-hunting-auth-access-control`) in the background without explicit developer consent.
- Before executing any skill, the assistant MUST:
  1. Call `explain_and_request_skill_approval` (or format the transparency brief).
  2. Clearly state to the developer: *what skill is being chosen*, *why it is relevant to this code*, *which files/endpoints will be inspected*, and *what actions/probes will occur*.
  3. Await explicit developer sign-off (`Proceed / Reject`) before taking action.

---

## References & Tools
- Reference Matrix: [purple-team-vuln-class-matrix.md](../../purple-team-vuln-class-matrix.md)
- Methodology: [purple-team-automation-methodology.md](../../purple-team-automation-methodology.md)
- MCP Tool: Use `lookup_vulnerability_class` and `evaluate_7_question_gate` via the MCP server.

