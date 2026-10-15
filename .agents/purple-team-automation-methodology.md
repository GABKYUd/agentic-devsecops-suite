# Purple Team Automation Methodology

## Purpose & Overview
This document defines the **Purple Team Automation Methodology**, adapting the autonomous hunting architecture of [`shuvonsec/claude-bug-bounty`](https://github.com/shuvonsec/claude-bug-bounty) (`bb-methodology`, specialized hunt routines, and the 7-Question Gate) into an operational **Defensive & Purple Team Framework**.

Instead of stopping at finding and reporting a vulnerability, our purple team methodology executes a complete closed-loop cycle:
1. **Discover & Map Attack Surface** (Recon & AST Mapping)
2. **Hunt Vulnerabilities across 20+ Classes** (Deep SAST & Staging DAST)
3. **Execute the Strict 7-Question Gate** (False-Positive Eradication)
4. **Synthesize Dual-Sided Outputs** (Developer Remediation Patch + Blue Team Detection Rule)
5. **Close the Loop via Purple Team Validation** (Atomic Red Team & Pipeline Automation)

```
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                        Purple Team Autonomous Closed-Loop Workflow                     │
├────────────────────────────────────────────────────────────────────────────────────────┤
│                                                                                        │
│   Phase 1: Surface Mapping ──► Phase 2: Vuln Hunting ──► Phase 3: 7-Question Gate      │
│   (AST, Routes, Sinks)         (20+ Vuln Classes)        (False-Positive Triage)       │
│                                                                  │                     │
│                                                                  ▼                     │
│   Phase 5: Continuous Loop ◄── Phase 4: Dual Outputs ◄───────────┘                     │
│   (Atomic Red Team Validation) ├─► Developer: PR Patch + Unit Test                     │
│                                └─► Blue Team: Sigma Rule + WAF Rule                    │
│                                                                                        │
└────────────────────────────────────────────────────────────────────────────────────────┘
```

---

## Phase 1: Reconnaissance & Attack Surface Mapping

Before analyzing vulnerabilities, the agent builds a complete structural model of the application's attack surface:

### 1.1 Source-Level Route & Entry Point Mining
- Scan Express/Fastify/Next.js/Django/Flask routing definitions.
- Identify all HTTP methods (`GET`, `POST`, `PUT`, `DELETE`, `PATCH`), path parameters (`:id`, `[param]`), query parameters, and header dependencies.
- Map WebSocket connections, GraphQL endpoints (`/graphql`), and message queue listeners (RabbitMQ, Kafka, SQS).

### 1.2 Authentication & Authorization Boundary Discovery
- Identify authentication middleware (`passport.authenticate`, `jwtVerify`, session checkers).
- Classify routes into permission tiers:
  - **Tier 0 (Public/Unauthenticated):** `/login`, `/register`, `/forgot-password`, `/health`.
  - **Tier 1 (Authenticated Standard User):** `/api/user/*`, `/api/orders/*`.
  - **Tier 2 (Administrative / Privileged):** `/api/admin/*`, `/api/internal/*`, `/api/metrics`.
- Flag any route lacking explicit middleware assignment.

### 1.3 Sink Discovery
- Trace all database drivers (`sequelize`, `prisma`, `knex`, raw queries).
- Trace all external command executions (`child_process`, `os.system`).
- Trace all file system writes/reads (`fs.readFile`, `open()`, `path.join`).
- Trace all outbound HTTP request clients (`axios`, `fetch`, `requests`, `got`).

---

## Phase 2: Autonomous Vulnerability Hunting

The agent executes focused, modular inspections against the mapped attack surface, referencing the 20+ vulnerability classes detailed in [`purple-team-vuln-class-matrix.md`](purple-team-vuln-class-matrix.md):

### 2.1 Code-Level Dataflow Tracing (SAST)
- For every identified source (HTTP query, param, body, header):
  - Follow variable assignments and transformations across function calls.
  - Inspect whether data crosses trust boundaries without sanitization, validation, or type casting before reaching a sink.

### 2.2 Business Logic & Authorization Integrity Checks
- **IDOR / Object-Level Authorization:** Verify that every database lookup with user-provided IDs filters explicitly on the authenticated session's tenant/user ID.
- **Mass Assignment:** Verify that models do not bind raw request bodies (`req.body`) without DTO/Zod schema whitelisting.
- **Concurrency / TOCTOU:** Verify that check-and-update workflows on balances, quantities, or quotas utilize atomic operations or row locks.

### 2.3 Staging DAST Validation (Non-Destructive)
- In authorized local or staging environments, run safe, non-destructive validation probes (e.g., header reflection checks, canary inputs, dual-account IDOR tests) to verify live behavior.

---

## Phase 3: The Strict 7-Question Validation Gate

To eliminate hallucinations, alert fatigue, and false positives, every finding must pass the **7-Question Gate** before generating alerts or remediation items. If a finding fails any criterion, it is downgraded or dismissed.

```markdown
### 7-Question Gate Evaluation Template

1. [ ] DIRECT EXPLOITABILITY:
   Can an input realistically reach the vulnerable sink and alter program execution, or does a framework/sanitization layer neutralize it?
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

6. [ ] EMPIRICAL REPRODUCIBILITY PATH:
   Is there an exact, empirically validated step-by-step reproduction sequence? (For authorization checks like IDOR, ensure differential responses between tenants; an HTTP 200 alone does not prove flaw if data is public).
   - Repro Payload: [Benign verification probe]

7. [ ] SEVERITY CALIBRATION (CVSS v3.1 / v4.0):
   Is the severity rating calibrated against actual environmental reachability rather than worst-case theoretical assumptions?
   - Calibrated Score: [Low / Medium / High / Critical]
```

---

## Phase 4: Dual-Output Engineering Engine

Unlike traditional vulnerability reports that only list bugs, our Purple Team framework produces **two simultaneous outputs** for every validated finding:

### Output A: The Developer Remediation Package
1. **Target File & Exact Diff:** The minimal, clean code modification resolving the vulnerability at the root cause.
2. **Automated Unit / Regression Test:** A Jest/Mocha/PyTest test case proving that the vulnerability cannot be reintroduced in future commits.
3. **Architectural Guardrail:** Recommendations for type safety (Zod/TypeScript), ORM parameterization, or middleware enforcement.

### Output B: The Blue Team Detection & Telemetry Package
1. **Sigma Detection Rule:** A portable YAML rule to detect exploitation attempts in web server access logs, WAF telemetry, or host process events.
2. **WAF / Virtual Patch Rule:** ModSecurity / AWS WAF rule definition to block the attack vector at the edge while code fixes are deployed.
3. **MITRE ATT&CK & D3FEND Mapping:** Documented mapping for detection matrix tracking and blue team posture metrics.

---

## Phase 5: Continuous Purple Team Feedback Loop

```
┌─────────────────────────────────────────────────────────────────────────┐
│                    Continuous Purple Team Validation                    │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│   1. Deploy Code Fix & Detection Rule                                  │
│         │                                                               │
│         ▼                                                               │
│   2. Execute Atomic Red Team / Benign Test in Staging                   │
│         │                                                               │
│         ▼                                                               │
│   3. Verify Blue Team Telemetry:                                        │
│      ├── Did the WAF / Middleware block the attempt?                    │
│      ├── Did the SIEM / Log Pipeline ingest the event?                  │
│      └── Did the Sigma detection rule trigger an alert?                 │
│         │                                                               │
│         ▼                                                               │
│   4. Record Purple Team Scorecard & Update CI/CD Regression Gate        │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

### 5.1 Verification Checklist
- Run the benign simulation test against the updated staging endpoint.
- Query the SIEM/log collector to confirm the alert fired with the expected severity and metadata.
- If the alert failed to fire: tune the detection rule threshold or log source field mapping until 100% detection fidelity is reached.
