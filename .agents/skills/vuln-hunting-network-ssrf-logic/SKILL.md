---
name: vuln-hunting-network-ssrf-logic
description: >-
  Deep inspection heuristics for SSRF, Path Traversal, CORS, TOCTOU Race Conditions, GraphQL, and CI/CD injection.
  Use when analyzing outbound network calls, file path operations, state concurrency, and workflow pipelines.
---

# Vulnerability Hunting: Network, Boundaries & Application Logic

This skill guides deep inspection of network boundaries, filesystem access, concurrency conditions, and pipeline logic.

---

## 1. Targeted Vulnerability Classes

| ID | Class Name | CWE | MITRE ATT&CK | Primary Risk |
|---|---|---|---|---|
| `ssrf` | Server-Side Request Forgery | CWE-918 | T1071 | Outbound requests fetching internal/cloud metadata IPs |
| `path_traversal` | Path Traversal / Local File Inclusion | CWE-22 | T1083 | Reading/writing arbitrary files via `../` sequences |
| `cors` | CORS Misconfiguration | CWE-942 | T1189 | `Access-Control-Allow-Origin: *` with credentials enabled |
| `race_condition` | Race Conditions & Concurrency (TOCTOU) | CWE-362 | T1068 | Time-of-check to time-of-use gaps on balances or quotas |
| `graphql` | GraphQL Introspection & Batching Abuse | CWE-770 | T1499 | Unbounded query depth, introspection exposed in production |
| `cicd_injection` | CI/CD Pipeline Runner Injection | CWE-78 | T1195 | Untrusted PR branch names or commit messages in workflow `run:` steps |

---

## 2. Inspection Heuristics & Search Patterns

### 2.1 Server-Side Request Forgery (SSRF)
- Look for endpoints taking URLs or webhooks:
  - `axios.get(req.query.url)`
  - `fetch(req.body.webhookUrl)`
- Common Vulnerability: Relying on weak blacklist filters (e.g. checking for `localhost` or `127.0.0.1` but failing against DNS rebinding, `0.0.0.0`, `[::1]`, or cloud metadata `169.254.169.254`).
- **Remediation:** Strict destination allowlisting + DNS resolution validation before making the request (rejecting private IP ranges: `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `169.254.169.254`).

### 2.2 Path Traversal / Arbitrary File Read
- Look for file system paths constructed from user parameters:
  - `fs.readFileSync(path.join('/uploads', req.query.filename))`
- **Remediation:** Validate that the resolved canonical path begins with the allowed base directory:
  ```javascript
  const safePath = path.resolve(BASE_DIR, userFilename);
  if (!safePath.startsWith(BASE_DIR)) {
    throw new Error('Access denied: Path Traversal detected');
  }
  ```

### 2.3 Race Conditions (TOCTOU)
- Look for multi-step non-atomic operations:
  ```javascript
  // VULNERABLE: Gap between balance check and deduction
  const user = await User.findById(id);
  if (user.balance >= amount) {
    await sleep(50); // Or IO operation
    user.balance -= amount;
    await user.save();
  }
  ```
- **Remediation:** Use database-level row locking (`SELECT FOR UPDATE`), atomic update queries (`UPDATE users SET balance = balance - $1 WHERE id = $2 AND balance >= $1`), or distributed Redis locks.

### 2.4 CI/CD Pipeline Injection
- Check `.github/workflows/*.yml` for direct interpolation of untrusted github context expressions in shell scripts:
  - `run: echo "Processing ${{ github.event.issue.title }}"`
- **Remediation:** Pass variables via environment variables instead of inline script strings:
  ```yaml
  env:
    TITLE: ${{ github.event.issue.title }}
  run: echo "Processing $TITLE"
  ```

---

## 3. Benign Staging Probes
- **SSRF:** Supply a benign loopback or canary endpoint to test protocol handling.
- **Path Traversal:** Request `../../package.json` to verify directory traversal resistance.
- **Concurrency:** Dispatch 10 parallel HTTP requests simultaneously with a single-use token or balance check to verify atomicity.

---

## 4. MCP Tool Integration
- Query detailed remediation and Sigma rules using `lookup_vulnerability_class` (`"ssrf"`, `"path_traversal"`, `"race_condition"`).
- Run findings through the `evaluate_7_question_gate` tool to produce dual-sided outputs.
