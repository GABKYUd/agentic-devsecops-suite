---
name: vuln-hunting-auth-access-control
description: >-
  Deep inspection heuristics for IDOR/BOLA, JWT flaws, OAuth 2.0, Mass Assignment (BOPLA), and Account Takeover.
  Use when auditing user authentication, authorization boundaries, token validations, and object-level permissions.
---

# Vulnerability Hunting: Authentication & Access Control

This skill guides deep inspection of authorization logic, token lifecycle, and object-level permissions to prevent unauthorized access and data leakage.

---

## 1. Targeted Vulnerability Classes

| ID | Class Name | CWE | MITRE ATT&CK | Primary Risk |
|---|---|---|---|---|
| `idor` | Insecure Direct Object Reference (IDOR / BOLA) | CWE-639 | T1078 | Missing tenant/user ownership check on object lookup |
| `broken_auth` | Broken Authentication & Session Hijacking | CWE-287 | T1078 | Weak session invalidation, credential stuffing, lack of lockout |
| `oauth` | OAuth 2.0 / OIDC Implementation Flaws | CWE-287 | T1556 | Missing `state` param (CSRF), redirect URI manipulation |
| `jwt` | JSON Web Token (JWT) Misconfigurations | CWE-347 | T1556 | `alg: none`, lack of signature verification, weak shared secrets |
| `mass_assignment` | Mass Assignment / Broken Property Auth (BOPLA) | CWE-915 | T1078 | Binding raw `req.body` to ORM models allowing role escalation |

---

## 2. Inspection Heuristics & Search Patterns

### 2.1 IDOR / Broken Object-Level Authorization (BOLA)
- Look for endpoints with ID parameters (e.g. `/api/documents/:id`, `/api/orders/:id`):
  ```javascript
  // VULNERABLE: Only checks if record exists, not who owns it
  const document = await db.Document.findByPk(req.params.id);
  res.json(document);
  ```
- **Remediation Pattern:**
  Enforce tenant/ownership checks at the data query layer:
  ```javascript
  // SECURE: Binds query to authenticated session user ID
  const document = await db.Document.findOne({
    where: { id: req.params.id, userId: req.user.id }
  });
  if (!document) return res.status(404).json({ error: 'Document not found' });
  ```

### 2.2 JSON Web Token (JWT) Misconfigurations
- Verify token verification calls:
  - Check if algorithm is explicitly pinned: `jwt.verify(token, secret, { algorithms: ['HS256'] })`.
  - Check for fallback to `none` algorithm or accepting unsigned tokens.
  - Verify secret strength: Ensure secrets are not hardcoded or short strings susceptible to offline brute-force.

### 2.3 Mass Assignment / BOPLA
- Look for ORM updates or user creation passing raw `req.body`:
  - `User.create(req.body)`
  - `User.update(req.body, { where: { id: req.user.id } })`
- If the schema contains privileged attributes (`role`, `isAdmin`, `verified`, `balance`), an attacker can inject `{"role": "admin"}`.
- **Remediation:** Whitelist permissible fields with DTO or Zod schema:
  - `const { name, phone } = req.body; await User.update({ name, phone }, ...)`

### 2.4 OAuth 2.0 State Verification
- Ensure the `state` parameter is cryptographically generated, stored in a signed cookie or session, and verified upon callback to prevent login CSRF.

---

## 3. Benign Staging Validation Probes
- **IDOR Dual-Account Test:** Authenticate as User A, retrieve a resource ID. Authenticate as User B, request User A's resource ID. If status is 200, IDOR is confirmed.
- **Mass Assignment Test:** Send unexpected field `{"role": "admin"}` in a user profile update request and observe if the field persists in the database response.

---

## 4. Triage & MCP Integration
- Pass all findings through the **7-Question Gate** using `evaluate_7_question_gate` via the MCP server.
- Retrieve remediation details using `lookup_vulnerability_class` with `vuln_name: "idor"` or `vuln_name: "mass_assignment"`.
