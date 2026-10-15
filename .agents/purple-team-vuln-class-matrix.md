# Purple Team Vulnerability Class Matrix (20+ Classes)

## Purpose & Architecture
This reference matrix translates the 20+ vulnerability classes analyzed by automated hunting engines (such as `claude-bug-bounty`) into a structured **Purple Team & DevSecOps Engineering Knowledge Base**.

For each vulnerability class, this document specifies:
1. **Classification:** CWE and MITRE ATT&CK mappings.
2. **Vulnerability Mechanics:** Common vulnerable patterns and source-to-sink data flow.
3. **SAST Rule (Semgrep / Static Pattern):** Code-level detection signature.
4. **Safe DAST / Staging Verification Probe:** Non-destructive probe syntax for authorized staging environments.
5. **The Strict 7-Question Verification Gate:** Step-by-step checklist to eliminate false positives and verify exploitability.
6. **Blue Team Detection Rule (Sigma / Log Analytics / WAF):** Behavioral detection for SIEM/EDR/WAF.
7. **Root-Cause Remediation & MITRE D3FEND Mapping:** Architectural fix and defensive countermeasure.

---

## Index of Vulnerability Classes

| # | Vulnerability Class | Primary Category | CWE | MITRE ATT&CK |
|---|---|---|---|---|
| 01 | **SQL Injection (SQLi)** | Injection & Execution | CWE-89 | T1190 |
| 02 | **NoSQL Injection (NoSQLi)** | Injection & Execution | CWE-943 | T1190 |
| 03 | **OS Command Injection** | Injection & Execution | CWE-78 | T1059 |
| 04 | **Server-Side Template Injection (SSTI)** | Injection & Execution | CWE-1336 | T1190 |
| 05 | **Insecure Deserialization** | Injection & Execution | CWE-502 | T1190 |
| 06 | **Insecure Direct Object Reference (IDOR / BOLA)** | Access Control & Auth | CWE-639 | T1078 |
| 07 | **Broken Authentication & Session Hijacking** | Access Control & Auth | CWE-287 | T1078 |
| 08 | **OAuth 2.0 / OIDC Implementation Flaws** | Access Control & Auth | CWE-287 | T1556 |
| 09 | **JSON Web Token (JWT) Misconfigurations** | Access Control & Auth | CWE-347 | T1556 |
| 10 | **Mass Assignment / Broken Property Auth (BOPLA)** | Access Control & Auth | CWE-915 | T1078 |
| 11 | **Server-Side Request Forgery (SSRF)** | Network & Boundary | CWE-918 | T1071 |
| 12 | **Path Traversal / Local File Inclusion (LFI)** | Network & Boundary | CWE-22 | T1083 |
| 13 | **Open Redirect & Host Header Injection** | Network & Boundary | CWE-601 | T1566 |
| 14 | **CORS Misconfiguration** | Network & Boundary | CWE-942 | T1189 |
| 15 | **Cross-Site Scripting (XSS - Stored / Reflected / DOM)** | Client & Dataflow | CWE-79 | T1189 |
| 16 | **Cross-Site Request Forgery (CSRF)** | Client & Dataflow | CWE-352 | T1189 |
| 17 | **Race Conditions & Concurrency (TOCTOU)** | Application Logic | CWE-362 | T1068 |
| 18 | **GraphQL Introspection, Batching & Depth Abuse** | API & Application Logic | CWE-770 | T1499 |
| 19 | **Hardcoded Secrets, Tokens & PII Exposure** | Data & Supply Chain | CWE-798 | T1552 |
| 20 | **CI/CD Pipeline Injection & Runner Poisoning** | Supply Chain & Infrastructure | CWE-78 | T1195 |
| 21 | **XML External Entity (XXE) Injection** | Injection & Execution | CWE-611 | T1190 |

---

## 01. SQL Injection (SQLi)

- **CWE:** CWE-89 (Improper Neutralization of Special Elements used in an SQL Command)
- **MITRE ATT&CK:** [T1190 - Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/)
- **MITRE D3FEND:** `d3f:DatabaseQueryParameterization`, `d3f:InputValidation`

### Mechanics & Source-to-Sink
Untrusted user input (HTTP params, headers, JSON body) is concatenated directly into SQL query strings executed by database drivers (e.g., `pg`, `mysql2`, `sqlite3`, raw ORM queries `sequelize.literal`, `prisma.$queryRawUnsafe`).

### SAST Rule (Semgrep Pattern)
```yaml
rules:
  - id: raw-sql-concatenation
    languages: [javascript, typescript, python]
    severity: ERROR
    message: "Detected unparameterized SQL query execution with concatenated user input."
    patterns:
      - pattern-either:
          - pattern: $DB.query(`... ${$INPUT} ...`)
          - pattern: $DB.raw("..." + $INPUT + "...")
          - pattern: $DB.query("SELECT " + $INPUT + " FROM ...")
          - pattern: cursor.execute("... %s ..." % $INPUT)
      - pattern-not: $DB.query("...", [...])
```

### Safe DAST Staging Probe
- **Payload/Probe:** Single quote `'`, benign arithmetic syntax `' OR 1=1 --`, or timing delay test `' AND (SELECT 1 FROM (SELECT(SLEEP(0.01)))a)--`.
- **Expected Safe Signal:** Check if HTTP status changes from 200 to 500 or if error response contains database driver error trace syntax.

### Strict 7-Question Gate Checklist
1. **Direct Exploitability:** Does input reach the SQL parser without ORM parameter binding?
2. **Access Prerequisites:** Accessible unauthenticated or by low-privileged tenant?
3. **Impact:** Enables arbitrary DB read, modification, or auth bypass?
4. **Novelty:** Checked and confirmed distinct from existing data-layer queries?
5. **Scope:** Endpoint verified as internal target?
6. **Repro Steps:** Verified with empirically validated HTTP request payload?
7. **Severity:** Critical (if authentication bypass / data exfiltration possible).

### Blue Team Detection (Sigma Rule)
```yaml
title: Potential SQL Injection in Web Server Access Logs
status: stable
logsource:
  category: webserver
detection:
  selection:
    cs-method: ['GET', 'POST']
    cs-uri-query|contains:
      - "UNION SELECT"
      - "' OR '1'='1"
      - "SLEEP("
      - "WAITFOR DELAY"
      - "BENCHMARK("
      - "information_schema"
  condition: selection
level: high
```

### Remediation
- Always enforce parameterized queries / prepared statements (e.g., `db.query('SELECT * FROM users WHERE id = $1', [userId])`).
- Avoid raw query helper escapes in ORMs (`$queryRawUnsafe`, `sequelize.literal`).

---

## 02. NoSQL Injection (NoSQLi)

- **CWE:** CWE-943 (Improper Neutralization in Data Query Logic)
- **MITRE ATT&CK:** [T1190 - Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/)
- **MITRE D3FEND:** `d3f:DatabaseQueryParameterization`, `d3f:InputValidation`

### Mechanics & Source-to-Sink
Express/Node/Python apps accepting nested JSON objects directly into MongoDB/Mongoose/CouchDB filters without casting to primitive types (e.g., `{ username: req.body.username, password: req.body.password }` receives `{"password": {"$ne": null}}`).

### SAST Rule (Semgrep Pattern)
```yaml
rules:
  - id: mongo-nosql-injection-object
    languages: [javascript, typescript]
    severity: HIGH
    message: "Direct user-controlled object passed to MongoDB query filter."
    patterns:
      - pattern: $COLL.find({ $FIELD: req.body.$PARAM })
      - pattern-not: $COLL.find({ $FIELD: String(req.body.$PARAM) })
```

### Safe DAST Staging Probe
- **Payload/Probe:** Send JSON payload `{"username": {"$gt": ""}}` to login or search endpoint.
- **Expected Safe Signal:** Response bypasses auth or returns all records unexpectedly.

### Strict 7-Question Gate Checklist
1. **Direct Exploitability:** Can JSON query selectors (`$gt`, `$ne`, `$regex`, `$where`) alter query logic?
2. **Access Prerequisites:** Unauthenticated public API route.
3. **Impact:** Authentication bypass or mass database record dump.
4. **Novelty:** Unsanitized body-parser endpoint.
5. **Scope:** Target API.
6. **Repro Steps:** Verified via JSON POST with non-string selector.
7. **Severity:** High / Critical.

### Blue Team Detection (Sigma Rule)
```yaml
title: Potential NoSQL Injection Attempt via JSON Body or Query
status: experimental
logsource:
  category: webserver
detection:
  selection:
    cs-uri-query|contains:
      - "[$ne]="
      - "[$gt]="
      - "[$regex]="
      - "[$where]="
  condition: selection
level: high
```

### Remediation
- Use `mongo-sanitize` middleware to strip leading `$` characters from `req.body`, `req.query`, and `req.params`.
- Enforce strict schema validation with `Zod`, `Joi`, or TypeScript runtime validators (`z.string().parse(req.body.username)`).

---

## 03. OS Command Injection

- **CWE:** CWE-78 (Improper Neutralization of Special Elements used in an OS Command)
- **MITRE ATT&CK:** [T1059 - Command and Scripting Interpreter](https://attack.mitre.org/techniques/T1059/)
- **MITRE D3FEND:** `d3f:ProcessSpawnAnalysis`, `d3f:InputValidation`

### Mechanics & Source-to-Sink
User input is interpolated into system shell calls (`child_process.exec`, `os.system`, `subprocess.Popen(..., shell=True)`).

### SAST Rule (Semgrep Pattern)
```yaml
rules:
  - id: node-command-injection
    languages: [javascript, typescript]
    severity: CRITICAL
    message: "Untrusted input passed to child_process.exec or child_process.execSync."
    patterns:
      - pattern-either:
          - pattern: child_process.exec(`... ${$VAR} ...`, ...)
          - pattern: child_process.execSync("..." + $VAR + "...", ...)
          - pattern: exec(`... ${$VAR} ...`, ...)
```

### Safe DAST Staging Probe
- **Payload/Probe:** Input containing benign command separators followed by `whoami` or `id` in staging testbed.
- **Expected Safe Signal:** Process response returns OS identity or executes separate command chain.

### Strict 7-Question Gate Checklist
1. **Direct Exploitability:** Command executes in shell subcontext without arg array splitting.
2. **Access Prerequisites:** Evaluated at caller's permission level.
3. **Impact:** Remote Code Execution (RCE) on host container/server.
4. **Novelty:** Verified unescaped shell call.
5. **Scope:** Authorized staging container.
6. **Repro Steps:** Request with chained command separator.
7. **Severity:** Critical.

### Blue Team Detection (Sigma Rule)
```yaml
title: Web Application Process Spawning Suspicious Shell Commands
status: stable
logsource:
  category: process_creation
  product: linux
detection:
  selection:
    ParentImage|endswith:
      - '/node'
      - '/python'
      - '/python3'
      - '/gunicorn'
      - '/uvicorn'
      - '/apache2'
      - '/nginx'
    Image|endswith:
      - '/sh'
      - '/bash'
      - '/zsh'
      - '/dash'
  condition: selection
level: high
```

### Remediation
- Use `child_process.execFile` or `child_process.spawn` with an argument array rather than `exec` with shell interpolation.
- Avoid passing data through system shells; use native language libraries (e.g., native image resizing, native file management).

---

## 04. Server-Side Template Injection (SSTI)

- **CWE:** CWE-1336 (Improper Neutralization of Special Elements Used in a Template Engine)
- **MITRE ATT&CK:** [T1190 - Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/)
- **MITRE D3FEND:** `d3f:InputValidation`, `d3f:ProcessSpawnAnalysis`

### Mechanics & Source-to-Sink
User input is concatenated into template strings (Jinja2, Pug, EJS, Handlebars, Thymeleaf) before compilation, allowing template directives (`{{...}}`, `<%= ... %>`) to access engine internals and global context objects.

### SAST Rule (Semgrep Pattern)
```yaml
rules:
  - id: ejs-ssti-render-string
    languages: [javascript, typescript]
    severity: HIGH
    message: "Dynamic string compilation in template engine with user input."
    patterns:
      - pattern: ejs.render($TEMPLATE + req.body.$PARAM, ...)
```

### Safe DAST Staging Probe
- **Payload/Probe:** Arithmetic expression `${7*7}`, `{{7*7}}`, `<%= 7*7 %>`.
- **Expected Safe Signal:** Rendered output evaluates to `49` instead of literal string `${7*7}`.

### Strict 7-Question Gate Checklist
1. **Direct Exploitability:** Arithmetic expression renders mathematically in response.
2. **Access Prerequisites:** Public or authenticated form field.
3. **Impact:** Remote code execution via template sandbox escape / global object traversal.
4. **Novelty:** Unescaped template compilation.
5. **Scope:** Target web view.
6. **Repro Steps:** Verified with mathematical expression injection.
7. **Severity:** Critical.

### Blue Team Detection (Sigma Rule)
```yaml
title: Potential SSTI Template Syntax in Web Request
status: experimental
logsource:
  category: webserver
detection:
  selection:
    cs-uri-query|contains:
      - "{{7*7}}"
      - "${7*7}"
      - "__class__"
      - "__mro__"
      - "__subclasses__"
      - "T(java.lang.Runtime)"
  condition: selection
level: high
```

### Remediation
- Never concatenate untrusted strings into template definitions. Pass user input strictly as template context variables (e.g., `render('profile.ejs', { username: userInput })`).
- Enable sandboxing and disable raw code execution capabilities in template engines.

---

## 05. Insecure Deserialization

- **CWE:** CWE-502 (Deserialization of Untrusted Data)
- **MITRE ATT&CK:** [T1190 - Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/)
- **MITRE D3FEND:** `d3f:TypeCoercionCheck`, `d3f:InputValidation`

### Mechanics & Source-to-Sink
Passing raw serialized byte streams or language-specific object dumps (Python `pickle`, PHP `unserialize`, Java `ObjectInputStream`, Node `node-serialize`) from untrusted network sources into deserializers that instantiate objects or execute magic methods.

### SAST Rule (Semgrep Pattern)
```yaml
rules:
  - id: dangerous-pickle-load
    languages: [python]
    severity: CRITICAL
    message: "Use of unsafe deserializer pickle.loads with untrusted input."
    patterns:
      - pattern: pickle.loads($INPUT)
```

### Safe DAST Staging Probe
- **Payload/Probe:** Serialized object containing benign test structure or header check.
- **Expected Safe Signal:** Verification of deserialization error traces or unexpected object construction.

### Strict 7-Question Gate Checklist
1. **Direct Exploitability:** Deserializer executes arbitrary code upon payload parsing.
2. **Access Prerequisites:** Endpoint receiving serialized session cookie or API payload.
3. **Impact:** Arbitrary Remote Code Execution.
4. **Novelty:** Insecure native deserialization in use.
5. **Scope:** Target endpoint.
6. **Repro Steps:** Base64-encoded serialized payload delivered to parser.
7. **Severity:** Critical.

### Blue Team Detection (Sigma Rule)
```yaml
title: Insecure Deserialization Java/Python Artifacts in HTTP Header/Body
status: experimental
logsource:
  category: webserver
detection:
  selection:
    cs-cookie|contains:
      - "rO0AB" # Java serialized object base64 prefix
      - "gASV"  # Python pickle protocol base64 prefix
  condition: selection
level: high
```

### Remediation
- Replace binary/native deserialization formats with standard, data-only formats like JSON or Protocol Buffers.
- If serialization is required, implement HMAC cryptographic signing (`crypto.createHmac`) to verify integrity before deserialization.

---

## 06. Insecure Direct Object Reference (IDOR / BOLA)

- **CWE:** CWE-639 (Authorization Bypass Through User-Controlled Key)
- **MITRE ATT&CK:** [T1078 - Valid Accounts](https://attack.mitre.org/techniques/T1078/)
- **MITRE D3FEND:** `d3f:UserAuthorizationAnalysis`

### Mechanics & Source-to-Sink
Application retrieves, updates, or deletes database records using an ID passed in parameters (`/api/documents/:id`) without validating that the authenticated session (`req.user.id` or `req.user.tenantId`) is the authorized owner of that resource.

### SAST Rule (Semgrep Pattern)
```yaml
rules:
  - id: potential-idor-unscoped-query
    languages: [javascript, typescript]
    severity: WARNING
    message: "Database record queried strictly by param ID without user/tenant session scoping."
    patterns:
      - pattern: $DB.findOne({ where: { id: req.params.id } })
      - pattern-not: $DB.findOne({ where: { id: req.params.id, userId: req.user.id } })
      - pattern-not: $DB.findOne({ where: { id: req.params.id, tenantId: req.user.tenantId } })
```

### Safe DAST Staging Probe
- **Methodology:** Use two test accounts (User A and User B). Have User A create a resource (e.g., Doc ID 101). Have User B request `/api/documents/101`.
- **Expected Signal:** Returns 200 OK with User A's data instead of 403 Forbidden / 404 Not Found.

### Strict 7-Question Gate Checklist
1. **Direct Exploitability:** Can User B access or modify User A's private resource?
2. **Access Prerequisites:** Standard authenticated user session.
3. **Impact:** Unauthorized horizontal or vertical data access / data tampering.
4. **Novelty:** Unscoped database query in controller.
5. **Scope:** Target API endpoint.
6. **Repro Steps:** Multi-account validation with exact HTTP request.
7. **Severity:** High.

### Blue Team Detection (Sigma Rule)
```yaml
title: Rapid Sequential Access to Numerical Resource IDs (IDOR Enumeration)
status: experimental
logsource:
  category: webserver
detection:
  selection:
    cs-method: 'GET'
    cs-uri-stem|re: '^/api/v1/[a-z]+/[0-9]+$'
  timeframe: 1m
  condition: selection | count(cs-uri-stem) by c-ip > 30
level: medium
```

### Remediation
- Enforce record-level authorization in the data access layer: always query by `WHERE id = :id AND tenant_id = :tenantId`.
- Use random, non-enumerable identifiers (UUIDv4 or ULID) to prevent sequential scraping, combined with strict authorization policies.

---

## 07. Broken Authentication & Session Management

- **CWE:** CWE-287 (Improper Authentication)
- **MITRE ATT&CK:** [T1078 - Valid Accounts](https://attack.mitre.org/techniques/T1078/)
- **MITRE D3FEND:** `d3f:CredentialRevocation`, `d3f:SessionLockout`

### Mechanics & Source-to-Sink
Flaws in password reset workflows, lack of rate limiting on login/MFA endpoints, predictable session tokens, or failure to invalidate existing sessions upon password reset/logout.

### SAST Rule (Semgrep Pattern)
```yaml
rules:
  - id: weak-crypto-session-token
    languages: [javascript, typescript]
    severity: HIGH
    message: "Predictable random number generator used for authentication token generation."
    patterns:
      - pattern: Math.random().toString(36)...
```

### Safe DAST Staging Probe
- **Methodology:** Test session token invalidation after logout or test password reset token generation entropy.

### Strict 7-Question Gate Checklist
1. **Direct Exploitability:** Does endpoint permit brute-force, token prediction, or session reuse?
2. **Access Prerequisites:** Unauthenticated or expired session.
3. **Impact:** Account Takeover (ATO).
4. **Novelty:** Flawed authentication state machine.
5. **Scope:** Auth endpoints.
6. **Repro Steps:** Documented request sequence.
7. **Severity:** Critical / High.

### Blue Team Detection (Sigma Rule)
```yaml
title: High Volume Authentication Failures From Single IP
status: stable
logsource:
  category: webserver
detection:
  selection:
    cs-uri-stem: '/api/auth/login'
    sc-status: 401
  timeframe: 5m
  condition: selection | count() by c-ip > 15
level: high
```

### Remediation
- Implement cryptographically secure token generation (`crypto.randomBytes(32)`).
- Enforce strict rate limiting and exponential backoff on all authentication endpoints.
- Store session state in centralized stores (e.g., Redis) and revoke all active tokens on password change or logout.

---

## 08. OAuth 2.0 & OIDC Implementation Flaws

- **CWE:** CWE-287 (Improper Authentication)
- **MITRE ATT&CK:** [T1556 - Modify Authentication Process](https://attack.mitre.org/techniques/T1556/)
- **MITRE D3FEND:** `d3f:AuthenticationTicketValidation`

### Mechanics & Source-to-Sink
Missing or unvalidated `state` parameter (enabling CSRF during login), unvalidated `redirect_uri` (enabling token/authorization code theft via open redirect), or insecure client secret handling.

### SAST Rule (Semgrep Pattern)
```yaml
rules:
  - id: oauth-missing-state-validation
    languages: [javascript, typescript]
    severity: HIGH
    message: "OAuth callback handler does not validate session state parameter."
    patterns:
      - pattern: |
          app.get('/auth/callback', (req, res) => {
            ...
            const code = req.query.code;
            ...
          })
      - pattern-not: |
          if (req.session.oauth_state !== req.query.state) { ... }
```

### Safe DAST Staging Probe
- **Methodology:** Initiate OAuth flow, alter `redirect_uri` to external host or omit `state` parameter to check validation enforcement.

### Strict 7-Question Gate Checklist
1. **Direct Exploitability:** Can auth codes be redirected or victim sessions bound to attacker accounts?
2. **Access Prerequisites:** Web browser / user interaction.
3. **Impact:** Account takeover via OAuth identity linking.
4. **Novelty:** Missing state verification or loose redirect regex.
5. **Scope:** OAuth callback endpoint.
6. **Repro Steps:** Flow diagram + HTTP parameter trace.
7. **Severity:** High.

### Blue Team Detection (Sigma Rule)
```yaml
title: OAuth Authorization Callback with Anomalous Redirect URI
status: experimental
logsource:
  category: webserver
detection:
  selection:
    cs-uri-stem: '/oauth/authorize'
    cs-uri-query|contains: 'redirect_uri='
  filter:
    cs-uri-query|contains:
      - 'https://app.yourdomain.com'
      - 'https://auth.yourdomain.com'
  condition: selection and not filter
level: high
```

### Remediation
- Strictly validate `redirect_uri` against an exact whitelist (no regex wildcards).
- Enforce unique, cryptographically random `state` parameters bound to the user's session cookie and PKCE (`code_challenge` / `code_verifier`).

---

## 09. JSON Web Token (JWT) Misconfigurations

- **CWE:** CWE-347 (Improper Verification of Cryptographic Signature)
- **MITRE ATT&CK:** [T1556 - Modify Authentication Process](https://attack.mitre.org/techniques/T1556/)
- **MITRE D3FEND:** `d3f:CertificateAnalysis`, `d3f:UserAuthorizationAnalysis`

### Mechanics & Source-to-Sink
Accepting `alg: none`, failing to verify signatures, key confusion (verifying asymmetric RS256 token with HMAC SHA256 using public key as secret), or vulnerable JWK header injection.

### SAST Rule (Semgrep Pattern)
```yaml
rules:
  - id: jwt-none-algorithm-allowed
    languages: [javascript, typescript]
    severity: CRITICAL
    message: "JWT verification allows none algorithm or lacks explicit algorithm specification."
    patterns:
      - pattern: jwt.verify($TOKEN, $SECRET, { algorithms: [..., 'none', ...] })
      - pattern: jwt.verify($TOKEN, $SECRET) # Missing algorithm whitelist
```

### Safe DAST Staging Probe
- **Methodology:** Submit JWT with header `{"alg":"none","typ":"JWT"}` and modified claims in test environment.

### Strict 7-Question Gate Checklist
1. **Direct Exploitability:** Token signature accepted with `none` or forged secret.
2. **Access Prerequisites:** Possession of any valid JWT format.
3. **Impact:** Complete authentication bypass / arbitrary privilege claim.
4. **Novelty:** Flawed `jwt.verify()` configuration.
5. **Scope:** API Authorization header.
6. **Repro Steps:** Forged token string tested against endpoint.
7. **Severity:** Critical.

### Blue Team Detection (Sigma Rule)
```yaml
title: JWT Header Specifying Alg None Received
status: stable
logsource:
  category: webserver
detection:
  selection:
    cs-header-authorization|contains:
      - "eyJhbGciOiJub25l" # Base64 for {"alg":"none"
      - "eyJhbGciOiJOT05F" # Base64 for {"alg":"NONE"
  condition: selection
level: critical
```

### Remediation
- Explicitly enforce expected algorithms in verifiers: `jwt.verify(token, secret, { algorithms: ['RS256'] })`.
- Never trust the `alg` header supplied by the client.

---

## 10. Mass Assignment & Broken Object Property Auth (BOPLA)

- **CWE:** CWE-915 (Improperly Controlled Modification of Dynamically-Determined Object Attributes)
- **MITRE ATT&CK:** [T1078 - Valid Accounts](https://attack.mitre.org/techniques/T1078/)
- **MITRE D3FEND:** `d3f:InputValidation`

### Mechanics & Source-to-Sink
Passing the entire unvalidated `req.body` directly into database ORM create/update methods (e.g., `User.update(req.body, { where: { id } })`), allowing users to overwrite privileged fields like `isAdmin: true`, `role: "admin"`, or `balance: 99999`.

### SAST Rule (Semgrep Pattern)
```yaml
rules:
  - id: sequelize-mass-assignment
    languages: [javascript, typescript]
    severity: HIGH
    message: "Direct passing of req.body to ORM update/create without property whitelisting."
    patterns:
      - pattern: $MODEL.update(req.body, ...)
      - pattern: $MODEL.create(req.body, ...)
```

### Safe DAST Staging Probe
- **Methodology:** Send profile update POST/PUT request adding extra fields: `{"name":"Alice","role":"admin","is_verified":true}` in staging.

### Strict 7-Question Gate Checklist
1. **Direct Exploitability:** Does database record reflect modified privileged property?
2. **Access Prerequisites:** Authenticated user with edit access to self profile.
3. **Impact:** Privilege escalation to administrator.
4. **Novelty:** Unfiltered object assignment in controller.
5. **Scope:** Update endpoints.
6. **Repro Steps:** JSON request with extra attribute key.
7. **Severity:** High.

### Blue Team Detection (Sigma Rule)
```yaml
title: Privileged Property Names in JSON Update Request
status: experimental
logsource:
  category: webserver
detection:
  selection:
    cs-method: ['POST', 'PUT', 'PATCH']
    cs-uri-stem|contains: '/profile'
    cs-body|contains:
      - '"isAdmin":'
      - '"role":'
      - '"is_admin":'
      - '"permissions":'
  condition: selection
level: medium
```

### Remediation
- Use strict DTOs (Data Transfer Objects) and schema validation (e.g., Zod) or explicitly whitelist modifiable attributes: `User.update({ name: req.body.name, bio: req.body.bio }, { where: { id } })`.

---

## 11. Server-Side Request Forgery (SSRF)

- **CWE:** CWE-918 (Server-Side Request Forgery)
- **MITRE ATT&CK:** [T1071 - Application Layer Protocol](https://attack.mitre.org/techniques/T1071/)
- **MITRE D3FEND:** `d3f:InboundTrafficFiltering`, `d3f:NetworkTrafficSignatureAnalysis`

### Mechanics & Source-to-Sink
Application fetches a remote URL provided by user input (e.g., webhook URL, avatar import, PDF generator, proxy) without restricting destination IP addresses, enabling connections to `169.254.169.254` (cloud metadata), `127.0.0.1`, or internal private networks (`10.0.0.0/8`, `192.168.0.0/16`).

### SAST Rule (Semgrep Pattern)
```yaml
rules:
  - id: axios-ssrf-user-url
    languages: [javascript, typescript]
    severity: HIGH
    message: "HTTP request client called with untrusted user-controlled URL."
    patterns:
      - pattern-either:
          - pattern: axios.get(req.body.$URL, ...)
          - pattern: fetch(req.query.$URL, ...)
          - pattern: requests.get(request.args.get($URL))
```

### Safe DAST Staging Probe
- **Methodology:** Supply loopback address `http://127.0.0.1:80` or cloud metadata URL `http://169.254.169.254/latest/meta-data/` in staging testbed.

### Strict 7-Question Gate Checklist
1. **Direct Exploitability:** Server initiates HTTP/TCP connection to supplied IP and returns response/timing.
2. **Access Prerequisites:** Any user with access to URL-fetching functionality.
3. **Impact:** Cloud credential exfiltration (IMDS), internal network port scanning, or remote service exploitation.
4. **Novelty:** Missing IP whitelist and DNS resolution check.
5. **Scope:** Target URL import endpoint.
6. **Repro Steps:** Verified with loopback/metadata probe.
7. **Severity:** Critical (if cloud metadata reachable) / High.

### Blue Team Detection (Sigma Rule)
```yaml
title: Outbound HTTP Connection to Cloud Metadata Service from App Tier
status: critical
logsource:
  category: network_connection
detection:
  selection:
    DestinationIp: '169.254.169.254'
    DestinationPort: 80
  filter_known_system:
    Image|endswith:
      - '/amazon-ssm-agent'
      - '/cloud-init'
  condition: selection and not filter_known_system
level: critical
```

### Remediation
- Resolve domain names to IP addresses *before* making the request and validate that resolved IPs do not fall into private/loopback/link-local ranges (CIDR blocks: `127.0.0.0/8`, `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `169.254.0.0/16`).
- Enforce IMDSv2 on AWS cloud instances (requiring session token header and hop limit 1).

---

## 12. Path Traversal / Local File Inclusion (LFI)

- **CWE:** CWE-22 (Improper Limitation of a Pathname to a Restricted Directory)
- **MITRE ATT&CK:** [T1083 - File and Directory Discovery](https://attack.mitre.org/techniques/T1083/)
- **MITRE D3FEND:** `d3f:FileAccessPatternAnalysis`, `d3f:InputValidation`

### Mechanics & Source-to-Sink
User input containing directory traversal sequences (`../`, `..%2f`, `%2e%2e%2f`) is passed directly to file system operations (`fs.readFile`, `open()`, `sendFile`) without path normalization or base directory containment checks.

### SAST Rule (Semgrep Pattern)
```yaml
rules:
  - id: path-traversal-fs-read
    languages: [javascript, typescript]
    severity: HIGH
    message: "File system read operation uses raw parameter path."
    patterns:
      - pattern: fs.readFile(path.join($BASE, req.query.$FILE), ...)
      - pattern-not: |
          const $SAFE = path.resolve($BASE, req.query.$FILE);
          if (!$SAFE.startsWith($BASE)) { ... }
```

### Safe DAST Staging Probe
- **Methodology:** Supply traversal sequences `../../../../etc/passwd` or `..\\..\\windows\\win.ini` in file download parameter in staging testbed.

### Strict 7-Question Gate Checklist
1. **Direct Exploitability:** File contents outside intended base folder returned in response.
2. **Access Prerequisites:** Public or authenticated file retrieval endpoint.
3. **Impact:** Arbitrary system configuration or source code disclosure.
4. **Novelty:** Unsanitized file path construction.
5. **Scope:** Download/view endpoint.
6. **Repro Steps:** Traversal string in HTTP GET request.
7. **Severity:** High.

### Blue Team Detection (Sigma Rule)
```yaml
title: Directory Traversal Sequences in HTTP Request
status: stable
logsource:
  category: webserver
detection:
  selection:
    cs-uri|contains:
      - "../"
      - "..%2f"
      - "%2e%2e%2f"
      - "..\\\\"
      - "%2e%2e/"
  condition: selection
level: high
```

### Remediation
- Use `path.basename()` to extract only the filename component, or use `path.resolve()` and verify that the target path begins with the allowed root directory: `if (!resolvedPath.startsWith(allowedRootDir)) throw new Error('Access denied');`.

---

## 13. Open Redirect & Host Header Injection

- **CWE:** CWE-601 (URL Redirection to Untrusted Site)
- **MITRE ATT&CK:** [T1566 - Phishing](https://attack.mitre.org/techniques/T1566/)
- **MITRE D3FEND:** `d3f:InputValidation`

### Mechanics & Source-to-Sink
Application passes untrusted input directly into HTTP redirect headers (`res.redirect(req.query.returnUrl)`) or builds password reset links dynamically using the untrusted HTTP `Host` header (`req.headers.host`).

### SAST Rule (Semgrep Pattern)
```yaml
rules:
  - id: open-redirect-res-redirect
    languages: [javascript, typescript]
    severity: MEDIUM
    message: "Unvalidated URL redirect using user-supplied query parameter."
    patterns:
      - pattern: res.redirect(req.query.$URL)
      - pattern-not: res.redirect('/' + ...)
```

### Safe DAST Staging Probe
- **Methodology:** Pass `returnUrl=https://example.com` or header `Host: attacker.com` in staging testbed.

### Strict 7-Question Gate Checklist
1. **Direct Exploitability:** Response returns HTTP 302/301 with `Location: https://example.com`.
2. **Access Prerequisites:** Accessible to public callers.
3. **Impact:** Credential phishing or password reset token poisoning.
4. **Novelty:** Unvalidated redirection parameter.
5. **Scope:** Login/redirect endpoint.
6. **Repro Steps:** GET request with external URL parameter.
7. **Severity:** Medium.

### Blue Team Detection (Sigma Rule)
```yaml
title: Open Redirect Pattern in Query String
status: experimental
logsource:
  category: webserver
detection:
  selection:
    cs-uri-query|contains:
      - "redirect=http://"
      - "redirect=https://"
      - "returnUrl=http://"
      - "next=http://"
  condition: selection
level: low
```

### Remediation
- Only allow relative redirect paths (e.g., paths starting with a single `/` and not followed by another `/` or `\`).
- If absolute URLs are required, validate against a strict whitelist of allowed domains.
- Hardcode the trusted application domain in server configuration rather than reading from `Host` or `X-Forwarded-Host` headers.

---

## 14. CORS Misconfiguration

- **CWE:** CWE-942 (Permissive Cross-Origin Resource Sharing Policy with Credential Inclusion)
- **MITRE ATT&CK:** [T1189 - Drive-by Compromise](https://attack.mitre.org/techniques/T1189/)
- **MITRE D3FEND:** `d3f:InputValidation`

### Mechanics & Source-to-Sink
Web server dynamically reflects the incoming `Origin` header into `Access-Control-Allow-Origin` while simultaneously setting `Access-Control-Allow-Credentials: true`, or sets `Access-Control-Allow-Origin: null`.

### SAST Rule (Semgrep Pattern)
```yaml
rules:
  - id: dynamic-cors-origin-reflection
    languages: [javascript, typescript]
    severity: HIGH
    message: "CORS configuration dynamically reflects request origin with credentials enabled."
    patterns:
      - pattern: |
          res.setHeader('Access-Control-Allow-Origin', req.headers.origin);
          res.setHeader('Access-Control-Allow-Credentials', 'true');
```

### Safe DAST Staging Probe
- **Methodology:** Send HTTP request with header `Origin: https://evil.com` to authenticated API endpoint.
- **Expected Signal:** Server responds with `Access-Control-Allow-Origin: https://evil.com` and `Access-Control-Allow-Credentials: true`.

### Strict 7-Question Gate Checklist
1. **Direct Exploitability:** Arbitrary origins allowed with credentials enabled.
2. **Access Prerequisites:** User browsing attacker webpage while authenticated.
3. **Impact:** Cross-origin data theft of sensitive user data.
4. **Novelty:** Insecure CORS header reflection.
5. **Scope:** Authenticated API routes.
6. **Repro Steps:** Verified with curl origin header probe.
7. **Severity:** High / Medium.

### Blue Team Detection (Sigma Rule)
```yaml
title: Insecure CORS Origin Reflected in Response
status: experimental
logsource:
  category: webserver
detection:
  selection:
    cs-method: 'OPTIONS'
    cs-header-origin|contains: '.'
  filter_known:
    cs-header-origin|endswith:
      - '.yourdomain.com'
  condition: selection and not filter_known
level: low
```

### Remediation
- Maintain an explicit whitelist of allowed origins.
- Never reflect untrusted `Origin` headers when `Access-Control-Allow-Credentials` is `true`. Never whitelist `null`.

---

## 15. Cross-Site Scripting (XSS - Stored, Reflected, DOM)

- **CWE:** CWE-79 (Improper Neutralization of Input During Web Page Generation)
- **MITRE ATT&CK:** [T1189 - Drive-by Compromise](https://attack.mitre.org/techniques/T1189/)
- **MITRE D3FEND:** `d3f:InputValidation`

### Mechanics & Source-to-Sink
Untrusted user input is rendered into HTML/JavaScript contexts without proper contextual encoding (e.g., React `dangerouslySetInnerHTML`, jQuery `innerHTML`, unescaped template variables `<%- ... %>`).

### SAST Rule (Semgrep Pattern)
```yaml
rules:
  - id: react-dangerously-set-inner-html
    languages: [javascript, typescript]
    severity: HIGH
    message: "Use of dangerouslySetInnerHTML with unsanitized dynamic variable."
    patterns:
      - pattern: <$TAG dangerouslySetInnerHTML={{ __html: $VAR }} ... />
      - pattern-not: <$TAG dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize($VAR) }} ... />
```

### Safe DAST Staging Probe
- **Payload/Probe:** Non-executing canary probe `<div id="xss-canary-test">canary</div>` or benign attribute escape.
- **Expected Signal:** Check if tags render raw in DOM without HTML entity encoding.

### Strict 7-Question Gate Checklist
1. **Direct Exploitability:** Payload renders unencoded in browser DOM context.
2. **Access Prerequisites:** Public parameter (reflected) or authenticated post (stored).
3. **Impact:** Session hijacking, unauthorized API actions, UI defacement.
4. **Novelty:** Unescaped sink in frontend or template.
5. **Scope:** Target web application.
6. **Repro Steps:** Request payload + rendered DOM verification.
7. **Severity:** High (Stored) / Medium (Reflected).

### Blue Team Detection (Sigma Rule)
```yaml
title: Common XSS Script Injection Patterns in Web Request
status: stable
logsource:
  category: webserver
detection:
  selection:
    cs-uri-query|contains:
      - "<script"
      - "javascript:"
      - "onerror="
      - "onload="
      - "<img src="
      - "<svg onload"
  condition: selection
level: high
```

### Remediation
- Use modern UI frameworks (React, Vue, Angular) that contextually auto-encode data by default.
- If raw HTML rendering is required, sanitize strictly using `DOMPurify`.
- Deploy a strict Content Security Policy (`Content-Security-Policy: default-src 'self'; script-src 'self'`).

---

## 16. Cross-Site Request Forgery (CSRF)

- **CWE:** CWE-352 (Cross-Site Request Forgery)
- **MITRE ATT&CK:** [T1189 - Drive-by Compromise](https://attack.mitre.org/techniques/T1189/)
- **MITRE D3FEND:** `d3f:InputValidation`

### Mechanics & Source-to-Sink
State-changing POST/PUT/DELETE requests rely solely on ambient credentials (cookies) without validating CSRF tokens or without configuring cookies with `SameSite=Lax` or `SameSite=Strict`.

### SAST Rule (Semgrep Pattern)
```yaml
rules:
  - id: cookie-missing-samesite
    languages: [javascript, typescript]
    severity: MEDIUM
    message: "Session cookie set without explicit SameSite attribute or CSRF protection."
    patterns:
      - pattern: res.cookie($NAME, $VAL, { ... })
      - pattern-not: res.cookie($NAME, $VAL, { ..., sameSite: 'lax', ... })
      - pattern-not: res.cookie($NAME, $VAL, { ..., sameSite: 'strict', ... })
```

### Safe DAST Staging Probe
- **Methodology:** Construct cross-origin HTML form submitting a POST request to state-changing endpoint with credentials included.

### Strict 7-Question Gate Checklist
1. **Direct Exploitability:** State-changing action executes from third-party cross-origin origin.
2. **Access Prerequisites:** Logged-in victim browsing malicious site.
3. **Impact:** Unauthorized state modification (email change, funds transfer).
4. **Novelty:** Missing anti-CSRF token and permissive cookie configuration.
5. **Scope:** State-changing API routes.
6. **Repro Steps:** Cross-origin form submission test.
7. **Severity:** Medium.

### Remediation
- Configure all authentication session cookies with `SameSite=Lax` or `SameSite=Strict` and `Secure`.
- Implement Anti-CSRF tokens (Synchronizer Token pattern or Double Submit Cookie pattern) for all state-changing endpoints.

---

## 17. Race Conditions & Concurrency (TOCTOU)

- **CWE:** CWE-362 (Concurrent Execution using Shared Resource with Improper Synchronization)
- **MITRE ATT&CK:** [T1068 - Exploitation for Privilege Escalation](https://attack.mitre.org/techniques/T1068/)
- **MITRE D3FEND:** `d3f:InputValidation`

### Mechanics & Source-to-Sink
Time-of-Check to Time-of-Use (TOCTOU) flaw: application checks balance or coupon eligibility in step 1, and deducts/applies it in step 2 without database row-level locking (`SELECT ... FOR UPDATE`) or transactional isolation.

### SAST Rule (Semgrep Pattern)
```yaml
rules:
  - id: unsynchronized-balance-check-update
    languages: [javascript, typescript]
    severity: HIGH
    message: "Database check followed by separate update without transaction or row lock."
    patterns:
      - pattern: |
          const user = await $DB.findById($ID);
          if (user.balance >= $AMOUNT) {
            ...
            await $DB.update({ balance: user.balance - $AMOUNT });
          }
```

### Safe DAST Staging Probe
- **Methodology:** Send parallel asynchronous requests (e.g., 10 concurrent requests to redeem a single-use coupon) using HTTP/2 multiplexing in staging.

### Strict 7-Question Gate Checklist
1. **Direct Exploitability:** Multi-request batch executes more times than allowed quota.
2. **Access Prerequisites:** Standard user account.
3. **Impact:** Financial loss, double-spending, coupon reuse.
4. **Novelty:** Missing atomic transaction or lock.
5. **Scope:** Financial, inventory, or voucher endpoints.
6. **Repro Steps:** Multi-threaded parallel request benchmark.
7. **Severity:** High.

### Remediation
- Use atomic database operations (e.g., `UPDATE accounts SET balance = balance - :amt WHERE id = :id AND balance >= :amt`).
- Use database transactions with row-level locks (`SELECT ... FOR UPDATE`) or distributed locks (e.g., Redis Redlock).

---

## 18. GraphQL Introspection, Batching & Depth Abuse

- **CWE:** CWE-770 (Allocation of Resources Without Limits or Throttling)
- **MITRE ATT&CK:** [T1499 - Endpoint Denial of Service](https://attack.mitre.org/techniques/T1499/)
- **MITRE D3FEND:** `d3f:InputValidation`

### Mechanics & Source-to-Sink
Production GraphQL endpoint leaves schema introspection enabled, allows unlimited query batching (bypassing rate limits), or permits deeply nested cyclical queries leading to CPU/memory exhaustion.

### SAST Rule (Semgrep Pattern)
```yaml
rules:
  - id: apollo-introspection-enabled
    languages: [javascript, typescript]
    severity: MEDIUM
    message: "GraphQL Apollo Server created with introspection explicitly enabled."
    patterns:
      - pattern: new ApolloServer({ ..., introspection: true, ... })
```

### Safe DAST Staging Probe
- **Methodology:** Send query `{"query":"query { __schema { types { name } } }"}` or deeply nested cyclical query `query { me { friends { friends { friends { id } } } } }`.

### Strict 7-Question Gate Checklist
1. **Direct Exploitability:** Schema completely enumerated or server experiences processing spike.
2. **Access Prerequisites:** Public GraphQL endpoint.
3. **Impact:** Complete API surface discovery or Denial of Service.
4. **Novelty:** Unconstrained GraphQL configuration.
5. **Scope:** `/graphql` endpoint.
6. **Repro Steps:** Introspection POST request.
7. **Severity:** Medium.

### Blue Team Detection (Sigma Rule)
```yaml
title: GraphQL Introspection Query in Production Request
status: stable
logsource:
  category: webserver
detection:
  selection:
    cs-uri-stem: '/graphql'
    cs-body|contains:
      - '__schema'
      - '__type'
  condition: selection
level: medium
```

### Remediation
- Disable GraphQL introspection in production environments (`introspection: false`).
- Implement query complexity analysis and query depth limiting middleware (`graphql-depth-limit`).
- Restrict query batching and enforce rate limiting per operation.

---

## 19. Hardcoded Secrets, Tokens & PII Exposure

- **CWE:** CWE-798 (Use of Hard-coded Credentials)
- **MITRE ATT&CK:** [T1552 - Unsecured Credentials](https://attack.mitre.org/techniques/T1552/)
- **MITRE D3FEND:** `d3f:CredentialRevocation`

### Mechanics & Source-to-Sink
API keys, private keys, database passwords, or JWT secrets hardcoded in source code files, configuration templates, or client-side bundles.

### SAST Rule (Semgrep / Gitleaks Pattern)
```yaml
rules:
  - id: hardcoded-api-key-assignment
    languages: [javascript, typescript, python]
    severity: CRITICAL
    message: "Potential hardcoded secret or API token assigned directly to variable."
    patterns:
      - pattern: const $KEY = "ghp_..."
      - pattern: const $KEY = "AKIA[0-9A-Z]{16}"
      - pattern: const $KEY = "sk_live_..."
```

### Safe DAST Staging Probe
- **Methodology:** Scan client-side JavaScript bundles (`.js`, `.js.map`) for exposed secrets and private environment variables.

### Strict 7-Question Gate Checklist
1. **Direct Exploitability:** Credential string verified valid against external API.
2. **Access Prerequisites:** Repository access or public client bundle.
3. **Impact:** Unauthorized third-party API or cloud resource access.
4. **Novelty:** Static secret in codebase.
5. **Scope:** Code repository / frontend build artifacts.
6. **Repro Steps:** Gitleaks detection output with commit hash.
7. **Severity:** Critical.

### Blue Team Detection (Sigma Rule)
```yaml
title: Cloud Provider API Access from Abnormal Geographic Region
status: high
logsource:
  category: cloudtrail
detection:
  selection:
    eventName: 'GetCallerIdentity'
  filter:
    sourceIPAddress|in: ['YOUR_OFFICE_IPS', 'YOUR_VPN_IPS']
  condition: selection and not filter
level: high
```

### Remediation
- Integrate `gitleaks` and `trufflehog` pre-commit hooks and CI/CD gates to block secret commits.
- Load secrets at runtime from environment variables populated by a managed secrets manager (AWS Secrets Manager, HashiCorp Vault, Doppler).

---

## 20. CI/CD Pipeline Injection & Runner Poisoning

- **CWE:** CWE-78 (Improper Neutralization of Special Elements used in an OS Command)
- **MITRE ATT&CK:** [T1195 - Supply Chain Compromise](https://attack.mitre.org/techniques/T1195/)
- **MITRE D3FEND:** `d3f:ProcessSpawnAnalysis`

### Mechanics & Source-to-Sink
GitHub Actions workflows or GitLab CI configurations that interpolate untrusted PR data (`${{ github.event.issue.title }}`, `${{ github.head_ref }}`) directly into inline `run:` shell commands, allowing attackers to execute commands within the runner context.

### SAST Rule (Semgrep Pattern)
```yaml
rules:
  - id: github-actions-untrusted-run-injection
    languages: [yaml]
    severity: CRITICAL
    message: "Untrusted GitHub context expression interpolated directly into run script."
    patterns:
      - pattern: |
          run: |
            ... ${{ github.event.issue.title }} ...
      - pattern: |
          run: |
            ... ${{ github.event.pull_request.title }} ...
      - pattern: |
          run: |
            ... ${{ github.head_ref }} ...
```

### Strict 7-Question Gate Checklist
1. **Direct Exploitability:** Untrusted PR title or branch name executes arbitrary commands in runner.
2. **Access Prerequisites:** External pull request or issue creation.
3. **Impact:** Pipeline runner compromise, access to `GITHUB_TOKEN`, and deployment secret exfiltration.
4. **Novelty:** Unquoted/unmitigated context expression in YAML.
5. **Scope:** `.github/workflows/*.yml`.
6. **Repro Steps:** Static workflow configuration analysis.
7. **Severity:** Critical.

### Remediation
- Pass all dynamic context values through intermediate environment variables:
  ```yaml
  - name: Process Title
    env:
      TITLE: ${{ github.event.issue.title }}
    run: echo "$TITLE"
  ```
- Use least-privilege `permissions:` blocks in GitHub Actions workflows (`permissions: read-all`).

---

## 21. XML External Entity (XXE) Injection

- **CWE:** CWE-611 (Improper Restriction of XML External Entity Reference)
- **MITRE ATT&CK:** [T1190 - Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/)
- **MITRE D3FEND:** `d3f:InputValidation`

### Mechanics & Source-to-Sink
XML parser parses documents with external entity resolution or DTD processing enabled (`libxml`, `DOMParser`), allowing attackers to include `<!ENTITY xxe SYSTEM "file:///etc/passwd">`.

### SAST Rule (Semgrep Pattern)
```yaml
rules:
  - id: insecure-xml-parser-entities
    languages: [javascript, typescript, python]
    severity: HIGH
    message: "XML parser configured without explicitly disabling external entities."
    patterns:
      - pattern: libxmljs.parseXml($INPUT, { noent: true })
      - pattern: xml.etree.ElementTree.parse(...)
```

### Safe DAST Staging Probe
- **Methodology:** Send XML document with benign internal entity reference `<!ENTITY test "canary">` in staging.

### Strict 7-Question Gate Checklist
1. **Direct Exploitability:** External entity resolves local file or initiates outbound connection.
2. **Access Prerequisites:** Public XML upload/API endpoint.
3. **Impact:** Local file disclosure or SSRF.
4. **Novelty:** Unsafe XML parser configuration.
5. **Scope:** XML ingest routes.
6. **Repro Steps:** XML payload with entity definition.
7. **Severity:** High.

### Remediation
- Configure XML parsers to completely disable DTDs (`disallow-doctype-decl`), external general entities, and external parameter entities. Prefer JSON where possible.
