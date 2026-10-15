---
name: vuln-hunting-injection-rce
description: >-
  Deep inspection heuristics for SQLi, NoSQLi, Command Injection, SSTI, Deserialization, and XXE.
  Use when analyzing code for untrusted data reaching database engines, system shells, or deserialization routines.
---

# Vulnerability Hunting: Injection & Remote Code Execution

This skill guides deep code-level dataflow inspections to discover and remediate high-severity injection and execution flaws.

---

## 1. Targeted Vulnerability Classes

| ID | Class Name | CWE | MITRE ATT&CK | Primary Risk |
|---|---|---|---|---|
| `sqli` | SQL Injection | CWE-89 | T1190 | Unparameterized query concatenation |
| `nosqli` | NoSQL Injection | CWE-943 | T1190 | Passing raw objects (`$ne`, `$gt`, `$regex`) to Mongo filters |
| `command_injection` | OS Command Injection | CWE-78 | T1059 | Unsanitized input into shell interpreters |
| `ssti` | Server-Side Template Injection | CWE-1336 | T1190 | User input passed directly to template engines (`renderString`) |
| `deserialization` | Insecure Deserialization | CWE-502 | T1190 | Parsing untrusted serialized objects (pickle, java, yaml.load) |
| `xxe` | XML External Entity Injection | CWE-611 | T1190 | Parsing XML with external entities enabled |

---

## 2. Inspection Heuristics & Search Patterns

### 2.1 SQL Injection
- Look for string interpolation in database calls:
  - `db.query("... " + req.query.id)`
  - `db.query(`SELECT * FROM users WHERE email = '${req.body.email}'`)`
  - `sequelize.literal(...)` or `prisma.$queryRawUnsafe(...)`
- **Mitigation:** Ensure parameter binding is used (`db.query('SELECT * FROM users WHERE email = $1', [email])`).

### 2.2 NoSQL Injection
- Look for Express body-parser endpoints directly passing `req.body.field` without string casting into MongoDB queries:
  - `User.findOne({ username: req.body.username, password: req.body.password })`
  - Attack: Attacker sends `{"password": {"$ne": null}}` to bypass authentication.
- **Mitigation:** Enforce string casting or Zod/Joi schema validation (`String(req.body.password)`).

### 2.3 Command Injection
- Look for commands built with user input:
  - `exec("convert " + req.body.filename + " output.png")`
  - `execSync(`ping -c 1 ${req.query.ip}`)`
- **Mitigation:** Use `execFile` or `spawn` with an array of arguments, never passing strings to a shell.

### 2.4 SSTI & Deserialization
- Check for Jinja2, EJS, Pug, Handlebars evaluating dynamic strings:
  - `ejs.render(req.body.template, data)`
- Check for `node-serialize.unserialize()`, Python `pickle.loads()`, or `yaml.load()` without `SafeLoader`.

---

## 3. Benign Staging Validation Probes
When authorized in local or staging environments:
- **SQLi Probe:** Inject single quotes `'` or arithmetic `' OR 1=1 --` to observe syntax errors or altered logic.
- **NoSQLi Probe:** Send JSON body with `{"$ne": null}`.
- **Command Injection Probe:** Inject benign command separators `; echo 'BENIGN_TEST'` or `& timeout 1`.

---

## 4. Triage & Output Integration
1. Validate every finding through the **7-Question Gate** via [bug-bounty-validator-gate](../bug-bounty-validator-gate/SKILL.md) or the MCP tool `evaluate_7_question_gate`.
2. Retrieve the complete matrix specifications using the MCP tool:
   ```json
   { "vuln_name": "sqli" }
   ```
3. Append finding to `findings-manifest.json` with code status `BLOCKING` and generate the developer remediation PR patch and blue team Sigma rule.
