---
name: threat-intel-skills-distiller
description: >-
  Ingests CVEs, bug bounty write-ups, and threat disclosures to auto-generate Semgrep rules, regression tests, and Sigma signatures.
  Use when converting external threat intelligence or newly disclosed vulnerabilities into concrete defensive controls.
---

# Threat Intelligence Skills Distiller

This skill automates the translation of external vulnerability disclosures, CVE advisories, and threat intelligence reports into actionable, permanent defensive controls.

---

## 1. Distillation Workflow: From Advisory to Defense

Whenever a new CVE, security advisory, or incident report is analyzed, follow the 3-pillar distillation process:

```
┌────────────────────────────────────────────────────────────────────────┐
│                   Threat Intelligence Distillation Pipeline            │
├────────────────────────────────────────────────────────────────────────┤
│                                                                        │
│   [CVE / Disclosure Advisory]                                          │
│              │                                                         │
│              ├──► Pillar 1: Semgrep SAST Rule (Prevent Code Insertion) │
│              │                                                         │
│              ├──► Pillar 2: Automated Regression Test (Verify Fix)     │
│              │                                                         │
│              └──► Pillar 3: Sigma Detection Rule (Monitor EDR / SIEM)  │
│                                                                        │
└────────────────────────────────────────────────────────────────────────┘
```

---

## 2. Pillar 1: Semgrep SAST Rule Generation

Convert the root-cause code pattern into a custom Semgrep YAML rule placed in `.agents/rules/` or CI/CD.

### Rule Template:
```yaml
rules:
  - id: custom-cve-pattern-check
    languages: [javascript, typescript, python]
    severity: ERROR
    message: "Potential pattern matching CVE-XXXX-XXXX detected: [Explanation]"
    metadata:
      cwe: "CWE-XXX"
      cve: "CVE-XXXX-XXXX"
      mitre_attack: "T1190"
    patterns:
      - pattern: $VULNERABLE_FUNCTION(...)
      - pattern-not: $SANITIZED_CALL(...)
```

---

## 3. Pillar 2: Automated Regression Unit Test

Generate a repeatable unit or integration test that reproduces the boundary condition without relying on weaponized exploits:

```javascript
describe('Security Regression: CVE-XXXX-XXXX', () => {
  it('should reject malformed or nested object payloads with 400 Bad Request', async () => {
    const res = await request(app)
      .post('/api/vulnerable-endpoint')
      .send({ input: { $ne: null } });

    expect(res.status).toBe(400);
    expect(res.body).not.toHaveProperty('internal_data');
  });
});
```

---

## 4. Pillar 3: Sigma Detection Rule for SIEM/EDR

Generate a Sigma-formatted rule to detect runtime exploitation attempts across web logs, EDR process events, or cloud audit trails:

```yaml
title: Detection for Exploit Pattern Matching CVE-XXXX-XXXX
status: experimental
description: Detects attempts to exploit CVE-XXXX-XXXX via specific URI or payload syntax.
logsource:
  category: webserver
detection:
  selection:
    cs-method: ['POST', 'PUT']
    cs-uri-stem|contains: '/api/vulnerable-endpoint'
    cs-uri-query|contains: 'suspicious_token'
  condition: selection
level: high
```

---

## 5. Automation via MCP
Use the MCP tools:
- `lookup_vulnerability_class`: Retrieve baseline patterns and CWE mappings.
- `get_detection_rule`: Search existing starter Sigma templates for tuning.
