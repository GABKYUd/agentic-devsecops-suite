# Detection Rules Starter Reference

Purpose: illustrative, Sigma-formatted starting templates for the
**[HIGH-FREQUENCY]** techniques flagged in `devsecops-pentest-tools-reference.md`.
These are teaching/tuning templates, not drop-in production rules — every
`filter_known` / threshold section needs to be adjusted to your own
environment's baseline before deployment, and each should be cross-checked
against the current maintained rule in the SigmaHQ repository
(github.com/SigmaHQ/sigma) rather than treated as authoritative on its own.

Validate every rule below with the matching Atomic Red Team test
(`devsecops-defense-playbooks.md` §3) before trusting it in production —
a rule that looks correct on paper and a rule that actually fires are two
different things.

---

## 1. LSASS memory access by an uncommon process (credential dumping / Mimikatz)

```yaml
title: Potential LSASS Memory Access by Uncommon Process
status: experimental
description: >
  Detects a process other than expected security tooling opening a
  high-privilege handle to lsass.exe — a common precursor to credential
  dumping.
logsource:
  category: process_access
  product: windows
detection:
  selection:
    TargetImage|endswith: '\lsass.exe'
    GrantedAccess:
      - '0x1010'
      - '0x1410'
      - '0x1438'
  filter_known:
    SourceImage|endswith:
      # Populate with your actual EDR/AV agent paths
      - '\MsMpEng.exe'
      - '\YourEdrAgent.exe'
  condition: selection and not filter_known
falsepositives:
  - Legitimate EDR/AV/backup agents reading LSASS — tune filter_known.
level: high
```

## 2. Abnormal Kerberos service-ticket request volume (Kerberoasting)

```yaml
title: Excessive Kerberos TGS Requests From Single Account
status: experimental
description: >
  Flags an account requesting an unusually high number of service tickets
  (Event ID 4769) in a short window — consistent with automated
  Kerberoasting rather than normal user/service activity.
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4769
  timeframe: 5m
  condition: selection | count(TargetUserName) by SubjectUserName > 15
falsepositives:
  - Legitimate service accounts with high normal ticket volume — baseline
    per-account thresholds before enabling in blocking/alerting mode.
level: medium
```

## 3. DCSync-pattern replication request from a non-DC principal

```yaml
title: Possible DCSync Attack
status: experimental
description: >
  Detects a security principal other than a domain controller exercising
  directory-replication rights (Event ID 4662 with
  DS-Replication-Get-Changes / DS-Replication-Get-Changes-All GUIDs).
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4662
    Properties|contains:
      - '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2'  # DS-Replication-Get-Changes
      - '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2'  # DS-Replication-Get-Changes-All
  filter_known_dcs:
    SubjectUserName|in:
      # Populate with your actual domain controller computer accounts
      - 'DC01$'
      - 'DC02$'
  condition: selection and not filter_known_dcs
falsepositives:
  - Legitimate replication tooling/service accounts — must be explicitly
    allow-listed, not broadly excluded.
level: critical
```

## 4. Lateral movement — one account authenticating to many hosts quickly

```yaml
title: Single Account Authenticating to Many Hosts in Short Window
status: experimental
description: >
  Correlation rule (not a single-event Sigma rule) for the
  CrackMapExec/NetExec-style lateral-movement signature: one credential
  used against an abnormal number of distinct hosts in a short period.
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID:
      - 4624  # successful logon
      - 4625  # failed logon
    LogonType:
      - 3     # network logon
  timeframe: 10m
  condition: selection | count(distinct TargetComputerName) by SubjectUserName > 8
falsepositives:
  - Legitimate admin/automation accounts performing fleet-wide operations —
    allow-list known automation identities explicitly.
level: high
```

## 5. C2 beaconing heuristic (network-layer, not host-layer)

Not a Sigma process/registry rule — this needs a network-flow or proxy log
source with periodicity analysis:

- **Signal**: outbound connections to the same destination at intervals
  that vary within a narrow jitter band (e.g. 55–65 seconds, repeating)
  over a sustained period (hours, not minutes).
- **Enrichment**: cross-reference destination IP/domain against threat
  intel, and compute a JA3/JA4 TLS client fingerprint — known C2 frameworks
  often reuse identifiable TLS stacks across campaigns.
- **Tooling note**: this is typically implemented in your NDR/network
  analytics platform or a custom detection (e.g. RITA-style beacon
  analysis) rather than a single Sigma rule, since it requires aggregation
  over time rather than single-event matching.

## 6. SQL Injection Attempt in Web Application Logs

```yaml
title: SQL Injection Query Patterns in Web Logs
status: experimental
description: >
  Detects SQL injection signatures (UNION SELECT, boolean delays, database
  schema enumeration) in web server request URI parameters.
logsource:
  category: webserver
detection:
  selection:
    cs-method: ['GET', 'POST']
    cs-uri-query|contains:
      - 'UNION SELECT'
      - 'UNION ALL SELECT'
      - "' OR '1'='1"
      - 'SLEEP('
      - 'WAITFOR DELAY'
      - 'information_schema'
  condition: selection
falsepositives:
  - Internal automated vulnerability scanning jobs — exclude authorized scanner source IPs.
level: high
```

## 7. Cloud Metadata SSRF Request from Application Tier

```yaml
title: Outbound HTTP Request to Cloud Instance Metadata Service (IMDS)
status: stable
description: >
  Detects network connections from application workloads to the link-local
  cloud metadata address (169.254.169.254) — indicator of SSRF or IMDS token theft.
logsource:
  category: network_connection
detection:
  selection:
    DestinationIp: '169.254.169.254'
    DestinationPort: 80
  filter_system_agents:
    Image|endswith:
      - '/amazon-ssm-agent'
      - '/cloud-init'
      - '/google_guest_agent'
  condition: selection and not filter_system_agents
falsepositives:
  - Authorized host configuration agents — add to filter_system_agents.
level: critical
```

## 8. CI/CD Workflow Modification or Runner Tampering

```yaml
title: Modification of GitHub Actions Workflow Files by Non-Admin Identity
status: experimental
description: >
  Detects commits modifying .github/workflows/*.yml files pushed directly or
  authored by unexpected automation accounts.
logsource:
  product: github
  service: audit
detection:
  selection:
    action: 'git.push'
    repo.path|startswith: '.github/workflows/'
  filter_authorized_maintainers:
    actor|in:
      # Populate with your senior release engineers / approved bot identities
      - 'lead-devops'
      - 'release-bot'
  condition: selection and not filter_authorized_maintainers
falsepositives:
  - Legitimate feature PRs touching workflows — verify review approval before dismissing.
level: high
```

---

## Coverage checklist

| Technique | Rule above | Sentinel native event | Atomic Red Team / Purple Validation |
|---|---|---|---|
| Credential dumping (LSASS) | §1 | — (host-layer only) | Test the matching T1003.001 atomic |
| Kerberoasting | §2 | — (AD-layer only) | Test the matching T1558.003 atomic |
| DCSync | §3 | — (AD-layer only) | Test the matching T1003.006 atomic |
| Lateral movement | §4 | — (network-layer only) | Test the matching T1021 atomic |
| C2 beaconing | §5 | — (NDR-layer only) | Run a benign beacon simulator and confirm the heuristic fires |
| SQL Injection | §6 | `INTRUSION_ANNEXED_SQLI` | Run benign `' OR 1=1 --` query in staging — verify Sentinel audit event fires |
| Cloud Metadata SSRF | §7 | `INTRUSION_ANNEXED_SSRF` | Send safe `169.254.169.254` probe in staging — verify Sentinel audit event fires |
| CI/CD Runner Poisoning | §8 | — (GitHub audit log only) | Test workflow modification check in test branch |
| Pentest tool use (sqlmap, Nuclei, etc.) | — (App-layer) | `INTRUSION_ANNEXED_<TOOL>` | Run any fingerprinted security tool — verify SIEM/SOC event fires |
| Directory fuzzing (ffuf/Gobuster) | — (App-layer) | `DISCOVERY_BURST_DETECTED` | Fire >20 requests to non-existent `/api/*` paths in 60s — verify event fires |
| Honeypot / canary access | — (App-layer) | `HONEYPOT_TRIGGERED_CRITICAL` | Access any of the 16 canary endpoints in staging — verify permanent quarantine + siren |
| Distributed password spray | — (App-layer) | `DISTRIBUTED_SPRAY_DETECTED` | Attempt login to the same account from 3+ distinct IPs in 15 min — verify event |
| Honey-user login attempt | — (App-layer) | `HONEY_USER_TRIPPED_CRITICAL` | Attempt login to `canary_admin_backup` — verify permanent quarantine |
| JWT token replay (browser→tool) | — (App-layer) | `ANOMALY_TOKEN_MUTATION_CRITICAL` | Re-use a browser-minted JWT from curl — verify CRITICAL anomaly event fires |
| IP anomaly (login from new IP) | — (App-layer) | `ANOMALY_IP_CHANGE` | Log in from a different IP — verify audit event fires |

Run each test in staging, confirm the corresponding Sentinel event or Sigma/SIEM rule fires, and only then consider that technique "covered" — an untested rule is a guess, not a control.

---

## Application SOC Native Audit Event Taxonomy

The following `action_type` values represent standard audit event identifiers produced by modern application security and SIEM/SOC engines. Use these as `sigma_rule_id` values in `findings-manifest.json` entries:

| action_type | Trigger | ATT&CK | Severity | Fired by |
|---|---|---|---|---|
| `INTRUSION_ANNEXED_<TOOL_TYPE>` | Offensive tool fingerprint match (40+ tools) | T1190 / T1595 | CRITICAL/HIGH | `threatMiddleware` |
| `HONEYPOT_TRIGGERED_CRITICAL` | Access to any of 16 canary endpoints | T1595.002 | CRITICAL | `botDefense.honeypotTrap` |
| `DISCOVERY_BURST_DETECTED` | >20 requests to non-existent `/api/*` in 60s | T1595.003 | HIGH | `discoveryMiddleware` |
| `DISTRIBUTED_SPRAY_DETECTED` | ≥3 distinct IPs targeting same account in 15 min | T1110.003 | CRITICAL | `surfaceDefense.recordAccountProbe` |
| `HONEY_USER_TRIPPED_CRITICAL` | Login attempt to a decoy honey-token account | T1552 | CRITICAL | `surfaceDefense.isHoneyUser` |
| `PASSWORD_SPRAY_DETECTED` | 1 IP attempting ≥5 distinct accounts in 15 min | T1110.003 | CRITICAL | `auth.routes.trackSpray` |
| `THREAT_ANOMALY_MISSING_UA` | Missing User-Agent header | T1059 | MEDIUM | `botDefenseMiddleware` |
| `THREAT_AI_BOT_BLOCKED` | Known AI scraper User-Agent matched | — | LOW | `botDefenseMiddleware` |
| `THREAT_HEADLESS_SCRAPER_BLOCKED` | Headless browser / scripting UA matched | T1059 | MEDIUM | `botDefenseMiddleware` |
| `ANOMALY_TOKEN_MUTATION_CRITICAL` | JWT presented by tool, originally minted for browser | T1539 | CRITICAL | `authenticateUser` |
| `ANOMALY_IP_CHANGE` | Successful login from new IP vs. last known | T1078 | INFO | `auth.routes.login` |
| `ANOMALY_UA_CHANGE` | Significant User-Agent change on login | T1078 | INFO | `auth.routes.login` |
| `LOGIN_FAILED` | Failed password attempt | T1110.001 | WARNING | `auth.routes.login` |
| `LOGIN_FAILED_2FA` | Failed TOTP code attempt | T1110.001 | WARNING | `auth.routes.login` |
| `IDOR_PROBING_ATTEMPT` | `assertOwnership()` failed — cross-tenant resource access | T1078 | HIGH | `assertOwnership` |
| `RBAC_DENIED` | Unauthorized RBAC action attempted | T1078 | HIGH | `authorize` middleware |
| `AUDIT_ONLY_<TOOL_TYPE>` | Tool matched but detection rule disabled by SOC policy | — | MONITOR | `threatMiddleware` |

