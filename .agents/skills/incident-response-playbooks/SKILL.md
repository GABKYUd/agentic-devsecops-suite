---
name: incident-response-playbooks
description: >-
  Operational incident response playbooks for Phishing, Ransomware, AD compromise, C2 beaconing, Cloud credentials, Web app exploitation, Container/Kubernetes compromise.
  Use when responding to active security alerts, triage, or running incident tabletop exercises.
---

# Operational Incident Response Playbooks

This skill provides step-by-step incident response procedures adhering to NIST SP 800-61 Rev. 3 and CISA federal incident guidelines across six phases: **Detect -> Analyze -> Contain -> Eradicate -> Recover -> Post-Incident**.

---

## 1. Supported Incident Playbooks

| Incident Scenario | Primary Trigger | Lead Role | Playbook File |
|---|---|---|---|
| **Phishing / Suspicious Email** | User report, gateway alert, BEC indicators | SOC Analyst | [playbook-phishing-response.md](../../playbook-phishing-response.md) |
| **Ransomware / Mass Encryption** | Shadow copy deletion, entropy spikes, ransom note | IR Lead / Infra | [playbook-ransomware-response.md](../../playbook-ransomware-response.md) |
| **Active Directory Compromise** | Kerberoasting, DCSync rights, LSASS dump, Mimikatz | AD / Identity Team | [playbook-ad-compromise-response.md](../../playbook-ad-compromise-response.md) |
| **C2 Beacon Detected** | Periodic jitter outbound traffic, JA3/JA4 anomaly | SOC / Network | [playbook-c2-beacon-response.md](../../playbook-c2-beacon-response.md) |
| **Cloud Credential Compromise** | GuardDuty anomaly, public secret leak, rogue IAM | Cloud / Platform | [playbook-cloud-credential-compromise.md](../../playbook-cloud-credential-compromise.md) |
| **Web App Exploitation** | WAF spike, webshell file, 5xx anomaly, ffuf burst | AppSec / Dev Lead | [playbook-web-app-exploitation.md](../../playbook-web-app-exploitation.md) |
| **Container / K8s Compromise** | Rogue `kubectl exec`, container escape syscall | Platform / K8s | [playbook-container-kubernetes-compromise.md](../../playbook-container-kubernetes-compromise.md) |

---

## 2. Standard 6-Phase Lifecycle

For any active incident, follow the structured response progression:

1. **Phase 1: Detect**
   - Triage alert source (SIEM, EDR, WAF, CloudTrail).
   - Capture initial indicators (IPs, hashes, user accounts, timestamps).
   - Open ticket and declare incident severity.

2. **Phase 2: Analyze**
   - Trace scope and blast radius (which accounts, hosts, or namespaces were touched).
   - Determine patient zero and initial access vector.
   - Check for pre-encryption staging or data exfiltration.

3. **Phase 3: Contain**
   - Isolate affected hosts from the network via EDR.
   - Disable compromised identities and revoke active session tokens (token revocation survives password reset).
   - Block malicious IPs/domains at perimeter WAF/firewall/DNS.

4. **Phase 4: Eradicate**
   - Rebuild affected systems from clean images rather than attempting manual cleaning.
   - Rotate all credentials that were active on or reachable from compromised systems (e.g. `krbtgt` twice for AD compromise).
   - Patch the underlying entry vector.

5. **Phase 5: Recover**
   - Restore workloads from verified immutable/offline backups.
   - Reconnect restored infrastructure in monitored, phased cohorts.
   - Enforce heightened telemetry observation windows (1–4 weeks).

6. **Phase 6: Post-Incident**
   - Conduct blameless root-cause analysis (identify system failure, not "human error").
   - Author permanent Sigma detection rules and add automated regression tests.
   - Fulfill regulatory and legal breach notification obligations in parallel.

---

## 3. Automation via MCP

Retrieve full playbook texts instantly using the MCP server:
```json
{
  "name": "get_incident_playbook",
  "arguments": {
    "incident_type": "ad_compromise"
  }
}
```
Available types: `phishing`, `ransomware`, `ad_compromise`, `c2_beacon`, `cloud_credential`, `web_app_exploitation`, `container_k8s`.
