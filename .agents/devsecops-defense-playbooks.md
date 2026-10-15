# DevSecOps Defense Playbooks & Frameworks (Companion)

Purpose: companion to `devsecops-threat-knowledge.md` and
`devsecops-pentest-tools-reference.md`. Where those two files map offensive
tools/techniques to individual controls, this file collects the actual published
playbooks, frameworks, and rule repositories your team can adopt wholesale rather
than building detection/response content from scratch. Current as of Aug 2026 —
these bodies of guidance get revised; re-check the source before treating any
version number below as final.

---

## 1. Foundational incident-response frameworks

**NIST SP 800-61 Rev. 3 — "Incident Response Recommendations and Considerations
for Cybersecurity Risk Management"** (published April 2025, csrc.nist.gov)
NIST withdrew the long-standing Rev. 2 ("Computer Security Incident Handling
Guide," with its Prepare→Detect/Analyze→Contain/Eradicate/Recover→Post-Incident
lifecycle) and replaced it with Rev. 3, which reorganizes incident response around
the six CSF 2.0 functions instead: Govern, Identify, Protect, Detect, Respond,
Recover. If any older internal playbook or training material still cites the Rev. 2
four-phase model as current, it's referencing a withdrawn document — worth a
find-and-replace pass. Source: https://csrc.nist.gov/projects/incident-response

**CISA Federal Government Cybersecurity Incident and Vulnerability Response
Playbooks** — two playbooks (incident response + vulnerability response) with
checklists built for federal agencies but explicitly designed to be adapted by any
organization. Good starting skeleton if you don't have a playbook template yet.
Source: https://www.cisa.gov/resources-tools/resources/federal-government-cybersecurity-incident-and-vulnerability-response-playbooks

**CIS Critical Security Controls v8.1** — 18 controls / safeguards organized into
three Implementation Groups (so a small team isn't expected to implement the same
scope as an enterprise). Functions as the baseline hygiene layer underneath
everything else in this file — most of the tool-specific defenses in the companion
tools doc trace back to one of these 18 controls (asset inventory, access control
management, secure configuration, continuous vulnerability management, etc.).
Source: https://www.cisecurity.org/controls/v8-1

> Worth internalizing: a real-world illustration of why this matters — in mid-2026
> a U.S. federal cybersecurity agency publicly acknowledged it had to build its own
> incident-response playbook *during* an active incident because one didn't already
> exist. The lesson generalizes: playbooks are only useful if they exist and are
> rehearsed before the day you need them.

## 2. Threat-specific playbooks

**#StopRansomware Guide** (CISA + FBI + NSA + MS-ISAC, Joint Ransomware Task Force)
— two-part guide: Part 1 is prevention/hardening best practices (asset management,
least privilege, cloud backup guidance, restricting PowerShell, securing domain
controllers, hardening SMB); Part 2 is a detection→analysis→containment→
eradication→recovery checklist specific to ransomware/data-extortion incidents.
Recommendations are mapped to CISA's Cross-Sector Cybersecurity Performance Goals.
Source: https://www.cisa.gov/stopransomware/stopransomware

**AWS Security Incident Response playbooks** — AWS publishes both a Security
Incident Response User Guide (what to include in a playbook, sample playbooks in
Appendix B) and a public GitHub template repo, refreshed in 2026 and realigned to
NIST SP 800-61r3, covering scenarios like credential compromise, S3 exposure, and
GuardDuty-finding response, with newer AI-assisted variants that keep a
human-in-the-loop before any action that modifies the environment.
Sources: https://docs.aws.amazon.com/security-ir/latest/userguide/develop-incident-response-playbooks.html
and https://github.com/aws-samples/aws-incident-response-playbooks

**Microsoft incident response playbooks** — platform-agnostic-leaning playbooks for
phishing, password spray, token theft, app consent grant abuse, and compromised/
malicious application scenarios, plus Azure-specific guidance aligned to NIST
800-61 phases. Microsoft Sentinel operationalizes the response side through SOAR
playbooks built on Azure Logic Apps, triggered automatically via automation rules
or run manually against a specific incident/alert/entity.
Source: https://learn.microsoft.com/en-us/azure/security/fundamentals/incident-response-overview

**NSA/CISA Kubernetes Hardening Guidance (v1.2)** — the standard reference for
securing Kubernetes clusters: scan images for vulnerabilities/misconfig, run
containers as non-root with least privilege, encrypt etcd at rest with mutual TLS
to the API server, disable anonymous authentication on control-plane interfaces,
enforce RBAC, never expose the API server to the internet, log broadly (audit
logs, metrics, seccomp). Directly closes the gaps that kube-hunter and similar
tools probe for. Source: https://media.defense.gov/2022/Aug/29/2003066362/-1/-1/0/CTR_KUBERNETES_HARDENING_GUIDANCE_1.2_20220829.PDF

**OWASP Top 10 / ASVS / WSTG** — use together, not separately: Top 10 (2025
edition is current) tells you what the major web risks are; the Application
Security Verification Standard gives testable, leveled requirements (L1 baseline
→ L3 high-assurance) to verify your defenses against them; the Web Security
Testing Guide gives testers a methodology. This is the direct counter-program to
the web-app tooling category (Burp/ZAP/sqlmap/ffuf) in the companion tools doc.
Available at owasp.org.

**Microsoft Enterprise Access Model / AD DS Tier Model** — the standard
countermeasure to nearly every AD attack tool in the companion doc (BloodHound,
Impacket, Rubeus, Responder, CrackMapExec/NetExec). Segments identities, devices,
and admin workflows into Tier 0 (domain controllers, forest/enterprise admins),
Tier 1 (server/app admins), and Tier 2 (workstation/help-desk), enforced with
Privileged Access Workstations, gMSA service accounts, LAPS for local admin
password rotation, Credential Guard, the Protected Users group, and Authentication
Silos. Microsoft's own telemetry has attributed a large share of breached
customers to having no privilege isolation in AD via a tiered model — this is
one of the highest-leverage single changes available to an AD-heavy environment.
Source: https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/tier-model

## 3. Detection engineering & purple-team validation

This is the layer that turns "we know Cobalt Strike/Mimikatz/Impacket exist" into
"our SIEM actually fires when they're used." Use these three together:

**MITRE ATT&CK + Center for Threat-Informed Defense** — the shared vocabulary for
tactics/techniques; the Center's "Top ATT&CK Techniques" project helps prioritize
which techniques matter most for your threat model instead of trying to cover the
entire matrix at once.

**MITRE D3FEND** — a knowledge graph that maps defensive countermeasures directly
to the ATT&CK techniques they counter (Hardening, Detection, Deception, Isolation,
Eviction categories). Reached 1.0 general availability in January 2025 and
extended to operational-technology environments in December 2025. Use it to go
from "we're worried about OS Credential Dumping (T1003)" to a concrete list of
named countermeasure techniques. Source: https://d3fend.mitre.org/

**SigmaHQ / Sigma rules** — a vendor-neutral, YAML-based detection-rule format
with an open GitHub repository of 15,000+ community-contributed rules, each
mapped to ATT&CK techniques and log sources, released under the Detection Rule
License. Rules convert to Splunk SPL, Microsoft Sentinel/Elastic KQL, and other
SIEM-native query languages via pySigma/sigma-cli, so one rule set covers multiple
platforms and stays under version control like code. This is the fastest path
from "we listed Mimikatz/Responder/Kerberoasting as things to detect" to an actual
deployed detection. Source: https://github.com/SigmaHQ/sigma

**Atomic Red Team** (Red Canary) — a library of small, self-contained tests, each
mapped to one ATT&CK technique, that you run against your own environment (via the
Invoke-Atomic execution framework) to check whether your EDR/SIEM actually
generates an alert. Coverage can be visualized directly on the ATT&CK Navigator —
colored cells show which techniques you've tested and which produced a detection,
making gaps visible at a glance. This is how you validate the Sigma rules above
actually fire, rather than assuming they do. Source: https://github.com/redcanaryco/atomic-red-team

## 4. How this fits together

A practical adoption order, mapped to what's already in the companion docs:

1. **Baseline** — implement CIS Controls v8.1 as the hygiene floor (asset inventory,
   access control, secure config, patch/vuln management).
2. **Structure your response program** — use NIST 800-61r3's six CSF functions as
   the scaffolding; adapt CISA's federal playbooks as your first-draft templates.
3. **Prioritize by what's most likely to hit you** — start detection engineering
   with the tools flagged **[HIGH-FREQUENCY]** in the tools companion doc (Cobalt
   Strike, Mimikatz, Impacket, Responder, CrackMapExec/NetExec, BloodHound-informed
   lateral movement).
4. **Pull, don't write from scratch** — grab the relevant Sigma rules for those
   techniques instead of authoring detections blind.
5. **Validate, don't assume** — run the matching Atomic Red Team tests against your
   own environment and confirm the Sigma-derived alerts actually fire.
6. **Layer domain-specific hardening** — AD tier model, Kubernetes hardening guide,
   OWASP ASVS, ransomware-specific playbook, cloud-provider playbooks — on top of
   the baseline, targeted at whichever of these environments you actually run.
7. **Rehearse** — tabletop the playbooks before an incident, not during one.

## 5. Usage guidance for this assistant

- Use this file to help design detection engineering roadmaps, incident response
  plans, tabletop exercises, and hardening backlogs, cross-referencing the tool and
  technique tables in the companion docs.
- Prefer adapting the named frameworks/playbooks above over generating incident
  response procedures from scratch — they're maintained, peer-reviewed, and
  already mapped to ATT&CK where relevant.
- Flag when a cited framework version may be stale (frameworks like these get
  revised on their own schedule) and suggest verifying against the source link.
- As with the other companion files: reason about detection and defense, don't
  generate operational attack content.
