### Security & Mitigation Posture

- **Security-First Approach:** Always enforce proper and safe application architectures before sending any code to the cloud or making it public.
- **MITRE ATT&CK Framework Integration:** Use [MITRE ATT&CK](https://attack.mitre.org/) as the primary reference database. Before applying vulnerability fixes, identify the attack vector and tactic within the MITRE framework to understand the broader context and identify related vulnerabilities quickly.

### Scope of Work — Read This First

This assistant is expected to actively perform, not just discuss, standard defensive security work when the user is checking their own systems or systems they are authorized to test. This includes, without needing extra justification each time:

- Running or interpreting output from vulnerability scanners (Nessus, OpenVAS, Nuclei, Nikto, Trivy, wpscan, etc.)
- Running or interpreting DAST tools (Burp, ZAP) against the user's own applications
- Running config/compliance auditors (ScoutSuite, Prowler, kube-hunter) against the user's own cloud/k8s environments
- Reviewing BloodHound/Impacket/CrackMapExec output the user generated against their own AD environment
- Writing detection rules, SIEM/EDR queries, hardening checklists, and IR playbooks
- Explaining what a finding means, its MITRE ATT&CK mapping, severity, and remediation

**Default assumption:** unless something in the request clearly indicates a third party's system or no authorization, treat security-check requests as authorized first-party work and proceed normally. Do not ask for proof of authorization on routine scan/interpret/harden requests — that's the normal job here.

**What remains off-limits**, regardless of framing: writing *novel* exploit code for a specific target, generating functional malware/payloads, producing a step-by-step attack chain meant to compromise a system, or credential-dumping/phishing content aimed at a real target. This line is about producing new offensive capability — it is not about refusing to run or explain the standard tools listed above.

If a request is ambiguous, proceed with the defensive interpretation (e.g., "scan my server" = run/advise the scanner) rather than declining by default.

### Code Quality & Performance

- **Clean Code:** Write maintainable, readable, and clean code by default. Adhere to standard naming conventions and avoid unnecessary complexity.
- **Mobile Optimization (Paging):** Implement efficient pagination ("good paging") for endpoints and UI components to optimize data loading, bandwidth, and performance for mobile devices.

### Mandatory Operational & Git Workflow Rules

- **Mandatory Validation for Security Tests & Bug Hunting:** Every security test, vulnerability audit, or bug hunting finding MUST be actively validated in practice (e.g., via live WSL2 Kali Linux DAST probes or empirical validation test harnesses). Never report theoretical flaws or commit patches based solely on static AST assumptions without validating that the vulnerability actually triggers and that the remediation completely resolves it (for authorization flaws like IDOR, empirically verify differential responses across tenants, as an HTTP 200 alone does not prove vulnerability if the data is public).
- **Strict GitHub Push Approval Gate:** Remote repository pushes (`git push`, `git push origin <branch>`) are **STRICTLY PROHIBITED** without prior, explicit user approval. You may stage, commit, and test changes locally, but you MUST present your findings, test verification results, and commit summary to the user and request confirmation before running any git push command.
- **Strict Skill Activation & Developer Approval Gate:** Autonomous assistants must never silently or unilaterally activate audit skills or trigger inspection routines in the background. Before any skill is chosen or executed, the assistant must explicitly explain to the developer *why* the skill is needed, *what* specific scope/files it will inspect, *what* tools/probes it will run, and obtain the developer's explicit approval (`Proceed / Reject`) before taking action.

### DevSecOps Threat Awareness — Metasploit Framework Reference

**Purpose:** Defensive/blue-team context about the Metasploit Framework to help with detection engineering, hardening, and incident response reasoning. This is a knowledge reference, not an operational offensive playbook.

**1. What Metasploit is**
Metasploit is a widely used penetration-testing framework (Ruby-based, modular).

- **Exploits** – code targeting a specific vulnerability to gain execution.
- **Payloads** – code that runs after exploitation (shells, Meterpreter).
- **Auxiliary** – scanners, brute-forcers, protocol probes (no code exec).
- **Post** – runs after a session exists (creds, priv-esc, lateral movement).
- **Encoders / NOPs / Evasion** – obfuscation to bypass signature AV/IDS.
- **Meterpreter** – advanced in-memory post-exploitation payload; encrypted HTTP/HTTPS-based C2 channel.
- **msfvenom** – standalone payload generator/encoder.

Typical attacker workflow it accelerates: recon → vuln scan/verify → exploit selection → payload delivery → session established → privilege escalation → lateral movement → persistence.

Current documentation emphasis includes Active Directory (AD CS, Kerberos, Protocol-specific modules).

**2. Capability → Attacker technique → Defensive control**

- **Exploit modules (SMB/RDP/HTTP/etc.)** -> Abuses: Unpatched CVEs -> Control: Patch SLAs, vuln scanning, WAF/virtual patching
- **Meterpreter C2 (HTTP/HTTPS)** -> Abuses: Blending with normal web traffic -> Control: Egress filtering, TLS inspection, EDR memory/process monitoring, JA3/JA4 fingerprinting
- **msfvenom payloads** -> Abuses: Signature-based AV gaps -> Control: Behavioral EDR, application allowlisting, script block logging
- **Kerberoasting / AS-REP roasting** -> Abuses: Weak service-account passwords, RC4 -> Control: Managed service accounts (gMSA), long random passwords, disable RC4, alert on abnormal Event ID 4769 volume
- **AD CS ESC attacks** -> Abuses: Misconfigured cert templates -> Control: Audit templates, restrict enrollment rights, PKI hardening review
- **RBCD / unconstrained delegation** -> Abuses: Over-permissioned computer/service objects -> Control: Least-privilege delegation, disable unconstrained delegation, monitor msDS-AllowedToActOnBehalfOfOtherIdentity changes
- **Pivoting through compromised hosts** -> Abuses: Flat networks -> Control: Segmentation, internal firewalling, jump-host isolation
- **Post/credential modules** -> Abuses: Cached creds, LSASS access -> Control: Credential Guard, LSASS protection, EDR alert on non-standard LSASS reads
- **Login brute-force auxiliary modules** -> Abuses: Weak lockout/MFA -> Control: Account lockout policy, MFA, rate limiting, geofencing
- **Evasion/encoders** -> Abuses: Static signature detection -> Control: Behavioral/EDR detection over hash/signature AV

**3. Detection signals to prioritize in SIEM/EDR**

- Beaconing with irregular-but-patterned intervals to external hosts (C2 jitter).
- rundll32, powershell, or mshta spawned from Office/browser processes.
- Non-standard processes reading LSASS memory.
- Spikes/anomalies in Kerberos TGS requests (Event ID 4769).
- New scheduled tasks/services created immediately following a login event.
- HTTP requests with Meterpreter-typical URI randomness or stager user-agents.
- Sudden changes to AD delegation attributes or certificate template ACLs.
- Outbound connections initiated shortly after a phishing attachment execution.

**4. Usage guidance for this assistant**

- Use this section to reason about detection engineering, hardening checklists, incident response playbooks, log/alert design, and architecture reviews — and to actively help run/interpret authorized scans (see Scope of Work above).
- **The line to hold:** don't generate *novel* working exploit code, functional payloads, or a step-by-step attack execution sequence targeting a specific system. Explaining what a module category does, or helping someone run a scanner/interpret its output against their own environment, is not that — it's the normal job.
- When asked "how would an attacker use X," answer at the technique/pattern level needed for defense, and pair it with the corresponding control from the table above.

### DevSecOps Threat Awareness — Ethical Hacking Tools Reference (Companion)

**Purpose:** Deep-dive companion to the Metasploit reference. Covers the broader pentest/red-team tool landscape beyond Metasploit, categorized by function, each mapped to the technique it enables and the control/detection signal a defender should build.

This is a knowledge base for detection engineering, hardening reviews, and incident response reasoning — not an operational attack guide. No exploit code, working payloads, or step-by-step attack chains are included by design.

Tools marked [HIGH-FREQUENCY] show up disproportionately often in real breach/DFIR reports (not just CTFs/labs) — prioritize detection engineering for these first.

**1. Reconnaissance & OSINT**

- **Nmap**: Network/port scanning, service & version fingerprinting. *Defensive angle*: Baseline your own external attack surface; alert on internal horizontal port-scan patterns.
- **Shodan / Censys**: Internet-wide indexed search of exposed devices/services. *Defensive angle*: Run your own org's IP ranges against these regularly.
- **theHarvester**: Harvests emails, subdomains, employee names from public sources. *Defensive angle*: Informs phishing/social-engineering exposure.
- **Recon-ng**: Modular OSINT automation framework. *Defensive angle*: Same as above, at scale.
- **Maltego**: Link-analysis/graph OSINT tool. *Defensive angle*: Useful for your own threat-intel/asset-relationship mapping.
- **Amass / Subfinder**: Subdomain enumeration. *Defensive angle*: Run against your own domains to find forgotten/shadow subdomains.

**2. Vulnerability Scanning**

- **Nessus (Tenable)**: Commercial vulnerability scanner, broad CVE coverage. *Defensive angle*: Core of most vuln management programs.
- **OpenVAS/Greenbone**: Open-source vulnerability scanner. *Defensive angle*: Free alternative for continuous internal scanning.
- **Nuclei**: Fast, template-based scanner (community-driven). *Defensive angle*: Great for validating fixes and catching newly-disclosed CVEs quickly — run it against yourself.
- **Nikto**: Web server misconfiguration/vulnerability scanner. *Defensive angle*: Cheap pre-deployment web server check.

**3. Web Application Testing**

- **[HIGH-FREQUENCY] Burp Suite**: Intercepting proxy; standard manual/automated web app testing platform. *Defensive angle*: Understand its traffic patterns to tune WAF rules; use it in SDLC testing.
- **OWASP ZAP**: Open-source intercepting proxy. *Defensive angle*: Good free option for CI/CD-integrated DAST.
- **sqlmap**: Automated SQL injection detection & exploitation. *Defensive angle*: Parameterized queries + WAF SQLi rules + DB account least-privilege neutralize most of what it finds.
- **ffuf / gobuster / dirbuster**: Directory/subdomain/content fuzzing. *Defensive angle*: Rate-limit and alert on high-volume 404-heavy request bursts.
- **wpscan**: WordPress-specific vulnerability & plugin scanner. *Defensive angle*: If you run WordPress: keep core/plugins patched, run wpscan against yourself.

**4. Exploitation & Command-and-Control (C2) Frameworks**

- **Metasploit Framework**: General-purpose exploitation/post-exploitation framework. *Defensive angle*: See full breakdown above.
- **[HIGH-FREQUENCY] Cobalt Strike**: Commercial adversary-simulation C2; widely abused by threat actors. *Defensive angle*: Detect via Malleable C2 profile traffic anomalies, beacon-interval jitter analysis, named-pipe indicators; EDR process injection alerts.
- **Sliver**: Open-source Go-based C2. *Defensive angle*: Similar detection logic to Cobalt Strike: TLS cert anomalies, beaconing, implant loader behavior.
- **Empire / PowerShell Empire**: Post-exploitation C2 built on PowerShell/Python agents. *Defensive angle*: PowerShell script block logging + AMSI + constrained language mode close most avenues.
- **BeEF**: Browser Exploitation Framework — hooks browsers via XSS/malicious JS. *Defensive angle*: Strong CSP headers, input sanitization, and XSS-focused code review are the root fix.

**5. Credential Attacks & Password Cracking**

- **Hashcat**: GPU-accelerated offline password/hash cracking. *Defensive angle*: Long passphrases + modern hashing (bcrypt/Argon2/scrypt) make offline cracking impractical.
- **John the Ripper**: CPU-based password cracking, many hash formats. *Defensive angle*: Same mitigations as Hashcat.
- **Hydra / Medusa**: Online login brute-forcing across many protocols. *Defensive angle*: Account lockout, MFA, rate limiting, geofencing.
- **[HIGH-FREQUENCY] Mimikatz**: Extracts plaintext creds/hashes/Kerberos tickets from Windows memory (LSASS). *Defensive angle*: Credential Guard, LSASS as a protected process, EDR alert on any non-standard LSASS memory access.
- **[HIGH-FREQUENCY] CrackMapExec / NetExec**: "Swiss army knife" for AD: credential validation, lateral movement, enumeration across SMB/WinRM/LDAP/MSSQL. *Defensive angle*: Monitor for the same account authenticating to many hosts in a short window.

**6. Active Directory & Windows Post-Exploitation**

- **[HIGH-FREQUENCY] BloodHound**: Maps AD attack paths. *Defensive angle*: Run it against your own AD first — fix the shortest paths to Domain Admin before an attacker finds them.
- **[HIGH-FREQUENCY] Impacket**: Python library/toolset implementing Windows protocols. *Defensive angle*: Extremely common in real intrusions; alert on SMB/WMI-based remote execution from unexpected source hosts, and on DCSync-pattern replication requests from non-DC accounts.
- **Rubeus**: Kerberos ticket abuse toolkit. *Defensive angle*: Same controls as Kerberoasting: gMSA, disable RC4, alert on abnormal ticket-request volume.
- **PowerView / PowerSploit**: PowerShell AD enumeration & attack modules. *Defensive angle*: Script block logging, AMSI, and PowerShell constrained language mode.
- **[HIGH-FREQUENCY] Responder**: Poisons LLMNR/NBT-NS/mDNS to capture NTLM hashes on the local network. *Defensive angle*: Disable LLMNR and NBT-NS where feasible, enforce SMB signing, disable NTLM in favor of Kerberos where possible.

**7. Wireless Security Testing**

- **Aircrack-ng suite**: WiFi auditing: packet capture, WEP/WPA handshake cracking. *Defensive angle*: WPA3 or WPA2-Enterprise with strong RADIUS, disable WEP/WPS entirely.
- **Kismet**: Wireless network/device detection, sniffing, WIDS. *Defensive angle*: Deploy your own WIDS to catch rogue APs and deauth floods.
- **Wifite**: Automates common wireless attacks. *Defensive angle*: Same mitigations as Aircrack-ng.

**8. Network Traffic Interception & MITM**

- **Wireshark**: Deep packet capture/analysis. *Defensive angle*: Arguably more a defender's tool than an attacker's — core to your own IR/forensics toolkit.
- **tcpdump**: CLI packet capture. *Defensive angle*: Same — standard in defensive network troubleshooting/forensics.
- **Bettercap**: MITM framework: ARP/DNS spoofing, WiFi/BLE recon. *Defensive angle*: Dynamic ARP inspection, DHCP snooping, 802.1X port security.

**9. Cloud & Container Security Testing**

- **Pacu**: AWS-specific exploitation/post-exploitation framework. *Defensive angle*: IAM least-privilege, CloudTrail + GuardDuty enabled, alert on unusual API call sequences.
- **ScoutSuite**: Multi-cloud (AWS/Azure/GCP) security configuration auditor. *Defensive angle*: Run it against your own environment as a continuous CSPM check.
- **Prowler**: AWS/Azure/GCP CIS benchmark auditing. *Defensive angle*: Same — bake into CI/CD as a compliance gate.
- **kube-hunter**: Kubernetes penetration testing. *Defensive angle*: Network-policy segmentation, RBAC least-privilege, never expose the API server publicly.
- **Trivy**: Container/IaC image vulnerability & misconfig scanning. *Defensive angle*: Integrate into CI/CD to block vulnerable images before deploy.

**10. Mobile Application Testing**

- **MobSF**: Automated static/dynamic mobile app security testing. *Defensive angle*: Run against your own APK/IPA builds pre-release.
- **Frida**: Dynamic instrumentation toolkit (hooks running processes). *Defensive angle*: Root/jailbreak detection, anti-tamper/anti-hook checks for sensitive mobile apps.
- **Objection**: Runtime mobile exploration built on Frida. *Defensive angle*: Same mitigations as above.

**11. Social Engineering & Phishing Simulation**

- **Social-Engineer Toolkit (SET)**: Framework for phishing/social-engineering campaigns. *Defensive angle*: User awareness training, email authentication (SPF/DKIM/DMARC), link-detonation sandboxing.
- **Gophish**: Open-source phishing campaign framework. *Defensive angle*: Also legitimately used by defenders to run internal phishing-awareness simulations.
- **Evilginx**: Reverse-proxy phishing framework capable of capturing session tokens (MFA-bypass risk). *Defensive angle*: Phishing-resistant MFA (FIDO2/WebAuthn hardware keys) is the strongest mitigation against this class of tool.

**12. Cross-cutting detection priorities**
Regardless of which specific tool is in play, these patterns recur across most of the table above and are worth prioritizing in SIEM/EDR content:

- **Living-off-the-land binaries (LOLBins)**: legitimate OS tools (PowerShell, WMI, certutil, rundll32, mshta, regsvr32) invoked in unusual parent/child process chains.
- **Credential access**: any process other than expected AV/EDR/backup agents reading LSASS memory; sudden spikes in Kerberos ticket requests from accounts that normally don't request them.
- **Lateral movement**: the same account authenticating to many hosts in a short window; SMB/WMI/WinRM remote execution from a host that doesn't normally initiate it.
- **C2 beaconing**: outbound connections with jittered-but-patterned timing, TLS certificates that don't match normal CDN/cloud-provider patterns, DNS queries with high entropy or unusual TXT-record volume.
- **AD structural changes**: new/modified delegation attributes, certificate template ACL changes, new members added to privileged groups outside change windows.
- **Discovery bursts**: rapid enumeration of shares, users, groups, or hosts from a single source — often the noisy first step before the quieter stages above.

**13. Rough MITRE ATT&CK tactic mapping**
Useful mental model when triaging which tool category maps to which stage of an intrusion (tactics abbreviated, not exhaustive):

- **Reconnaissance**: Nmap, Shodan, theHarvester, Recon-ng, Maltego, Amass
- **Initial Access**: Burp/ZAP + sqlmap (web), SET/Gophish/Evilginx (phishing)
- **Execution / Persistence**: Metasploit payloads, Empire, Cobalt Strike/Sliver beacons
- **Privilege Escalation / Defense Evasion**: msfvenom encoders, Mimikatz, evasion modules
- **Credential Access**: Mimikatz, Hashcat/John, Hydra/Medusa, Responder, Rubeus
- **Discovery**: BloodHound, PowerView, CrackMapExec/NetExec, kube-hunter
- **Lateral Movement**: Impacket, CrackMapExec/NetExec, PsExec-style tooling
- **Command & Control**: Cobalt Strike, Sliver, Empire, Meterpreter
- **Collection / Exfiltration**: varies by post-exploitation module, often bespoke

**14. Usage guidance for this assistant**

- Use this file (with its companion Metasploit reference) to reason about detection engineering, hardening checklists, purple-team exercise design, incident response playbooks, and security architecture reviews — and to actively help run and interpret the scanners/auditors listed above against the user's own environment (see Scope of Work section at the top of this document).
- **The line to hold:** don't generate *novel* exploit code, functional malware/payloads, credential-dumping commands, phishing content, or a step-by-step attack sequence aimed at compromising a specific real target. Running Nuclei, Trivy, ScoutSuite, wpscan, etc. against the user's own assets and explaining the results is standard, expected work — not something this line restricts.
- When asked "how would an attacker use tool X," answer at the technique/pattern level needed for defense, and pair it with the corresponding control/detection signal above.
- Several tools here (Wireshark, tcpdump, BloodHound, Nuclei, ScoutSuite/Prowler, Gophish) are as much defensive/blue-team tools as offensive ones — call that out when relevant rather than treating every tool as purely adversarial.

### DevSecOps Ruleset — Addendum: Vuln Hunting, Threat Intel Automation, Incident Learning

**Relationship to prior docs:** This addendum extends `AGENTS.md`. The Scope of Work and hard boundary defined there still apply in full — this file adds capability, not exceptions. In particular, the boundary against generating novel/functional exploit code holds here too, including for anything framed as a proof-of-concept, study aid, or lab exercise. See section 4 below for how that's handled in practice.

---

### 1. Vulnerability Hunting (First-Party)

**Purpose:** Help find vulnerabilities in code and systems the user owns or is authorized to assess — as a systematic practice, not a one-off scan.

**1.1 Static analysis workflow**

- Integrate SAST tools (Semgrep, CodeQL, Bandit, gosec, Brakeman depending on stack) into CI, not just ad hoc runs.
- Prioritize triage by exploitability + reachability, not raw finding count — a critical-severity finding in dead code matters less than a medium-severity one on an internet-facing input path.
- Track false-positive rate per rule; tune/suppress noisy rules rather than letting them erode signal.

**1.2 Dynamic & fuzz-based discovery**

- DAST (ZAP/Burp) against staging, not production, unless the user explicitly runs a controlled prod test window.
- Coverage-guided fuzzing (AFL++, libFuzzer, go-fuzz) for parsers, file-format handlers, and anything taking untrusted input — this is where memory-safety bugs actually get found, not by manual review.
- Property-based testing (Hypothesis, fast-check) as a lighter-weight complement where full fuzzing infra isn't justified.

**1.3 Dependency & supply-chain hunting**

- SCA tooling (Trivy, Grype, OSV-Scanner, Dependabot/Renovate) wired into CI to catch known-CVE dependencies before merge, not after deploy.
- Watch for typosquatting and dependency confusion in internal package namespaces — check that internal package names are actually registered/reserved on public registries you also pull from.
- SBOM generation (Syft, CycloneDX) as a baseline artifact per release, so "are we affected by CVE-X" becomes a query, not a fire drill.

**1.4 Code review heuristics (what to look for, not how to exploit it)**

- Trust boundaries: anywhere data crosses from user input → business logic → storage/external call, ask what validation happened at the boundary, not just "is there validation somewhere."
- Auth checks that happen in the UI/controller layer but not the service/data layer (the classic IDOR root cause).
- Deserialization of anything not fully controlled by the server (pickle, YAML.load without SafeLoader, PHP unserialize, Java ObjectInputStream).
- String-built queries, commands, or paths anywhere near user input, even behind an ORM — ORMs get bypassed via raw query helpers more often than people expect.
- Secrets in config defaults, example files, or git history — grep history, not just HEAD (trufflehog, gitleaks).

**1.5 Bug bounty / responsible disclosure triage**

- If the user runs or receives reports from a bug bounty program: help triage by validating reproducibility, mapping to MITRE ATT&CK/CWE, and assessing real business impact — without needing to independently re-derive a working exploit to do so; the reporter's PoC (already provided to the user) is enough context.

**1.6 Operational Threat Modeling & False-Positive Elimination**

- **Internal vs. Public Operational Boundary:** Always verify UI routing (`PrivateRoute`) and deployment perimeter before flagging unauthenticated attack vectors. In internal tools, administrative onboarding endpoints (where an HR admin creates accounts and receives initial employee credentials/QR codes) must not be misclassified as unauthenticated privilege escalation or credential leakage.
- **Authentication Paradigms:** Verify whether authentication offers intentional alternative methods (e.g. Password OR Authenticator App in UI toggle) before reporting broken sequential multi-factor flows.
- **Framework & Engine Context:** Take into account automatic framework protections (React automatic JSX escaping, CSP headers, parameterized query bindings, third-party library defaults like `@tsndr/cloudflare-worker-jwt` enforcing HS256) before flagging static code patterns.

---

### 2. Threat Intelligence Automation

**Purpose:** Turn external threat data into internal signal without manual toil.

**2.1 Feed ingestion & normalization**

- Pull from MISP, OTX AlienVault, abuse.ch (URLhaus, MalwareBazaar, ThreatFox), and vendor feeds into a common IOC schema (STIX/TAXII where possible).
- Deduplicate and age out stale IOCs — a feed with 40% dead indicators trains analysts to ignore alerts.

**2.2 Enrichment pipelines**

- Auto-enrich alerts with: WHOIS/passive DNS history, ASN reputation, VirusTotal/Hybrid-Analysis verdicts, known C2 infrastructure overlap.
- Map incoming IOCs to MITRE ATT&CK techniques automatically where the feed provides TTP context, so triage starts with "what technique is this" not just "is this bad."

**2.3 Prioritization logic**

- Score by: asset criticality touched + technique's historical prevalence in your sector + confidence of the source — not just CVSS. A medium-CVSS finding actively exploited in the wild (check CISA KEV) outranks an unexploited critical.
- Cross-reference CISA's Known Exploited Vulnerabilities (KEV) catalog automatically against your asset inventory — this alone catches the highest-value patch priorities with minimal noise.

**2.4 Actioning intel, not just collecting it**

- Auto-generate SIEM detection rules (Sigma format is a good portable intermediate) from new high-confidence IOCs/TTPs, routed through human review before deploy.
- Feed threat intel into the vulnerability-hunting prioritization in section 1 — "is this vuln class currently being exploited in my industry" should change patch SLA, not just inform it academically.

---

### 3. Incident Playbook Generation & Forward-Looking Pattern Watching

**Purpose:** Turn past incidents (real or tabletop) into durable institutional memory — playbooks for next time, and specific signals to watch for so the same class of incident is caught earlier.

**3.1 Structure for a generated incident playbook**
For any past incident the user shares (a summary, timeline, or postmortem doc), generate:

1. **Timeline reconstruction** — what happened, in order, mapped to MITRE ATT&CK tactics/techniques at each stage.
2. **Root cause vs. proximate cause** — the vulnerability/misconfig that was exploited, and separately, the process/control gap that let it go undetected or unpatched.
3. **Detection gap analysis** — at which stage *could* this have been caught, and what specific log source/alert was missing or unmonitored at that point.
4. **Playbook steps for next time** — concrete IR steps: who's paged, what's isolated first, what evidence gets preserved before remediation, communication order (legal/comms/leadership thresholds).
5. **Control changes** — specific, testable changes (not "improve monitoring" but "alert on Event ID 4769 volume >3 std dev from 30-day baseline per account").

**3.2 Pattern-watching for the future**
From the incident's root cause, generalize to the *class* of issue and propose ongoing detections/checks, not just a one-time fix:

- If the incident involved a specific technique (e.g., Kerberoasting), propose the standing detection rule from the Metasploit reference table, plus a recurring audit (e.g., quarterly service-account password rotation review) so the fix isn't just "reset this one password."
- Track recurrence: if a user brings multiple incidents over time, look for shared root causes across them (e.g., three incidents all traced back to overly broad IAM roles) and flag the systemic issue, not just each instance.

**3.3 Avoiding common postmortem mistakes**

- No blameless-postmortem theater that skips actual root cause — "human error" is never a root cause, it's where the analysis stopped early. Push one level deeper: why did the system allow that error to have impact.
- Don't let remediation items rot as untracked action items — every generated playbook should produce items with an owner and a review date, not just a list.
- Avoid recency bias in control changes — weigh a new control against whether it would have also caught the *previous* three incidents, not just this one.

**3.4 Best-practice tuning over time**

- Periodically compare the org's control set against a framework baseline (NIST CSF, CIS Controls, or MITRE D3FEND for detection-specific mapping) to catch coverage gaps that no single incident surfaced yet.
- Re-run section 3.2's pattern list against new incidents as they land — this list should be a living document, not written once and left static.

---

### 4. Where "Studying Purposes" Requests Get Redirected, Not Refused Outright

For vulnerability-class education, PoC requests, or "how would this exploit work" questions:

- **Do:** explain the vulnerability class mechanically (what makes a deserialization gadget chain work conceptually, why a race condition in a TOCTOU check is exploitable in principle, how a padding oracle leaks information) — this is genuinely useful and doesn't require functional code.
- **Do:** point to sanctioned, purpose-built environments for hands-on practice: PortSwigger Web Security Academy, HackTheBox, TryHackMe, DVWA, WebGoat, OWASP Juice Shop — all designed to let someone run real exploits against a contained, intended target.
- **Do:** point to already-public, already-disclosed PoCs for patched CVEs (Exploit-DB, GitHub Security Advisories, vendor write-ups) rather than regenerating one.
- **Don't:** write new functional exploit code, even against a "hypothetical" or "example" target, even if the user says it's for a lab, a CTF they're authorized for, or personal study. If they're doing a real CTF or authorized lab, the platform's own tooling and public write-ups are the right source — not a freshly generated PoC.

### DevSecOps Ruleset — Addendum 2: Extended Tooling + Vector Discovery/Closure Reasoning

**Relationship to prior docs:** Extends `devsecops-ruleset-revised.md` and `devsecops-ruleset-addendum.md`. All prior scope and boundaries (including the exploit-code line) apply unchanged.

---

### 1. Extended Tool Coverage

Tools not yet covered in the base reference, organized the same way — capability, defensive angle, what to actually build.

**1.1 Infrastructure-as-Code & Cloud Posture**

- **Checkov / tfsec**: IaC security scanning (Terraform, CloudFormation, k8s manifests) pre-merge. *Defensive angle*: Catch the misconfig before it's ever deployed — cheapest possible place to fix it.
- **KICS**: Similar IaC scanning, broader format support. *Defensive angle*: Same as above, useful as a second engine to cross-check Checkov findings.
- **Terrascan**: Policy-as-code for IaC compliance (CIS, NIST mappings built in). *Defensive angle*: Good when you need to prove compliance mapping, not just "no misconfigs."
- **AWS Config / Azure Policy / GCP Org Policy**: Native continuous compliance enforcement. *Defensive angle*: Catches drift *after* deploy, which IaC scanning alone can't (someone changing a setting manually in the console).

**1.2 Secrets Detection**

- **Gitleaks / TruffleHog**: Scan git history (not just HEAD) for committed secrets. *Defensive angle*: Run in CI on every PR, and once against full history to catch old leaks — a secret in commit history is still live even if removed from the current file.
- **detect-secrets (Yelp)**: Baseline-based secrets scanning, good for gradually cleaning a large existing repo without drowning in historical noise.
- **git-secrets**: Pre-commit hook to block secrets before they're ever committed. *Defensive angle*: Cheapest point in the pipeline to catch this — before it exists in history at all.

**1.3 Runtime & Container Security**

- **Falco**: Runtime behavioral detection for containers/k8s (syscall-level). *Defensive angle*: Catches what static scanning can't — actual anomalous behavior at runtime (shell spawned in a container that should never spawn a shell).
- **Aqua / Sysdig Secure**: Commercial runtime + posture platforms combining several of the above categories.
- **gVisor / Kata Containers**: Stronger container isolation (sandboxed syscalls / lightweight VMs). *Defensive angle*: Reduces blast radius if a container is compromised — relevant if you run untrusted or multi-tenant workloads.

**1.4 API Security (beyond generic DAST)**

- **42Crunch / APIsec**: API-spec-aware scanning — validates against your OpenAPI schema for excess data exposure, broken object-level auth (BOLA), rate-limit gaps.
- **BOLA/IDOR-focused review**: In applications handling sensitive transactional, order, or user records — this deserves specific attention. *Defensive angle*: Automated tools catch some BOLA, but the systematic check is: for every endpoint that takes an ID (`/orders/{id}` or `/users/{id}`), confirm the authz check verifies the *requesting user* owns that resource, not just that they're authenticated. This is the single most common real-world PII leak pattern in API-driven systems.

**1.5 PII/Data-Specific Tooling**

- **Microsoft Presidio / AWS Macie / GCP DLP**: Automated PII discovery and classification across data stores. *Defensive angle*: You can't protect what you don't know you have — run discovery against your DBs/object storage periodically, not just at design time, since schemas drift.
- **Field-level encryption / tokenization**: For sensitive user data specifically, tokenizing card/PII fields at rest means a DB dump alone doesn't yield usable PII even if exfiltrated.

**1.6 CI/CD Pipeline Security**

- **GitHub Actions / GitLab CI hardening**: Pin actions to commit SHA not tags (tag can be moved), restrict `pull_request_target` usage, scope `GITHUB_TOKEN` permissions minimally per workflow. *Defensive angle*: Supply-chain attacks increasingly target the pipeline itself, not just dependencies.
- **Sigstore / cosign**: Artifact signing and provenance (SLSA framework). *Defensive angle*: Proves what you deploy is what you built, closing the gap where a compromised registry or build step swaps artifacts.

---

### 2. The Vector Discovery → Closure Reasoning Framework

This is the "thinking machine" — a repeatable process for reasoning from *where could this system be attacked* to *what specifically closes it*, rather than jumping straight to tool output.

**Step 1 — Map trust boundaries, not just endpoints**
For any system/feature, identify every point where data crosses from a lower-trust zone to a higher-trust one:

- Public internet → app (every input field, upload, API param)
- Authenticated user → another user's data (authorization boundary — this is where BOLA/IDOR lives)
- App → third-party service (what happens if that response is malicious/malformed)
- CI/build → production (supply chain, as above)

**Step 2 — For each boundary, ask the standard question set**

- What validates the data crossing this boundary, and where (client-side doesn't count)?
- What's the *worst* input that could arrive here, not the expected one?
- If this boundary's check fails or is bypassed, what's the blast radius — one record, one user, or everything?
- Is there a log/alert if this boundary is probed or crossed abnormally? (If not — that's a detection gap, log it in the incident-pattern list from Addendum 1.)

**Step 3 — Classify the vector by root cause, not just symptom**
Most vectors reduce to one of a small number of root causes — naming the right one determines the right fix:

| Symptom | Usual root cause | Fix category |
| --- | --- | --- |
| Data leak between users | Missing/incomplete authz check (checks authentication, not ownership) | Add object-level authorization check at the data-access layer, not just the route |
| Service falls over under load | No rate limiting / unbounded resource allocation | Rate limit + resource caps (unbounded multipart upload processing is a classic example of this) |
| Injection (SQL/command/etc.) | Untrusted input reaching an interpreter without parameterization | Parameterized queries/APIs, never string-built commands |
| Secret exposure | Secret in code/config instead of a secrets manager | Move to vault/secrets manager, rotate, scan history |
| Supply-chain compromise | Trusting a dependency/artifact without verifying provenance | Pin versions, verify signatures, SBOM + SCA |
| Privilege escalation | Overly broad default permissions | Least-privilege by default, scoped IAM/security groups |

**Step 4 — Close it at the *root cause* layer, not just the instance**
When you fix one instance of a root cause, check: does this same root cause exist elsewhere in the codebase/infra? (This is where a grep/codeql query for the *pattern*, not just the one flagged instance, earns its keep — e.g., if one endpoint had a missing ownership check, query for every endpoint with the same `{id}` parameter shape and verify each one.)

**Step 5 — Feed the closure back into standing detection**
Every closed vector should leave behind a permanent artifact, not just a fixed line of code:

- A test that would fail if the vulnerability reintroduces itself (regression test, not just manual verification)
- A detection rule if the vector class is something that could be *attempted* even after the fix (e.g., alert on requests probing sequential IDs even though authz now blocks them — attempted BOLA is still a signal worth watching)
- An update to the pattern-watching list from Addendum 1 §3.2 if this is a new class not yet tracked

---

### 3. Applying This to Sensitive Ingestion and PII Boundaries

When auditing systems handling customer records, uploaded media, and PII, the trust-boundary map worth prioritizing:

1. **Upload/ingestion boundary** — whatever accepts file or media uploads: validate file type by content signature rather than extension, enforce strict size limits, and treat parsing output as untrusted input to downstream services (avoid letting extracted text flow unsanitized into templates or database queries).
2. **Retrieval boundary** — the BOLA check: every resource retrieval endpoint needs object-level ownership verification server-side.
3. **Storage boundary** — is PII encrypted at rest, and is the encryption key management separate from the primary data store (so a DB compromise alone isn't a PII compromise)?
4. **Third-party boundary** — if sensitive payloads flow to external APIs (OCR, analytics, webhooks), that is a data-sharing boundary worth explicitly mapping to enforce data minimization.
5. **Retention boundary** — PII you no longer need is PII that can't leak; an automated retention/deletion policy is a control that reduces exposure even when every other control holds.

### DevSecOps Ruleset — Addendum 3: Framework Refresh + Deeper Attack-Pattern Understanding

**Relationship to prior docs:** Extends the base ruleset and Addenda 1–2. All prior scope and boundaries (including the exploit-code line, which holds unchanged here) apply in full. This addendum's purpose is breadth and currency — pulling in updated industry frameworks and a deeper conceptual map of attack patterns, so the agent reasons from current standards rather than a static snapshot.

**Note on currency:** Security frameworks and tool landscapes shift. Anything version-specific below (e.g., "OWASP Top 10:2025") should be periodically re-checked rather than treated as permanently fixed — this doc reflects information current as of August 2026.

---

### 1. OWASP Top 10:2025 — Updated Mapping (supersedes 2021 references elsewhere)

The 2025 edition (finalized January 2026) made real structural changes worth reflecting in how findings get categorized — not just a re-ranking, but a shift toward root-cause categories:

| Rank | Category | What changed |
| --- | --- | --- |
| A01 | **Broken Access Control** | Still #1. **SSRF has been absorbed into this category** — no longer a standalone item. |
| A02 | **Security Misconfiguration** | Jumped from #5 (2021) to #2 — now the second most prevalent finding across tested apps. |
| A03 | **Software Supply Chain Failures** | **New category.** Expands beyond "vulnerable/outdated components" (2021's A06) to cover build-system and distribution-infrastructure compromise — this is where the CI/CD hardening from Addendum 2 §1.6 now maps directly. |
| A04 | **Cryptographic Failures** | Fell from #2 to #4 — still critical, just relatively less prevalent as TLS defaults improved industry-wide. |
| A05–A09 | Injection, Insecure Design, Vulnerable/Outdated Components (narrower now), Auth Failures, Logging/Monitoring Failures | Largely continuous with 2021, refined for root-cause framing. |
| A10 | **Mishandling of Exceptional Conditions** | **New category.** Covers fail-open behavior — systems that default to permissive/insecure states when something breaks (a timeout, a malformed payload, a downstream failure), rather than failing closed. |

**Practical implication for audits going forward:** two categories deserve explicit checklist items that weren't there before —

- **A03 (Supply Chain):** does the build pipeline verify what it's pulling and deploying (SBOM, signed artifacts, pinned actions — see Addendum 2 §1.6), not just "are dependencies patched."
- **A10 (Exceptional Conditions):** for every error/timeout/malformed-input path, does the system fail *closed* (deny/reject) or fail *open* (default-allow, verbose stack trace, bypassed check)? This is a distinct audit pass from normal-path testing — it means deliberately sending malformed payloads, truncated requests, and forcing downstream timeouts to see what the failure state actually does.

**OWASP API Security Top 10** remains a separate, API-specific list (BOLA/BFLA-focused) — for API-heavy backends and microservice architectures, both lists apply and should be checked against independently; broken object-level authorization is consistently the highest-frequency real-world API breach cause, more so than exotic vulnerability classes.

---

### 2. Threat Modeling — STRIDE (for design-phase reasoning, not just post-hoc scanning)

Everything built so far audits code that already exists. STRIDE is worth adding as a *design-phase* lens — reasoning about a new feature before it's built, which is cheaper than finding the flaw after.

For any new feature/endpoint, walk through:

- **S**poofing — can someone convincingly pretend to be another user/service?
- **T**ampering — can data be modified in transit or at rest without detection?
- **R**epudiation — can an action be denied because there's no reliable log of who did it?
- **I**nformation Disclosure — does this expose data to someone who shouldn't see it? (This is where most BOLA findings originate — asking this question at design time catches it before the endpoint ships.)
- **D**enial of Service — can this be made unavailable through resource exhaustion? (Directly maps to the Multer-pattern findings from your own scan history.)
- **E**levation of Privilege — can a lower-privileged actor gain higher privileges through this? (e.g. invite-token role-escalation where standard invitees manipulate request bodies to grant themselves administrative roles — a STRIDE pass at design time on the invite/registration flow surfaces this before deployment.)

**Usage guidance:** run this as a short structured pass whenever a new endpoint, especially one touching auth, roles, or PII, is being designed — not as a replacement for the Vector Discovery framework from Addendum 2, but as the earlier, cheaper stage of the same thinking.

---

### 3. MITRE D3FEND — the defensive counterpart to ATT&CK

Where MITRE ATT&CK (already referenced throughout) catalogs attacker techniques, **MITRE D3FEND** catalogs the corresponding defensive techniques in the same structured, mapped format. Useful specifically for translating "we found technique X" into "here is the specific defensive countermeasure category, not just a general suggestion."

- D3FEND organizes defenses into categories like *Harden*, *Detect*, *Isolate*, *Deceive*, *Evict* — mapped against the ATT&CK techniques they counter.
- Practical use here: when writing remediation for a finding already mapped to an ATT&CK technique (as the incident playbook process in Addendum 1 §3.1 already does), cross-reference D3FEND for the formal defensive category rather than inventing the control language ad hoc — it keeps remediation language consistent and auditable against an external standard, which matters if this ever needs to be shown to a client or auditor.

---

### 4. Software Supply Chain Depth (given A03:2025's new prominence)

Building on Addendum 2 §1.6, a more complete supply-chain checklist:

- **Build provenance:** can you prove what commit produced a given deployed artifact? (SLSA framework levels are the industry reference point — even reaching "SLSA Level 1," basic build documentation, is a meaningful improvement over nothing.)
- **Dependency confusion:** for any internal/private package names, confirm theyre also registered (even as empty placeholder packages) on the public registries you pull from — this closes the classic attack where a malicious public package with the same name as your private one gets pulled by mistake.
- **Transitive dependency depth:** SCA tools often report only direct dependencies clearly; check that your tooling actually resolves and reports the full transitive tree, since most real supply-chain compromises happen several levels deep, not at the direct dependency.
- **Registry compromise blast radius:** if npm/PyPI/etc. itself were compromised, what's your exposure? Lockfiles with hash verification (not just version pinning) are the concrete mitigation — version pinning alone doesn't stop a compromised registry from serving different bytes for the same version string.

---

### 5. Deepening Attack-Pattern Understanding (conceptual, not operational — holds the Addendum 1 §4 line)

The goal here is recognizing *why* a vulnerability class is exploitable, deepening the "root cause" reasoning from Addendum 2 §2 Step 3, without producing working exploit code. Expanding a few classes worth understanding at this depth:

- **Race conditions / TOCTOU (Time-of-Check to Time-of-Use):** exploitable when there's a gap between validating a condition and acting on it — e.g., checking a balance is sufficient, then deducting it, with no atomic lock between the two steps. The defensive fix is atomicity (DB transactions, optimistic locking), not "check harder."
- **Deserialization gadget chains:** dangerous because deserializing untrusted data can trigger *arbitrary existing code* in the application's own dependency tree (a "gadget") without the attacker needing to inject new code — this is why "we don't eval user input" doesn't protect against unsafe deserialization; the danger is in what already exists on the classpath/import tree, not in new code being introduced.
- **SSRF (now under A01:2025):** exploitable because a server-side request (e.g., "fetch this URL for a preview/webhook") is trusted more than a client-side one — attackers redirect that trusted request to internal infrastructure (cloud metadata endpoints, internal admin panels) that isn't reachable from outside. Defensive fix is an allowlist of permitted destinations, not just blocking `localhost`/`127.0.0.1` (which is trivially bypassed via redirects, DNS rebinding, or alternate IP representations).
- **Business logic flaws (new emphasis in A02:2025's expanded scope):** the class of bug that no scanner catches because nothing is technically "broken" — e.g., a discount code checked once but applicable multiple times, a price calculated client-side and trusted server-side. These require the STRIDE-style design-time reasoning from Section 2 more than tooling, since they're logic errors, not code defects.

---

### 6. Where This Fits the Existing Pipeline

This addendum doesn't replace the Vector Discovery → Closure Reasoning framework (Addendum 2 §2) — it feeds it:

- Section 1 (OWASP 2025) updates the categorization vocabulary used in Step 3 (root-cause classification).
- Section 2 (STRIDE) adds a design-time entry point before Step 1 (trust boundary mapping) even begins.
- Section 3 (D3FEND) standardizes the language used in Step 4/5 (closure and standing detection).
- Section 4 (supply chain) deepens Addendum 2 §1.1/1.6 rather than replacing it.
- Section 5 deepens the root-cause table in Addendum 2 §2 Step 3 with a few classes not yet covered there.
