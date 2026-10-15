# Playbook: Ransomware / Mass Encryption Event

**Trigger conditions:** EDR alert for mass file rename/encryption, shadow-copy or
backup deletion commands, a ransom note discovered, or multiple endpoints going
unreachable in a short window.

**Roles:** IR lead, network/infra team, backup team, executive sponsor,
Legal/Comms, and — per CISA/FBI guidance — a law-enforcement liaison.

## 1. Detect
- EDR behavioral alerts: `vssadmin delete shadows`, `wmic shadowcopy delete`,
  mass file-rename/entropy-spike activity, backup-agent service being stopped.
- Correlate timing across hosts — near-simultaneous activity indicates
  automated/worm-like deployment rather than isolated incidents.

## 2. Analyze
- Identify the ransom note / file extension to fingerprint the family if
  possible (informs known TTPs and decryption possibilities, if any exist).
- Trace back to patient zero and the initial access vector (phishing, exposed
  RDP, exploited public-facing app, stolen credentials).
- Scope the blast radius: which hosts, shares, and backup repositories are
  affected or reachable by the compromised identity.
- Check for signs of pre-encryption data staging/exfiltration (large outbound
  transfers, unusual cloud-storage uploads) — assume double extortion until
  ruled out.

## 3. Contain
- Isolate affected hosts from the network (EDR network isolation, or physical
  disconnect if EDR isn't responding).
- Disable the compromised account(s) and any service accounts used in the
  spread.
- Block identified C2 IPs/domains at the firewall/DNS layer.
- Verify backups are offline/immutable and untouched — do not let the
  containment process itself expose your last clean copy.
- Preserve volatile evidence (memory, running process list) before powering
  off a host, where forensic capability allows.

## 4. Eradicate
- Do not attempt to "clean" infected hosts — rebuild from known-good images.
  Standard guidance from CISA's #StopRansomware program is that partial
  cleanup routinely misses persistence.
- Rotate all credentials that touched compromised systems, prioritizing
  domain admin / Tier 0 accounts (see AD playbook below for krbtgt handling
  if domain compromise is suspected).
- Patch or remove the confirmed initial access vector before reconnecting
  anything.

## 5. Recover
- Restore from immutable/offline backups only, validating integrity before
  reconnecting to the network.
- Reconnect in phases (critical systems first) with heightened monitoring on
  each newly restored host.

## 6. Post-incident
- Engage CISA/FBI (or local equivalent) per #StopRansomware guidance —
  reporting also helps attribute the campaign for the wider community.
- Run the legal/regulatory breach-notification assessment in parallel with
  technical recovery, not after.
- Ransom-payment decisions are a legal/executive risk call, not a technical
  one — this playbook doesn't make that determination.
- After-action review mapped back to CIS Controls v8.1 — most ransomware
  incidents trace to a small number of missing baseline controls (backup
  isolation, least privilege, patch cadence, MFA).

## Ties to companion docs
- Pre-ransomware activity commonly involves the C2/credential-theft tooling
  in the tools reference (Cobalt Strike, Sliver, Mimikatz, Impacket,
  CrackMapExec/NetExec) — the AD and C2 playbooks below often run *before*
  this one triggers.
- Full prevention/detection detail: CISA #StopRansomware Guide
  (devsecops-defense-playbooks.md §2).
