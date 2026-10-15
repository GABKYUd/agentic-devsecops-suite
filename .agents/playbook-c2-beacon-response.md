# Playbook: Command-and-Control (C2) Beacon Detected

**Trigger conditions:** EDR/network alert for jittered periodic outbound
beaconing, a Sigma rule firing on a known C2 traffic profile, a threat-intel
match on a destination IP/domain, or a process-injection/named-pipe alert
consistent with Cobalt Strike, Sliver, or Empire.

**Roles:** SOC/IR lead, network team, threat intel (if available).

## 1. Detect
- Outbound connections with irregular-but-patterned timing (beacon jitter),
  especially to infrastructure with no prior business relationship.
- TLS certificate anomalies: self-signed certs, mismatched SNI/cert subject,
  or certs that don't match the normal CDN/cloud-provider pattern for that
  destination.
- Sigma/YARA hits matching known Malleable C2 profile signatures, or EDR
  process-injection alerts (e.g. a process writing/executing memory in
  another process's address space).

## 2. Analyze
- Fingerprint the implant if possible via JA3/JA4 TLS hash or C2 profile
  match — this narrows down tooling (Cobalt Strike vs. Sliver vs. custom)
  and therefore likely attacker TTPs.
- Estimate dwell time from the beaconing history (how long has this been
  running unnoticed).
- Reconstruct the execution chain: what spawned the beacon process, and was
  it delivered via phishing, an exploited service, or a prior compromised
  credential.
- Check whether the host has already attempted lateral movement (auth logs,
  SMB/WinRM connections initiated from it).

## 3. Contain
- Isolate the host from the network via EDR network isolation.
- Block the C2 IP/domain at the firewall and DNS layer (sinkhole if you have
  that capability, to keep observing without giving the attacker live
  access).
- Capture a memory dump before killing the process, if your forensic
  capability supports it — killing first destroys volatile evidence.
- Disable any account credentials that were active on or used from that
  host.

## 4. Eradicate
- Fully reimage the host rather than attempting to "clean" it — an active C2
  implant implies the attacker had arbitrary code execution, and you cannot
  fully enumerate what else they may have staged.
- Rotate any credentials that were cached or used on the host.
- Hunt across the environment for other hosts beaconing to the same
  infrastructure or matching the same C2 profile fingerprint.

## 5. Recover
- Restore/reimage from a known-good baseline.
- Reconnect in a monitored, phased manner rather than all at once.

## 6. Post-incident
- Feed the C2 IOCs (IPs, domains, JA3/JA4 hashes, file hashes) into your
  threat-intel platform and blocklists.
- If the beacon evaded detection for a while, treat that as a detection gap:
  pull/author the relevant Sigma rule, then run the matching Atomic Red Team
  test to confirm the gap is actually closed — don't just assume the new
  rule works.

## Ties to companion docs
- Offensive tooling: Cobalt Strike, Sliver, Empire, BeEF (tools reference §4).
- Detection engineering loop: SigmaHQ rules + Atomic Red Team validation +
  MITRE D3FEND isolation/eviction countermeasures
  (devsecops-defense-playbooks.md §3).
