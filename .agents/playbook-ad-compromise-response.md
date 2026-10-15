# Playbook: Active Directory Compromise / Credential Theft

**Trigger conditions:** abnormal Kerberos TGS request volume (Kerberoasting),
a DCSync-pattern replication request from a non-domain-controller account,
EDR alert on non-standard LSASS memory access (Mimikatz-style), or a lateral
authentication pattern consistent with CrackMapExec/NetExec (one account
authenticating to many hosts in a short window).

**Roles:** SOC/IR lead, Active Directory / identity team, Tier 0 admins.

## 1. Detect
- Event ID 4769 (Kerberos service ticket request) spikes, especially for
  accounts that don't normally request tickets.
- Event ID 4662 (directory-object access) showing `DS-Replication-Get-Changes`
  rights exercised by a non-DC principal — the DCSync signature.
- EDR alerts for LSASS access by an unexpected process.
- Unusually high-volume LDAP queries (possible BloodHound-style AD
  reconnaissance) from a single host/account.

## 2. Analyze
- Identify exactly which accounts and tickets are involved, and whether the
  targeted service accounts have old/weak passwords.
- Reconstruct scope: which hosts did the account authenticate to, and in
  what order (this is the lateral-movement path).
- Check for delegation or ACL changes (e.g. `msDS-AllowedToActOnBehalfOf-
  OtherIdentity` modifications — RBCD abuse) and any new members added to
  privileged groups outside a change window.
- Determine whether the activity indicates only credential harvesting, or
  active domain-wide compromise (golden/silver ticket use, DCSync success).

## 3. Contain
- Disable the compromised account(s) immediately.
- Revoke active sessions/Kerberos tickets where your tooling supports it.
- Isolate any hosts confirmed as pivot points in the lateral-movement chain.
- If a Tier 0 (domain admin-equivalent) account is confirmed compromised,
  treat this as a full domain compromise, not an isolated incident — escalate
  scope immediately rather than waiting for further confirmation.

## 4. Eradicate
- If golden/silver ticket abuse is suspected: rotate the `krbtgt` account
  password **twice**, with a replication-convergence wait between rotations
  (a single reset is not sufficient — cached tickets can survive it).
- Remove any unauthorized delegation/ACL changes and attacker-created
  accounts or group memberships.
- Rotate passwords for affected service accounts; migrate high-value service
  accounts to gMSA (managed, auto-rotating, not human-guessable).

## 5. Recover
- Re-enable remediated accounts with new credentials and MFA where
  applicable.
- Validate AD replication health across all domain controllers post-rotation.
- Monitor previously affected accounts/hosts closely for 2–4 weeks for
  recurrence.

## 6. Post-incident
- If not already in place, implement the AD tier model (T0/T1/T2) with
  Privileged Access Workstations for Tier 0 admin activity.
- Add affected privileged accounts to the Protected Users group and consider
  Authentication Silos to restrict where they can log on.
- Re-run BloodHound defensively against your own AD to find and close the
  next-shortest attack path before someone else finds it.

## Ties to companion docs
- Offensive tooling: BloodHound, Impacket, Rubeus, Responder, CrackMapExec/
  NetExec, Mimikatz — all flagged [HIGH-FREQUENCY] in the tools reference.
- Structural fix: Microsoft's Enterprise Access Model / AD DS Tier Model
  (devsecops-defense-playbooks.md §2).
