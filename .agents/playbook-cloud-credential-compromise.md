# Playbook: Cloud Account / API Credential Compromise

**Trigger conditions:** a GuardDuty/Defender-for-Cloud finding (anomalous API
calls, impossible-travel sign-in, known-compromised credential use), a
secret-scanning alert from your repo host (key committed to a public repo),
or unexplained new IAM users/roles/trust relationships.

**Roles:** Cloud/platform team (lead), SOC/IR, IAM/identity owner.

## 1. Detect
- Cloud-native alerts: GuardDuty `UnauthorizedAccess`/`CredentialAccess`
  finding types, Azure AD risky sign-in flags, or a secret-scanner hit on a
  code repository.
- Unusual IAM activity: new access keys, new roles, or new trust-policy
  entries you didn't create.

## 2. Analyze
- Identify exactly which credential/key/role is compromised and its
  permission scope (this defines your blast radius).
- Review CloudTrail / Activity Log for what the credential actually did:
  reconnaissance-only enumeration, persistence (new IAM principal, new
  Lambda/Function trigger), or direct data access.
- Check for public-exposure changes (S3 bucket policy edits, storage account
  network rules loosened) made during the compromise window.

## 3. Contain
- Revoke/disable the compromised credential and terminate active sessions
  immediately.
- If a full revoke risks breaking dependent production workflows mid-
  investigation, apply a deny-all/quarantine policy to the identity instead
  of an outright delete, so you don't destroy evidence of what it can reach.
- Rotate the underlying access keys/secrets.
- Remove or disable any newly created IAM principals or trust-policy changes
  found during analysis.

## 4. Eradicate
- Delete attacker-created resources: backdoor IAM users/roles, unexpected
  Lambda/Function code, unauthorized compute instances.
- Fix the root cause of exposure — rotate the leaked-secret source, tighten
  the overly permissive policy that allowed the blast radius you found.

## 5. Recover
- Reissue least-privilege credentials for the affected workload/service.
- Re-enable the service with enhanced monitoring for a defined observation
  window.
- Confirm no persistence remains: scheduled tasks, function triggers, and
  IAM trust relationships all match your known-good baseline.

## 6. Post-incident
- Confirm GuardDuty/CloudTrail (or your cloud's equivalents) are enabled
  organization-wide, not just on the affected account.
- Add/verify secret scanning in CI/CD so leaked keys are caught before
  they're exploited, not after.
- Review IAM policies for least privilege across the affected service and
  adjacent ones with similar permission patterns.

## Ties to companion docs
- Offensive tooling: Pacu, ScoutSuite, Prowler (tools reference §9) — run
  ScoutSuite/Prowler against your own environment regularly as a preventive
  check, not just after an incident.
- Playbook templates this was adapted from: AWS Security Incident Response
  playbooks and Microsoft's Azure incident response guidance
  (devsecops-defense-playbooks.md §2).
