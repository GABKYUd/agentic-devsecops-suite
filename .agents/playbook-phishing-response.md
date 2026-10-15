# Playbook: Phishing / Suspicious Email

**Trigger conditions:** user-reported suspicious email, email-gateway/SIEM phishing
alert, or a "report phishing" button submission.

**Roles:** SOC analyst (lead), IT helpdesk (user support), Comms/Legal (only if
sensitive data exposure is confirmed).

## 1. Detect
- Capture the report: sender address, subject, timestamp, and — critically — ask
  the reporting user *not* to forward the raw email from a trusted device.
- Pull matching alerts from the email security gateway / SIEM for the same
  sender infrastructure, subject pattern, or URL.
- Open a ticket immediately; this playbook runs in parallel across roles, not
  strictly sequentially.

## 2. Analyze
- Detonate any links/attachments only in a sandbox or isolated analysis VM —
  never on a device with access to production credentials.
- Extract IOCs: sender domain/IP, URLs, attachment hashes, embedded tracking
  pixels.
- OSINT the sending domain (registration age, reverse WHOIS) to gauge intent.
- Ask the affected user directly: did they click the link, open the
  attachment, or enter any credentials/OTP codes? Get specifics, not just
  yes/no.
- Search all mailboxes org-wide for the same message (sender, subject, or
  hash) to find other recipients.
- Check the affected mailbox for attacker-created auto-forward or inbox rules
  — a common sign of a BEC follow-on, not just a one-off click.

## 3. Contain
- Block the sender domain/IP and malicious URLs at the gateway/proxy/DNS layer.
- Purge the message from every mailbox it reached.
- If credentials were entered: disable the account immediately, revoke active
  sessions/tokens (not just a password reset — token theft survives password
  changes), and force a password reset on next login.
- Remove any attacker-created mailbox forwarding/rules found above.

## 4. Eradicate
- If an attachment was executed: correlate with EDR for follow-on process
  activity, scan the endpoint, and check for persistence (scheduled tasks,
  new services, registry run keys).
- Confirm no lateral use of the harvested credential (check auth logs from
  the account across other systems).

## 5. Recover
- Reissue credentials with MFA enforced; verify mailbox rules are back to
  baseline.
- Monitor the account for 1–2 weeks for delayed follow-on abuse.

## 6. Post-incident
- Notify other potentially affected users with clear guidance.
- Escalate to Legal/Comms if personal or sensitive business data was exposed.
- Feed extracted IOCs into your blocklist/threat-intel platform.
- If the pattern targeted a specific role (finance, exec assistants), consider
  a targeted awareness refresh for that group.

## Ties to companion docs
- Offensive tooling: SET, Gophish, Evilginx (§11, tools reference) — Evilginx
  specifically defeats password-only MFA via session-token theft, which is
  why containment above revokes sessions, not just passwords.
- Strongest structural defense: phishing-resistant MFA (FIDO2/WebAuthn).
