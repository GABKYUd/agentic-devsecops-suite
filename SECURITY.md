# 🛡️ Security Policy

## Responsible Disclosure & Reporting

The **Agentic DevSecOps Suite** is an open-source defensive cybersecurity and purple-team engineering framework. We take the security of this project and any projects adopting it seriously.

If you believe you have found a security vulnerability in this framework, its MCP server implementation, or any of its reference playbooks, please report it responsibly.

### How to Report a Vulnerability

1. **GitHub Private Vulnerability Reporting (Preferred):**
   - Navigate to the **Security** tab of the repository on GitHub.
   - Click **"Report a vulnerability"** to open a confidential advisory draft.
2. **Alternative Contact:**
   - You can also report findings directly to the maintainers at **[KYO INC](https://github.com/GABKYUd)** via GitHub issues marked confidential or private discussion.

Please include:
* A description of the vulnerability class and affected component (e.g. MCP server tool, pipeline template).
* An empirically validated, non-destructive proof-of-concept or reproduction sequence.
* Potential security impact on adopting projects.

We commit to acknowledging your report within **48 hours** and coordinating a remediation patch prior to any public disclosure.

---

## 🔒 Scope & Operational Safety

* **Defensive Scope Only:** This repository contains defensive detection engineering rules, static analysis heuristics, and non-destructive runtime validation probes. It strictly prohibits the publication of weaponized exploits, malware payloads, or automated offensive attack chains.
* **Staging-Only Probes:** All DAST probes, Kali validation routines, and CI pipeline stages provided in this framework are designed exclusively for **local development and authorized staging environments**. Never direct automated probes toward production environments or third-party targets without explicit authorization.
* **Zero Secrets Policy:** Never commit secrets, private tokens, passwords, or production keys. All examples in this repository use RFC-compliant dummy values (e.g., `127.0.0.1`, `example.com`, `<TOKEN>`).
