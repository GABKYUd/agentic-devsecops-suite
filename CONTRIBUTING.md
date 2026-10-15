# 🤝 Contributing to Agentic DevSecOps Suite

Thank you for your interest in contributing to the **Agentic DevSecOps Suite**! This project is maintained by **KYO INC** and the open-source community to build reliable, empirically validated purple-team capabilities for AI coding assistants.

---

## 🧭 Contribution Guidelines

### 1. Defensive & Purple-Team Scope
* All contributions must align with a **defensive, remediation-focused posture**.
* We welcome:
  - New vulnerability class specifications in `purple-team-vuln-class-matrix.md` (mapped to CWE, MITRE ATT&CK, and MITRE D3FEND).
  - New agent skills (`SKILL.md` specifications) for application frameworks.
  - Incident response playbooks (`playbook-*.md`).
  - Sigma detection rules and CI/CD security gate blueprints.
* **Prohibited:** Weaponized exploit code, active malware payloads, credential harvesters, or novel evasion bypasses.

### 2. The 7-Question Gate Standard
Any vulnerability rule or testing pattern submitted to the repository must satisfy the **7-Question Gate**:
1. Clear source-to-sink data flow.
2. Explicit access prerequisites (unauthenticated, user, admin).
3. Demonstrable business impact (C-I-A loss).
4. Independent root cause (not duplicate middleware noise).
5. Authorized scope boundary.
6. Empirically validated, non-destructive reproduction sequence (with differential verification).
7. Appropriate CVSS/CWE risk classification.

### 3. Dual-Sided Outputs
Whenever contributing a vulnerability pattern or playbook, provide both:
* **Developer Remediation Guidance:** Root-cause architectural fix and regression testing advice.
* **Blue Team Detection Rule:** Sigma rule, SIEM query, or WAF signature.

### 4. Hygiene & Path Privacy
* **Never commit secrets:** Run `gitleaks` or `trufflehog` on your branch before submitting.
* **Portable Relative Paths:** Never use absolute filesystem paths (e.g., `C:\Users\...`, `/home/...`). Use relative repository links (e.g., `.agents/mcp/server.js`).
* **Dummy Identifiers:** Use standard RFC placeholders (`example.com`, `http://localhost:3000`, `<TOKEN>`).

---

## 🚀 Development & Testing Workflow

1. **Fork and Clone:**
   ```bash
   git clone https://github.com/<your-username>/agentic-devsecops-suite.git
   cd agentic-devsecops-suite
   ```

2. **Verify the MCP Server:**
   Ensure the MCP server runs and responds to JSON-RPC calls over `stdio`:
   ```bash
   node .agents/mcp/server.js
   ```

3. **Open a Pull Request:**
   * Create a feature branch: `git checkout -b feature/new-playbook`
   * Commit with clear, conventional commit messages: `feat: add GraphQL depth-limit inspection skill`
   * Submit your PR against the `main` branch.
