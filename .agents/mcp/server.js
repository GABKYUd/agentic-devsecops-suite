#!/usr/bin/env node
/**
 * DevSecOps Knowledge Base & Purple Team MCP Server
 * Exposes threat intelligence, 21 vulnerability classes, 7-Question Gate evaluation,
 * incident response playbooks, detection engineering (Sigma), and CI/CD automation.
 */

const fs = require('fs');
const path = require('path');
const readline = require('readline');
const crypto = require('crypto');

const AGENTS_DIR = path.resolve(__dirname, '..');

// In-memory token store for approved findings
// Map: token -> { finding_id, vuln_class, target_endpoint, created_at, expires_at }
const approvedFindingTokens = new Map();

function issueApprovalToken(findingId, vulnClass, targetEndpoint) {
  const token = `gate_${crypto.randomBytes(16).toString('hex')}`;
  const now = Date.now();
  approvedFindingTokens.set(token, {
    finding_id: findingId,
    vuln_class: vulnClass,
    target_endpoint: targetEndpoint,
    created_at: now,
    expires_at: now + 3600000 // 1 hour TTL
  });
  return token;
}

function validateApprovalToken(token) {
  if (!token || typeof token !== 'string') return null;
  const clean = token.trim();
  const entry = approvedFindingTokens.get(clean);
  if (!entry) return null;
  if (Date.now() > entry.expires_at) {
    approvedFindingTokens.delete(clean);
    return null;
  }
  return entry;
}

// Target URL Guard: Restricts destinations to loopback, RFC 1918 private subnets, test domains, or explicit allowlist
const PRIVATE_IP_PATTERNS = [
  /^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$/,           // 127.0.0.0/8 Loopback
  /^10\.\d{1,3}\.\d{1,3}\.\d{1,3}$/,            // 10.0.0.0/8 Private
  /^172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}$/, // 172.16.0.0/12 Private
  /^192\.168\.\d{1,3}\.\d{1,3}$/,              // 192.168.0.0/16 Private
  /^169\.254\.\d{1,3}\.\d{1,3}$/               // 169.254.0.0/16 Link-Local
];

function validateTargetUrl(urlString) {
  try {
    const parsed = new URL(urlString);
    const hostname = parsed.hostname.toLowerCase();

    // 1. Loopback addresses
    if (hostname === 'localhost' || hostname === '127.0.0.1' || hostname === '::1' || hostname === '0.0.0.0') {
      return { allowed: true, category: 'loopback' };
    }

    // 2. RFC 1918 & Link-Local private IPs
    for (const pattern of PRIVATE_IP_PATTERNS) {
      if (pattern.test(hostname)) {
        return { allowed: true, category: 'private_ip' };
      }
    }

    // 3. Local and internal test domains
    if (hostname.endsWith('.local') || hostname.endsWith('.test') || hostname.endsWith('.internal') || hostname === 'example.com' || hostname.endsWith('.example.com')) {
      return { allowed: true, category: 'test_domain' };
    }

    // 4. Custom allowlist from environment variable DEVSECOPS_ALLOWED_HOSTS
    if (process.env.DEVSECOPS_ALLOWED_HOSTS) {
      const allowedList = process.env.DEVSECOPS_ALLOWED_HOSTS.split(',').map(h => h.trim().toLowerCase());
      if (allowedList.includes(hostname) || allowedList.some(h => hostname.endsWith('.' + h))) {
        return { allowed: true, category: 'allowlist' };
      }
    }

    return {
      allowed: false,
      reason: `Target host '${hostname}' is outside authorized boundaries. Probes are strictly restricted to localhost (127.0.0.1), RFC 1918 private subnets (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16), *.local/*.internal, or hosts explicitly permitted via DEVSECOPS_ALLOWED_HOSTS.`
    };
  } catch (err) {
    return {
      allowed: false,
      reason: `Malformed target URL: ${err.message}`
    };
  }
}

// Cache knowledge base files
function readFileSafe(filePath) {
  try {
    return fs.readFileSync(filePath, 'utf8');
  } catch (err) {
    return '';
  }
}

// Map of vulnerability classes
const VULN_CLASSES = [
  { id: 'sqli', number: '01', name: 'SQL Injection (SQLi)', cwe: 'CWE-89', attack: 'T1190', category: 'Injection & Execution' },
  { id: 'nosqli', number: '02', name: 'NoSQL Injection (NoSQLi)', cwe: 'CWE-943', attack: 'T1190', category: 'Injection & Execution' },
  { id: 'command_injection', number: '03', name: 'OS Command Injection', cwe: 'CWE-78', attack: 'T1059', category: 'Injection & Execution' },
  { id: 'ssti', number: '04', name: 'Server-Side Template Injection (SSTI)', cwe: 'CWE-1336', attack: 'T1190', category: 'Injection & Execution' },
  { id: 'deserialization', number: '05', name: 'Insecure Deserialization', cwe: 'CWE-502', attack: 'T1190', category: 'Injection & Execution' },
  { id: 'idor', number: '06', name: 'Insecure Direct Object Reference (IDOR / BOLA)', cwe: 'CWE-639', attack: 'T1078', category: 'Access Control & Auth' },
  { id: 'broken_auth', number: '07', name: 'Broken Authentication & Session Hijacking', cwe: 'CWE-287', attack: 'T1078', category: 'Access Control & Auth' },
  { id: 'oauth', number: '08', name: 'OAuth 2.0 / OIDC Implementation Flaws', cwe: 'CWE-287', attack: 'T1556', category: 'Access Control & Auth' },
  { id: 'jwt', number: '09', name: 'JSON Web Token (JWT) Misconfigurations', cwe: 'CWE-347', attack: 'T1556', category: 'Access Control & Auth' },
  { id: 'mass_assignment', number: '10', name: 'Mass Assignment / Broken Property Auth (BOPLA)', cwe: 'CWE-915', attack: 'T1078', category: 'Access Control & Auth' },
  { id: 'ssrf', number: '11', name: 'Server-Side Request Forgery (SSRF)', cwe: 'CWE-918', attack: 'T1071', category: 'Network & Boundary' },
  { id: 'path_traversal', number: '12', name: 'Path Traversal / Local File Inclusion (LFI)', cwe: 'CWE-22', attack: 'T1083', category: 'Network & Boundary' },
  { id: 'open_redirect', number: '13', name: 'Open Redirect & Host Header Injection', cwe: 'CWE-601', attack: 'T1566', category: 'Network & Boundary' },
  { id: 'cors', number: '14', name: 'CORS Misconfiguration', cwe: 'CWE-942', attack: 'T1189', category: 'Network & Boundary' },
  { id: 'xss', number: '15', name: 'Cross-Site Scripting (XSS - Stored / Reflected / DOM)', cwe: 'CWE-79', attack: 'T1189', category: 'Client & Dataflow' },
  { id: 'csrf', number: '16', name: 'Cross-Site Request Forgery (CSRF)', cwe: 'CWE-352', attack: 'T1189', category: 'Client & Dataflow' },
  { id: 'race_condition', number: '17', name: 'Race Conditions & Concurrency (TOCTOU)', cwe: 'CWE-362', attack: 'T1068', category: 'Application Logic' },
  { id: 'graphql', number: '18', name: 'GraphQL Introspection, Batching & Depth Abuse', cwe: 'CWE-770', attack: 'T1499', category: 'API & Application Logic' },
  { id: 'hardcoded_secrets', number: '19', name: 'Hardcoded Secrets, Tokens & PII Exposure', cwe: 'CWE-798', attack: 'T1552', category: 'Data & Supply Chain' },
  { id: 'cicd_injection', number: '20', name: 'CI/CD Pipeline Injection & Runner Poisoning', cwe: 'CWE-78', attack: 'T1195', category: 'Supply Chain & Infrastructure' },
  { id: 'xxe', number: '21', name: 'XML External Entity (XXE) Injection', cwe: 'CWE-611', attack: 'T1190', category: 'Injection & Execution' }
];

// Map of Incident Playbooks
const INCIDENT_PLAYBOOKS = [
  { id: 'phishing', file: 'playbook-phishing-response.md', title: 'Phishing / Suspicious Email' },
  { id: 'ransomware', file: 'playbook-ransomware-response.md', title: 'Ransomware / Mass Encryption Event' },
  { id: 'ad_compromise', file: 'playbook-ad-compromise-response.md', title: 'Active Directory Compromise / Credential Theft' },
  { id: 'c2_beacon', file: 'playbook-c2-beacon-response.md', title: 'Command-and-Control (C2) Beacon Detected' },
  { id: 'cloud_credential', file: 'playbook-cloud-credential-compromise.md', title: 'Cloud Account / API Credential Compromise' },
  { id: 'web_app_exploitation', file: 'playbook-web-app-exploitation.md', title: 'Web Application Exploitation (SQLi / RCE / Webshell)' },
  { id: 'container_k8s', file: 'playbook-container-kubernetes-compromise.md', title: 'Container / Kubernetes Compromise' }
];

// Helper to extract a section from the matrix
function extractVulnFromMatrix(vulnNumber) {
  const matrixPath = path.join(AGENTS_DIR, 'purple-team-vuln-class-matrix.md');
  const content = readFileSafe(matrixPath);
  if (!content) return null;

  const headerRegex = new RegExp(`## ${vulnNumber}\\.[\\s\\S]*?(?=\\n## \\d{2}\\. |\\n---?\\s*$|$)`, 'i');
  const match = content.match(headerRegex);
  return match ? match[0].trim() : null;
}

// Tools definitions
const TOOLS = [
  {
    name: 'list_vulnerability_classes',
    description: 'Lists all 21 application, API, and cloud vulnerability classes covered in the DevSecOps & Purple Team matrix, with CWE and MITRE ATT&CK mappings.',
    inputSchema: {
      type: 'object',
      properties: {
        category: {
          type: 'string',
          description: 'Optional filter by category (e.g. "Injection & Execution", "Access Control & Auth", "Network & Boundary", "Client & Dataflow", "Application Logic", "Data & Supply Chain", "Supply Chain & Infrastructure")'
        }
      }
    }
  },
  {
    name: 'lookup_vulnerability_class',
    description: 'Retrieves comprehensive deep-dive details for a specific vulnerability class from the purple team matrix: CWE, MITRE ATT&CK, mechanics, Semgrep SAST rule, benign DAST probe, 7-Question Gate checklist, Sigma detection rule, and root-cause remediation.',
    inputSchema: {
      type: 'object',
      properties: {
        vuln_name: {
          type: 'string',
          description: 'Identifier, name, or number of the vulnerability class (e.g., "sqli", "nosqli", "command_injection", "ssti", "deserialization", "idor", "broken_auth", "oauth", "jwt", "mass_assignment", "ssrf", "path_traversal", "open_redirect", "cors", "xss", "csrf", "race_condition", "graphql", "hardcoded_secrets", "cicd_injection", "xxe", or "01".."21")'
        }
      },
      required: ['vuln_name']
    }
  },
  {
    name: 'evaluate_7_question_gate',
    description: 'Evaluates a potential security finding against the strict 7-Question Gate to dismiss false positives, enforce empirical validation, issue a cryptographic approval_token required for probe synthesis, synthesize dual-sided outputs (Developer PR patch + Blue Team Sigma rule), and format a pipeline contract entry (findings-manifest.json).',
    inputSchema: {
      type: 'object',
      properties: {
        finding_id: {
          type: 'string',
          description: 'Unique finding ID (e.g. "FINDING-2026-001")'
        },
        vuln_class: {
          type: 'string',
          description: 'The vulnerability class identifier (e.g. "sqli", "idor", "ssrf", etc.)'
        },
        source_to_sink_evidence: {
          type: 'string',
          description: 'Trace showing how user-controlled input reaches the sensitive sink without neutralization'
        },
        access_prerequisites: {
          type: 'string',
          enum: ['unauthenticated', 'standard_user', 'admin', 'internal_network', 'physical'],
          description: 'Access tier required to reach the vulnerable flow'
        },
        business_impact: {
          type: 'string',
          description: 'Demonstrable impact on Confidentiality, Integrity, or Availability'
        },
        is_unique: {
          type: 'boolean',
          description: 'Whether this finding represents an independent root cause rather than a duplicate symptom of shared middleware'
        },
        is_in_scope: {
          type: 'boolean',
          description: 'Whether the affected asset is verified within the authorized first-party target boundary'
        },
        empirical_repro_steps: {
          type: 'string',
          description: 'Concrete, reproducible proof or benign staging request sequence demonstrating differential behavior'
        },
        deterministic_repro_steps: {
          type: 'string',
          description: 'Backward-compatible alias for empirical_repro_steps'
        },
        target_endpoint: {
          type: 'string',
          description: 'The affected file, route, or endpoint (e.g. "/api/orders/:id", "backend/routes/auth.js")'
        }
      },
      required: ['finding_id', 'vuln_class', 'source_to_sink_evidence', 'access_prerequisites', 'business_impact', 'is_unique', 'is_in_scope', 'target_endpoint']
    }
  },
  {
    name: 'list_incident_playbooks',
    description: 'Lists all available incident response playbooks with their trigger conditions and assigned roles.',
    inputSchema: {
      type: 'object',
      properties: {}
    }
  },
  {
    name: 'get_incident_playbook',
    description: 'Retrieves the complete step-by-step incident response playbook (Detect -> Analyze -> Contain -> Eradicate -> Recover -> Post-incident) for a specific security incident type.',
    inputSchema: {
      type: 'object',
      properties: {
        incident_type: {
          type: 'string',
          enum: ['phishing', 'ransomware', 'ad_compromise', 'c2_beacon', 'cloud_credential', 'web_app_exploitation', 'container_k8s'],
          description: 'The incident type identifier'
        }
      },
      required: ['incident_type']
    }
  },
  {
    name: 'get_detection_rule',
    description: 'Retrieves illustrative Sigma-formatted detection engineering rules for high-frequency attack techniques (LSASS memory access, Kerberoasting, Web app attacks, Cloud metadata exfiltration, CI/CD runner poisoning).',
    inputSchema: {
      type: 'object',
      properties: {
        technique: {
          type: 'string',
          description: 'Technique keyword or ID (e.g. "lsass", "kerberoasting", "sqli", "ssrf", "cicd", "mimikatz")'
        }
      },
      required: ['technique']
    }
  },
  {
    name: 'search_security_kb',
    description: 'Performs full-text keyword search across all DevSecOps and threat intelligence files in the knowledge base, returning relevant snippets and file citations.',
    inputSchema: {
      type: 'object',
      properties: {
        query: {
          type: 'string',
          description: 'Search keyword, technique, tool name, or CVE/CWE reference'
        },
        max_results: {
          type: 'number',
          description: 'Maximum number of matches to return (default: 5)'
        }
      },
      required: ['query']
    }
  },
  {
    name: 'get_pipeline_automation',
    description: 'Retrieves CI/CD automation templates: the reusable GitHub Actions Purple Pipeline workflow or the Python SARIF 7-Question Gate automated triage script.',
    inputSchema: {
      type: 'object',
      properties: {
        asset: {
          type: 'string',
          enum: ['github_actions_workflow', 'sarif_triage_script', 'manifest_contract'],
          description: 'Which pipeline asset to retrieve'
        }
      },
      required: ['asset']
    }
  },
  {
    name: 'get_wsl_validation_probe',
    description: 'Generates non-destructive Kali Linux DAST probe commands (runnable via WSL2, Docker containers, or dedicated VMs using curl, ffuf, nuclei, etc.) to validate code findings against local/staging environments. REQUIRES a valid approval_token issued by evaluate_7_question_gate and enforces strict target perimeter checks.',
    inputSchema: {
      type: 'object',
      properties: {
        approval_token: {
          type: 'string',
          description: 'Mandatory cryptographic approval token issued by evaluate_7_question_gate upon passing the gate. Probe generation is refused without a valid token.'
        },
        vuln_class: {
          type: 'string',
          description: 'Vulnerability class identifier (e.g. "sqli", "nosqli", "idor", "ssrf", "path_traversal", "cors", "command_injection", "jwt", "race_condition")'
        },
        target_url: {
          type: 'string',
          description: 'Target URL on local or staging (e.g. "http://localhost:3000/api/orders/1" or "http://127.0.0.1:8080/search"). Restricted by server guard to localhost, RFC 1918 private subnets, *.local/*.internal, or DEVSECOPS_ALLOWED_HOSTS.'
        },
        method: {
          type: 'string',
          default: 'GET',
          description: 'HTTP method (GET, POST, PUT, DELETE)'
        },
        param_name: {
          type: 'string',
          description: 'Vulnerable parameter name (e.g. "id", "q", "url", "file")'
        },
        auth_header: {
          type: 'string',
          description: 'Optional Authorization header (e.g. "Bearer <TOKEN>")'
        }
      },
      required: ['approval_token', 'vuln_class', 'target_url']
    }
  },
  {
    name: 'list_available_skills',
    description: 'Lists all available purple-team and audit skills in the suite with their scope and purpose. Use this before proposing a skill to the user.',
    inputSchema: {
      type: 'object',
      properties: {}
    }
  },
  {
    name: 'explain_and_request_skill_approval',
    description: 'Generates a structured Skill Transparency Brief and Developer Approval Gate prompt. The assistant MUST call this tool and present its output to the developer/user to request explicit approval before activating or executing any skill.',
    inputSchema: {
      type: 'object',
      properties: {
        skill_name: {
          type: 'string',
          description: 'Name of the skill to be activated (e.g. "bug-hunting-recon-surface", "vuln-hunting-injection-rce", "vuln-hunting-auth-access-control", "vuln-hunting-network-ssrf-logic", "bug-bounty-validator-gate", "threat-intel-skills-distiller", "incident-response-playbooks")'
        },
        target_scope: {
          type: 'string',
          description: 'The specific directory, file, endpoint, or architecture component that will be inspected'
        },
        reasoning: {
          type: 'string',
          description: 'Clear developer-friendly explanation of why this specific skill is needed at this phase'
        },
        planned_actions: {
          type: 'string',
          description: 'Summary of checks, static AST queries, or non-destructive DAST verification probes that will be run'
        }
      },
      required: ['skill_name', 'target_scope', 'reasoning', 'planned_actions']
    }
  }
];

// Tool Handlers
function handleToolCall(name, args) {
  switch (name) {
    case 'list_vulnerability_classes': {
      let list = VULN_CLASSES;
      if (args.category) {
        list = list.filter(v => v.category.toLowerCase().includes(args.category.toLowerCase()));
      }
      return {
        total_count: list.length,
        classes: list
      };
    }

    case 'lookup_vulnerability_class': {
      const term = String(args.vuln_name).trim().toLowerCase();
      const item = VULN_CLASSES.find(v =>
        v.id === term ||
        v.number === term ||
        v.number === term.padStart(2, '0') ||
        v.name.toLowerCase().includes(term) ||
        v.cwe.toLowerCase() === term
      );

      if (!item) {
        return {
          error: `Vulnerability class '${args.vuln_name}' not found. Use list_vulnerability_classes to see all supported classes.`
        };
      }

      const rawDetails = extractVulnFromMatrix(item.number);
      return {
        id: item.id,
        number: item.number,
        name: item.name,
        cwe: item.cwe,
        mitre_attack: item.attack,
        category: item.category,
        details: rawDetails || 'Details not found in matrix.'
      };
    }

    case 'evaluate_7_question_gate': {
      const {
        finding_id,
        vuln_class,
        source_to_sink_evidence,
        access_prerequisites,
        business_impact,
        is_unique,
        is_in_scope,
        empirical_repro_steps,
        deterministic_repro_steps,
        target_endpoint
      } = args;

      const reproSteps = empirical_repro_steps || deterministic_repro_steps;
      const hasDirectExploit = source_to_sink_evidence && source_to_sink_evidence.length > 20;
      const hasImpact = business_impact && business_impact.length > 10;
      const hasRepro = reproSteps && reproSteps.length > 15;

      const passedAll = hasDirectExploit && access_prerequisites && hasImpact && is_unique && is_in_scope && hasRepro;

      const matchedVuln = VULN_CLASSES.find(v => v.id === vuln_class.toLowerCase() || v.name.toLowerCase().includes(vuln_class.toLowerCase()));
      const cwe = matchedVuln ? matchedVuln.cwe : 'CWE-Unknown';
      const attack = matchedVuln ? matchedVuln.attack : 'T1190';
      const vulnId = matchedVuln ? matchedVuln.id : vuln_class;

      let approvalToken = null;
      if (passedAll) {
        approvalToken = issueApprovalToken(finding_id, vulnId, target_endpoint);
      }

      const status = passedAll ? 'PASSED_GATE' : 'REJECTED_OR_DOWNGRADED';

      return {
        finding_id,
        status,
        approval_token: approvalToken,
        approval_status: passedAll ? 'AUTHORIZED_TOKEN_ISSUED' : 'REFUSED_GATE_FAILED',
        approval_token_ttl_seconds: passedAll ? 3600 : 0,
        gate_evaluation: {
          q1_direct_exploitability: hasDirectExploit ? 'PASS' : 'FAIL (Insufficient source-to-sink proof)',
          q2_access_prerequisites: access_prerequisites,
          q3_demonstrable_business_impact: hasImpact ? 'PASS' : 'FAIL (Vague or theoretical impact)',
          q4_novelty_and_deduplication: is_unique ? 'PASS' : 'FAIL (Duplicate root cause)',
          q5_scope_verification: is_in_scope ? 'PASS' : 'FAIL (Out of authorized boundary)',
          q6_empirical_reproducibility: hasRepro ? 'PASS' : 'FAIL (No concrete empirical steps)',
          q7_severity_classification: access_prerequisites === 'unauthenticated' ? 'CRITICAL / HIGH' : 'HIGH / MEDIUM'
        },
        empirical_validation_guidance: 'Note: For authorization flaws like IDOR, an HTTP 200 alone does not prove a vulnerability if the data is shared or public. Always perform differential testing: verify that unprivileged/cross-tenant requests access private records that should return 403 or 404.',
        dual_sided_outputs: {
          developer_remediation_spec: {
            endpoint: target_endpoint,
            cwe,
            action_required: 'Implement architectural control at data access / route layer. Parameterize queries or enforce tenant-level ownership checks.',
            unit_test_requirement: `Add automated regression test asserting that invalid/unauthorized input is rejected with 400/403 without data leakage.`
          },
          blue_team_detection_spec: {
            mitre_attack: attack,
            sigma_rule_action: `Deploy or tune Sigma detection rule for ${matchedVuln ? matchedVuln.name : vuln_class}.`,
            telemetry_source: access_prerequisites === 'unauthenticated' ? 'WAF / Ingress Access Logs' : 'Application Audit & DB Logs'
          }
        },
        pipeline_manifest_contract: {
          finding_id,
          target_endpoint,
          vuln_class: vulnId,
          cwe,
          code_status: passedAll ? 'BLOCKING' : 'DISMISSED',
          detection_status: 'UNTESTED',
          sigma_rule_id: `sigma-${vulnId}-detect`
        }
      };
    }

    case 'list_incident_playbooks': {
      return {
        total_playbooks: INCIDENT_PLAYBOOKS.length,
        playbooks: INCIDENT_PLAYBOOKS.map(p => ({
          id: p.id,
          title: p.title,
          file: p.file
        }))
      };
    }

    case 'get_incident_playbook': {
      const pb = INCIDENT_PLAYBOOKS.find(p => p.id === args.incident_type);
      if (!pb) {
        return { error: `Playbook '${args.incident_type}' not found.` };
      }
      const filePath = path.join(AGENTS_DIR, pb.file);
      const content = readFileSafe(filePath);
      return {
        id: pb.id,
        title: pb.title,
        content: content || 'Playbook file is empty or missing.'
      };
    }

    case 'get_detection_rule': {
      const term = args.technique.toLowerCase();
      const rulesPath = path.join(AGENTS_DIR, 'detection-rules-starter-reference.md');
      const content = readFileSafe(rulesPath);
      if (!content) return { error: 'Detection rules file not found.' };

      const sections = content.split(/\n(?=## \d+\. )/);
      const matches = sections.filter(sec => sec.toLowerCase().includes(term));

      if (matches.length === 0) {
        return {
          error: `No detection rules matching '${args.technique}' found.`,
          available_sections: sections.map(s => {
            const h = s.match(/## \d+\. ([^\n]+)/);
            return h ? h[1] : null;
          }).filter(Boolean)
        };
      }

      return {
        matches_found: matches.length,
        rules: matches.map(m => m.trim())
      };
    }

    case 'search_security_kb': {
      const q = args.query.toLowerCase();
      const maxResults = args.max_results || 5;
      const files = fs.readdirSync(AGENTS_DIR).filter(f => f.endsWith('.md'));
      const results = [];

      for (const file of files) {
        const fullPath = path.join(AGENTS_DIR, file);
        const text = readFileSafe(fullPath);
        if (!text) continue;

        const lines = text.split('\n');
        for (let i = 0; i < lines.length; i++) {
          if (lines[i].toLowerCase().includes(q)) {
            const start = Math.max(0, i - 2);
            const end = Math.min(lines.length - 1, i + 3);
            const snippet = lines.slice(start, end + 1).join('\n');
            results.push({
              file,
              line: i + 1,
              snippet
            });
            if (results.length >= maxResults) break;
          }
        }
        if (results.length >= maxResults) break;
      }

      return {
        query: args.query,
        count: results.length,
        results
      };
    }

    case 'get_pipeline_automation': {
      const pipePath = path.join(AGENTS_DIR, 'devsecops-pipeline-automation.md');
      const content = readFileSafe(pipePath);
      if (!content) return { error: 'Pipeline automation file not found.' };

      if (args.asset === 'github_actions_workflow') {
        const wfMatch = content.match(/```yaml\s*name: DevSecOps Purple Pipeline[\s\S]*?```/);
        return {
          asset: 'github_actions_workflow',
          content: wfMatch ? wfMatch[0] : 'Workflow YAML not extracted.'
        };
      } else if (args.asset === 'sarif_triage_script') {
        const scriptMatch = content.match(/```python[\s\S]*?def evaluate_7_question_gate[\s\S]*?```/);
        return {
          asset: 'sarif_triage_script',
          content: scriptMatch ? scriptMatch[0] : 'Python script not extracted.'
        };
      } else if (args.asset === 'manifest_contract') {
        const manifestMatch = content.match(/## 3\. Finding Manifest Schema[\s\S]*?(?=\n## 4\.|$)/);
        return {
          asset: 'manifest_contract',
          content: manifestMatch ? manifestMatch[0].trim() : 'Manifest schema not extracted.'
        };
      }

      return { error: `Asset '${args.asset}' not recognized.` };
    }

    case 'get_wsl_validation_probe': {
      // 1. Mandatory Gate Token Enforcement Check
      if (!args.approval_token) {
        return {
          error: "GATE ENFORCEMENT REFUSAL: Missing required 'approval_token'. The 7-Question Gate evaluation tool ('evaluate_7_question_gate') must be executed and successfully passed to issue a cryptographic approval token before validation probes can be synthesized or executed.",
          code: "APPROVAL_TOKEN_REQUIRED",
          required_action: "Execute 'evaluate_7_question_gate' with verified source-to-sink evidence, access prerequisites, business impact, and empirical steps to acquire an authorized approval_token."
        };
      }

      const tokenRecord = validateApprovalToken(args.approval_token);
      if (!tokenRecord) {
        return {
          error: "GATE ENFORCEMENT REFUSAL: Invalid or expired 'approval_token'. The provided token is not recognized or has exceeded its 60-minute TTL.",
          code: "INVALID_APPROVAL_TOKEN",
          required_action: "Re-run 'evaluate_7_question_gate' to issue a new valid approval_token."
        };
      }

      // 2. Mandatory Target Perimeter Guard Check
      const url = args.target_url;
      const targetCheck = validateTargetUrl(url);
      if (!targetCheck.allowed) {
        return {
          error: `TARGET GUARD REFUSAL: ${targetCheck.reason}`,
          code: "TARGET_HOST_NOT_ALLOWED",
          target_url: url,
          safety_policy: "The DevSecOps suite strictly refuses probe synthesis against external, unverified, or public third-party hosts to prevent outbound SSRF and unauthorized external scanning."
        };
      }

      const vuln = (args.vuln_class || '').toLowerCase();
      const method = (args.method || 'GET').toUpperCase();
      const param = args.param_name || 'id';
      const authHeader = args.auth_header ? `-H "Authorization: ${args.auth_header}" ` : '';

      let rawCmd = '';
      let toolName = 'curl';
      let expectedVuln = '';
      let expectedSafe = '';

      switch (vuln) {
        case 'sqli':
          rawCmd = `curl -s -o /dev/null -w "%{http_code}" ${authHeader}"${url}?${param}=1%27%20OR%201=1--"`;
          expectedVuln = 'Returns HTTP 200 with all records OR HTTP 500 with SQL syntax error stack trace.';
          expectedSafe = 'Returns HTTP 400 Bad Request, empty array, or clean parameterized result.';
          break;
        case 'nosqli':
          rawCmd = `curl -s -X POST ${authHeader}-H "Content-Type: application/json" -d '{"${param}":{"$ne":null}}' "${url}"`;
          expectedVuln = 'Bypasses auth / returns unauthorized data when passing MongoDB operator.';
          expectedSafe = 'Returns HTTP 400 or treats object as invalid input string.';
          break;
        case 'idor':
          rawCmd = `curl -i -s ${authHeader}"${url}"`;
          expectedVuln = 'Returns HTTP 200 with unauthorized tenant/user private data (empirically confirmed via differential check).';
          expectedSafe = 'Returns HTTP 403 Forbidden or HTTP 404 Not Found (tenant isolation enforced). Note: if data is public, 200 does not indicate IDOR.';
          break;
        case 'ssrf':
          rawCmd = `curl -s -X POST ${authHeader}-H "Content-Type: application/json" -d '{"${param}":"http://127.0.0.1:80"}' "${url}"`;
          expectedVuln = 'Application initiates request to loopback/metadata and returns internal response.';
          expectedSafe = 'Returns HTTP 400/422 with validation error rejecting private IP ranges.';
          break;
        case 'path_traversal':
          rawCmd = `curl -s -i "${url}?${param}=../../package.json"`;
          expectedVuln = 'Returns package.json contents or root directory files.';
          expectedSafe = 'Returns HTTP 400 or HTTP 404 with path traversal blocked.';
          break;
        case 'cors':
          rawCmd = `curl -s -I -H "Origin: https://evil.attacker.com" "${url}"`;
          expectedVuln = 'Returns Access-Control-Allow-Origin: https://evil.attacker.com with Access-Control-Allow-Credentials: true.';
          expectedSafe = 'Does not reflect untrusted origin, or omits Access-Control-Allow-Credentials.';
          break;
        case 'command_injection':
          rawCmd = `curl -s "${url}?${param}=1;echo%20BENIGN_TEST"`;
          expectedVuln = 'Output reflects BENIGN_TEST indicating shell execution.';
          expectedSafe = 'Input treated strictly as argument literal, no shell interpretation.';
          break;
        case 'jwt':
          rawCmd = `curl -i -H "Authorization: Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwicm9sZSI6ImFkbWluIn0." "${url}"`;
          expectedVuln = 'Accepts unsigned or alg:none token with HTTP 200.';
          expectedSafe = 'Rejects invalid signature with HTTP 401 Unauthorized.';
          break;
        default:
          rawCmd = `curl -i -s ${authHeader}-X ${method} "${url}"`;
          expectedVuln = 'Endpoint accepts malformed or boundary payload.';
          expectedSafe = 'Request neutralized by framework validation layers.';
          break;
      }

      return {
        approval_token: args.approval_token,
        authorized_finding_id: tokenRecord.finding_id,
        target_perimeter: targetCheck.category,
        vuln_class: vuln,
        target_url: url,
        tool: toolName,
        raw_command: rawCmd,
        wsl_command: `wsl -d kali-linux -e ${rawCmd}`,
        docker_command: `docker run --rm --net=host kalilinux/kali-rolling ${rawCmd}`,
        vm_ssh_command: `ssh kali@<KALI_VM_IP> "${rawCmd}"`,
        purpose: 'Non-destructive runtime empirical validation via Kali Linux (WSL2, Docker container, or dedicated VM) to eliminate static code / AST false positives.',
        expected_vulnerable_signal: expectedVuln,
        expected_safe_signal: expectedSafe,
        safety_assertion: 'Benign staging verification probe only. Never executes destructive payloads or out-of-scope requests.'
      };
    }

    case 'list_available_skills': {
      const skillsDir = path.join(AGENTS_DIR, 'skills');
      let items = [];
      try {
        items = fs.readdirSync(skillsDir, { withFileTypes: true })
          .filter(d => d.isDirectory())
          .map(d => {
            const skillFile = path.join(skillsDir, d.name, 'SKILL.md');
            const content = readFileSafe(skillFile);
            const descMatch = content.match(/description:\s*>?-?\s*([^\n]+(?:\n\s+[^\n]+)*)/);
            const desc = descMatch ? descMatch[1].replace(/\s+/g, ' ').trim() : 'Skill for DevSecOps operations.';
            return {
              name: d.name,
              description: desc,
              path: `.agents/skills/${d.name}/SKILL.md`
            };
          });
      } catch (err) {
        return { error: 'Failed to read skills directory: ' + err.message };
      }
      return {
        total_skills: items.length,
        skills: items,
        mandatory_policy: 'Before activating or executing any skill, the assistant MUST explain the plan to the developer and receive explicit approval.'
      };
    }

    case 'explain_and_request_skill_approval': {
      const { skill_name, target_scope, reasoning, planned_actions } = args;
      const cleanSkill = String(skill_name).trim().toLowerCase();
      const skillPath = path.join(AGENTS_DIR, 'skills', cleanSkill, 'SKILL.md');
      const content = readFileSafe(skillPath);
      let skillDesc = '';
      if (content) {
        const descMatch = content.match(/description:\s*>?-?\s*([^\n]+(?:\n\s+[^\n]+)*)/);
        skillDesc = descMatch ? descMatch[1].replace(/\s+/g, ' ').trim() : '';
      }

      return {
        gate_status: 'PENDING_DEVELOPER_APPROVAL',
        gate_rule: 'MANDATORY HUMAN-IN-THE-LOOP: The assistant MUST NOT execute any steps of this skill until the developer explicitly confirms approval in conversation.',
        proposal: {
          skill: cleanSkill,
          skill_summary: skillDesc || 'Specialized DevSecOps agent skill.',
          target_scope: target_scope || 'Entire workspace',
          reasoning: reasoning || 'Required for security verification phase.',
          planned_actions: planned_actions || 'Static AST review and non-destructive runtime validation.',
          safety_contract: {
            is_non_destructive: true,
            modifies_remote_repo: false,
            executes_exploit_payloads: false,
            scope_limitation: 'Read-only code inspection and local/staging verification only.'
          }
        },
        developer_prompt: `⚠️ **Skill Activation Request: [${cleanSkill}]**\n\n` +
          `• **Target Scope:** ${target_scope}\n` +
          `• **Why This Skill:** ${reasoning}\n` +
          `• **Planned Actions:** ${planned_actions}\n` +
          `• **Safety Guarantee:** Non-destructive, read-only analysis / benign local probes only. No remote git push.\n\n` +
          `*Developer sign-off is required: Do you approve activating this skill? (Reply with "Proceed" or specify adjustments)*`
      };
    }

    default:
      return { error: `Unknown tool: ${name}` };
  }
}

// JSON-RPC stdio server loop
const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout,
  terminal: false
});

function send(msg) {
  process.stdout.write(JSON.stringify(msg) + '\n');
}

rl.on('line', (line) => {
  const trimmed = line.trim();
  if (!trimmed) return;

  let request;
  try {
    request = JSON.parse(trimmed);
  } catch (err) {
    send({
      jsonrpc: '2.0',
      id: null,
      error: { code: -32700, message: 'Parse error' }
    });
    return;
  }

  const { id, method, params } = request;

  // Handle Notifications
  if (method === 'notifications/initialized') {
    return; // No response needed
  }

  // Handle Methods
  if (method === 'initialize') {
    send({
      jsonrpc: '2.0',
      id,
      result: {
        protocolVersion: '2024-11-05',
        capabilities: {
          tools: {}
        },
        serverInfo: {
          name: 'devsecops-knowledge-base',
          version: '1.0.0'
        }
      }
    });
  } else if (method === 'ping') {
    send({
      jsonrpc: '2.0',
      id,
      result: {}
    });
  } else if (method === 'tools/list') {
    send({
      jsonrpc: '2.0',
      id,
      result: {
        tools: TOOLS
      }
    });
  } else if (method === 'tools/call') {
    const { name, arguments: args } = params || {};
    try {
      const toolResult = handleToolCall(name, args || {});
      send({
        jsonrpc: '2.0',
        id,
        result: {
          content: [
            {
              type: 'text',
              text: typeof toolResult === 'string' ? toolResult : JSON.stringify(toolResult, null, 2)
            }
          ]
        }
      });
    } catch (err) {
      send({
        jsonrpc: '2.0',
        id,
        result: {
          content: [
            {
              type: 'text',
              text: `Error executing tool '${name}': ${err.message}`
            }
          ],
          isError: true
        }
      });
    }
  } else {
    send({
      jsonrpc: '2.0',
      id,
      error: { code: -32601, message: `Method not found: ${method}` }
    });
  }
});
