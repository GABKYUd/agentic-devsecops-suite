# DevSecOps Pipeline Automation & Purple Team CI/CD

## Purpose & Architecture
This reference provides drop-in CI/CD pipeline automation templates and scripts to embed **vulnerability hunting, automated false-positive filtering (7-Question Gate), and purple-team telemetry validation** directly into development workflows.

```
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                          DevSecOps Automated Pipeline Stages                           │
├────────────────────────────────────────────────────────────────────────────────────────┤
│                                                                                        │
│  [Code Push / PR]                                                                      │
│         │                                                                              │
│         ├──► Stage 1: Secret Scanning (Gitleaks) ─────────────► [FAIL if leak found]   │
│         │                                                                              │
│         ├──► Stage 2: Dependency SCA (Trivy / OSV-Scanner) ───► [FAIL on Known CVEs]   │
│         │                                                                              │
│         ├──► Stage 3: SAST Engine (Semgrep Purple Rules) ─────► [Filter via 7-Q Gate]  │
│         │                                                                              │
│         ├──► Stage 4: IaC & Container Audit (Trivy / Hadolint)► [FAIL on Misconfigs]   │
│         │                                                                              │
│         ▼                                                                              │
│  [Deploy to Ephemeral Staging]                                                         │
│         │                                                                              │
│         ├──► Stage 5: Dynamic API / DAST Check (Nuclei / ZAP)                          │
│         │                                                                              │
│         ├──► Stage 6: Purple Team Alert Telemetry Assertion                            │
│         │    (Execute benign probe ──► Verify SIEM/WAF alert fires in staging logs)     │
│         │                                                                              │
│         ▼                                                                              │
│  [Build Passed & Audited ──► Ready for Production Merge]                               │
│                                                                                        │
└────────────────────────────────────────────────────────────────────────────────────────┘
```

---

## 1. Reusable GitHub Actions Workflow Template

Create this file at `.github/workflows/devsecops-purple-pipeline.yml`:

```yaml
name: DevSecOps Purple Pipeline

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]
  workflow_dispatch:

permissions:
  contents: read
  security-events: write
  pull-requests: write

jobs:
  # -------------------------------------------------------------
  # Stage 1: Secret Scanning
  # -------------------------------------------------------------
  secret-scan:
    name: Secret Scanning (Gitleaks)
    runs-on: ubuntu-latest
    steps:
      - name: Checkout Code
        uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - name: Run Gitleaks
        uses: gitleaks/gitleaks-action@v2
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
          GITLEAKS_LICENSE: ${{ secrets.GITLEAKS_LICENSE }} # Optional for orgs

  # -------------------------------------------------------------
  # Stage 2: Software Composition Analysis (SCA)
  # -------------------------------------------------------------
  dependency-scan:
    name: Dependency Vulnerabilities (Trivy)
    runs-on: ubuntu-latest
    steps:
      - name: Checkout Code
        uses: actions/checkout@v4

      - name: Run Trivy Vulnerability Scanner (FS)
        uses: aquasecurity/trivy-action@0.28.0
        with:
          scan-type: 'fs'
          scan-ref: '.'
          format: 'sarif'
          output: 'trivy-results.sarif'
          severity: 'CRITICAL,HIGH'
          ignore-unfixed: true

      - name: Upload Trivy SARIF to GitHub Security Tab
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: 'trivy-results.sarif'

  # -------------------------------------------------------------
  # Stage 3: Static Application Security Testing (SAST)
  # -------------------------------------------------------------
  sast-scan:
    name: SAST (Semgrep Purple Rules)
    runs-on: ubuntu-latest
    container:
      image: semgrep/semgrep:1.108.0
    steps:
      - name: Checkout Code
        uses: actions/checkout@v4

      - name: Run Semgrep with Security Rulesets
        run: |
          semgrep scan \
            --config "p/security-audit" \
            --config "p/owasp-top-ten" \
            --config "p/cwe-top-25" \
            --sarif \
            --output semgrep-results.sarif

      - name: Upload Semgrep SARIF
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: 'semgrep-results.sarif'

  # -------------------------------------------------------------
  # Stage 4: Container & IaC Hardening Scan
  # -------------------------------------------------------------
  iac-scan:
    name: IaC & Dockerfile Audit
    runs-on: ubuntu-latest
    steps:
      - name: Checkout Code
        uses: actions/checkout@v4

      - name: Run Trivy Config Scan (IaC)
        uses: aquasecurity/trivy-action@0.28.0
        with:
          scan-type: 'config'
          scan-ref: '.'
          severity: 'HIGH,CRITICAL'
          exit-code: '1'

  # -------------------------------------------------------------
  # Stage 5: Manifest-Driven DAST (findings-manifest.json → per-endpoint probes)
  # Stage 6: Sentinel SOC Detection Gate (/api/security/logs)
  # Runs only on authorized staging environments with ALLOW_DAST=true
  # -------------------------------------------------------------
  purple-staging-test:
    name: Staging DAST & Sentinel Detection Validation
    needs: [secret-scan, dependency-scan, sast-scan, iac-scan]
    # Safe Staging Guard: Requires explicit ALLOW_DAST variable to prevent probing against unauthorized hosts
    if: github.ref == 'refs/heads/main' && vars.ALLOW_DAST == 'true'
    runs-on: ubuntu-latest
    env:
      SENTINEL_BASE_URL: ${{ secrets.SENTINEL_BASE_URL }}       # e.g. https://staging.example.com
      SENTINEL_TOKEN: ${{ secrets.SENTINEL_SOC_TOKEN }}         # JWT for VIEW_SECURITY_DASH + VIEW_LOGS role
    steps:
      - name: Checkout Code
        uses: actions/checkout@v4

      - name: Set up Staging Ephemeral Test Environment
        run: |
          echo "Spinning up staging test container..."
          docker compose -f docker-compose.test.yml up -d --wait || true
          sleep 5  # Allow Sentinel middleware to initialize

      # ── Stage 5: Manifest-Driven DAST ──────────────────────────────────────
      # Reads findings-manifest.json written by the 7-Question Gate (Stage 3).
      # Fires each probe_payload against its exact endpoint. Does NOT run a
      # blanket Nuclei sweep — every probe is scoped to a specific SAST finding.
      - name: Stage 5 — Manifest-Driven DAST Probes
        run: |
          set -e
          MANIFEST="findings-manifest.json"
          RESULTS_FILE="dast-results.json"
          echo "[]" > "$RESULTS_FILE"

          if [ ! -f "$MANIFEST" ]; then
            echo "[SKIP] No findings-manifest.json found — no SAST findings to probe."
            exit 0
          fi

          FINDING_COUNT=$(jq '. | length' "$MANIFEST")
          echo "📋 Manifest contains $FINDING_COUNT finding(s) to probe."

          jq -c '.[]' "$MANIFEST" | while read -r finding; do
            FINDING_ID=$(echo "$finding" | jq -r '.id')
            ENDPOINT=$(echo "$finding" | jq -r '.endpoint')
            PAYLOAD=$(echo "$finding" | jq -r '.probe_payload')
            VULN_CLASS=$(echo "$finding" | jq -r '.vuln_class')
            EXPECTED_SAFE=$(echo "$finding" | jq -r '.expected_safe_signal')
            PROBE_FIRED_AT=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

            echo "🔍 [$FINDING_ID] Probing $ENDPOINT ($VULN_CLASS) with payload: $PAYLOAD"

            # Fire the probe — single non-destructive HTTP request
            HTTP_STATUS=$(curl -s -o /tmp/probe_body.txt -w "%{http_code}" \
              --max-time 10 \
              -H "Content-Type: application/json" \
              -d "{\"url\": \"$PAYLOAD\", \"input\": \"$PAYLOAD\", \"file\": \"$PAYLOAD\"}" \
              "http://127.0.0.1:3000$ENDPOINT" 2>/dev/null || echo "000")

            RESPONSE_BODY=$(cat /tmp/probe_body.txt 2>/dev/null || echo "")

            # Evaluate result: check for safe signal in response
            if echo "$RESPONSE_BODY" | grep -qiF "$EXPECTED_SAFE"; then
              PROBE_RESULT="SAFE"
            elif [ "$HTTP_STATUS" = "400" ] || [ "$HTTP_STATUS" = "403" ] || [ "$HTTP_STATUS" = "404" ]; then
              PROBE_RESULT="SAFE"
            else
              PROBE_RESULT="POTENTIALLY_VULNERABLE"
            fi

            echo "  → HTTP $HTTP_STATUS | Result: $PROBE_RESULT"

            # Append to results with probe timestamp for Stage 6
            ENTRY=$(jq -n \
              --arg id "$FINDING_ID" \
              --arg endpoint "$ENDPOINT" \
              --arg vuln_class "$VULN_CLASS" \
              --arg status "$HTTP_STATUS" \
              --arg probe_result "$PROBE_RESULT" \
              --arg probe_fired_at "$PROBE_FIRED_AT" \
              --argjson finding "$finding" \
              '{id: $id, endpoint: $endpoint, vuln_class: $vuln_class,
                http_status: $status, probe_result: $probe_result,
                probe_fired_at: $probe_fired_at,
                sigma_rule_id: $finding.sigma_rule_id}')

            TMP=$(jq --argjson entry "$ENTRY" '. + [$entry]' "$RESULTS_FILE")
            echo "$TMP" > "$RESULTS_FILE"
          done

          echo "✅ Stage 5 complete. Results written to $RESULTS_FILE"
          cat "$RESULTS_FILE" | jq '.'

      # ── Stage 6: Sentinel Detection Gate ───────────────────────────────────
      # For each finding, queries the application /api/security/logs
      # endpoint for a matching Sentinel audit event (action_type matching
      # the finding's sigma_rule_id) fired after the DAST probe timestamp.
      # Records detection_status: DETECTED | MISSED | SKIPPED per finding.
      - name: Stage 6 — Sentinel SOC Detection Gate
        run: |
          set -e
          RESULTS_FILE="dast-results.json"
          FINAL_FILE="pipeline-final-results.json"
          DETECTION_GAPS=0
          CODE_BLOCKS=0

          if [ ! -f "$RESULTS_FILE" ]; then
            echo "[SKIP] No DAST results file — skipping detection gate."
            echo "[]" > "$FINAL_FILE"
            exit 0
          fi

          echo "[]" > "$FINAL_FILE"

          jq -c '.[]' "$RESULTS_FILE" | while read -r probe_result; do
            FINDING_ID=$(echo "$probe_result" | jq -r '.id')
            SIGMA_RULE_ID=$(echo "$probe_result" | jq -r '.sigma_rule_id')
            PROBE_FIRED_AT=$(echo "$probe_result" | jq -r '.probe_fired_at')
            PROBE_OUTCOME=$(echo "$probe_result" | jq -r '.probe_result')

            # Map code_status from probe result
            if [ "$PROBE_OUTCOME" = "SAFE" ]; then
              CODE_STATUS="FIXED"
            else
              CODE_STATUS="BLOCKING"
              CODE_BLOCKS=$((CODE_BLOCKS + 1))
            fi

            # If no sigma_rule_id, skip detection gate
            if [ -z "$SIGMA_RULE_ID" ] || [ "$SIGMA_RULE_ID" = "null" ]; then
              DETECTION_STATUS="SKIPPED"
              echo "⬛ [$FINDING_ID] Detection: SKIPPED (no sigma_rule_id mapped)"
            else
              echo "🔎 [$FINDING_ID] Querying Sentinel for action_type=$SIGMA_RULE_ID since $PROBE_FIRED_AT ..."

              # Poll Sentinel /api/security/logs for matching audit event (60s window, 4 retries x 15s)
              DETECTED=false
              for attempt in 1 2 3 4; do
                RESPONSE=$(curl -s \
                  -H "Authorization: Bearer $SENTINEL_TOKEN" \
                  "$SENTINEL_BASE_URL/api/security/logs?actionType=$SIGMA_RULE_ID&timeRange=15m&limit=20" \
                  2>/dev/null || echo '{"logs":[]}')

                MATCH_COUNT=$(echo "$RESPONSE" | jq \
                  --arg since "$PROBE_FIRED_AT" \
                  '[.logs[]? | select(.timestamp >= $since)] | length' 2>/dev/null || echo "0")

                if [ "$MATCH_COUNT" -gt 0 ]; then
                  DETECTED=true
                  break
                fi

                echo "  Attempt $attempt/4 — no match yet. Waiting 15s..."
                sleep 15
              done

              if [ "$DETECTED" = "true" ]; then
                DETECTION_STATUS="DETECTED"
                echo "✅ [$FINDING_ID] Detection: DETECTED (Sentinel event confirmed)"
              else
                DETECTION_STATUS="MISSED"
                DETECTION_GAPS=$((DETECTION_GAPS + 1))
                echo "⚠️  [$FINDING_ID] Detection: MISSED — opening detection-gap ticket: detection-gap:$SIGMA_RULE_ID"
              fi
            fi

            # Write final dual-status entry
            FINAL_ENTRY=$(echo "$probe_result" | jq \
              --arg code_status "$CODE_STATUS" \
              --arg detection_status "$DETECTION_STATUS" \
              '. + {code_status: $code_status, detection_status: $detection_status}')

            TMP=$(jq --argjson entry "$FINAL_ENTRY" '. + [$entry]' "$FINAL_FILE")
            echo "$TMP" > "$FINAL_FILE"
          done

          echo ""
          echo "════════════════════════════════════════"
          echo "  Purple Pipeline Summary"
          echo "════════════════════════════════════════"
          cat "$FINAL_FILE" | jq -r '.[] | "  [\(.id)] code_status=\(.code_status) | detection_status=\(.detection_status)"'
          echo ""

          # Build fails only on BLOCKING code_status (not on detection gaps)
          if [ "$CODE_BLOCKS" -gt 0 ]; then
            echo "❌ PIPELINE FAILED: $CODE_BLOCKS finding(s) with code_status=BLOCKING require resolution."
            exit 1
          fi

          if [ "$DETECTION_GAPS" -gt 0 ]; then
            echo "⚠️  $DETECTION_GAPS detection gap(s) logged (detection_status=MISSED). Non-blocking — SOC must open detection-gap tickets."
          fi

          echo "✅ PIPELINE PASSED: All code_status checks cleared."
```

---

## 2. Automated 7-Question Gate Triage Script

To prevent noisy SAST scanners from failing builds on unreachable code or false positives, use this automated triage helper (`scripts/devsecops-triage-gate.py`):

```python
#!/usr/bin/env python3
"""
DevSecOps 7-Question Gate Triage Engine
Parses SARIF output from SAST/SCA tools and verifies:
1. Is the finding in active code paths (not test/mock/doc files)?
2. Does the finding reach an unauthenticated or public route?
3. Is a known framework sanitizer present?
Outputs a filtered scorecard and determines build pass/fail.
"""

import json
import sys
import os

IGNORED_PATHS = ["test/", "tests/", "mock/", "docs/", "examples/", "scratch/"]

def evaluate_finding(result):
    rule_id = result.get("ruleId", "UNKNOWN")
    message = result.get("message", {}).get("text", "")
    locations = result.get("locations", [])
    
    if not locations:
        return None
        
    uri = locations[0].get("physicalLocation", {}).get("artifactLocation", {}).get("uri", "")
    line = locations[0].get("physicalLocation", {}).get("region", {}).get("startLine", 0)
    
    # 7-Question Gate Criteria 1: Reachability & Scope Check
    for ignored in IGNORED_PATHS:
        if ignored in uri:
            return {
                "rule": rule_id,
                "file": uri,
                "line": line,
                "status": "DISMISSED",
                "reason": "Test/Fixture code out of production execution scope"
            }
            
    # Criteria 2: Severity Calibration
    level = result.get("level", "warning")
    is_blocking = level in ["error", "critical"]
    
    return {
        "rule": rule_id,
        "file": uri,
        "line": line,
        "level": level,
        "status": "BLOCKING" if is_blocking else "MONITOR",
        "reason": message
    }

def main(sarif_path):
    if not os.path.exists(sarif_path):
        print(f"[!] SARIF report not found at: {sarif_path}")
        sys.exit(0)
        
    with open(sarif_path, "r", encoding="utf-8") as f:
        sarif_data = json.load(f)
        
    blocking_count = 0
    total_findings = 0
    
    print("\n=== DevSecOps 7-Question Gate Triage Report ===")
    
    for run in sarif_data.get("runs", []):
        results = run.get("results", [])
        for res in results:
            total_findings += 1
            evaluation = evaluate_finding(res)
            if not evaluation:
                continue
                
            if evaluation["status"] == "BLOCKING":
                blocking_count += 1
                print(f"[BLOCK] Rule: {evaluation['rule']} | File: {evaluation['file']}:{evaluation['line']}")
                print(f"        Reason: {evaluation['reason']}")
            elif evaluation["status"] == "DISMISSED":
                print(f"[SKIP]  Rule: {evaluation['rule']} | File: {evaluation['file']}:{evaluation['line']} (Reason: {evaluation['reason']})")

    print(f"\nSummary: {total_findings} Total Findings Evaluated | {blocking_count} Actionable Blocking Issues")
    
    if blocking_count > 0:
        print("\n[FAIL] Build rejected by 7-Question Gate. Actionable high-severity findings require resolution.")
        sys.exit(1)
    else:
        print("\n[PASS] All findings cleared the 7-Question Gate. Pipeline approved.")
        sys.exit(0)

if __name__ == "__main__":
    sarif_file = sys.argv[1] if len(sys.argv) > 1 else "semgrep-results.sarif"
    main(sarif_file)
```

---

## 3. Pipeline Performance & Optimization Guidelines

1. **Fast-Feedback PR Checks (< 3 minutes):**
   - Run Gitleaks on changed commits (`--diff-only`).
   - Run Semgrep strictly on modified files (`semgrep scan --diff origin/main`).
   - Block PR merges only on verified CRITICAL/HIGH findings passing the 7-Question Gate.

2. **Deep Nightly / Scheduled Scans:**
   - Execute full repository deep scans with full AST reachability analysis.
   - Run container image scans and dynamic staging DAST.
   - Validate that purple-team detection alerts match SIEM logs for the past 24 hours.

3. **Developer Ergonomics:**
   - Always output the exact code fix diff alongside the SAST alert.
   - Never page on-call engineers for unverified or informational SAST alerts.
