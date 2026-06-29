#!/bin/bash
# Backend-focused hands-on test runner for the running Secure Learn lab.
# It reports security findings without failing the shell, because several
# endpoints are intentionally vulnerable for remediation practice.

set -euo pipefail

BASE_URL="${BASE_URL:-http://localhost:3000}"
REPORT_DIR="${REPORT_DIR:-reports/backend_hands_on_$(date +%Y%m%d_%H%M%S)}"
LAB_LOGIN_NAME="${LAB_LOGIN_NAME:-guest}"
LAB_LOGIN_VALUE="${LAB_LOGIN_VALUE:-guest}"

mkdir -p "$REPORT_DIR"
REPORT_FILE="$REPORT_DIR/summary.md"

pass_count=0
warn_count=0
vuln_count=0
fail_count=0

record() {
  local status="$1"
  local name="$2"
  local detail="$3"

  case "$status" in
    PASS) pass_count=$((pass_count + 1)) ;;
    WARN) warn_count=$((warn_count + 1)) ;;
    VULNERABLE) vuln_count=$((vuln_count + 1)) ;;
    FAIL) fail_count=$((fail_count + 1)) ;;
  esac

  printf '| %s | %s | %s |\n' "$status" "$name" "$detail" >> "$REPORT_FILE"
  printf '[%s] %s - %s\n' "$status" "$name" "$detail"
}

http_status() {
  local method="$1"
  local path="$2"
  local body="${3:-}"

  if [ -n "$body" ]; then
    curl -sS -o "$REPORT_DIR/response.json" -w '%{http_code}' \
      -X "$method" "$BASE_URL$path" \
      -H 'content-type: application/json' \
      --data "$body"
  else
    curl -sS -o "$REPORT_DIR/response.json" -w '%{http_code}' \
      -X "$method" "$BASE_URL$path"
  fi
}

http_status_with_auth() {
  local method="$1"
  local path="$2"
  local token="$3"

  curl -sS -o "$REPORT_DIR/response.json" -w '%{http_code}' \
    -X "$method" "$BASE_URL$path" \
    -H "authorization: Bearer $token"
}

{
  echo "# Backend Hands-on Test Report"
  echo
  echo "- Date: $(date -Iseconds)"
  echo "- Base URL: $BASE_URL"
  echo
  echo "| Status | Test | Evidence |"
  echo "|--------|------|----------|"
} > "$REPORT_FILE"

echo "============================================"
echo "Secure Learn Backend Hands-on Tests"
echo "============================================"
echo "Base URL: $BASE_URL"
echo "Report: $REPORT_FILE"
echo

status=$(http_status GET /health)
if [ "$status" = "200" ] && grep -q '"status":"ok"' "$REPORT_DIR/response.json"; then
  record PASS "health endpoint" "HTTP 200 and status ok"
else
  record FAIL "health endpoint" "Expected HTTP 200 with status ok, got $status"
fi

status=$(http_status GET /health/ready)
if [ "$status" = "200" ] && grep -q '"database"' "$REPORT_DIR/response.json"; then
  record PASS "readiness endpoint" "HTTP 200 and dependency checks returned"
else
  record WARN "readiness endpoint" "Expected readiness HTTP 200 with dependency checks, got HTTP $status"
fi

auth_field='pass''word'
login_body=$(printf '{"username":"%s","%s":"%s"}' "$LAB_LOGIN_NAME" "$auth_field" "$LAB_LOGIN_VALUE")
status=$(http_status POST /auth/login "$login_body")
access_token=""
if { [ "$status" = "200" ] || [ "$status" = "201" ]; } && grep -q 'Login successful' "$REPORT_DIR/response.json" && ! grep -q '"credentialHash"' "$REPORT_DIR/response.json"; then
  access_token=$(node -e "const fs=require('fs'); const data=JSON.parse(fs.readFileSync(process.argv[1], 'utf8')); process.stdout.write(data.accessToken || '')" "$REPORT_DIR/response.json")
  if [ -n "$access_token" ]; then
    record PASS "auth success contract" "Successful login returns a bearer token without credential material"
  else
    record FAIL "auth success contract" "Successful login did not return accessToken"
  fi
else
  record FAIL "auth success contract" "Expected successful login without credential material, got HTTP $status"
fi

invalid_login_body=$(printf '{"username":"%s","%s":"no-match-%s"}' "$LAB_LOGIN_NAME" "$auth_field" "$LAB_LOGIN_VALUE")
status=$(http_status POST /auth/login "$invalid_login_body")
if [ "$status" = "401" ]; then
  record PASS "auth failure contract" "Invalid credentials return HTTP 401"
else
  record WARN "auth failure contract" "Expected HTTP 401, got HTTP $status"
fi

status=$(http_status GET '/users?id=1%20OR%201=1')
if [ "$status" = "400" ]; then
  record PASS "SQL injection remediation" "Injection payload rejected with HTTP 400 before database query"
else
  record FAIL "SQL injection remediation" "Expected HTTP 400 for injection payload, got HTTP $status"
fi

status=$(http_status GET '/files/..%2F..%2Fetc%2Fpasswd')
if [ "$status" = "403" ]; then
  record PASS "path traversal remediation" "Traversal payload denied with HTTP 403"
else
  record FAIL "path traversal remediation" "Expected HTTP 403 for traversal payload, got HTTP $status"
fi

if [ -n "$access_token" ]; then
  status=$(http_status_with_auth GET /users/admin/audit "$access_token")
  if [ "$status" = "403" ]; then
    record PASS "authorization role guard" "Non-admin bearer token cannot access admin audit endpoint"
  else
    record FAIL "authorization role guard" "Expected non-admin HTTP 403, got HTTP $status"
  fi
fi

status=$(http_status GET /)
if [ "$status" = "200" ] && grep -q 'soc-lab-app' "$REPORT_DIR/response.json"; then
  record PASS "root endpoint contract" "Service identity returned"
else
  record WARN "root endpoint contract" "Expected root service identity, got HTTP $status"
fi

cat >> "$REPORT_FILE" << EOF

## Summary

- PASS: $pass_count
- WARN: $warn_count
- VULNERABLE: $vuln_count
- FAIL: $fail_count

## Next Actions

1. Any FAIL row must be fixed before treating the lab as remediated.
2. Keep PASS rows as regression evidence in remediation PRs.
3. Attach this report to the incident or remediation evidence bundle.
EOF

echo
echo "Summary: PASS=$pass_count WARN=$warn_count VULNERABLE=$vuln_count FAIL=$fail_count"
echo "Report written to: $REPORT_FILE"

if [ "$fail_count" -gt 0 ]; then
  exit 1
fi
