#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${1:-http://localhost:5000}"

check() {
  local path="$1"
  local expected="$2"
  local status
  status=$(curl -s -o /dev/null -w "%{http_code}" "${BASE_URL}${path}")
  if [[ "$status" != "$expected" ]]; then
    echo "FAIL ${path}: expected ${expected}, got ${status}" >&2
    exit 1
  fi
  echo "OK ${path} (${status})"
}

# Public health/version endpoints
check "/api/health" "200"
check "/api/version" "200"

# Auth should require login (expects redirect or 302/401). Adjust as needed.
status=$(curl -s -o /dev/null -w "%{http_code}" "${BASE_URL}/api/hosts")
if [[ "$status" == "200" ]]; then
  echo "WARN /api/hosts returned 200 without auth"
else
  echo "OK /api/hosts requires auth (${status})"
fi

echo "Smoke tests finished."
