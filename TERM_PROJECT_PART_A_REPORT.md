# 2190413 Computer Security — Term Project Part A (DVWA)

Student deliverable draft for **at least 8 vulnerabilities/threats** in DVWA, with OWASP-style risk scoring and fix/mitigation guidance.

## Scoring method used

Per the assignment rubric, each vulnerability is scored on 4 criteria:

- **Exploitability (E)**: Difficult=1, Average=2, Easy=3
- **Weakness Prevalence (P)**: Uncommon=1, Common=2, Widespread=3
- **Weakness Detectability (D)**: Difficult=1, Average=2, Easy=3
- **Technical Impact (I)**: Minor=1, Moderate=2, Severe=3

**Total Risk Score = E + P + D + I** (range: 4 to 12)

Suggested interpretation:
- **10–12**: High
- **7–9**: Medium
- **4–6**: Low

> Notes:
> - URLs and methods below are based on standard DVWA modules and typical requests.
> - You should capture screenshots or HTTP evidence from your own lab run when submitting.

## Re-rated vulnerability summary (quick view)

| # | Vulnerability | E | P | D | I | Total | Risk |
|---|---|---:|---:|---:|---:|---:|---|
| 1 | SQL Injection (Classic) | 3 | 3 | 3 | 3 | 12 | High |
| 2 | Blind SQL Injection | 2 | 2 | 2 | 3 | 9 | Medium |
| 3 | Command Injection | 3 | 2 | 2 | 3 | 10 | High |
| 4 | Reflected XSS | 3 | 3 | 3 | 2 | 11 | High |
| 5 | Stored XSS | 3 | 2 | 2 | 3 | 10 | High |
| 6 | CSRF | 3 | 2 | 2 | 2 | 9 | Medium |
| 7 | File Inclusion (LFI/RFI) | 2 | 2 | 2 | 3 | 9 | Medium |
| 8 | Unrestricted File Upload | 3 | 2 | 2 | 3 | 10 | High |
| 9 | Weak Brute-Force Protection | 3 | 3 | 3 | 2 | 11 | High |
| 10 | Weak Session ID / Session Management | 2 | 2 | 2 | 3 | 9 | Medium |

> Interpretation reminder: 10–12 = High, 7–9 = Medium, 4–6 = Low.

---

## 1) SQL Injection (Classic)

- **Endpoint/Module**: `/vulnerabilities/sqli/`
- **HTTP Method**: `GET`
- **Typical parameter**: `id`
- **Threat description**: The server builds SQL queries by concatenating unsanitized user input. An attacker can inject SQL syntax to read, alter, or delete database data.

### Example attack flow (for lab demonstration only)
1. User input is expected to be numeric ID (e.g., `id=1`).
2. Attacker sends payload such as `id=1' OR '1'='1`.
3. Query logic becomes always true and returns unintended rows.
4. With union/error-based techniques, attacker can enumerate schema and extract sensitive records.

### Risk scoring (OWASP 4 factors)
- **Exploitability**: `3 (Easy)` — payloads are simple and widely documented.
- **Weakness Prevalence**: `3 (Widespread)` — historically common in apps with dynamic SQL.
- **Weakness Detectability**: `3 (Easy)` — scanners/manual probes detect quickly.
- **Technical Impact**: `3 (Severe)` — confidentiality/integrity impact can be complete DB compromise.
- **Total Risk Score**: `12/12 (High)`

### Vulnerable coding pattern (concept)
```php
// ❌ vulnerable pattern
$sql = "SELECT first_name, last_name FROM users WHERE user_id = '$id'";
$result = mysqli_query($conn, $sql);
```

### Secure fix (recommended)
Use **prepared statements** and bind parameters to keep user input as data, not SQL code.

```php
// ✅ secure pattern with PDO
$stmt = $pdo->prepare('SELECT first_name, last_name FROM users WHERE user_id = :id');
$stmt->bindValue(':id', (int)$_GET['id'], PDO::PARAM_INT);
$stmt->execute();
$rows = $stmt->fetchAll();
```

### Additional hardening
- Enforce strict server-side validation (`id` must be integer and in allowed range).
- Use least-privilege DB account (`SELECT` only where possible).
- Suppress verbose SQL errors from end users (log internally).
- Add monitoring/WAF signatures for SQLi patterns as defense in depth.

### Verification after fix
- Normal request `id=1` still works.
- Attack payloads (e.g., tautology, UNION) return no unauthorized data.
- Security scanner no longer reports injectable parameter.

---

## 2) Blind SQL Injection

- **Endpoint/Module**: `/vulnerabilities/sqli_blind/`
- **Method**: `GET`/`POST` (depends on DVWA level)
- **Threat description**: No direct SQL error output, but boolean/time-based payloads still leak data.

### Risk scoring
- Exploitability: **2 (Average)**
- Weakness Prevalence: **2 (Common)**
- Weakness Detectability: **2 (Average)**
- Technical Impact: **3 (Severe)**
- **Total = 9 (Medium)**

### Fix / Mitigation
- Same primary fix as SQLi: **prepared statements**.
- Generic error handling (no DB error details in responses).
- WAF/rate limiting to reduce automation of inference attacks.

---

## 3) Command Injection

- **Endpoint/Module**: `/vulnerabilities/exec/`
- **Method**: `POST` (e.g., `ip` argument passed to shell command)
- **Threat description**: User input is injected into OS command, enabling arbitrary command execution.

### Risk scoring
- Exploitability: **3 (Easy)**
- Weakness Prevalence: **2 (Common)**
- Weakness Detectability: **2 (Average)**
- Technical Impact: **3 (Severe)**
- **Total = 10 (High)**

### Fix / Mitigation
- Avoid shell execution entirely; use safe library/network APIs.
- If unavoidable, use strict allowlist validation and argument escaping.
- Run web service with least OS privileges and container/AppArmor/SELinux confinement.

---

## 4) Reflected Cross-Site Scripting (XSS)

- **Endpoint/Module**: `/vulnerabilities/xss_r/`
- **Method**: `GET` (reflected parameter)
- **Threat description**: Malicious JavaScript is reflected to victim browser and executed in app origin.

### Risk scoring
- Exploitability: **3 (Easy)**
- Weakness Prevalence: **3 (Widespread)**
- Weakness Detectability: **3 (Easy)**
- Technical Impact: **2 (Moderate)**
- **Total = 11 (High)**

### Fix / Mitigation
- Context-aware output encoding (`htmlspecialchars` for HTML context).
- Input validation for expected format.
- Add CSP (`Content-Security-Policy`) as defense in depth.

---

## 5) Stored Cross-Site Scripting (XSS)

- **Endpoint/Module**: `/vulnerabilities/xss_s/`
- **Method**: `POST` (payload stored server-side, then rendered)
- **Threat description**: Persistent script executes for every viewer of infected content.

### Risk scoring
- Exploitability: **3 (Easy)**
- Weakness Prevalence: **2 (Common)**
- Weakness Detectability: **2 (Average)**
- Technical Impact: **3 (Severe)**
- **Total = 10 (High)**

### Fix / Mitigation
- Output encode on rendering and sanitize rich text inputs.
- Use HTTPOnly + SameSite cookies to reduce session theft risk.
- CSP and modern framework templating auto-escaping.

---

## 6) Cross-Site Request Forgery (CSRF)

- **Endpoint/Module**: `/vulnerabilities/csrf/`
- **Method**: `GET` or `POST` state-changing action (password change)
- **Threat description**: Victim browser sends authenticated request without user intent.

### Risk scoring
- Exploitability: **3 (Easy)**
- Weakness Prevalence: **2 (Common)**
- Weakness Detectability: **2 (Average)**
- Technical Impact: **2 (Moderate)**
- **Total = 9 (Medium)**

### Fix / Mitigation
- Synchronizer **CSRF token** on all state-changing actions.
- Enforce `SameSite` cookies and verify Origin/Referer headers.
- Require re-authentication for sensitive operations.

---

## 7) File Inclusion (LFI/RFI)

- **Endpoint/Module**: `/vulnerabilities/fi/`
- **Method**: `GET` (page/file parameter)
- **Threat description**: Attacker controls include path; can read local files or include remote code (if enabled).

### Risk scoring
- Exploitability: **2 (Average)**
- Weakness Prevalence: **2 (Common)**
- Weakness Detectability: **2 (Average)**
- Technical Impact: **3 (Severe)**
- **Total = 9 (Medium)**

### Fix / Mitigation
- Never pass raw user input to `include/require`.
- Use route allowlist mapping (ID -> known file).
- Disable remote URL includes; harden PHP config and filesystem permissions.

---

## 8) Unrestricted File Upload

- **Endpoint/Module**: `/vulnerabilities/upload/`
- **Method**: `POST` multipart upload
- **Threat description**: Upload of executable script/web shell leading to remote code execution.

### Risk scoring
- Exploitability: **3 (Easy)**
- Weakness Prevalence: **2 (Common)**
- Weakness Detectability: **2 (Average)**
- Technical Impact: **3 (Severe)**
- **Total = 10 (High)**

### Fix / Mitigation
- Allowlist file type by MIME + extension + magic-byte checks.
- Store files outside web root and rename to random UUID.
- Disable script execution in upload directory.
- Virus scan and size limits.

---

## 9) Weak Brute-Force Protection (Authentication Threat)

- **Endpoint/Module**: `/vulnerabilities/brute/`
- **Method**: `GET`/`POST` login attempts
- **Threat description**: No effective lockout/rate limit enables credential stuffing/brute force.

### Risk scoring
- Exploitability: **3 (Easy)**
- Weakness Prevalence: **3 (Widespread)**
- Weakness Detectability: **3 (Easy)**
- Technical Impact: **2 (Moderate)**
- **Total = 11 (High)**

### Fix / Mitigation
- Rate limiting, exponential backoff, temporary account/IP lockout.
- MFA for privileged users.
- Detect and alert suspicious authentication patterns.

---

## 10) Weak Session ID / Session Management

- **Endpoint/Module**: `/vulnerabilities/weak_id/`
- **Method**: Session issuance and cookie handling
- **Threat description**: Predictable or poorly protected session tokens can be guessed/stolen.

### Risk scoring
- Exploitability: **2 (Average)**
- Weakness Prevalence: **2 (Common)**
- Weakness Detectability: **2 (Average)**
- Technical Impact: **3 (Severe)**
- **Total = 9 (Medium)**

### Fix / Mitigation
- Use cryptographically secure random session IDs.
- Set cookie flags: `Secure`, `HttpOnly`, `SameSite`.
- Regenerate session ID on login/privilege changes.
- Short idle timeout + server-side invalidation.

---

## Optional bonus vulnerabilities to discuss

If you want to score more than 10 entries (bonus up to 12), you can add:
- DOM XSS (`/vulnerabilities/xss_d/`)
- CSP misconfiguration (`/vulnerabilities/csp/`)
- CAPTCHA bypass logic weaknesses (`/vulnerabilities/captcha/`)
- Insecure anti-CSRF implementation in custom flows

---

## Suggested submission format (for peer review clarity)

For each item, include:
1. Module URL + HTTP method
2. Vulnerability explanation + example payload (safe/redacted)
3. Risk score breakdown (E/P/D/I) + total
4. Concrete fix in code/config + why it works
5. Verification steps after fixing (negative test)

This structure maps directly to your grading criteria and makes your work easy to evaluate.
