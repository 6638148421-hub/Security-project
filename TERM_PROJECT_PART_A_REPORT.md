# 2190413 Computer Security — Term Project Part A (DVWA)

This document is the final Part A write-up for DVWA and is optimized for peer grading.

## Scope and scoring model

OWASP-style 4-factor score per vulnerability:
- **Exploitability (E)**: Difficult=1, Average=2, Easy=3
- **Weakness Prevalence (P)**: Uncommon=1, Common=2, Widespread=3
- **Weakness Detectability (D)**: Difficult=1, Average=2, Easy=3
- **Technical Impact (I)**: Minor=1, Moderate=2, Severe=3

**Total score = E + P + D + I** (min 4, max 12)
- **High**: 10–12
- **Medium**: 7–9
- **Low**: 4–6

---

## Re-rated summary table (10 vulnerabilities)

| # | Vulnerability | Module/Endpoint | Method | E | P | D | I | Total | Risk |
|---|---|---|---|---:|---:|---:|---:|---:|---|
| 1 | SQL Injection (Classic) | `/vulnerabilities/sqli/` | GET | 3 | 3 | 3 | 3 | 12 | High |
| 2 | Blind SQL Injection | `/vulnerabilities/sqli_blind/` | GET | 2 | 2 | 2 | 3 | 9 | Medium |
| 3 | Command Injection | `/vulnerabilities/exec/` | POST | 3 | 2 | 2 | 3 | 10 | High |
| 4 | Reflected XSS | `/vulnerabilities/xss_r/` | GET | 3 | 3 | 3 | 2 | 11 | High |
| 5 | Stored XSS | `/vulnerabilities/xss_s/` | POST | 3 | 2 | 2 | 3 | 10 | High |
| 6 | CSRF | `/vulnerabilities/csrf/` | GET/POST state-change | 3 | 2 | 2 | 2 | 9 | Medium |
| 7 | File Inclusion (LFI/RFI) | `/vulnerabilities/fi/` | GET | 2 | 2 | 2 | 3 | 9 | Medium |
| 8 | Unrestricted File Upload | `/vulnerabilities/upload/` | POST multipart | 3 | 2 | 2 | 3 | 10 | High |
| 9 | Weak Brute-Force Protection | `/vulnerabilities/brute/` | GET/POST login attempts | 3 | 3 | 3 | 2 | 11 | High |
| 10 | Weak Session ID | `/vulnerabilities/weak_id/` | POST session generation | 2 | 2 | 2 | 3 | 9 | Medium |

---

## Per-vulnerability grading blocks (concise and consistent)

## 1) SQL Injection (Classic)
- **Endpoint/Method**: `/vulnerabilities/sqli/` (GET, `id` parameter)
- **Description**: Input is concatenated into SQL; attacker can dump/modify DB data.
- **Score**: E3 P3 D3 I3 = **12 (High)**
- **Fix/Mitigation**: Prepared statements (parameterized SQL), strict type validation, least-privilege DB user, generic error responses.
- **Verify after fix**: `id=1' OR '1'='1` does not expand result set.

## 2) Blind SQL Injection
- **Endpoint/Method**: `/vulnerabilities/sqli_blind/` (GET)
- **Description**: Data leaked via inference (boolean/time-based) without visible SQL errors.
- **Score**: E2 P2 D2 I3 = **9 (Medium)**
- **Fix/Mitigation**: Prepared statements, remove differential error/timing behaviors where possible, rate limit probing.
- **Verify after fix**: `SLEEP` payload does not create reliable timing delta.

## 3) Command Injection
- **Endpoint/Method**: `/vulnerabilities/exec/` (POST)
- **Description**: Shell metacharacters in user input execute arbitrary OS commands.
- **Score**: E3 P2 D2 I3 = **10 (High)**
- **Fix/Mitigation**: Avoid shell calls, use safe APIs, strict allowlist validation, least OS privileges.
- **Verify after fix**: payload `127.0.0.1;id` returns no injected command output.

## 4) Reflected XSS
- **Endpoint/Method**: `/vulnerabilities/xss_r/` (GET)
- **Description**: Input is reflected unescaped and can execute JavaScript in victim browser.
- **Score**: E3 P3 D3 I2 = **11 (High)**
- **Fix/Mitigation**: Context-aware output encoding (`htmlspecialchars`), CSP defense-in-depth, input constraints.
- **Verify after fix**: script payload is encoded, not executed.

## 5) Stored XSS
- **Endpoint/Method**: `/vulnerabilities/xss_s/` (POST)
- **Description**: Malicious payload persists and executes for any viewer of stored content.
- **Score**: E3 P2 D2 I3 = **10 (High)**
- **Fix/Mitigation**: Encode on output, sanitize rich text, CSP, secure cookie settings.
- **Verify after fix**: payload is stored safely (not executable context).

## 6) CSRF
- **Endpoint/Method**: `/vulnerabilities/csrf/` (state-changing request)
- **Description**: Authenticated user can be tricked into unintended state changes.
- **Score**: E3 P2 D2 I2 = **9 (Medium)**
- **Fix/Mitigation**: CSRF token, SameSite cookies, Origin/Referer verification, re-auth for sensitive actions.
- **Verify after fix**: forged request without valid token is rejected.

## 7) File Inclusion (LFI/RFI)
- **Endpoint/Method**: `/vulnerabilities/fi/` (GET, `page`)
- **Description**: User-controlled include path enables local file disclosure / remote include risk.
- **Score**: E2 P2 D2 I3 = **9 (Medium)**
- **Fix/Mitigation**: Route allowlist mapping, never include raw user input, harden PHP include settings.
- **Verify after fix**: traversal payload cannot read `/etc/passwd`.

## 8) Unrestricted File Upload
- **Endpoint/Method**: `/vulnerabilities/upload/` (POST multipart)
- **Description**: Executable file upload can lead to web shell / remote code execution.
- **Score**: E3 P2 D2 I3 = **10 (High)**
- **Fix/Mitigation**: extension+MIME+magic-byte allowlist, store outside web root, disable script execution in upload path.
- **Verify after fix**: `.php` upload rejected and unreachable.

## 9) Weak Brute-Force Protection
- **Endpoint/Method**: `/vulnerabilities/brute/` (repeated login attempts)
- **Description**: Missing lockout/rate limit allows automated password guessing.
- **Score**: E3 P3 D3 I2 = **11 (High)**
- **Fix/Mitigation**: throttling/backoff, lockout, MFA, detection + alerts.
- **Verify after fix**: repeated failures trigger measurable controls.

## 10) Weak Session ID
- **Endpoint/Method**: `/vulnerabilities/weak_id/` (session generation)
- **Description**: Predictable session IDs enable hijacking/guessing.
- **Score**: E2 P2 D2 I3 = **9 (Medium)**
- **Fix/Mitigation**: cryptographically random IDs, regenerate on login/privilege change, secure cookie flags.
- **Verify after fix**: generated IDs are non-predictable and high entropy.

---

## Why these 10 are strong for DVWA Part A

These 10 map directly to core DVWA modules and represent high-value web security classes typically expected in secure-coding coursework. They are defensible in low mode and still useful for comparing behavior at higher security levels.

---

## Evidence files to attach with this report

- `dvwa_results.md` (smoke run)
- `dvwa_deep_results.md` (deep run)
- `dvwa_results_grading.md` (smoke grading view)
- `dvwa_deep_results_grading.md` (deep grading view)
- screenshots of manual validation points listed in `VULNERABILITY_TEST_RUNBOOK.md`
