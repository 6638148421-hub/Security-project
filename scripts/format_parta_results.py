#!/usr/bin/env python3
"""Format DVWA result tables into grading-friendly tables for Part A."""
from pathlib import Path
import sys

RISK = {
    "SQL Injection (Classic)": "E3/P3/D3/I3 = 12 (High)",
    "Blind SQL Injection": "E2/P2/D2/I3 = 9 (Medium)",
    "Command Injection": "E3/P2/D2/I3 = 10 (High)",
    "Reflected XSS": "E3/P3/D3/I2 = 11 (High)",
    "Stored XSS": "E3/P2/D2/I3 = 10 (High)",
    "CSRF": "E3/P2/D2/I2 = 9 (Medium)",
    "File Inclusion (LFI/RFI)": "E2/P2/D2/I3 = 9 (Medium)",
    "Unrestricted File Upload": "E3/P2/D2/I3 = 10 (High)",
    "Weak Brute-Force Protection": "E3/P3/D3/I2 = 11 (High)",
    "Weak Session ID": "E2/P2/D2/I3 = 9 (Medium)",
}

WHAT_IT_MEANS = {
    "WARN (vulnerable)": "Exploit indicator observed in this run",
    "OK/UNCLEAR": "No indicator observed or check is inconclusive",
}


def parse_rows(md: str):
    rows = []
    for line in md.splitlines():
        if not line.startswith("|"):
            continue
        if line.startswith("|---"):
            continue
        cols = [c.strip() for c in line.strip().strip("|").split("|")]
        if cols and cols[0] in {"Vulnerability", "# DVWA Smoke Results (Part A)", "# DVWA Deep Results (Part A)"}:
            continue
        if len(cols) >= 6:
            rows.append(cols)
    return rows


def format_smoke(rows):
    out = [
        "# DVWA Smoke Results (Grading View)",
        "",
        "| Vulnerability | Module | Method | Payload/Action | Indicator | Status | Risk Score | Interpretation |",
        "|---|---|---|---|---|---|---|---|",
    ]
    for r in rows:
        vuln, module, method, payload, indicator, status = r[:6]
        risk = RISK.get(vuln, "N/A")
        interp = WHAT_IT_MEANS.get(status, "Review manually")
        out.append(f"| {vuln} | {module} | {method} | {payload} | {indicator} | {status} | {risk} | {interp} |")
    return "\n".join(out) + "\n"


def format_deep(rows):
    out = [
        "# DVWA Deep Results (Grading View)",
        "",
        "| Vulnerability | Security | Module | Method | Payload Count | Positive Indicators | Status | Notes | Risk Score | Interpretation |",
        "|---|---|---|---|---:|---:|---|---|---|---|",
    ]
    for r in rows:
        vuln, security, module, method, payload_count, pos_ind, status, notes = r[:8]
        risk = RISK.get(vuln, "N/A")
        interp = WHAT_IT_MEANS.get(status, "Review manually")
        out.append(f"| {vuln} | {security} | {module} | {method} | {payload_count} | {pos_ind} | {status} | {notes} | {risk} | {interp} |")
    return "\n".join(out) + "\n"


def main():
    if len(sys.argv) != 3 or sys.argv[1] not in {"smoke", "deep"}:
        print("Usage: format_parta_results.py {smoke|deep} <input_md>")
        sys.exit(1)

    mode = sys.argv[1]
    src = Path(sys.argv[2])
    if not src.exists():
        print(f"Input file not found: {src}")
        sys.exit(1)

    rows = parse_rows(src.read_text())
    if mode == "smoke":
        out = format_smoke(rows)
        dst = Path("dvwa_results_grading.md")
    else:
        out = format_deep(rows)
        dst = Path("dvwa_deep_results_grading.md")

    dst.write_text(out)
    print(f"Wrote {dst}")


if __name__ == "__main__":
    main()
