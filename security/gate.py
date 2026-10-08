#!/usr/bin/env python3
"""Acceptance security gate (Phase 2).

Reads the scan results in security/out/, compares them with security/accepted-risks.json and
decides if the build may go to production. Fails secure: missing or unreadable results block it.

Blocking rules (course policy):
  zap, trivy, trivy_fs: any unaccepted critical, or 5+ unaccepted high
  checkov, gauntlt: any unaccepted finding (violated IaC rule / failed acceptance scenario)
  secrets_scan, sast: block in their own jobs (new finding since `baseline`); the workflow passes their
  results in the NEEDS environment variable so the decision and the attestation say so too
Accepted risks need a reason and an expiry date; an expired entry counts as unaccepted.

  python security/gate.py                  evaluate, write attestation.md, exit 1 if blocked
  python security/gate.py --write-baseline accept everything currently found (first run only)
"""
import argparse
import datetime as dt
import hashlib
import json
import os
import re
import sys
from collections import Counter
from pathlib import Path

ZAP_RISK = {"3": "high", "2": "medium", "1": "low", "0": "info"}
SEMGREP_SEV = {"error": "high", "warning": "medium", "info": "low"}
SEVS = ["critical", "high", "medium", "low", "info"]
STRICT_TOOLS = ("checkov", "gauntlt")
ANSI = re.compile(r"\x1b\[[0-9;]*m")
BASELINE_REASON = ("Baseline: present in the unmodified OWASP Juice Shop import (tag `baseline`), "
                   "not individually reviewed. Accepted so that only new findings block; must be "
                   "reviewed before any real deployment.")


def finding(tool, fid, sev, title, file=None, line=None, where=None):
    """file/line: where the finding is in the repo; where: a location outside it (URL, path in the image).
    Only used to show findings (security/annotate.py), never to decide."""
    sev = sev if sev in SEVS else "low"
    return {"tool": tool, "id": f"{tool}:{fid}", "severity": sev, "title": title,
            "file": file, "line": line, "where": where}


def read_zap(p):
    out = {}
    for site in json.loads(p.read_text(encoding="utf-8")).get("site", []):
        for a in site.get("alerts", []):
            uris = [i["uri"] for i in a.get("instances") or []]
            where = uris[0] + (f" (+{len(uris) - 1} more URLs)" if len(uris) > 1 else "") if uris else None
            f = finding("zap", a["pluginid"], ZAP_RISK.get(str(a.get("riskcode")), "info"), a["alert"], where=where)
            out[f["id"]] = f
    return list(out.values())


def read_trivy(p, tool="trivy"):
    out = {}
    for r in json.loads(p.read_text(encoding="utf-8")).get("Results", []):
        for v in r.get("Vulnerabilities") or []:
            title = f'{v["PkgName"]} {v.get("InstalledVersion", "")}: {v.get("Title") or v["VulnerabilityID"]}'
            f = finding(tool, f'{v["VulnerabilityID"]}:{v["PkgName"]}', v["Severity"].lower(), title,
                        where=v.get("PkgPath") or r.get("Target"))
            out[f["id"]] = f
    return list(out.values())


def read_checkov(p):
    data = json.loads(p.read_text(encoding="utf-8"))
    out = {}
    for rep in data if isinstance(data, list) else [data]:
        for c in (rep.get("results") or {}).get("failed_checks", []):
            fid = f'{c["check_id"]}:{c["file_path"]}:{c["resource"]}'
            f = finding("checkov", fid, (c.get("severity") or "medium").lower(), c["check_name"],
                        c["file_path"].lstrip("/"), (c.get("file_line_range") or [None])[0])
            out[f["id"]] = f
    return list(out.values())


def read_gauntlt(p):
    text = ANSI.sub("", p.read_text(encoding="utf-8", errors="replace"))
    if not re.search(r"\d+ scenarios? \(", text):
        raise ValueError("no Gauntlt summary line found, the tests did not run")
    out = {}
    for m in re.finditer(r"^cucumber (\S+?):(\d+)\s+# Scenario: (.+)$", text, re.M):
        attack, name = Path(m.group(1)).name, m.group(3).strip()
        # the attack files are mounted from security/gauntlt/ (run-acceptance.sh)
        f = finding("gauntlt", f"{attack}:{name}", "high", name, f"security/gauntlt/{attack}", int(m.group(2)))
        out[f["id"]] = f
    return list(out.values())


def read_semgrep(p):
    out = {}
    for r in json.loads(p.read_text(encoding="utf-8"))["results"]:
        line, sev = r["start"]["line"], r["extra"]["severity"].lower()
        f = finding("semgrep", f'{r["check_id"]}:{r["path"]}:{line}', SEMGREP_SEV.get(sev, sev),
                    f'{r["check_id"].rsplit(".", 1)[-1]}: {r["extra"]["message"]}', r["path"], line)
        out[f["id"]] = f
    return list(out.values())


def read_gitleaks(p):
    out = {}
    for s in json.loads(p.read_text(encoding="utf-8")):   # run with --redact: no secret value in the report
        f = finding("gitleaks", s["Fingerprint"], "high", f'{s["RuleID"]}: {s["Description"]}',
                    s["File"], s["StartLine"], f'commit {s["Commit"][:7]}')
        out[f["id"]] = f
    return list(out.values())


INPUTS = {
    "zap": ("zap-report.json", read_zap),
    "trivy": ("trivy.json", read_trivy),
    "trivy_fs": ("trivy-fs.json", lambda p: read_trivy(p, "trivy_fs")),
    "checkov": ("checkov/results_json.json", read_checkov),
    "gauntlt": ("gauntlt.txt", read_gauntlt),
}
# Shown in the gate's table only. They block in their own jobs (sast, secrets_scan) on anything new
# since the `baseline` tag; the decision below only records that outcome (upstream_reasons).
INFO_INPUTS = {
    "semgrep": ("semgrep-full.json", read_semgrep),
    "gitleaks": ("gitleaks-full.json", read_gitleaks),
}
SOURCE_JOBS = ("secrets_scan", "sast")


def source_reason(job, state):
    """Why a source-scan job blocks, or None when it succeeded."""
    if state == "success":
        return None
    return f"{job}: " + ("new finding since baseline" if state == "failure" else state)


def upstream_reasons(needs_json):
    """Blocking reasons from the workflow's `needs` context (JSON), so the attestation matches the run."""
    needs = json.loads(needs_json or "{}")
    return [r for r in (source_reason(j, needs.get(j, {}).get("result", "success")) for j in SOURCE_JOBS) if r]


def location(f):
    return f'{f["file"]}:{f["line"] or 1}' if f["file"] else f["where"]


def decide(findings, accepted, today):
    valid = {a["id"] for a in accepted if dt.date.fromisoformat(a["expires"]) >= today}
    expired = [a for a in accepted if dt.date.fromisoformat(a["expires"]) < today]
    new = [f for f in findings if f["id"] not in valid]
    reasons = []
    for tool in STRICT_TOOLS:
        n = sum(1 for f in new if f["tool"] == tool)
        if n:
            reasons.append(f"{tool}: {n} unaccepted finding(s)")
    for tool in ("zap", "trivy", "trivy_fs"):
        c = Counter(f["severity"] for f in new if f["tool"] == tool)
        if c["critical"] >= 1 or c["high"] >= 5:
            reasons.append(f'{tool}: {c["critical"]} critical / {c["high"]} high unaccepted (limit: 1 critical or 5 high)')
    return new, expired, reasons


def sev_table(findings):
    tools = sorted({f["tool"] for f in findings})
    rows = ["| Tool | " + " | ".join(SEVS) + " |", "|---|" + "---|" * len(SEVS)]
    for t in tools:
        c = Counter(f["severity"] for f in findings if f["tool"] == t)
        rows.append(f"| {t} | " + " | ".join(str(c[s]) for s in SEVS) + " |")
    return "\n".join(rows)


def attestation(findings, new, expired, reasons, errors, hashes, now, info=(), info_errors=()):
    run = ""
    if os.environ.get("GITHUB_RUN_ID"):
        run = f'{os.environ.get("GITHUB_SERVER_URL", "")}/{os.environ.get("GITHUB_REPOSITORY", "")}/actions/runs/{os.environ["GITHUB_RUN_ID"]}'
    blocked = bool(reasons or errors)
    lines = [
        "# Acceptance attestation", "",
        f"- Decision: **{'BLOCKED' if blocked else 'ACCEPTED for deployment'}**",
        f"- Timestamp (UTC): {now.strftime('%Y-%m-%d %H:%M:%S')}",
        f"- Commit: {os.environ.get('GITHUB_SHA', 'local run')}",
        f"- Image: {os.environ.get('IMAGE_REF', 'local build')}",
        f"- CI run: {run or 'n/a'}", "",
        "## Policy",
        "zap/trivy/trivy_fs: block on 1+ critical or 5+ high not in the accepted-risk list. "
        "checkov/gauntlt: block on any finding not in the list. Missing results block (fail secure).", "",
        "## All findings (before exceptions)", sev_table(findings + list(info)) if findings or info else "none", "",
    ]
    if info or info_errors:
        lines += ["semgrep and gitleaks are listed for completeness: they block in their own jobs (`sast`, "
                  "`secrets_scan`) on anything new since the `baseline` tag."] + [f"- {e}" for e in info_errors] + [""]
    lines += [f"## Unaccepted findings: {len(new)}"]
    lines += [f"- [{f['severity']}] {f['id']}: {f['title']}" for f in sorted(new, key=lambda f: (SEVS.index(f['severity']), f['id']))[:100]]
    if len(new) > 100:
        lines.append(f"- ... and {len(new) - 100} more")
    lines += ["", f"## Accepted risks in use: {len(findings) - len(new)} (see security/accepted-risks.json)"]
    if expired:
        lines += ["", f"## Expired exceptions: {len(expired)}"] + [f"- {a['id']} (expired {a['expires']})" for a in expired[:50]]
    if errors:
        lines += ["", "## Errors"] + [f"- {e}" for e in errors]
    if reasons:
        lines += ["", "## Reasons for blocking"] + [f"- {r}" for r in reasons]
    lines += ["", "## Input integrity (SHA-256)"] + [f"- {k}: `{v}`" for k, v in sorted(hashes.items())]
    lines += ["", "Note: hashes prove which files were evaluated; this is not a cryptographic signature."]
    return "\n".join(lines) + "\n"


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--results", default="security/out")
    ap.add_argument("--accepted", default="security/accepted-risks.json")
    ap.add_argument("--write-baseline", action="store_true")
    ap.add_argument("--baseline-days", type=int, default=90)
    ap.add_argument("--today", default=None, help="ISO date, for tests")
    a = ap.parse_args(argv)

    now = dt.datetime.now(dt.timezone.utc)
    today = dt.date.fromisoformat(a.today) if a.today else now.date()
    results = Path(a.results)
    findings, errors, hashes = [], [], {}
    for tool, (rel, reader) in INPUTS.items():
        p = results / rel
        try:
            findings += reader(p)
            hashes[rel] = hashlib.sha256(p.read_bytes()).hexdigest()
        except (OSError, ValueError, KeyError, TypeError) as e:
            errors.append(f"{tool}: cannot read {p} ({type(e).__name__}: {e})")

    if a.write_baseline:
        if errors:
            print("\n".join(errors), file=sys.stderr)
            return 2
        exp = (today + dt.timedelta(days=a.baseline_days)).isoformat()
        entries = [{"id": f["id"], "tool": f["tool"], "severity": f["severity"], "title": f["title"],
                    "reason": BASELINE_REASON, "owner": "team", "expires": exp}
                   for f in sorted(findings, key=lambda f: f["id"]) if f["severity"] != "info"]
        Path(a.accepted).write_text(json.dumps({"accepted": entries}, indent=1) + "\n", encoding="utf-8")
        print(f"wrote {len(entries)} accepted risks to {a.accepted} (expire {exp})")
        return 0

    try:
        accepted = json.loads(Path(a.accepted).read_text(encoding="utf-8"))["accepted"]
    except (OSError, ValueError, KeyError) as e:
        errors.append(f"accepted-risks: cannot read {a.accepted} ({e})")
        accepted = []
    new, expired, reasons = decide(findings, accepted, today)
    reasons = upstream_reasons(os.environ.get("NEEDS")) + reasons

    info, info_errors = [], []   # report only: a missing file is noted, it does not block here
    for tool, (rel, reader) in INFO_INPUTS.items():
        p = results / rel
        try:
            info += reader(p)
            hashes[rel] = hashlib.sha256(p.read_bytes()).hexdigest()
        except (OSError, ValueError, KeyError, TypeError) as e:
            info_errors.append(f"{tool}: cannot read {p} ({type(e).__name__}: {e})")

    report = attestation(findings, new, expired, reasons, errors, hashes, now, info, info_errors)
    (results / "attestation.md").write_text(report, encoding="utf-8")
    everything = findings + info   # same scope as the attestation's table; read by security/notify.py
    result = {"blocked": bool(reasons or errors), "reasons": reasons + errors,
              "counts": {t: dict(Counter(f["severity"] for f in everything if f["tool"] == t))
                         for t in sorted({f["tool"] for f in everything})},
              "new": [{"severity": f["severity"], "title": f["title"], "where": location(f)}
                      for f in sorted(new, key=lambda f: (SEVS.index(f["severity"]), f["id"]))[:10]],
              "new_total": len(new)}
    (results / "gate-result.json").write_text(json.dumps(result, indent=1), encoding="utf-8")
    print(report)
    return 1 if (reasons or errors) else 0


if __name__ == "__main__":
    sys.exit(main())
