#!/usr/bin/env python3
"""Shows where each finding is, in the GitHub Actions UI (brief §6). Decides nothing: blocking stays
in the scanner jobs and in gate.py, whose report readers this script reuses.

  python3 security/annotate.py TOOL REPORT [--new REPORT]

- One annotation per finding, on its file and line (run page, and the "Files changed" tab of a PR):
    error   = new finding of a kind that blocks (not in the baseline / accepted-risk list)
    warning = known finding, or a new one below the blocking threshold
    notice  = informational finding
  GitHub keeps 10 of each per step and 50 per job, so new and severe findings come first.
- The full list goes to the job summary, each row linked to its file and line in this commit.

New = not in security/accepted-risks.json (gate tools), or present in --new, the report of the
tool's own baseline scan (semgrep and gitleaks only report what changed since the `baseline` tag).
"""
import argparse
import datetime as dt
import json
import os
import re
from collections import Counter
from pathlib import Path

import gate

READERS = {tool: reader for tool, (_, reader) in {**gate.INPUTS, **gate.INFO_INPUTS}.items()}
ANY_NEW_BLOCKS = gate.STRICT_TOOLS + ("semgrep", "gitleaks")
LIMIT = 10   # GitHub: per step, 10 errors, 10 warnings and 10 notices


def esc(s, prop=False):
    s = str(s).replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
    return s.replace(":", "%3A").replace(",", "%2C") if prop else s


def cell(s, n=180):
    s = " ".join(str(s).split()).replace("|", "\\|")
    return s if len(s) <= n else s[:n - 1] + "…"


def via_package_json(findings, report):
    """Trivy fs points at the lockfiles, which CI generates (.npmrc has package-lock=false), so they
    are not in git. Point each finding at the package.json line of the direct dependency that pulls
    the vulnerable package in."""
    by_id = {f["id"]: f for f in findings}
    for r in json.loads(Path(report).read_text(encoding="utf-8")).get("Results", []):
        manifest = Path(r["Target"]).with_name("package.json")
        try:
            lines = manifest.read_text(encoding="utf-8").splitlines()
        except OSError:
            continue
        pkgs = {p["ID"]: p for p in r.get("Packages") or []}
        parents = {}
        for p in pkgs.values():
            for d in p.get("DependsOn") or []:
                parents.setdefault(d, []).append(p["ID"])
        for v in r.get("Vulnerabilities") or []:
            f = by_id.get(f'trivy_fs:{v["VulnerabilityID"]}:{v["PkgName"]}')
            # one finding per CVE and package name; map the installed version the gate kept in the title
            if not f or f["file"] or not f["title"].startswith(f'{v["PkgName"]} {v.get("InstalledVersion", "")}:'):
                continue
            direct, todo, seen = set(), [v["PkgID"]], set()
            while todo:   # walk up the dependency tree until the direct dependencies
                pid = todo.pop()
                if pid in seen:
                    continue
                seen.add(pid)
                if pkgs.get(pid, {}).get("Relationship") == "direct":
                    direct.add(pkgs[pid]["Name"])
                else:
                    todo += parents.get(pid, [])
            for name in sorted(direct):
                n = next((i for i, l in enumerate(lines, 1) if re.match(rf'\s*"{re.escape(name)}"\s*:', l)), None)
                if n:
                    f.update(file=manifest.as_posix(), line=n, where=None if name == v["PkgName"] else f"via {name}")
                    break


def level(f, new):
    if f["severity"] == "info":
        return "notice"
    if new and (f["tool"] in ANY_NEW_BLOCKS or f["severity"] in ("critical", "high")):
        return "error"
    return "warning"


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("tool", choices=sorted(READERS))
    ap.add_argument("report")
    ap.add_argument("--new", help="semgrep/gitleaks: report of the scan limited to changes since `baseline`")
    ap.add_argument("--accepted", default="security/accepted-risks.json")
    a = ap.parse_args(argv)
    read = READERS[a.tool]
    try:
        findings = read(Path(a.report))
    except (OSError, ValueError, KeyError, TypeError) as e:
        print(f"::warning title={a.tool}::no report to annotate ({esc(e)}); the quality gate treats a missing report as a block")
        return 0
    if a.tool == "trivy_fs":
        via_package_json(findings, a.report)
    if a.new:
        try:
            new_findings = read(Path(a.new))
        except (OSError, ValueError, KeyError, TypeError) as e:
            print(f"::warning title={a.tool}::no baseline-scan report ({esc(e)}); new findings cannot be told apart")
            new_findings = []
        ids = {f["id"] for f in findings}
        findings += [f for f in new_findings if f["id"] not in ids]
        new = {f["id"] for f in new_findings}
    else:
        accepted = json.loads(Path(a.accepted).read_text(encoding="utf-8"))["accepted"]
        new = {f["id"] for f in gate.decide(findings, accepted, dt.date.today())[0]}

    findings.sort(key=lambda f: (f["id"] not in new, gate.SEVS.index(f["severity"]), f["file"] or "", f["line"] or 0))
    n_new = sum(f["id"] in new for f in findings)
    print("::notice title=" + esc(f"{a.tool}: {len(findings)} findings, {n_new} new", True) +
          "::Each one is listed with its location in this job's summary (run page, Summary).")
    shown = Counter(notice=1)
    for f in findings:
        lv = level(f, f["id"] in new)
        shown[lv] += 1
        if shown[lv] > LIMIT:
            continue
        status = "NEW" if f["id"] in new else "known"
        props = "title=" + esc(f"{a.tool} [{f['severity']}] {status}", True)
        if f["file"]:
            props = f"file={esc(f['file'], True)},line={f['line'] or 1},{props}"
        msg = f["title"] + (f" ({f['where']})" if f["where"] else "")
        print(f"::{lv} {props}::{esc(msg)}")

    base = f'{os.environ.get("GITHUB_SERVER_URL", "")}/{os.environ.get("GITHUB_REPOSITORY", "")}/blob/{os.environ.get("GITHUB_SHA", "")}'
    rows = [f"### {a.tool}: {len(findings)} findings, {n_new} new", "",
            "| | Severity | Where | Finding |", "|---|---|---|---|"]
    for f in findings:
        where = ""
        if f["file"]:
            loc = f'{f["file"]}:{f["line"] or 1}'
            where = f'[{loc}]({base}/{f["file"]}#L{f["line"] or 1})' if os.environ.get("GITHUB_SHA") else loc
        if f["where"]:
            where = f'{where} {cell(f["where"], 90)}'.strip()
        rows.append(f'| {"**new**" if f["id"] in new else "known"} | {f["severity"]} | {where} | {cell(f["title"])} |')
    summary = "\n".join(rows) + "\n"
    if os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(os.environ["GITHUB_STEP_SUMMARY"], "a", encoding="utf-8") as fh:
            fh.write(summary)
    else:
        print(summary)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
