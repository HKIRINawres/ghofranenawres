#!/usr/bin/env python3
"""Converts the scanners' reports into SonarQube's external-issue format, so SonarQube shows every
tool's findings next to its own analysis, on the file and line: one central view with history (brief §6).

  python3 security/sonar_issues.py [RESULTS]   reads RESULTS (default security/out), writes RESULTS/sonar-issues.json

Reuses the gate's report readers. Findings without a file in the repo (ZAP, the image scan) cannot be
attached to code in SonarQube; they stay in the attestation and the job summaries.
"""
import json
import sys
from pathlib import Path

import annotate
import gate

IMPACT = {"critical": "BLOCKER", "high": "HIGH", "medium": "MEDIUM", "low": "LOW", "info": "INFO"}


def main(results="security/out"):
    out = Path(results)
    findings = []
    for tool, (rel, reader) in {**gate.INPUTS, **gate.INFO_INPUTS}.items():
        try:
            found = reader(out / rel)
        except (OSError, ValueError, KeyError, TypeError) as e:
            print(f"{tool}: skipped, no report ({type(e).__name__})")
            continue
        if tool == "trivy_fs":
            annotate.via_package_json(found, out / rel)
        findings += [f for f in found if f["file"]]
    rules = {(f["tool"], f["severity"]) for f in findings}   # one rule per tool and severity
    report = {
        "rules": [{"id": f"{t}-{s}", "name": f"{t} ({s})", "engineId": t, "cleanCodeAttribute": "TRUSTWORTHY",
                   "impacts": [{"softwareQuality": "SECURITY", "severity": IMPACT[s]}]} for t, s in sorted(rules)],
        "issues": [{"ruleId": f'{f["tool"]}-{f["severity"]}',
                    "primaryLocation": {"message": (f["title"] + (f' ({f["where"]})' if f["where"] else ""))[:1000],
                                        "filePath": f["file"],
                                        **({"textRange": {"startLine": f["line"]}} if f["line"] else {})}}
                   for f in findings],
    }
    (out / "sonar-issues.json").write_text(json.dumps(report, indent=1), encoding="utf-8")
    print(f"{len(findings)} findings with a file -> {out / 'sonar-issues.json'}")
    return 0


if __name__ == "__main__":
    sys.exit(main(*sys.argv[1:]))
