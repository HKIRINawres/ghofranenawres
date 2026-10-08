"""Self-check for gate.py: python security/test_gate.py (no dependencies)."""
import datetime as dt
import gate

D = dt.date(2026, 10, 1)


def f(tool, n, sev):
    return gate.finding(tool, str(n), sev, "t")


def accept(findings, expires="2027-01-01"):
    return [{"id": x["id"], "expires": expires} for x in findings]


base = [f("trivy", i, "high") for i in range(9)] + [f("zap", 1, "high"), f("checkov", 1, "medium")]

# everything accepted -> passes
assert gate.decide(base, accept(base), D)[2] == []
# new critical trivy finding -> blocked
assert gate.decide(base + [f("trivy", 99, "critical")], accept(base), D)[2]
# 4 new highs pass, 5 block
assert gate.decide(base + [f("zap", 10 + i, "high") for i in range(4)], accept(base), D)[2] == []
assert gate.decide(base + [f("zap", 10 + i, "high") for i in range(5)], accept(base), D)[2]
# any new checkov / gauntlt finding blocks, even low severity
assert gate.decide(base + [f("checkov", 2, "low")], accept(base), D)[2]
assert gate.decide(base + [f("gauntlt", 1, "high")], accept(base), D)[2]
# dependency scan (trivy_fs) follows the same critical/high thresholds
assert gate.decide(base + [f("trivy_fs", 1, "critical")], accept(base), D)[2]
assert gate.decide(base + [f("trivy_fs", 1, "medium")], accept(base), D)[2] == []
# expired exceptions no longer count
assert gate.decide(base, accept(base, "2026-09-01"), D)[2]
# gauntlt parser: needs a summary line, finds failing scenarios
import pathlib, tempfile
p = pathlib.Path(tempfile.mkdtemp()) / "g.txt"
p.write_text("x\nFailing Scenarios:\ncucumber /attacks/a.attack:12 # Scenario: CSP set\n\n3 scenarios (1 failed, 2 passed)\n")
assert [(x["id"], x["file"], x["line"]) for x in gate.read_gauntlt(p)] == [
    ("gauntlt:a.attack:CSP set", "security/gauntlt/a.attack", 12)]
p.write_text("gem install failed")
try:
    gate.read_gauntlt(p)
    raise SystemExit("gauntlt parser accepted output without summary")
except ValueError:
    pass

# annotate.py: a Trivy fs finding points at the package.json line of the direct dependency
import json
import annotate
d = p.parent
(d / "package.json").write_text('{\n  "dependencies": {\n    "express-jwt": "0.1.3",\n    "jsonwebtoken": "0.4.0"\n  }\n}\n')
pkgs = [{"ID": "express-jwt@0.1.3", "Name": "express-jwt", "Relationship": "direct", "DependsOn": ["jsonwebtoken@0.1.0"]},
        {"ID": "jsonwebtoken@0.1.0", "Name": "jsonwebtoken", "Relationship": "indirect"},
        {"ID": "jsonwebtoken@0.4.0", "Name": "jsonwebtoken", "Relationship": "direct"},
        {"ID": "lodash@2.4.2", "Name": "lodash", "Relationship": "indirect"}]
vuln = lambda pid, cve: {"VulnerabilityID": cve, "PkgID": pid, "PkgName": pid.split("@")[0],
                         "InstalledVersion": pid.split("@")[1], "Severity": "CRITICAL"}
(d / "t.json").write_text(json.dumps({"Results": [{"Target": str(d / "package-lock.json"), "Packages": pkgs, "Vulnerabilities": [
    vuln("jsonwebtoken@0.1.0", "CVE-1"), vuln("jsonwebtoken@0.4.0", "CVE-1"), vuln("jsonwebtoken@0.1.0", "CVE-2"),
    vuln("lodash@2.4.2", "CVE-3")]}]}))
fs = {x["id"]: x for x in gate.read_trivy(d / "t.json", "trivy_fs")}
annotate.via_package_json(list(fs.values()), d / "t.json")
loc = lambda i: (fs[i]["line"], fs[i]["where"])
assert loc("trivy_fs:CVE-1:jsonwebtoken") == (4, None)            # same CVE in 0.1.0 and 0.4.0: the kept 0.4.0 is direct
assert loc("trivy_fs:CVE-2:jsonwebtoken") == (3, "via express-jwt")
assert fs["trivy_fs:CVE-3:lodash"]["file"] is None                 # no direct parent found: no location invented
assert annotate.esc("a,b: 5%\n", True) == "a%2Cb%3A 5%25%0A"

# notify.py: no gate result = blocked; a failed source-level job blocks and says what and where
import os
import notify
os.environ["NEEDS"] = json.dumps({"sast": {"result": "failure"}, "secrets_scan": {"result": "success"}})
(d / "semgrep-new.json").write_text(json.dumps({"results": [{"check_id": "r.sqli", "path": "routes/x.ts",
    "start": {"line": 12}, "extra": {"severity": "ERROR", "message": "SQL injection"}}]}))
r = notify.result(d)
assert r["blocked"]
assert r["reasons"][0] == "sast: new finding since baseline"
assert r["new"][0]["where"] == "routes/x.ts:12"
assert r["new_total"] == 1
# the gate records a failed source-level job itself (attestation = run outcome); notify does not repeat it
(d / "gate-result.json").write_text(json.dumps({"blocked": True, "reasons": ["sast: new finding since baseline"], "counts": {}, "new": [], "new_total": 0}))
assert notify.result(d)["reasons"] == ["sast: new finding since baseline"]
assert gate.upstream_reasons(None) == []
assert gate.upstream_reasons(json.dumps({"sast": {"result": "success"}, "secrets_scan": {"result": "success"}})) == []
assert gate.upstream_reasons(json.dumps({"sast": {"result": "failure"}, "secrets_scan": {"result": "cancelled"}})) == [
    "secrets_scan: cancelled", "sast: new finding since baseline"]
(d / "gate-result.json").write_text(json.dumps({"blocked": False, "reasons": [], "counts": {}, "new": [], "new_total": 0}))
(d / "semgrep-new.json").unlink()
os.environ["NEEDS"] = json.dumps({"sast": {"result": "success"}, "secrets_scan": {"result": "success"}})
assert not notify.result(d)["blocked"]
del os.environ["NEEDS"]
print("gate self-check OK")
