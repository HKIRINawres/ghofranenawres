#!/usr/bin/env python3
"""pre-commit hook (brief §3): a package.json change must not bring a NEW critical vulnerability.

Runs `npm audit` in the folder of each changed package.json and compares the vulnerable packages with
security/accepted-risks.json, the list the CI gate uses, so the Juice Shop baseline does not block.
Only critical blocks here; the CI gate applies the full rule (1 critical or 5 high), CVE by CVE.
The dependency tree is resolved from the registry each time (no node_modules needed); it needs network access.
"""
import json
import shutil
import subprocess  # nosec B404 - reviewed, see vulnerable()
import sys
import tempfile
from pathlib import Path

ACCEPTED = Path(__file__).with_name("accepted-risks.json")


def vulnerable(folder):
    """{package: severity}, only packages with their own advisory (npm also flags all their parents)."""
    npm = shutil.which("npm") or "npm"
    # npm audit reads the lockfile, not package.json: the repo has none (package-lock=false) and a local one
    # can be older than the change, which hides the new package. So resolve a fresh one in a temp folder.
    # Bandit B603 reviewed: fixed commands, no shell; the only input is the staged package.json
    pkg = json.loads((folder / "package.json").read_text(encoding="utf-8"))
    pkg.pop("devDependencies", None)   # audited with --omit=dev anyway; resolving them was most of the time
    with tempfile.TemporaryDirectory() as tmp:
        Path(tmp, "package.json").write_text(json.dumps(pkg), encoding="utf-8")
        lock = subprocess.run([npm, "install", "--package-lock-only", "--package-lock=true", "--ignore-scripts",  # nosec B603
                               "--no-audit", "--no-fund"], cwd=tmp, capture_output=True, text=True, encoding="utf-8")
        if lock.returncode:
            raise SystemExit(f"npm could not resolve {folder / 'package.json'}:\n{lock.stderr[-800:]}")
        out = subprocess.run([npm, "audit", "--omit=dev", "--json"], cwd=tmp,  # nosec B603
                             capture_output=True, text=True, encoding="utf-8").stdout
    data = json.loads(out)   # no output at all is an error too (fail closed)
    if "error" in data:
        raise SystemExit(f"npm audit failed in {folder}: {data['error'].get('summary', data['error'])}")
    return {name: v["severity"] for name, v in data.get("vulnerabilities", {}).items()
            if any(isinstance(x, dict) for x in v["via"])}


def main(files):
    known = {a["id"].rsplit(":", 1)[-1] for a in json.loads(ACCEPTED.read_text(encoding="utf-8"))["accepted"]
             if a["tool"] in ("trivy", "trivy_fs")}
    new = [f"{folder / 'package.json'}: {name} has a critical vulnerability (npm audit)"
           for folder in sorted({Path(f).parent for f in files})
           for name, sev in sorted(vulnerable(folder).items()) if sev == "critical" and name not in known]
    if new:
        print("\n".join(new))
        print("Upgrade or remove it, or accept the risk in security/accepted-risks.json (docs/security-policy.md §3).")
    return 1 if new else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
