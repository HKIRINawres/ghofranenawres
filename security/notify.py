#!/usr/bin/env python3
"""Sends the pipeline's result to the team (brief §6): Microsoft Teams, Slack, Discord and an HTML email.

Runs at the end of quality_gate. A channel is used only when its GitHub secret is set:
  TEAMS_WEBHOOK_URL    Teams channel > Workflows > "Post to a channel when a webhook request is received"
  DISCORD_WEBHOOK_URL  Discord channel > Integrations > Webhooks
  SLACK_WEBHOOK_URL    Slack incoming webhook
  SMTP_USERNAME + SMTP_PASSWORD + NOTIFY_EMAIL_TO   (SMTP_SERVER, default smtp.gmail.com, port 587)
Blocked runs are always sent; accepted runs only for main (what gets deployed). A channel that fails
is reported in the log; it never changes the decision.

  python3 security/notify.py [--dry-run]   (--dry-run prints the messages instead of sending them)
"""
import html
import json
import os
import smtplib
import sys
import urllib.request
from email.message import EmailMessage
from pathlib import Path

import gate

# block in their own job on anything new since `baseline`; their baseline-scan report says what and where
SOURCE_GATES = {"secrets_scan": ("gitleaks", "gitleaks-new.json"), "sast": ("semgrep", "semgrep-new.json")}
SEVS = ("critical", "high", "medium", "low")
RED, GREEN = "#cf222e", "#1a7f37"


def result(results="security/out"):
    """The gate's decision (gate-result.json), plus the source-level gates' own results (NEEDS)."""
    try:
        r = json.loads(Path(results, "gate-result.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        r = {"blocked": True, "reasons": ["the gate produced no result"], "counts": {}, "new": [], "new_total": 0}
    needs = json.loads(os.environ.get("NEEDS") or "{}")
    for job, (tool, report) in SOURCE_GATES.items():
        state = needs.get(job, {}).get("result", "success")
        reason = gate.source_reason(job, state)
        if reason:
            r["blocked"] = True
            if reason not in r["reasons"]:   # the gate already records it when it ran with NEEDS
                r["reasons"].insert(0, reason)
        try:
            found = gate.INFO_INPUTS[tool][1](Path(results, report))
        except (OSError, ValueError, KeyError, TypeError):
            found = []
        r["new"][:0] = [{"severity": f["severity"], "title": f"{tool}: {f['title']}", "where": gate.location(f)} for f in found]
        r["new_total"] += len(found)
    return r


def context():
    env = os.environ.get
    repo = env("GITHUB_REPOSITORY", "local run")
    run = f'{env("GITHUB_SERVER_URL", "")}/{repo}/actions/runs/{env("GITHUB_RUN_ID", "")}'
    return repo, env("GITHUB_HEAD_REF") or env("GITHUB_REF_NAME", ""), env("GITHUB_SHA", "")[:7], run


def lines(r):
    """(title, reasons, per-tool counts, new findings) in plain text, shared by every channel."""
    repo, ref, sha, _ = context()
    title = f'{"BLOCKED" if r["blocked"] else "ACCEPTED"}: {repo} {ref} @ {sha}'
    counts = [f'{tool}: ' + ", ".join(f'{c.get(s, 0)} {s}' for s in SEVS) for tool, c in sorted(r["counts"].items())]
    new = [f'[{f["severity"]}] {f["title"][:150]}' + (f' ({f["where"]})' if f.get("where") else "") for f in r["new"][:5]]
    if r["new_total"] > len(new):
        new.append(f'... {r["new_total"] - len(new)} more in the attestation')
    return title, r["reasons"], counts, new


def teams(r):
    title, reasons, counts, new = lines(r)
    body = [{"type": "TextBlock", "size": "Large", "weight": "Bolder", "wrap": True, "text": title,
             "color": "Attention" if r["blocked"] else "Good"}]
    body += [{"type": "TextBlock", "wrap": True, "text": "Why: " + "; ".join(reasons)}] if reasons else []
    body += [{"type": "FactSet", "facts": [{"title": c.split(": ")[0], "value": c.split(": ", 1)[1]} for c in counts]}]
    body += [{"type": "TextBlock", "wrap": True, "text": "New: " + "\n\n".join(new)}] if new else []
    card = {"$schema": "https://adaptivecards.io/schemas/adaptive-card.json", "type": "AdaptiveCard", "version": "1.4",
            "body": body, "actions": [{"type": "Action.OpenUrl", "title": "Open the run", "url": context()[3]}]}
    return {"type": "message", "attachments": [{"contentType": "application/vnd.microsoft.card.adaptive", "content": card}]}


def discord(r):
    title, reasons, counts, new = lines(r)
    desc = "\n".join(["**Why:** " + "; ".join(reasons)] if reasons else []) + ("\n**New:**\n" + "\n".join(new) if new else "")
    return {"username": "devsecops", "embeds": [{
        "title": title[:256], "url": context()[3], "color": int((RED if r["blocked"] else GREEN)[1:], 16),
        "description": desc[:4000] or "No new finding.",
        "fields": [{"name": c.split(": ")[0], "value": c.split(": ", 1)[1], "inline": True} for c in counts][:25]}]}


def slack(r):
    title, reasons, counts, new = lines(r)
    text = [f"*{title}*"] + (["Why: " + "; ".join(reasons)] if reasons else []) + counts + new + [f"<{context()[3]}|Open the run>"]
    return {"text": "\n".join(text)}


def email(r):
    title, reasons, counts, new = lines(r)
    color, e = RED if r["blocked"] else GREEN, html.escape
    rows = "".join(f'<tr><td style="padding:4px 12px 4px 0">{e(tool)}</td>' + "".join(
        f'<td style="padding:4px 8px;text-align:right">{c.get(s, 0)}</td>' for s in SEVS) + "</tr>"
        for tool, c in sorted(r["counts"].items()))
    page = f"""<div style="font-family:Segoe UI,Arial,sans-serif;max-width:640px">
<div style="background:{color};color:#fff;padding:14px 18px;font-size:18px;font-weight:600">{e(title)}</div>
<div style="padding:14px 18px;border:1px solid #d0d7de;border-top:0">
{"<p><b>Why:</b> " + "<br>".join(map(e, reasons)) + "</p>" if reasons else ""}
<table style="border-collapse:collapse;font-size:14px"><tr><th style="text-align:left;padding:4px 12px 4px 0">Tool</th>
{"".join(f'<th style="padding:4px 8px">{s}</th>' for s in SEVS)}</tr>{rows}</table>
{"<p><b>New findings:</b><br>" + "<br>".join(map(e, new)) + "</p>" if new else "<p>No new finding.</p>"}
<p><a href="{e(context()[3])}" style="background:#24292f;color:#fff;padding:8px 14px;text-decoration:none">Open the run</a></p>
</div></div>"""
    msg = EmailMessage()
    msg["Subject"], msg["From"], msg["To"] = f"[devsecops] {title}", os.environ.get("SMTP_USERNAME", ""), os.environ.get("NOTIFY_EMAIL_TO", "")
    msg.set_content("\n".join([title] + reasons + counts + new + [context()[3]]))
    msg.add_alternative(page, subtype="html")
    return msg


def post(url, payload):
    if not url.startswith("https://"):
        raise ValueError("webhook URL must start with https://")
    req = urllib.request.Request(url, json.dumps(payload).encode(),
                                 {"Content-Type": "application/json", "User-Agent": "devsecops-pipeline-notify"})
    # Reviewed (Bandit B310, Semgrep dynamic-urllib-use-detected): the URL comes from a repository
    # secret and is checked above to be https, so no file:// or other scheme can be used.
    # nosemgrep: python.lang.security.audit.dynamic-urllib-use-detected.dynamic-urllib-use-detected
    with urllib.request.urlopen(req, timeout=20) as resp:  # nosec B310
        return resp.status


def send_email(msg):
    server, port = os.environ.get("SMTP_SERVER") or "smtp.gmail.com", int(os.environ.get("SMTP_PORT") or 587)
    with smtplib.SMTP(server, port, timeout=20) as s:   # STARTTLS below, before the password is sent
        s.starttls()
        s.login(os.environ["SMTP_USERNAME"], os.environ["SMTP_PASSWORD"])
        s.send_message(msg)


def main(argv):
    dry = "--dry-run" in argv
    r = result()
    env = os.environ.get
    main_push = env("GITHUB_EVENT_NAME") == "push" and env("GITHUB_REF") == "refs/heads/main"
    if not (r["blocked"] or main_push or dry):
        print("accepted run outside main: no notification")
        return 0
    channels = [("Teams", env("TEAMS_WEBHOOK_URL"), teams), ("Discord", env("DISCORD_WEBHOOK_URL"), discord),
                ("Slack", env("SLACK_WEBHOOK_URL"), slack)]
    failed = 0
    for name, url, build in channels:
        if dry:
            print(f"--- {name}\n{json.dumps(build(r), indent=1)}")
        elif url:
            try:
                print(f"{name}: HTTP {post(url, build(r))}")
            except Exception as e:   # one broken channel must not stop the others
                failed += 1
                print(f"::warning title=notify::{name} failed: {type(e).__name__} {getattr(e, 'code', '')}")
    mail_ready = all(env(k) for k in ("SMTP_USERNAME", "SMTP_PASSWORD", "NOTIFY_EMAIL_TO"))
    if dry:
        print("--- email\n" + email(r).as_string()[:3000])
    elif mail_ready:
        try:
            send_email(email(r))
            print("email: sent")
        except Exception as e:
            failed += 1
            print(f"::warning title=notify::email failed: {type(e).__name__}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
