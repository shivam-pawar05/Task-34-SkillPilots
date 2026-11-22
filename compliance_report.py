#!/usr/bin/env python3
"""PostgreSQL DDL compliance report.

Parses syslog files collected by rsyslog, keeps DDL statements from the last N hours
(default 24), writes a detail CSV and a per-user summary CSV, and optionally e-mails both.

Examples
  python3 compliance_report.py --log-glob "/var/log/remote/postgres/*.log"
  python3 compliance_report.py --log-glob "sample_logs/*.log" --now 2026-11-22T12:00:00+05:30
  python3 compliance_report.py --log-glob "/var/log/remote/postgres/*.log" --email-to compliance@example.com
  python3 compliance_report.py --log-glob "..." --email-to a@b.com --dry-run     # build mail, don't send

E-mail settings come from environment variables (never put passwords on the command line):
  SMTP_HOST, SMTP_PORT (default 587), SMTP_USER, SMTP_PASS, MAIL_FROM
Requires the PostgreSQL settings in config/1_postgresql_syslog.conf
(log_line_prefix = 'user=%u,db=%d,app=%a,client=%h ' and log_statement = 'ddl').
"""
import argparse
import csv
import glob
import os
import re
import smtplib
import sys
from collections import OrderedDict, defaultdict
from datetime import datetime, timedelta
from email.message import EmailMessage

# ---- syslog line formats -------------------------------------------------
LINE_RE = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}T\S+|[A-Z][a-z]{2}\s+\d{1,2}\s\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+(?P<prog>[^\s\[:]+)(?:\[(?P<pid>\d+)\])?:\s(?P<msg>.*)$")
SEQ_RE = re.compile(r"^\s*\[(?P<seq>\d+)-(?P<part>\d+)\]\s?(?P<rest>.*)$")
PREFIX_RE = re.compile(
    r"^user=(?P<user>[^,]*),db=(?P<db>[^,]*),app=(?P<app>.*?),client=(?P<client>\S*)\s+"
    r"(?P<level>[A-Z0-9]+):\s+(?P<body>.*)$", re.S)
DDL_RE = re.compile(
    r"^\s*(?P<cmd>CREATE|ALTER|DROP|TRUNCATE|GRANT|REVOKE|COMMENT|REINDEX|CLUSTER|SECURITY\s+LABEL)\b",
    re.I)
SKIP_WORDS = {"OR", "REPLACE", "UNIQUE", "TEMP", "TEMPORARY", "UNLOGGED", "GLOBAL", "LOCAL",
              "RECURSIVE", "TRUSTED", "PROCEDURAL", "MATERIALIZED"}
MONTHS = {m: i for i, m in enumerate(
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], 1)}


def parse_ts(text, now):
    """ISO 8601 (rsyslog RSYSLOG_FileFormat) or traditional 'Nov 22 10:15:01' (assumed in now's zone)."""
    if text[0].isdigit():
        return datetime.fromisoformat(text.replace("Z", "+00:00"))
    mon, day, clock = text.split(None, 2)
    h, m, s = map(int, clock.split(":"))
    ts = datetime(now.year, MONTHS[mon], int(day), h, m, s, tzinfo=now.tzinfo)
    return ts - timedelta(days=365) if ts > now + timedelta(days=1) else ts  # Dec log read in Jan


def classify(statement):
    """Return (command, object_type) e.g. ('CREATE', 'TABLE')."""
    m = DDL_RE.match(statement)
    cmd = re.sub(r"\s+", " ", m.group("cmd").upper())
    tokens = re.findall(r"[A-Za-z_]+", statement[m.end():m.end() + 80])
    obj = ""
    if cmd in ("CREATE", "ALTER", "DROP"):
        for t in tokens:
            if t.upper() not in SKIP_WORDS:
                obj = t.upper(); break
    elif cmd == "COMMENT" and tokens and tokens[0].upper() == "ON" and len(tokens) > 1:
        obj = tokens[1].upper()
    return cmd, obj


def read_events(paths, now):
    """Yield one dict per complete log message (multi-line statements are re-joined)."""
    pending = OrderedDict()
    for path in paths:
        with open(path, encoding="utf-8", errors="replace") as fh:
            for raw in fh:
                m = LINE_RE.match(raw.rstrip("\n"))
                if not m or m.group("prog") != "postgres":
                    continue
                s = SEQ_RE.match(m.group("msg"))
                text = (s.group("rest") if s else m.group("msg")).replace("#011", "\t")
                key = (m.group("host"), m.group("pid"), s.group("seq") if s else raw)
                if s and int(s.group("part")) > 1 and key in pending:
                    pending[key]["text"] += "\n" + text      # continuation line
                else:
                    pending[key] = {"ts": parse_ts(m.group("ts"), now), "host": m.group("host"), "text": text}
    return pending.values()


def extract_ddl(events, since, until):
    rows = []
    for ev in events:
        if not (since <= ev["ts"] <= until):
            continue
        p = PREFIX_RE.match(ev["text"])
        if not p or not p.group("body").startswith("statement:"):
            continue
        stmt = re.sub(r"\s+", " ", p.group("body")[len("statement:"):]).strip()
        if not DDL_RE.match(stmt):
            continue
        cmd, obj = classify(stmt)
        rows.append({"timestamp": ev["ts"].isoformat(timespec="seconds"), "server": ev["host"],
                     "user": p.group("user") or "(none)", "database": p.group("db") or "(none)",
                     "client": p.group("client") or "[local]", "application": p.group("app"),
                     "command": cmd, "object_type": obj, "action": f"{cmd} {obj}".strip(),
                     "statement": stmt[:1000]})
    return sorted(rows, key=lambda r: r["timestamp"])


def write_csv(path, rows, fields):
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=fields); w.writeheader(); w.writerows(rows)


def summarize(rows):
    groups = defaultdict(list)
    for r in rows:
        groups[(r["user"], r["database"], r["action"])].append(r["timestamp"])
    return [{"user": u, "database": d, "action": a, "count": len(t), "first_seen": min(t), "last_seen": max(t)}
            for (u, d, a), t in sorted(groups.items())]


def send_email(args, subject, body, attachments):
    msg = EmailMessage()
    msg["Subject"], msg["To"] = subject, ", ".join(args.email_to)
    msg["From"] = args.mail_from or os.environ.get("MAIL_FROM") or os.environ.get("SMTP_USER", "pg-report@localhost")
    msg.set_content(body)
    for path in attachments:
        with open(path, "rb") as fh:
            msg.add_attachment(fh.read(), maintype="text", subtype="csv", filename=os.path.basename(path))
    if args.dry_run:
        print("[dry-run] e-mail NOT sent. Headers:", {k: msg[k] for k in ("From", "To", "Subject")},
              "attachments:", [os.path.basename(a) for a in attachments])
        return
    host = os.environ.get("SMTP_HOST")
    if not host:
        sys.exit("SMTP_HOST is not set - cannot send e-mail (use --dry-run to test).")
    port = int(os.environ.get("SMTP_PORT", "587"))
    with smtplib.SMTP(host, port, timeout=30) as smtp:
        smtp.ehlo()
        if port != 25:
            smtp.starttls(); smtp.ehlo()
        if os.environ.get("SMTP_USER"):
            smtp.login(os.environ["SMTP_USER"], os.environ.get("SMTP_PASS", ""))
        smtp.send_message(msg)
    print("E-mail sent to", msg["To"])


def main():
    ap = argparse.ArgumentParser(description="PostgreSQL DDL compliance report from syslog files")
    ap.add_argument("--log-glob", required=True, help='e.g. "/var/log/remote/postgres/*.log"')
    ap.add_argument("--hours", type=float, default=24)
    ap.add_argument("--output-dir", default="reports")
    ap.add_argument("--now", help="override current time (ISO 8601 with offset) - for testing")
    ap.add_argument("--email-to", nargs="+", help="recipient address(es)")
    ap.add_argument("--mail-from")
    ap.add_argument("--dry-run", action="store_true", help="build the e-mail but do not send it")
    args = ap.parse_args()

    now = datetime.fromisoformat(args.now) if args.now else datetime.now().astimezone()
    if now.tzinfo is None:
        now = now.astimezone()
    since = now - timedelta(hours=args.hours)
    paths = sorted(glob.glob(args.log_glob))
    if not paths:
        sys.exit(f"No log files match {args.log_glob}")

    rows = extract_ddl(read_events(paths, now), since, now)
    os.makedirs(args.output_dir, exist_ok=True)
    stamp = now.strftime("%Y%m%d_%H%M")
    detail = os.path.join(args.output_dir, f"ddl_detail_{stamp}.csv")
    summary = os.path.join(args.output_dir, f"ddl_summary_{stamp}.csv")
    write_csv(detail, rows, ["timestamp", "server", "user", "database", "client", "application",
                             "command", "object_type", "action", "statement"])
    summ = summarize(rows)
    write_csv(summary, summ, ["user", "database", "action", "count", "first_seen", "last_seen"])

    per_user = defaultdict(int)
    for r in rows:
        per_user[r["user"]] += 1
    lines = [f"PostgreSQL DDL compliance report",
             f"Window: {since.isoformat(timespec='seconds')}  ->  {now.isoformat(timespec='seconds')}",
             f"Log files read: {len(paths)}", f"Total DDL statements: {len(rows)}", ""]
    lines += [f"  {u}: {n} statement(s)" for u, n in sorted(per_user.items(), key=lambda x: -x[1])] or ["  (no DDL activity)"]
    lines += ["", "Attached: summary CSV (per user/database/action) and detail CSV (every statement)."]
    body = "\n".join(lines)
    print(body); print(f"\nWrote {summary}\nWrote {detail}")

    if args.email_to:
        send_email(args, f"[Compliance] PostgreSQL DDL report {now:%Y-%m-%d} - {len(rows)} statement(s)",
                   body, [summary, detail])


if __name__ == "__main__":
    main()
