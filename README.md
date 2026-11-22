# Centralized PostgreSQL syslog collector + DDL compliance report

```
 DB server(s)                          Collector server                      Compliance
 PostgreSQL --syslog LOCAL0--> rsyslog --TCP 514--> rsyslog (imtcp)
                                                    /var/log/remote/postgres/<host>.log
                                                              |
                                          compliance_report.py (cron, daily)
                                                              |
                                              summary + detail CSV --e-mail--> compliance@
```

## Steps mapped to files
| Step | What | File | Where it runs |
|---|---|---|---|
| 1 | PostgreSQL sends logs to syslog (+ log DDL, user/db prefix) | config/1_postgresql_syslog.conf | DB server, postgresql.conf |
| 1 | Forward LOCAL0 to collector | config/1b_db_server_forward.conf | DB server, /etc/rsyslog.d/ |
| 2 | Install rsyslog, define PostgreSQL log source | config/2_collector_rsyslog.conf | Collector, /etc/rsyslog.d/ |
| 3 | Python parser: DDL in last 24 h | compliance_report.py | Collector |
| 4 | CSV report + e-mail | compliance_report.py, config/cron_compliance, config/pg-compliance.env.example | Collector |
| - | Log retention | config/logrotate_remote_postgres | Collector |

## Setup order
1. **Collector:** install rsyslog, copy `2_collector_rsyslog.conf`, create `/var/log/remote/postgres`, open TCP 514 only to your DB servers, restart rsyslog.
2. **DB server:** add the settings from `1_postgresql_syslog.conf` to postgresql.conf, install `1b_db_server_forward.conf`
   (edit the collector address), run `SELECT pg_reload_conf();` and restart rsyslog.
3. **Test the pipeline:** on the DB server run `logger -p local0.info -t postgres "test message"`, then on the collector
   `tail /var/log/remote/postgres/<dbhost>.log`. Then run a DDL statement in psql and check it appears with `user=...,db=...`.
4. **Report script:** copy `compliance_report.py` to `/opt/pg-compliance/`, create `/etc/pg-compliance.env` (chmod 600) from the example,
   install `cron_compliance` as `/etc/cron.d/pg-compliance-report`.

## Try the script without any servers
```
python3 compliance_report.py --log-glob "sample_logs/*.log" --now 2026-11-22T12:00:00+05:30 \
        --output-dir out --email-to compliance@example.com --dry-run
```
Expected: 9 DDL statements (alice 4, bob 2, carol 2, dave 1). Skipped on purpose: a statement older than 24 h, a SELECT,
a connection line and an sshd line. `sample_output/` holds the CSVs this command produces.
Python 3.8+ standard library only (no pip install).

## What the script does
- Reads every file matching `--log-glob`; understands rsyslog ISO timestamps and the traditional `Nov 22 11:30:00` format.
- Re-joins multi-line statements (`[7-1]`, `[7-2]` ...) and keeps only `statement:` lines whose SQL is DDL
  (CREATE, ALTER, DROP, TRUNCATE, GRANT, REVOKE, COMMENT, REINDEX, CLUSTER, SECURITY LABEL).
- Writes `ddl_summary_*.csv` (user / database / action / count / first / last) and `ddl_detail_*.csv` (every statement).
- E-mails both via SMTP (STARTTLS) using SMTP_* environment variables; `--dry-run` builds the mail without sending.

## Notes
- `log_statement='ddl'` logs the full SQL text, which can include passwords (e.g. `CREATE ROLE ... PASSWORD '...'`). Restrict access to the log files (done via file mode 0640) and consider TLS for the syslog link (rsyslog gtls) in production.
- Only DDL statements are logged; `log_statement='mod'` or `'all'` would be needed to report DML as well.
