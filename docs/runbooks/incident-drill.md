# Incident Drill Runbook

Use this runbook to practice SRE incident response with concrete evidence.

## Drill 1: Security Regression

```bash
scripts/backend_hands_on_tests.sh
```

Expected result:

- SQL injection payload returns HTTP 400.
- Path traversal payload returns HTTP 403.
- Login returns a bearer token without credential material.
- Non-admin token cannot access `/users/admin/audit`.

## Drill 2: Load SLO

```bash
REQUESTS=100 CONCURRENCY=10 SLO_MS=500 scripts/load_hands_on_tests.sh
```

Expected result:

- No failed health requests.
- P95 latency is within the configured SLO.

## Drill 3: Dependency Outage

Run this only against the Docker Compose lab, because it pauses the `db` service.

```bash
RUN_CHAOS=1 scripts/incident_drill.sh
```

Expected result:

- `/health/ready` returns HTTP 503 while the database is paused.
- `/health/ready` returns HTTP 200 after database recovery.

## Evidence to Capture

- `reports/incident_drill_*/summary.md`
- App access/error/auth logs
- Fail2ban status when security abuse is part of the drill
- Kibana screenshots or saved searches
- Timeline and follow-up items in `docs/templates/postmortem.md`
