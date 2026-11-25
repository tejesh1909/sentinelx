# SentinelX – Unified Security Intelligence Platform

Modular-monolith SIEM-style demo: FastAPI + SQLAlchemy + PostgreSQL/Redis backend, React/TS/Tailwind/Recharts dashboard.

## Run
```
docker compose up --build        # UI: http://localhost:3000   API docs: http://localhost:3000/api/docs
```
Dev demo login (development only): `admin@sentinelx.local` / `ChangeMe!Dev2026` (from `.env`). The UI forces a visible
reminder to change it, and `APP_ENV=production` refuses to start with the default password or without `JWT_SECRET`.
First start seeds roles, 8 detection rules, integrations and ~175 synthetic events (only if the events table is empty; idempotent).
`docker compose exec backend python -m app.seed dump > sample_events.json` exports the dataset (uploadable via the Events page).

Local backend tests (SQLite): `cd backend && pip install -r requirements.txt && pytest`

## Layout
`backend/app/{core,models,services,ai,seed,main}.py` – services.py holds normalization, ingestion, detection, risk scoring, correlation.
`backend/alembic` – migrations. `frontend/src/App.tsx` – all 9 pages. `docker-compose.yml`, `.env.example`.

## What the demo data shows
(A) 12 failed logins -> success from new IP -> payroll export => correlated, critical incident. (B) API probing with 403s from one IP.
(C) privilege grant + off-hours admin action (threats, no incident). (D) request flood.

## Honest limitations
- Detection is simple threshold/rule logic on controlled data; it is not complete real-world attack detection.
- AWS CloudTrail is **simulated** (`POST /api/integrations/cloudtrail/simulate`). No AWS connection exists. Real path: CloudTrail -> S3 -> SQS -> worker -> `services.ingest()` (mapping in `from_cloudtrail`).
- Ingestion/detection run synchronously in the request. Redis is used for rate limiting only (in-memory fallback); no background queue yet.
- LLM output is advisory: the model gets real incident data, cannot act, and falls back to deterministic text if no key/API failure. It is instructed not to invent evidence but is not mechanically verified.
- The Alembic initial migration creates tables from model metadata; use `alembic revision --autogenerate` for later changes.
- Tokens are kept in localStorage in the UI (XSS-exposed); use httpOnly cookies + CSRF protection for production. Add HTTPS/TLS at the edge.
- Public registration creates `analyst` users (set `ALLOW_REGISTRATION=0` to disable). Rate limiting keys on client IP.
- Untested in the authoring sandbox (no package install/network): run `pytest` and `docker compose up --build` and fix anything that surfaces.

## AWS-ready deploy
Images are stateless: run backend/frontend on ECS Fargate (or App Runner), RDS PostgreSQL, ElastiCache Redis, secrets in Secrets Manager, ALB with TLS in front of nginx.

## v2 additions
MITRE ATT&CK mapping + coverage grid (indicative/approximate), live threat feed (SSE) + "Simulate attack" (synthetic, 3-stage demo), statistical volume-anomaly rule
(per-user z-score; basic, not ML), IP lookup (synthetic geo for documentation ranges; real reputation only with `ABUSEIPDB_API_KEY`), RQ background worker
(`POST /api/events/ingest?async_mode=true` -> 202 + job id, `GET /api/jobs/{id}`; falls back to sync without Redis; UI uses sync), TOTP MFA + 5-strike/15-min lockout,
Slack-compatible webhook for critical incidents (`WEBHOOK_URL`), printable HTML incident report ("Open report" -> browser Print > Save as PDF; no server-side PDF),
manual playbooks per threat type (never auto-executed), attack-chain view, toasts, skeleton loaders, shortcuts (`/` search, `1`-`9` pages), light/dark toggle (CSS invert filter).
**Schema changed**: if you ran v1, use `docker compose down -v` first. Caveats: MFA secret stored unencrypted; lockout can be abused to lock a known account;
not implemented: GeoIP world map, email notifications, server-side PDF, ML models. Still unrun in the authoring sandbox.
