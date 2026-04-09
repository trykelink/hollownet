# Hollownet — Progress Log

## Current phase
Phase 2 — Collector pipeline

## What exists
- Cowrie running via Docker Compose, port 2222
- Cloudflare Tunnel validated end-to-end
- PostgreSQL container defined in docker-compose.yml
- Named volume `cowrie_logs` for Cowrie JSON logs

## What to build next
Collector: `database.py` → `models.py` → `parser.py` → `enricher.py` → `main.py` → tests

## Log
- [2026-04-08] Cowrie honeypot running, Cloudflare Tunnel validated, repo initialized
- [2026-04-08] Added async collector database engine and session helpers
- [2026-04-08] Added collector ORM models for events and IP intelligence
- [2026-04-08] Added Cowrie event parser with normalization and deduping
- [2026-04-08] Added lazy IP enricher with AbuseIPDB caching
- [2026-04-08] Added collector FastAPI app and Cowrie polling loop
- [2026-04-08] Added database tests for engine, sessions, and schema
- [2026-04-08] Added ORM tests for events and IP intelligence
- [2026-04-08] Added parser tests for supported and invalid Cowrie logs
- [2026-04-08] Added enricher tests for caching and provider failures
- [2026-04-08] Added main service and API tests for collector
- [2026-04-08] Added collector Python dependency manifest
- [2026-04-08] Added greenlet to collector dependencies
- [2026-04-08] Fixed cached datetime normalization in IP enricher
- [2026-04-08] Normalized returned IP intel datetimes across backends
- [2026-04-08] Added collector service, Dockerfile, and .env.example to compose
- [2026-04-08] Moved POSTGRES_PASSWORD to env; added non-root user to Dockerfile
- [2026-04-08] Switched Cowrie log reads to Docker archive streaming
- [2026-04-08] Replaced exec_run with get_archive for shell-free Cowrie log reading
- [2026-04-08] Added configurable collector logging via LOG_LEVEL
- [2026-04-08] Fixed collector logging levels under Uvicorn startup
- [2026-04-08] Added Telegram alerts for brute force and successful logins
- [2026-04-08] Fixed event deduplication by deriving per-event IDs
- [2026-04-08] Added Telegram notifier and CollectorService alert triggers
- [2026-04-08] Added Grafana provisioning and Hollownet threat dashboard
- [2026-04-08] Made Grafana root URL configurable via environment
- [2026-04-08] Added brute force alert cooldown by source IP
- [2026-04-08] Added ML anomaly scoring pipeline and daily reporting
- [2026-04-08] Added ML review fixes with non-root Dockerfile and mocked tests
- [2026-04-08] Hardened security: pinned deps, removed Docker socket, locked DB and Grafana ports
- [2026-04-08] Removed dead ML cron shim; systemd timer is scheduler of record
