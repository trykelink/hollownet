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
