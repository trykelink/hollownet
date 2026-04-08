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
