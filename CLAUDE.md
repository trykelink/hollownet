# CLAUDE.md

> Provisional — update this file when you find recurring errors or new preferences.
> Keep it under 300 lines. Prune rules that become redundant.

---

## Project

**Hollownet** — Production honeypot with real-time threat intelligence and ML-powered attack classification.
Repo: `trykelink/hollownet` | Owner: Nacho (Computer Engineering student, Buenos Aires)

---

## Critical Rules (read first)

- **Never commit secrets** — no `.env`, no AWS keys, no `.pem`, no `.pkl` models
- **Never use root AWS account** — always use `hollownet-dev` IAM profile
- **AWS CLI profile is `hollownet`** — always pass `--profile hollownet` or set `AWS_PROFILE=hollownet`
- **Never install packages globally** — always use virtualenv inside each module
- **Python target: 3.12** — Zenbook runs 3.12.3, keep compatibility
- **All infrastructure via CDK** — never create AWS resources manually from console

---

## Architecture

```
Zenbook Ubuntu (local server)       AWS (forever free tier)
─────────────────────────────       ───────────────────────
Cowrie :2222 (SSH honeypot)         Lambda — ML inference
FastAPI Collector                   Lambda — weekly retraining
Cloudflare Tunnel (exposes :2222)   DynamoDB — events
                                    S3 — dataset + models (.pkl)
                                    SNS → Telegram alerts
                                    EventBridge — cron retraining
                                    CloudFront — dashboard hosting

Dashboard: Next.js → S3 + CloudFront
```

---

## Module Map

| Dir | Language | Purpose |
|---|---|---|
| `honeypot/` | Config only | Cowrie setup, systemd service, iptables rules |
| `collector/` | Python/FastAPI | Parse Cowrie JSON logs, enrich IPs, write to DynamoDB |
| `ml/` | Python | Feature engineering, train Isolation Forest + Random Forest, Lambda inference |
| `dashboard/` | Next.js/TypeScript | Real-time threat visualization, consumes collector API |
| `infra/` | Python/AWS CDK | All AWS resources as code |
| `docs/` | Markdown | Architecture diagrams, ML metrics, red team session logs |

---

## Stack & Versions

| Layer | Tech | Notes |
|---|---|---|
| Honeypot | Cowrie (latest) | Runs as `cowrie` user, port 2222 |
| API | FastAPI + uvicorn | Python 3.12, virtualenv in `collector/` |
| DB | AWS DynamoDB | Table: `hollownet-events`, GSI on `src_ip` |
| Storage | AWS S3 | Buckets: `hollownet-dataset`, `hollownet-models` |
| ML | scikit-learn | Isolation Forest (anomaly) + Random Forest (classification) |
| Inference | AWS Lambda | Loads `.pkl` from S3, writes predictions to DynamoDB |
| Alerts | AWS SNS + Lambda | Telegram Bot API |
| Scheduler | AWS EventBridge | Cron: every Monday 3am UTC |
| Dashboard | Next.js 14 + Tailwind | TypeScript, deployed to S3 + CloudFront |
| IaC | AWS CDK v2 | Python, profile: `hollownet` |

---

## Infrastructure

- **AWS region:** `us-east-1`
- **AWS profile:** `hollownet`
- **Zenbook IP (local):** `192.168.1.237`
- **Zenbook SSH port:** `2200` (22 is reserved for Cowrie)
- **Cowrie port:** `2222`
- **Cowrie user:** `cowrie` (disabled password, dedicated system user)
- **Cowrie path:** `/home/cowrie/cowrie`
- **Cowrie logs:** `/home/cowrie/cowrie/var/log/cowrie/cowrie.json`
- **Cowrie venv:** `/home/cowrie/cowrie/cowrie-env`

---

## DynamoDB Schema

**Table: `hollownet-events`**

| Field | Type | Notes |
|---|---|---|
| `event_id` | String (PK) | UUID from Cowrie |
| `timestamp` | String (SK) | ISO8601 |
| `src_ip` | String | GSI partition key |
| `event_type` | String | login_success / login_failed / command / file_download |
| `session_id` | String | Cowrie session ID |
| `username` | String | Attempted username |
| `password` | String | Attempted password |
| `command` | String | Command if event_type=command |
| `country` | String | From ip-api.com |
| `city` | String | From ip-api.com |
| `abuse_score` | Number | From AbuseIPDB (0-100) |
| `anomaly_score` | Number | From Isolation Forest |
| `attack_type` | String | From Random Forest |
| `risk_level` | String | CRITICAL / HIGH / MEDIUM / LOW |
| `raw_payload` | Map | Full Cowrie JSON event |

---

## ML Pipeline

**Features used:**
- `attempt_frequency` — attempts from same IP in last hour
- `time_of_day` — hour of attack (0-23)
- `unique_credentials` — distinct user/pass combos per session
- `session_duration` — seconds
- `abuse_score` — AbuseIPDB score
- `is_known_admin_user` — 1 if root/admin/administrator
- `commands_executed` — count of commands in session
- `files_downloaded` — 1 if file download attempted

**Models:**
- `isolation_forest.pkl` — anomaly detection (unsupervised)
- `random_forest.pkl` — attack classification (supervised)
- Labels: `SSH_BRUTEFORCE`, `PORT_SCAN`, `CREDENTIAL_STUFFING`, `WEB_SCRAPING`, `UNKNOWN`

**Retraining:** Every Monday 3am UTC via EventBridge → Lambda

---

## External APIs

| API | Purpose | Limit |
|---|---|---|
| `ip-api.com` | Geolocation | 45 req/min, free |
| `AbuseIPDB` | IP reputation | 1000 req/day, free |
| Telegram Bot API | Alerts | No limit |

- Cache IP enrichment in DynamoDB with 24h TTL to avoid re-querying

---

## Alert Thresholds (SNS → Telegram)

Trigger alert when:
- `abuse_score > 80`
- Same IP attempts > 10 times in 5 minutes
- Username is `root`, `admin`, or `administrator`
- File download detected inside honeypot
- Rate limit: max 1 alert per IP per hour

---

## Commands

```bash
# Connect to Zenbook
ssh zenbook  # alias: nacho@192.168.1.237 -p 2200

# Cowrie (on Zenbook, as cowrie user)
sudo systemctl status cowrie
sudo systemctl restart cowrie
tail -f /home/cowrie/cowrie/var/log/cowrie/cowrie.json

# Collector API (collector/)
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
uvicorn main:app --reload

# Run tests
pytest tests/ -v

# Dashboard (dashboard/)
npm install
npm run dev

# CDK deploy (infra/)
source venv/bin/activate
cdk deploy --profile hollownet

# Copy Cowrie logs to local for testing
scp zenbook:/home/cowrie/cowrie/var/log/cowrie/cowrie.json /tmp/cowrie_test.json

# AWS CLI (always use profile)
aws dynamodb list-tables --profile hollownet
```

---

## Code Style

- **Python:** PEP8, type hints required, docstrings on public functions
- **TypeScript:** strict mode enabled, no `any`
- **Naming:** snake_case Python, camelCase TS/JS
- **Error handling:** never swallow exceptions silently — always log with context
- **Logging:** structured JSON logs in all Python services
- **Tests:** pytest for Python, Jest for Next.js — write tests alongside code, not after

---

## What NOT to do

- Don't run Cowrie as root
- Don't hardcode AWS region or account ID — use CDK context or env vars
- Don't query ip-api or AbuseIPDB without checking cache first
- Don't deploy Lambda without updating the `.pkl` version reference in S3
- Don't use `SELECT *` patterns in DynamoDB — always specify attributes
- Don't add rules to this file that are already enforced by linters

---

## Self-Modification Protocol

If you (Claude/agent) notice a recurring error or new constraint:
1. Add a concise rule under the relevant section
2. Add a comment: `# added YYYY-MM-DD: reason`
3. If this file exceeds 300 lines, split into `.claude/rules/` subdirectory