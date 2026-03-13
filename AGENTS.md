# AGENTS.md

> Instructions for AI coding agents (Claude Code, Codex, Cursor, etc.) working on Hollownet.
> Read CLAUDE.md first — this file extends it with agent-specific behavior rules.

---

## Identity & Context

You are working on **Hollownet**, a production honeypot with ML-powered threat intelligence.
- Owner: Nacho (cybersecurity-focused CV project)
- Repo: `trykelink/hollownet`
- This is a real production system — the Zenbook is always on and exposed to internet

---

## Before You Write Any Code

1. **Read CLAUDE.md** — architecture, stack, ports, AWS profile, DynamoDB schema
2. **Identify the module** — which of `collector/`, `ml/`, `dashboard/`, `infra/`, `honeypot/` are you touching?
3. **Check for existing tests** — run them before and after your changes
4. **Never assume AWS resources exist** — check CDK stacks in `infra/` first

---

## Task Execution Rules

### General
- Make the smallest change that solves the problem — don't refactor unrelated code
- If a task is ambiguous, implement the most conservative interpretation and note alternatives in a comment
- Always explain what you changed and why at the end of your response
- If you add a dependency, update the relevant `requirements.txt` or `package.json` immediately

### Python (collector/, ml/, infra/)
- Always activate the module's virtualenv before installing — never install globally
- Use type hints on all function signatures
- Use `dataclasses` or `pydantic` models for structured data — no raw dicts passed between functions
- Catch specific exceptions — never bare `except:` or `except Exception:` without logging
- Use `boto3` with explicit `region_name="us-east-1"` and `profile_name="hollownet"`
- Log with structured JSON: `{"level": "info", "msg": "...", "context": {...}}`

### FastAPI (collector/)
- All endpoints must have response models defined with Pydantic
- Use dependency injection for DynamoDB client — don't instantiate boto3 inside route handlers
- Return consistent error shapes: `{"error": "...", "detail": "..."}`
- Never expose raw Cowrie payloads in API responses — always use sanitized models

### AWS Lambda (ml/)
- Cache `.pkl` models in `/tmp` after first load — never re-download on every invocation
- Always handle cold starts gracefully — model download can take 2-3 seconds
- Keep Lambda packages under 50MB — use Lambda layers for heavy deps if needed
- Set explicit timeouts in CDK: inference Lambda = 30s, training Lambda = 300s
- Never log sensitive data (passwords, raw payloads) to CloudWatch

### AWS CDK (infra/)
- One stack per concern: `DatabaseStack`, `LambdaStack`, `StorageStack`, `AlertStack`
- Always use `RemovalPolicy.RETAIN` on DynamoDB and S3 — never risk data loss
- Tag all resources: `{"project": "hollownet", "env": "prod"}`
- Use `aws_cdk.aws_lambda_python_alpha` for Python Lambdas with automatic bundling
- Never hardcode account ID or region — use `Stack.of(self).account` and `.region`

### Next.js Dashboard (dashboard/)
- TypeScript strict mode — no `any`, no `// @ts-ignore`
- Fetch data server-side where possible (Next.js Server Components)
- No API keys or AWS credentials in frontend code — ever
- Use `SWR` or `React Query` for client-side data fetching with auto-refresh
- Dark theme only — background `#0a0a0a`, primary `#00ff88` (see CLAUDE.md color system)

---

## File Structure Conventions

```
collector/
  main.py           ← FastAPI app entry point
  parser.py         ← Cowrie log parser
  enricher.py       ← IP geolocation + AbuseIPDB
  models.py         ← Pydantic models / dataclasses
  dynamo.py         ← DynamoDB client wrapper
  tests/
    test_parser.py
    test_enricher.py

ml/
  feature_engineering.py   ← Raw events → feature vectors
  train.py                 ← Training script (runs locally or in Lambda)
  lambda_inference.py      ← Lambda handler for per-event scoring
  lambda_training.py       ← Lambda handler for weekly retraining
  export_dataset.py        ← DynamoDB → CSV export
  models/                  ← Local model artifacts (gitignored)
  tests/
    test_features.py

infra/
  app.py                   ← CDK app entry point
  stacks/
    database_stack.py
    storage_stack.py
    lambda_stack.py
    alert_stack.py

dashboard/
  app/                     ← Next.js 14 app directory
    page.tsx               ← Overview / map
    events/page.tsx        ← Timeline
    intel/page.tsx         ← IP intelligence
    ml/page.tsx            ← ML insights
  components/
  lib/
    api.ts                 ← Collector API client
```

---

## Testing Requirements

- Every new function in `collector/` and `ml/` needs at least one unit test
- Use `pytest` with fixtures — no hardcoded test data inline
- Mock all external calls: boto3, ip-api, AbuseIPDB, Telegram
- Test file naming: `test_<module>.py` inside `tests/` subfolder
- Run tests before committing: `pytest tests/ -v`

---

## Git Conventions

```
feat: add IP enrichment to collector
fix: handle missing password field in login_failed events
chore: update requirements.txt
docs: add ML metrics to docs/
refactor: extract DynamoDB client to dynamo.py
test: add unit tests for feature engineering
infra: add EventBridge cron for weekly retraining
```

- One logical change per commit
- Never commit directly to `main` — use feature branches: `feat/collector-api`, `fix/parser-edge-case`
- PR title = commit message format above

---

## Security Rules (non-negotiable)

- Never log passwords or credentials to CloudWatch, stdout, or any file other than Cowrie's own logs
- Never expose the Zenbook's real SSH port (2200) publicly — it's LAN only
- Never store IP reputation API keys in code — use AWS Secrets Manager or env vars
- Sanitize all data before writing to DynamoDB — strip null bytes, limit string lengths
- The Telegram bot token lives only in AWS Secrets Manager and GitHub Secrets — nowhere else

---

## Known Constraints

- Zenbook e2-micro equivalent — keep Cowrie + FastAPI lightweight, no heavy background workers
- AbuseIPDB: 1000 req/day free — always check DynamoDB cache before calling
- ip-api.com: 45 req/min free — batch requests when possible
- Lambda memory: 512MB for inference, 1024MB for training
- DynamoDB: on-demand billing — avoid scan operations, always use GSI for IP queries

---

## Self-Modification Protocol

If you encounter a recurring pattern, edge case, or constraint not covered here:
1. Add a concise rule to the relevant section
2. Append `# added YYYY-MM-DD: <reason>` as a comment on the same line
3. Remove rules that are no longer relevant
4. If this file exceeds 250 lines, notify Nacho to review and prune