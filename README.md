# Security Analysis and Detection

Python starter implementation for the capstone security log analysis project.

## Features
- T-04 Log collection from local files and Linux syslog, with optional AWS CloudWatch.
- T-05 Parsing and normalization of common Linux SSH authentication messages.
- T-06 Detection rules for repeated failed logins, successful login after repeated failures, and configured suspicious process names.
- T-12 Input validation and pytest security/functional tests.
- SQLite persistence and a FastAPI interface for events and alerts.

## Requirements
Python 3.11+.

## Setup
```bash
python -m venv .venv
# Windows: .venv\Scripts\activate
# Linux/macOS: source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
```

## Run sample logs
```bash
python -m app.main --file sample_logs/auth.log
```

## Run API
```bash
uvicorn app.api:app --reload
```
Open http://127.0.0.1:8000/docs.

Endpoints: `GET /health`, `GET /events?limit=100`, `GET /alerts?limit=100`, and `PATCH /alerts/{alert_id}/status` with JSON `{"status":"acknowledged"}`.

## Run tests
```bash
pytest -q
```

## Optional CloudWatch
Set AWS credentials through the normal AWS profile/environment and run:
```bash
python -m app.main --cloudwatch --log-group "/technova/security" --start-minutes 60
```
Use least-privilege read permissions. Never commit credentials.

## Security notes
The detection rules are demonstrations, not a complete SIEM or malware detector. Before exposing the API beyond localhost, add authentication/authorization, TLS, rate limiting, secret management, audit logging, and retention controls. Extend parsers and rules to match the actual log sources in use.
