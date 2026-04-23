# CyberGuard AI Telegram Bot

CyberGuard AI is a defensive Telegram bot for triaging suspicious indicators and generating evidence-backed reports from public and breach-intelligence sources.

[![Python](https://img.shields.io/badge/Python-3.11%2B-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![Platform](https://img.shields.io/badge/Platform-Telegram%20Bot-26A5E4?logo=telegram&logoColor=white)](https://core.telegram.org/bots)
[![Deployment](https://img.shields.io/badge/Deploy-Railway-0B0D0E?logo=railway&logoColor=white)](https://railway.app/)
[![License](https://img.shields.io/badge/License-See%20LICENSE-16a34a)](LICENSE)

[![Deploy on Railway](https://railway.app/button.svg)](https://railway.app/new)

## Architecture

![CyberGuard Architecture](docs/images/architecture.svg)

## Tier and Privacy Model

![Tier Privacy Matrix](docs/images/tier-privacy-matrix.svg)

## Product Screenshots

![Investigate Flow Screenshot](docs/images/screenshot-investigate.svg)
![Scan Flow Screenshot](docs/images/screenshot-scan.svg)

Core visibility policy:

- `basic`: IP, MAC, and social identifiers are masked.
- `pro` and `master`: real IP, MAC, and social identifiers are available when `privacy:off`.
- all tiers with `privacy:on`: identifiers are masked.
- all tiers with no consent (`consent:no` / missing consent token): sensitive identity enrichment is redacted.
- tracking remains disabled in all modes.

## Feature Highlights

- Cross-source investigation for phone, email, IP, MAC, and social identifiers.
- Tier-aware output controls (`basic`, `pro`, `master`).
- Consent-aware enrichment redaction.
- Report scoring, evidence source attribution, and risk flags.
- Media handler coverage for URL, file, image, and voice workflows.
- Production-ready deployment for Railway with PostgreSQL and Redis.

## Project Layout

```text
cyberguard-telegram/
	handlers/        # Telegram command and media handlers
	services/        # Investigation, scanning, enrichment services
	middleware/      # Quota and moderation controls
	database/        # Models and persistence
	tests/           # Unit, handler, integration, and e2e tests
	docs/images/     # README diagrams
```

## Quick Start (Local)

1. Clone and enter the project directory.
2. Create and activate a virtual environment.
3. Install dependencies.
4. Copy `.env.example` to `.env` and fill required values.
5. Run the bot.

```bash
python -m venv .venv
. .venv/Scripts/activate  # Windows PowerShell: .\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python main.py
```

## Required Environment Variables

| Variable | Required | Description | Example |
|---|---|---|---|
| `BOT_TOKEN` | Yes | Telegram bot token | `123456:ABCDEF` |
| `ANTHROPIC_API_KEY` | Yes | LLM API key for AI analysis | `sk-ant-api03-xxxx` |
| `DATABASE_URL` | Yes | PostgreSQL connection string | `postgresql://user:pass@host/db` |
| `REDIS_URL` | Yes | Redis connection string | `redis://default:pass@host:6379` |
| `ADMIN_IDS` | Yes | Comma-separated Telegram admin IDs | `123456789,987654321` |
| `BACKEND_URL` | Yes | Optional companion backend URL | `https://your-api.up.railway.app` |
| `ENVIRONMENT` | Yes | Runtime profile | `production` |

## Investigation Command Examples

```text
/investigate +919876543210
/investigate pro consent:yes email:test@example.com
/investigate master privacy:off ip:1.1.1.1 mac:00-1A-2B-3C-4D-5E
/investigate pro tg:sample_user group:fraud_watch twitter:samplex
```

## Railway Deployment

### CLI Workflow

```bash
npm i -g @railway/cli
railway login
railway init

railway vars set BOT_TOKEN=xxx
railway vars set ANTHROPIC_API_KEY=xxx
railway vars set DATABASE_URL=xxx
railway vars set REDIS_URL=xxx
railway vars set ADMIN_IDS=123,456
railway vars set BACKEND_URL=https://your-api.up.railway.app
railway vars set ENVIRONMENT=production

railway up
```

### Free Database Pairing

- PostgreSQL: Neon (`DATABASE_URL`)
- Redis: Upstash (`REDIS_URL`)

After setting both URLs, redeploy and verify startup logs include a successful `python main.py` launch.

## Backend API Integration

This Telegram bot can run standalone, but it can also integrate with an external backend service via `BACKEND_URL`.

Common integration patterns:

- Enrich scan/investigation flows with central policy services.
- Store results in a shared backend for dashboards and analytics.
- Centralize admin workflows and incident handling.

Suggested backend endpoints (example contract):

```text
POST /api/scan
POST /api/investigate
GET  /api/health
GET  /api/reports/{artifact_id}
```

Suggested payload fields for scan/investigate:

```json
{
	"source": "telegram",
	"consent_confirmed": true,
	"privacy_mode": false,
	"tier": "pro",
	"content": "suspicious input or identifier"
}
```

Set backend URL in environment:

```bash
railway vars set BACKEND_URL=https://your-api.up.railway.app
```

## Quality and Testing

Run the full test suite:

```bash
pytest -q
```

Run only investigation tests:

```bash
pytest -q tests/handlers/test_investigate_handler.py
```

## Security and Usage Policy

- Defensive and educational use only.
- Illegal or abusive requests are blocked by design.
- Reports are generated from public and breach-intelligence sources.
- Real-time tracking and covert surveillance are not supported.

## License

This project is licensed under the terms of the `LICENSE` file in this repository.
