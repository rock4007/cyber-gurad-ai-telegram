# CyberGuard AI Telegram Bot

CyberGuard AI is a defensive Telegram bot for analyzing suspicious phone numbers, URLs, social media profiles, files, images, and voice messages. It is designed for scam detection, fraud triage, and user safety guidance only.

## Features

- Phone number scam analysis with country and carrier context
- URL and phishing link analysis with detailed explanation output
- Social media handle and profile scanning with local threat-intel checks
- File scanning with hash generation and malware-style reporting
- Image metadata analysis with GPS detection and approximate location lookup
- Voice message transcription with Whisper-compatible APIs and scam phrase detection
- Backend explanation output for clearer user-facing reasoning
- Optional live threat-intel enrichment from external providers

## Setup

1. Copy [.env.example](d:\telegram bot\cyberguard-telegram\.env.example) to `.env`.
2. Fill in the required bot settings:

```env
BOT_TOKEN=
ANTHROPIC_API_KEY=
DATABASE_URL=
REDIS_URL=
ADMIN_IDS=
BACKEND_URL=
ENVIRONMENT=development
```

3. Install dependencies:

```powershell
pip install -r requirements.txt
```

4. Start the Telegram bot:

```powershell
python main.py
```

## Optional AI Keys

These enable richer transcription and model integrations:

```env
OPENAI_API_KEY=
WHISPER_API_KEY=
WHISPER_API_URL=https://api.openai.com/v1/audio/transcriptions
WHISPER_MODEL=whisper-1
```

`WHISPER_API_KEY` or `OPENAI_API_KEY` is required for real voice transcription.

## Optional Threat Intel And Dark Web Keys

These keys are optional. When present in the backend environment, live enrichment can add indicators, explanation context, and score boosts.

```env
SHODAN_API_KEY=
VIRUSTOTAL_API_KEY=
HIBP_API_KEY=
INTELLIGENCEX_API_KEY=
DEHASHED_API_KEY=
DEHASHED_EMAIL=
HUNTER_API_KEY=
URLSCAN_API_KEY=
```

Current live integrations use the most direct supported providers:

- `HIBP_API_KEY` for Have I Been Pwned email breach lookups
- `DEHASHED_API_KEY` and `DEHASHED_EMAIL` for exposed-record lookups
- `HUNTER_API_KEY` for email verification risk context
- `VIRUSTOTAL_API_KEY` for domain reputation checks
- `URLSCAN_API_KEY` for historical scan context
- `SHODAN_API_KEY` for IP infrastructure exposure context

`INTELLIGENCEX_API_KEY` is wired into config for future provider expansion.

## Safety Scope

CyberGuard AI is for defensive analysis only.

- Scan only user-provided content
- Do not use it for tracking or offensive purposes
- Do not treat results as legal proof without independent verification

## Notes

- On Windows, temporary voice and file scans use the OS temp directory instead of a Unix `/tmp` path.
- Image location display is privacy-gated and only revealed on explicit user action.
- Live threat-intel results are cached with a shorter TTL than standard AI-only scans.
