# CyberGuard AI Telegram Bot

CyberGuard AI is a defensive Telegram bot that analyzes suspicious phone numbers, URLs, files, images, and voice notes. This repository is ready for Railway.app deployment on a free stack.

[![Deploy on Railway](https://railway.app/button.svg)](https://railway.app/new)

## Required Environment Variables

| Variable | Required | Example |
|---|---|---|
| BOT_TOKEN | Yes | 123456:ABCDEF |
| ANTHROPIC_API_KEY | Yes | sk-ant-api03-xxxx |
| DATABASE_URL | Yes | postgresql://user:pass@host/db |
| REDIS_URL | Yes | redis://default:pass@host:6379 |
| ADMIN_IDS | Yes | 123456789,987654321 |
| BACKEND_URL | Yes | https://your-api.up.railway.app |
| ENVIRONMENT | Yes | production |

## Setup (Max 5 Steps)

1. Clone this repo and open the cyberguard-telegram folder.
2. Install Python dependencies from requirements.txt.
3. Create Railway project and set all required environment variables.
4. Add free PostgreSQL and Redis connection strings.
5. Deploy and verify bot startup logs show python main.py running.

## Railway CLI Commands (Exact)

# Install Railway CLI
npm i -g @railway/cli

# Login
railway login

# Create project
railway init

# Set environment variables
railway vars set BOT_TOKEN=xxx
railway vars set ANTHROPIC_API_KEY=xxx
railway vars set DATABASE_URL=xxx
railway vars set REDIS_URL=xxx

# Deploy
railway up

## Free Database Options

### PostgreSQL (Neon free tier)

- Provider: neon.tech
- Free tier: up to 3 GB storage
- Steps:
1. Create a Neon project and database.
2. Copy the pooled PostgreSQL connection string.
3. In Railway, set DATABASE_URL to the Neon URL.
4. Ensure sslmode=require is present if Neon requires SSL.

### Redis (Upstash free tier)

- Provider: upstash.com
- Free tier: 10k commands/day
- Steps:
1. Create an Upstash Redis database.
2. Copy the Redis URL.
3. In Railway, set REDIS_URL to the Upstash URL.
4. Redeploy after variables are saved.

## Connect Neon + Upstash to Railway

1. Open Railway project Settings and Variables.
2. Paste Neon URL as DATABASE_URL.
3. Paste Upstash URL as REDIS_URL.
4. Add remaining required bot variables.
5. Run railway up and monitor logs until worker is healthy.

## Screenshot Placeholder

![CyberGuard AI Telegram Bot Screenshot Placeholder](https://via.placeholder.com/1280x720.png?text=CyberGuard+AI+Telegram+Bot)
