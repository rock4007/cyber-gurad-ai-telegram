async def plans_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not update.message:
        return
    text = (
        "*CyberGuard AI Plans*\n\n"
        "🆓 *Free*: 5 scans/month\n\n"
        "💎 *Pro*: 500 scans/month - ₹999/mo\n\n"
        "🔥 *Full Plan*: 5000 scans/month + Darkweb intelligence, Malware analysis, Google scam research, IP/MAC geo trace - **₹499/mo** *NEW*\n\n"
        "🏢 *Enterprise*: Unlimited scans - Contact sales\n\n"
        "*Upgrade:* https://cyberguard.ai/pricing\n\n"
        "*Current status:* Use /status"
    )
