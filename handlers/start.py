from telegram import Update
from telegram.ext import ContextTypes


async def start_handler(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Handle the /start command and greet the user."""
    user = update.effective_user
    welcome_message = (
        f"👋 Hello, {user.first_name}!\n\n"
        "🛡️ *Welcome to CyberGuard AI*\n\n"
        "I can help you stay safe online. Send me:\n"
        "• 🔗 A URL to check for phishing or malware\n"
        "• 📞 A phone number to verify\n"
        "• 📄 A file to scan\n"
        "• 🎤 A voice message to analyse\n"
        "• 🖼️ An image to inspect\n\n"
        "Stay safe! 🔒"
    )
    await update.message.reply_text(welcome_message, parse_mode="Markdown")
