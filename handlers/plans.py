"""Subscription plans handler with payment links."""

from telegram import InlineKeyboardButton, InlineKeyboardMarkup, Update
from telegram.constants import ParseMode
from telegram.ext import Application, CallbackQueryHandler, CommandHandler, ContextTypes

from middleware.quota import _next_month_reset_text, quota_guard
from services.payment import MultiGatewayPayment, PaymentPlans


async def plans_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Display subscription plans with payment buttons."""
    if not update.effective_user or not update.message:
        return

    user_id = str(update.effective_user.id)
    
    keyboard = [
        [
            InlineKeyboardButton("🇮🇳 Pro - ₹999/mo", callback_data=f"pay_pro_inr_{user_id}"),
            InlineKeyboardButton("💎 Pro - $12/mo", callback_data=f"pay_pro_usd_{user_id}"),
        ],
        [
            InlineKeyboardButton("🔥 Master - ₹499/mo", callback_data=f"pay_full_inr_{user_id}"),
            InlineKeyboardButton("🌍 Master - $6/mo", callback_data=f"pay_full_usd_{user_id}"),
        ],
        [InlineKeyboardButton("🏢 Enterprise (Custom)", callback_data="enterprise_contact")],
        [InlineKeyboardButton("📊 My Status", callback_data="show_status")]
    ]
    reply_markup = InlineKeyboardMarkup(keyboard)
    
    text = (
        "*🤖 CyberGuard AI Subscription Plans (3DS Secure)*\n\n"
        f"🆓 *Free*: {PaymentPlans.FREE['limit']} scans/month\n\n"
        f"💎 *Pro*: {PaymentPlans.PRO['limit']} scans/month\n"
        f"  • Priority scans • Darkweb lookup\n"
        f"  *India*: ₹{PaymentPlans.PRO['price_inr']} | *Global*: ${PaymentPlans.PRO['price_usd']}\n\n"
        f"🔥 *Master* (Full): {PaymentPlans.FULL['limit']} scans/month\n"
        f"  • Agentic voice catch + deep scam cues\n"
        f"  • Agentic chat/social threat graph\n"
        f"  • IP/MAC/social advanced intel + all detection stack\n"
        f"  *India*: ₹{PaymentPlans.FULL['price_inr']} | *Global*: ${PaymentPlans.FULL['price_usd']}\n\n"
        f"🏢 *Enterprise*: Unlimited + Dedicated API + Custom\n\n"
        f"*✅ All payments 3DS Secure (Stripe + Razorpay)*\n"
        "*⚡ Instant activation after successful payment*\n\n"
        f"*Tap buttons to pay & upgrade instantly!* 🚀"
    )
    
    await update.message.reply_text(
        text, 
        reply_markup=reply_markup, 
        parse_mode=ParseMode.MARKDOWN
    )


async def payment_callback(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Handle payment button clicks and generate checkout links."""
    query = update.callback_query
    if not query:
        return
    
    await query.answer()
    
    data = query.data or ""
    if data.startswith('pay_'):
        parts = data.split('_', 2)
        plan = parts[1]
        currency = parts[2].split('-')[0]
        user_id = query.from_user.id if query.from_user else None
        
        if user_id:
            payment = MultiGatewayPayment(None)
            checkout_url = await payment.create_checkout_session(str(user_id), plan, currency)
            
            keyboard = [[InlineKeyboardButton("✅ Payment Success", callback_data="status")]]
            await query.edit_message_text(
                f"🔗 Payment Link for *{plan.title()}* ({currency.upper()}):\n{checkout_url}",
                reply_markup=InlineKeyboardMarkup(keyboard),
                parse_mode=ParseMode.MARKDOWN
            )
    elif data == 'enterprise_contact':
        await query.message.reply_text("🏢 *Enterprise Plans*\nContact: enterprise@cyberguard.ai")
    elif data == 'show_status':
        await show_status_callback(update, context)


async def show_status_callback(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Show user current plan/status."""
    query = update.callback_query
    if not query or not query.from_user:
        return
    
    await query.answer()
    
    user_id = query.from_user.id
    allowed, plan, used, limit = await quota_guard.check_and_increment(
        user_id=user_id, username=query.from_user.username, first_name=query.from_user.first_name
    )
    
    text = (
        f"*📊 Your Status*\n\n"
        f"Plan: *{plan.title()}*\n"
        f"Used: `{used}/{limit}` scans\n"
        f"Remaining: `{limit-used}`\n"
        f"Resets: {_next_month_reset_text()}"
    )
    
    keyboard = [[InlineKeyboardButton("💳 Upgrade", callback_data="plans")]]
    await query.edit_message_text(
        text,
        reply_markup=InlineKeyboardMarkup(keyboard),
        parse_mode=ParseMode.MARKDOWN
    )


def register_plans_handlers(application: Application) -> None:
    """Register all payment handlers."""

    application.add_handler(CommandHandler("plans", plans_command))
    application.add_handler(CallbackQueryHandler(payment_callback, pattern=r"^(pay_|enterprise_contact$|show_status$|status$)"))
    application.add_handler(CallbackQueryHandler(show_status_callback, pattern="^show_status$"))

