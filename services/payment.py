"""Multi-gateway payment service with 3DS support."""
import stripe
from typing import Dict, Any, Optional
import razorpay
from dataclasses import dataclass
from datetime import timedelta, datetime
from cyberguard-telegram.database.models import User
from sqlalchemy.ext.asyncio import AsyncSession

@dataclass
class PaymentPlans:
    FREE: Dict[str, Any] = {
        'limit': 5,
        'features': ['Basic scans']
    }
    PRO: Dict[str, Any] = {
        'price_inr': 999,
        'price_usd': 12,
        'limit': 500,
        'features': ['Pro scans', 'Priority support']
    }
    ENTERPRISE: Dict[str, Any] = {
        'price_inr': 4999,
        'price_usd': 60,
        'limit': 999999,
        'features': ['Unlimited', 'API access', 'Darkweb intel']
    }

class MultiGatewayPayment:
    def __init__(self, session: AsyncSession):
        self.session = session
        stripe.api_key = 'sk_test_...'  # From config
        self.razorpay_client = razorpay.Client(
            auth=("rzp_test_...", "rzp_test_...")  # From config
        )

    async def create_checkout_session(self, user_id: str, plan: str, currency: str = 'inr') -> str:
        """Create Stripe Checkout or Razorpay order."""
        if currency == 'usd':
            return await self._stripe_checkout(user_id, plan)
        return await self._razorpay_order(user_id, plan)

    async def _stripe_checkout(self, user_id: str, plan: str) -> str:
        session = stripe.checkout.Session.create(
            payment_method_types=['card'],
            line_items=[{
                'price_data': {
                    'currency': 'usd',
                    'product_data': {'name': f'CyberGuard {plan.title()}'},
                    'unit_amount': PaymentPlans[plan.upper()]['price_usd'] * 100,
                },
                'quantity': 1,
            }],
            mode='subscription',
            success_url='https://cyberguard.ai/success?session_id={CHECKOUT_SESSION_ID}',
            cancel_url='https://cyberguard.ai/pricing',
            metadata={'user_id': user_id, 'plan': plan}
        )
        return session.url

    async def _razorpay_order(self, user_id: str, plan: str) -> str:
        """Razorpay 3DS order (India)."""
        order_data = {
            'amount': PaymentPlans[plan.upper()]['price_inr'] * 100,  # paise
            'currency': 'INR',
            'receipt': f'cyberguard_{user_id}_{plan}',
            'notes': {'user_id': user_id, 'plan': plan}
        }
        order = self.razorpay_client.order.create(data=order_data)
        return f"https://rzp.io/i/{order['id']}"  # Mobile SDK URL

    async def handle_webhook(self, payload: Dict[str, Any], signature: str) -> None:
        """Process Stripe/Razorpay webhooks."""
        if 'stripe' in payload.get('source', ''):
            await self._stripe_webhook(payload, signature)
        # Razorpay webhook logic

    async def _stripe_webhook(self, payload: Dict[str, Any], signature: str) -> None:
        stripe.Webhook.construct_event(
            payload, signature, 'whsec_...'  # From config
        )
        if payload['type'] == 'checkout.session.completed':
            session = payload['data']['object']
            user_id = session['metadata']['user_id']
            plan = session['metadata']['plan']
            await self._upgrade_user(user_id, plan, session['id'])

    async def _upgrade_user(self, user_id: str, plan: str, sub_id: str) -> None:
        """Update user subscription."""
        async with self.session.begin():
            user = await self.session.get(User, user_id)
            if user:
                user.plan = plan
                user.subscription_id = sub_id
                user.scans_used = 0
                user.scans_limit = PaymentPlans[plan.upper()]['limit']
                user.expiry_date = datetime.now(timezone.utc) + timedelta(days=30)
                # Log subscription


payment_service = MultiGatewayPayment(None)  # Session injected

