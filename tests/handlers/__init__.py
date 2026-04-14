from pathlib import Path

_HERE = Path(__file__).resolve().parent
# _HERE          = d:\telegram bot\cyberguard-telegram\tests\handlers
# parents[0]     = d:\telegram bot\cyberguard-telegram\tests
# parents[1]     = d:\telegram bot\cyberguard-telegram   ← bot root
_BOT_HANDLERS = _HERE.parents[1] / "handlers"

# Merge so `from handlers import investigate` finds the production module.
__path__ = [str(_HERE), str(_BOT_HANDLERS)]
