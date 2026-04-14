from pathlib import Path


_HERE = Path(__file__).resolve().parent
# _HERE          = d:\telegram bot\cyberguard-telegram\tests\database
# parents[0]     = d:\telegram bot\cyberguard-telegram\tests
# parents[1]     = d:\telegram bot\cyberguard-telegram   ← bot root
_BOT_DATABASE = _HERE.parents[1] / "database"

# Keep tests importable while allowing `import database.models` to resolve to bot models.
__path__ = [str(_HERE), str(_BOT_DATABASE)]
