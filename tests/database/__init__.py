from pathlib import Path


_HERE = Path(__file__).resolve().parent
_BOT_DATABASE = _HERE.parents[1] / "cyberguard-telegram" / "database"

# Keep tests importable while allowing `import database.models` to resolve to bot models.
__path__ = [str(_HERE), str(_BOT_DATABASE)]
