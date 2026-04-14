from pathlib import Path


_HERE = Path(__file__).resolve().parent
_BOT_HANDLERS = _HERE.parents[1] / "cyberguard-telegram" / "handlers"

# Keep tests importable while allowing `import handlers.start` to resolve to bot handlers.
__path__ = [str(_HERE), str(_BOT_HANDLERS)]
