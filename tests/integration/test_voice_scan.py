from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest


@pytest.mark.asyncio
async def test_voice_scan_returns_parsed_payload(scanner_service, tmp_path):
    voice_path = tmp_path / "voice.ogg"
    voice_path.write_bytes(b"dummy audio")

    scanner_service.transcriber.transcribe_file = AsyncMock(return_value="urgent transfer now")

    chunk = SimpleNamespace(text='{"risk_level":"LOW","score":12,"summary":"ok","flags":["none"]}')
    response = SimpleNamespace(content=[chunk])
    scanner_service._claude = MagicMock()
    scanner_service._claude.messages = MagicMock()
    scanner_service._claude.messages.create = AsyncMock(return_value=response)

    result = await scanner_service.scan_voice(str(voice_path), "user-4")

    assert result["scan_type"] == "voice"
    assert result["risk_level"] == "LOW"
