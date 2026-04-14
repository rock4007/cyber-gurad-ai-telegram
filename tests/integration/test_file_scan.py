from unittest.mock import AsyncMock

import pytest


@pytest.mark.asyncio
async def test_file_scan_returns_hashes(scanner_service, tmp_path, mock_virustotal_api):
    file_path = tmp_path / "sample.txt"
    file_path.write_text("hello world", encoding="utf-8")

    scanner_service._http_get_json = AsyncMock(return_value=mock_virustotal_api)

    result = await scanner_service.scan_file(str(file_path), "user-3")

    assert result["scan_type"] == "file"
    assert "md5" in result["details"]
    assert "sha256" in result["details"]
