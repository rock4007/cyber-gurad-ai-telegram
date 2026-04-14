from unittest.mock import AsyncMock

import pytest


@pytest.mark.asyncio
async def test_phone_scan_returns_result(scanner_service):
    scanner_service._http_get_json = AsyncMock(return_value=None)
    scanner_service.origin_intel.resolve = AsyncMock(return_value={"best_estimate": {}})

    result = await scanner_service.scan_phone("+14155552671", "user-1")

    assert result["scan_type"] == "phone"
    assert "risk_level" in result
    assert "score" in result
