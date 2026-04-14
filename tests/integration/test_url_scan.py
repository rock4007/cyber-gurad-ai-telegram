from unittest.mock import AsyncMock

import pytest


@pytest.mark.asyncio
async def test_url_scan_returns_result(scanner_service):
    scanner_service._http_get_json = AsyncMock(return_value={})
    scanner_service._http_post_json = AsyncMock(return_value={"query_status": "no_results"})
    scanner_service.origin_intel.resolve = AsyncMock(return_value={"best_estimate": {"vpn_detected": False}})

    result = await scanner_service.scan_url("https://example.com", "user-2")

    assert result["scan_type"] == "url"
    assert "details" in result
