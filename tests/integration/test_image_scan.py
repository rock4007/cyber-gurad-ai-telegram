import pytest
from PIL import Image


@pytest.mark.asyncio
async def test_image_scan_returns_metadata(scanner_service, tmp_path):
    image_path = tmp_path / "sample.png"
    image = Image.new("RGB", (64, 64), color="red")
    image.save(image_path)

    result = await scanner_service.scan_image(str(image_path), "user-5")

    assert result["scan_type"] == "image"
    assert "exif" in result["details"]
