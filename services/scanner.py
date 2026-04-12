import httpx

from config import SCAN_TIMEOUT


class ScannerService:
    def __init__(self, backend_url: str) -> None:
        self.backend_url = backend_url.rstrip("/")

    async def analyze_text(
        self,
        *,
        content: str,
        source: str,
        external_user_id: str | None,
    ) -> dict:
        endpoint = f"{self.backend_url}/v1/scan"
        payload = {
            "source": source,
            "content": content,
            "consent_confirmed": True,
            "external_user_id": external_user_id,
        }

        timeout = httpx.Timeout(SCAN_TIMEOUT)
        async with httpx.AsyncClient(timeout=timeout) as client:
            response = await client.post(endpoint, json=payload)

        if response.status_code >= 400:
            raise RuntimeError(
                f"Backend scan failed ({response.status_code}): {response.text[:200]}"
            )

        return response.json()
