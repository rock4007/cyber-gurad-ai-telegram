import os
from pathlib import Path

import httpx


class WhisperTranscriptionService:
    def __init__(self) -> None:
        self.api_key = os.getenv("WHISPER_API_KEY", "").strip() or os.getenv("OPENAI_API_KEY", "").strip()
        self.api_url = os.getenv("WHISPER_API_URL", "https://api.openai.com/v1/audio/transcriptions").strip()
        self.model = os.getenv("WHISPER_MODEL", "whisper-1").strip() or "whisper-1"

    @property
    def configured(self) -> bool:
        return bool(self.api_key)

    async def transcribe_file(self, file_path: str, *, mime_type: str) -> str:
        if not self.configured:
            raise RuntimeError(
                "Whisper transcription is not configured. Set WHISPER_API_KEY or OPENAI_API_KEY."
            )

        filename = Path(file_path).name
        headers = {
            "Authorization": f"Bearer {self.api_key}",
        }

        with open(file_path, "rb") as file_handle:
            files = {
                "file": (filename, file_handle, mime_type or "application/octet-stream"),
            }
            data = {
                "model": self.model,
                "response_format": "json",
            }

            async with httpx.AsyncClient(timeout=90.0) as client:
                response = await client.post(self.api_url, headers=headers, data=data, files=files)

        if response.status_code >= 400:
            raise RuntimeError(
                f"Whisper transcription failed ({response.status_code}): {response.text[:200]}"
            )

        payload = response.json()
        transcript = str(payload.get("text", "")).strip()
        if not transcript:
            raise RuntimeError("Whisper returned an empty transcript.")
        return transcript