from anthropic import AsyncAnthropic


class ScannerService:
    def __init__(self, api_key: str) -> None:
        self.client = AsyncAnthropic(api_key=api_key)

    async def analyze_text(self, content: str) -> str:
        prompt = (
            "You are a defensive cybersecurity assistant. "
            "Analyze only user-provided content for fraud indicators and return concise prevention advice."
        )
        response = await self.client.messages.create(
            model="claude-3-haiku-20240307",
            max_tokens=300,
            temperature=0,
            system=prompt,
            messages=[{"role": "user", "content": content}],
        )
        return response.content[0].text if response.content else "No response"
