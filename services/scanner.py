import hashlib
import anthropic

from config import ANTHROPIC_API_KEY

_anthropic_client = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)


async def scan_url(url: str) -> dict:
    """Analyse a URL for phishing or malware using Anthropic Claude."""
    prompt = (
        f"Analyse the following URL for potential security threats such as phishing, "
        f"malware distribution, or scam activity. URL: {url}\n\n"
        "Respond with a JSON object containing:\n"
        "- risk_level: one of 'safe', 'suspicious', 'dangerous'\n"
        "- summary: a brief explanation (2-3 sentences)\n"
        "- indicators: a list of observed threat indicators (empty list if none)"
    )
    message = _anthropic_client.messages.create(
        model="claude-3-opus-20240229",
        max_tokens=512,
        messages=[{"role": "user", "content": prompt}],
    )
    return {"url": url, "raw_response": message.content[0].text}


async def scan_phone(phone_number: str, is_valid: bool) -> dict:
    """Analyse a phone number for potential fraud or spam."""
    prompt = (
        f"Analyse the following phone number for potential fraud, spam, or scam activity.\n"
        f"Phone number: {phone_number}\n"
        f"Is valid number format: {is_valid}\n\n"
        "Respond with a JSON object containing:\n"
        "- risk_level: one of 'safe', 'suspicious', 'dangerous'\n"
        "- summary: a brief explanation (2-3 sentences)\n"
        "- indicators: a list of observed threat indicators (empty list if none)"
    )
    message = _anthropic_client.messages.create(
        model="claude-3-opus-20240229",
        max_tokens=512,
        messages=[{"role": "user", "content": prompt}],
    )
    return {"phone_number": phone_number, "is_valid": is_valid, "raw_response": message.content[0].text}


async def scan_file(file_path: str, file_name: str, mime_type: str) -> dict:
    """Analyse a file for malware or suspicious content."""
    with open(file_path, "rb") as f:
        file_hash = hashlib.sha256(f.read()).hexdigest()

    prompt = (
        f"A user uploaded a file for security analysis.\n"
        f"File name: {file_name}\n"
        f"MIME type: {mime_type}\n"
        f"SHA-256 hash: {file_hash}\n\n"
        "Based on the file metadata, assess the potential security risk.\n"
        "Respond with a JSON object containing:\n"
        "- risk_level: one of 'safe', 'suspicious', 'dangerous'\n"
        "- summary: a brief explanation (2-3 sentences)\n"
        "- indicators: a list of observed threat indicators (empty list if none)"
    )
    message = _anthropic_client.messages.create(
        model="claude-3-opus-20240229",
        max_tokens=512,
        messages=[{"role": "user", "content": prompt}],
    )
    return {
        "file_name": file_name,
        "mime_type": mime_type,
        "sha256": file_hash,
        "raw_response": message.content[0].text,
    }


async def scan_voice(file_path: str, duration: int) -> dict:
    """Analyse a voice message for suspicious content."""
    prompt = (
        f"A user sent a voice message of {duration} seconds for security analysis.\n"
        "Assess whether this voice message could be part of a social engineering or scam attempt.\n"
        "Respond with a JSON object containing:\n"
        "- risk_level: one of 'safe', 'suspicious', 'dangerous'\n"
        "- summary: a brief explanation (2-3 sentences)\n"
        "- indicators: a list of observed threat indicators (empty list if none)"
    )
    message = _anthropic_client.messages.create(
        model="claude-3-opus-20240229",
        max_tokens=512,
        messages=[{"role": "user", "content": prompt}],
    )
    return {"duration": duration, "raw_response": message.content[0].text}


async def scan_image(file_path: str) -> dict:
    """Analyse an image for suspicious or malicious content."""
    import base64

    with open(file_path, "rb") as f:
        image_data = base64.standard_b64encode(f.read()).decode("utf-8")

    message = _anthropic_client.messages.create(
        model="claude-3-opus-20240229",
        max_tokens=512,
        messages=[
            {
                "role": "user",
                "content": [
                    {
                        "type": "image",
                        "source": {
                            "type": "base64",
                            "media_type": "image/jpeg",
                            "data": image_data,
                        },
                    },
                    {
                        "type": "text",
                        "text": (
                            "Analyse this image for potential security threats such as QR codes "
                            "leading to malicious URLs, phishing content, or social engineering material.\n"
                            "Respond with a JSON object containing:\n"
                            "- risk_level: one of 'safe', 'suspicious', 'dangerous'\n"
                            "- summary: a brief explanation (2-3 sentences)\n"
                            "- indicators: a list of observed threat indicators (empty list if none)"
                        ),
                    },
                ],
            }
        ],
    )
    return {"raw_response": message.content[0].text}
