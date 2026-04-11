def is_defensive_request(text: str) -> bool:
    lower_text = text.lower()
    blocked_terms = ["hack", "exploit", "malware", "phishing kit"]
    return not any(term in lower_text for term in blocked_terms)
