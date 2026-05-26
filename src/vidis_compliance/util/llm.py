import os
import httpx
from typing import Iterable, Optional

# Hermes local API server (OpenAI-compatible)
HERMES_BASE = os.getenv("HERMES_API_BASE", "http://127.0.0.1:8642/v1")
HERMES_MODEL = os.getenv("HERMES_MODEL", "auto")
HERMES_KEY = os.getenv("HERMES_API_KEY", "")

_headers = {"Content-Type": "application/json"}
if HERMES_KEY:
    _headers["Authorization"] = f"Bearer {HERMES_KEY}"


def chat(messages: Iterable[dict], temperature: float = 0.0, max_tokens: Optional[int] = None) -> str:
    url = f"{HERMES_BASE}/chat/completions"
    payload = {
        "model": HERMES_MODEL,
        "messages": list(messages),
        "temperature": temperature,
        "stream": False,
    }
    if max_tokens is not None:
        payload["max_tokens"] = max_tokens
    with httpx.Client(timeout=60) as client:
        resp = client.post(url, headers=_headers, json=payload)
        resp.raise_for_status()
        data = resp.json()
    return data["choices"][0]["message"]["content"].strip()
