"""Gemini on Google Vertex AI, used for optional screenshot reviews.

Configuration (all optional; without credentials the checker stays fully
deterministic):

- ``GOOGLE_SA_JSON``: service-account key as JSON text, or
  ``GOOGLE_APPLICATION_CREDENTIALS``: path to that file
- ``GOOGLE_CLOUD_PROJECT``: defaults to ``project_id`` from the key
- ``GOOGLE_CLOUD_LOCATION``: defaults to ``global``
- ``VIDIS_LLM_MODEL_FAST``: quick, cheap model (default ``gemini-3.8-flash``)
- ``VIDIS_LLM_MODEL_STRONG``: model for judgement tasks (default ``gemini-3.1-pro-preview``)
- ``VIDIS_LLM_DISABLED=1`` switches the model off even with credentials

Each task names a tier in ``TASK_TIERS``; if the strong model is unavailable
the call falls back to the fast one.
"""

from __future__ import annotations

import base64
import json
import os
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import httpx

DEFAULT_MODELS = {"fast": "gemini-3.8-flash", "strong": "gemini-3.1-pro-preview"}
# Which tier each task uses: judging screenshots needs the stronger model.
TASK_TIERS = {"screenshot_review": "strong", "default": "fast"}
SCOPE = "https://www.googleapis.com/auth/cloud-platform"
TIMEOUT_SECONDS = 60


class LlmError(RuntimeError):
    """The model call failed; callers fall back to manual review."""


@dataclass(frozen=True)
class LlmConfig:
    provider: str
    models: dict[str, str]
    project: str
    location: str
    service_account: dict[str, Any]

    def model_for(self, task: str) -> str:
        return self.models[TASK_TIERS.get(task, TASK_TIERS["default"])]

    def public(self) -> dict[str, Any]:
        """Status without secrets, for /health and /discovery."""
        return {
            "configured": True,
            "provider": self.provider,
            "location": self.location,
            "models": dict(self.models),
            "tasks": {task: self.model_for(task) for task in TASK_TIERS if task != "default"},
        }


def _truthy(name: str) -> bool:
    return os.environ.get(name, "").strip().lower() in {"1", "true", "yes", "on"}


def _service_account() -> dict[str, Any] | None:
    raw = os.environ.get("GOOGLE_SA_JSON", "").strip()
    if not raw:
        path = os.environ.get("GOOGLE_APPLICATION_CREDENTIALS", "").strip()
        if not path or not Path(path).is_file():
            return None
        raw = Path(path).read_text(encoding="utf-8")
    try:
        info = json.loads(raw)
    except json.JSONDecodeError:
        return None
    if not isinstance(info, dict) or info.get("type") != "service_account":
        return None
    return info


def load_config() -> LlmConfig | None:
    if _truthy("VIDIS_LLM_DISABLED"):
        return None
    info = _service_account()
    if info is None:
        return None
    project = os.environ.get("GOOGLE_CLOUD_PROJECT", "").strip() or str(info.get("project_id") or "")
    if not project:
        return None
    return LlmConfig(
        provider="vertex",
        models={
            tier: os.environ.get(f"VIDIS_LLM_MODEL_{tier.upper()}", "").strip() or default
            for tier, default in DEFAULT_MODELS.items()
        },
        project=project,
        location=os.environ.get("GOOGLE_CLOUD_LOCATION", "").strip() or "global",
        service_account=info,
    )


def llm_status() -> dict[str, Any]:
    config = load_config()
    if config is None:
        return {"configured": False, "disabled": _truthy("VIDIS_LLM_DISABLED")}
    return config.public()


_TOKEN_LOCK = threading.Lock()
_CREDENTIALS: dict[str, Any] = {}


def _access_token(config: LlmConfig) -> str:
    from google.auth.transport.requests import Request
    from google.oauth2 import service_account

    key = str(config.service_account.get("client_email") or "")
    with _TOKEN_LOCK:
        credentials = _CREDENTIALS.get(key)
        if credentials is None:
            credentials = service_account.Credentials.from_service_account_info(config.service_account, scopes=[SCOPE])
            _CREDENTIALS[key] = credentials
        if not credentials.valid:
            credentials.refresh(Request())
        return str(credentials.token)


def _endpoint(config: LlmConfig, model: str) -> str:
    host = "aiplatform.googleapis.com" if config.location == "global" else f"{config.location}-aiplatform.googleapis.com"
    return (
        f"https://{host}/v1/projects/{config.project}/locations/{config.location}"
        f"/publishers/google/models/{model}:generateContent"
    )


def generate_json(
    prompt: str,
    *,
    task: str = "default",
    image: bytes | None = None,
    image_mime: str = "image/png",
    config: LlmConfig | None = None,
    max_output_tokens: int = 2048,
) -> dict[str, Any]:
    """Ask the task's model for a JSON object; returns it with ``_model`` set.

    Raises ``LlmError`` on any failure.
    """
    config = config or load_config()
    if config is None:
        raise LlmError("LLM not configured")
    parts: list[dict[str, Any]] = [{"text": prompt}]
    if image is not None:
        parts.append({"inlineData": {"mimeType": image_mime, "data": base64.b64encode(image).decode("ascii")}})
    payload = {
        "contents": [{"role": "user", "parts": parts}],
        "generationConfig": {"temperature": 0, "maxOutputTokens": max_output_tokens, "responseMimeType": "application/json"},
    }
    model = config.model_for(task)
    response = _post(config, model, payload)
    if response.status_code == 404 and model != config.models["fast"]:
        model = config.models["fast"]
        response = _post(config, model, payload)
    if response.status_code != 200:
        raise LlmError(f"Vertex AI answered HTTP {response.status_code} for {model}")
    try:
        candidate = response.json()["candidates"][0]
        text = "".join(part.get("text", "") for part in candidate["content"]["parts"])
        data = json.loads(text)
    except (KeyError, IndexError, TypeError, ValueError) as exc:
        raise LlmError("Vertex AI returned no usable JSON") from exc
    if not isinstance(data, dict):
        raise LlmError("Vertex AI returned no JSON object")
    data["_model"] = model
    return data


def _post(config: LlmConfig, model: str, payload: dict[str, Any]) -> httpx.Response:
    try:
        token = _access_token(config)
        return httpx.post(
            _endpoint(config, model),
            headers={"Authorization": f"Bearer {token}"},
            json=payload,
            timeout=TIMEOUT_SECONDS,
        )
    except Exception as exc:  # network or auth failure
        raise LlmError(f"Vertex AI request failed: {type(exc).__name__}") from exc


PROBE_CACHE_SECONDS = 600
# A forced refresh still waits this long, so ?refresh=true cannot be used to run up costs.
PROBE_MIN_INTERVAL_SECONDS = 60
_PROBE_LOCK = threading.Lock()
_PROBE: dict[str, Any] = {}


def last_probe() -> dict[str, Any] | None:
    """The most recent model availability check, without starting a new one."""
    return dict(_PROBE) if _PROBE else None


def probe_models(force: bool = False) -> dict[str, Any] | None:
    """Check with a tiny request which configured models answer.

    Results are kept for ``PROBE_CACHE_SECONDS`` so a public status page cannot
    run up model costs. Returns ``None`` when no model is configured.
    """
    import time
    from datetime import datetime, timezone

    config = load_config()
    if config is None:
        return None
    with _PROBE_LOCK:
        age = time.time() - _PROBE["_checked"] if _PROBE else None
        limit = PROBE_MIN_INTERVAL_SECONDS if force else PROBE_CACHE_SECONDS
        if age is not None and age < limit and _PROBE.get("_models") == sorted(set(config.models.values())):
            return last_probe()
        payload = {
            "contents": [{"role": "user", "parts": [{"text": "Antworte nur mit: ok"}]}],
            "generationConfig": {"temperature": 0, "maxOutputTokens": 32},
        }
        models: dict[str, Any] = {}
        for model in sorted(set(config.models.values())):
            started = time.monotonic()
            try:
                response = _post(config, model, payload)
                ok = response.status_code == 200
                entry: dict[str, Any] = {"available": ok, "http_status": response.status_code}
            except LlmError as exc:
                entry = {"available": False, "error": str(exc)}
            entry["latency_ms"] = int((time.monotonic() - started) * 1000)
            entry["tiers"] = [tier for tier, name in config.models.items() if name == model]
            models[model] = entry
        _PROBE.clear()
        _PROBE.update(
            {
                "checked_at": datetime.now(timezone.utc).isoformat(),
                "cache_seconds": PROBE_CACHE_SECONDS,
                "models": models,
                "_checked": time.time(),
                "_models": sorted(models),
            }
        )
        return last_probe()


def public_probe(probe: dict[str, Any] | None) -> dict[str, Any] | None:
    if probe is None:
        return None
    return {key: value for key, value in probe.items() if not key.startswith("_")}
