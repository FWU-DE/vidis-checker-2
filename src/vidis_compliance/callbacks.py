"""Notify a caller-supplied URL when a job has finished.

The request is a JSON ``POST`` with a summary and links, never the full
result: the receiver fetches details with its API key. With a
``callback_secret`` the body is signed:

    X-VIDIS-Signature: sha256=<hex HMAC-SHA256 of "<timestamp>.<body>">
    X-VIDIS-Timestamp: <unix seconds>

Delivery runs in its own small thread pool, retries up to four times with
backoff, never follows redirects and re-checks right before each attempt that
the target is still a public address.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import time
import uuid
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from typing import Any, Callable

import httpx

EVENT = "job.finished"
TIMEOUT_SECONDS = 10
RETRY_DELAYS_SECONDS = (0, 5, 30, 120)
USER_AGENT = "vidis-compliance-callback/1"

_EXECUTOR = ThreadPoolExecutor(max_workers=2, thread_name_prefix="vidis-callback")


def sign(secret: str, timestamp: str, body: bytes) -> str:
    digest = hmac.new(secret.encode("utf-8"), timestamp.encode("ascii") + b"." + body, hashlib.sha256).hexdigest()
    return f"sha256={digest}"


def build_payload(metadata: Any, base_url: str) -> dict[str, Any]:
    job_id = metadata.id
    counts: Counter[str] = Counter()
    if metadata.result is not None:
        counts.update(finding.status for finding in metadata.result.findings)
    base = base_url.rstrip("/")
    return {
        "event": EVENT,
        "job_id": job_id,
        "status": metadata.status,
        "error": metadata.error,
        "finished_at": metadata.updated_at,
        "checks": list(metadata.request.checks),
        "target_url": str(metadata.request.target_url) if metadata.request.target_url else None,
        "summary": {"findings": sum(counts.values()), **{status: counts.get(status, 0) for status in ("PASS", "FAIL", "MANUELL")}},
        "links": {
            "job": f"{base}/jobs/{job_id}",
            "reports": f"{base}/jobs/{job_id}/reports",
            "archive": f"{base}/jobs/{job_id}/archive.zip",
        },
    }


def deliver(
    url: str,
    payload: dict[str, Any],
    *,
    secret: str | None,
    check_target: Callable[[str], None],
    sleep: Callable[[float], None] = time.sleep,
    post: Callable[..., httpx.Response] | None = None,
) -> dict[str, Any]:
    """Send the payload; returns the delivery record kept in job.json."""
    post = post or httpx.post
    body = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    delivery_id = uuid.uuid4().hex
    record: dict[str, Any] = {"url": url, "delivered": False, "attempts": 0, "delivery_id": delivery_id, "signed": bool(secret)}
    for delay in RETRY_DELAYS_SECONDS:
        if delay:
            sleep(delay)
        record["attempts"] += 1
        timestamp = str(int(time.time()))
        headers = {
            "Content-Type": "application/json; charset=utf-8",
            "User-Agent": USER_AGENT,
            "X-VIDIS-Event": EVENT,
            "X-VIDIS-Delivery": delivery_id,
            "X-VIDIS-Timestamp": timestamp,
        }
        if secret:
            headers["X-VIDIS-Signature"] = sign(secret, timestamp, body)
        try:
            check_target(url)
            response = post(url, content=body, headers=headers, timeout=TIMEOUT_SECONDS, follow_redirects=False)
        except ValueError as exc:  # target no longer public: do not retry
            record["last_error"] = str(exc)
            break
        except httpx.HTTPError as exc:
            record["last_error"] = type(exc).__name__
            continue
        record["last_status"] = response.status_code
        if 200 <= response.status_code < 300:
            record["delivered"] = True
            record["delivered_at"] = datetime.now(timezone.utc).isoformat()
            record.pop("last_error", None)
            break
        record["last_error"] = f"HTTP {response.status_code}"
        if 400 <= response.status_code < 500 and response.status_code not in (408, 429):
            break  # the receiver rejects it; retrying will not help
    return record


def submit(fn: Callable[[], None]) -> None:
    _EXECUTOR.submit(fn)
