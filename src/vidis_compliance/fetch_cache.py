"""Reuse recent plain HTTP fetches (legal pages, AGB, privacy policy, AVV).

A test suite calling checks one by one would otherwise download the same
documents and legal pages again for every call. While a cache is active
(``with active(cache):``), ``net.safe_get`` serves successful responses
younger than ``max_age`` seconds from disk and stores new ones. Parallel jobs
fetching the same URL wait for each other, so it is downloaded once.

Only 2xx responses are kept; errors are always fetched again. The cache is
shared by all callers like the crawl cache: it only holds public web content.
"""

from __future__ import annotations

import hashlib
import json
import threading
import time
import uuid
from contextlib import contextmanager
from contextvars import ContextVar
from pathlib import Path
from typing import Callable, Iterator

DEFAULT_MAX_AGE_SECONDS = 30 * 60
# Directory inside the crawl cache.
SUBDIR = "fetch"
PURGE_AFTER_SECONDS = 24 * 60 * 60

_ACTIVE: ContextVar["FetchCache | None"] = ContextVar("vidis_fetch_cache", default=None)
_LOCKS: dict[str, threading.Lock] = {}
_LOCKS_GUARD = threading.Lock()


class FetchCache:
    def __init__(self, root: Path, max_age: int = DEFAULT_MAX_AGE_SECONDS) -> None:
        self.root = Path(root)
        self.max_age = max_age
        self.hits = 0
        self.misses = 0
        self._purged = False

    def stats(self) -> dict:
        return {"hits": self.hits, "fetched": self.misses, "max_age_seconds": self.max_age}

    def _key(self, url: str, headers: dict[str, str] | None) -> str:
        extra = json.dumps(sorted((headers or {}).items()))
        return hashlib.sha256(f"{url.strip()}|{extra}".encode()).hexdigest()[:32]

    def get(self, url: str, headers: dict[str, str] | None, max_bytes: int, fetch: Callable):
        """Return a cached response for ``url`` or call ``fetch()`` and keep a 2xx result."""
        if self.max_age <= 0:
            self.misses += 1
            response = fetch()
            if 200 <= response.status_code < 300:
                self._store(self._key(url, headers), url, response)
            return response
        key = self._key(url, headers)
        with _lock(f"{self.root}:{key}"):
            hit = self._load(key, url, max_bytes)
            if hit is not None:
                self.hits += 1
                return hit
            self.misses += 1
            response = fetch()
            if 200 <= response.status_code < 300:
                self._store(key, url, response)
            return response

    def _load(self, key: str, url: str, max_bytes: int):
        from .net import SafeResponse
        import httpx

        try:
            meta = json.loads((self.root / f"{key}.json").read_text(encoding="utf-8"))
            if meta.get("request_url") != url or time.time() - float(meta.get("created", 0)) > self.max_age:
                return None
            content = (self.root / f"{key}.body").read_bytes()
        except (OSError, ValueError):
            return None
        if len(content) > max_bytes:
            return None
        headers = httpx.Headers({"content-type": meta["content_type"]} if meta.get("content_type") else {})
        return SafeResponse(url=meta.get("url") or url, status_code=int(meta.get("status_code", 200)), headers=headers, content=content)

    def _store(self, key: str, url: str, response) -> None:
        """Best effort: the cache is an optimisation, failures are ignored."""
        try:
            self.root.mkdir(parents=True, exist_ok=True)
            self._purge()
            tmp = uuid.uuid4().hex
            body_tmp = self.root / f".{tmp}.body"
            meta_tmp = self.root / f".{tmp}.json"
            body_tmp.write_bytes(response.content)
            meta = {
                "request_url": url,
                "url": response.url,
                "status_code": response.status_code,
                "content_type": response.headers.get("content-type", ""),
                "created": time.time(),
            }
            meta_tmp.write_text(json.dumps(meta), encoding="utf-8")
            body_tmp.replace(self.root / f"{key}.body")
            meta_tmp.replace(self.root / f"{key}.json")
        except OSError:
            return

    def _purge(self) -> None:
        if self._purged:
            return
        self._purged = True
        now = time.time()
        for entry in self.root.iterdir():
            try:
                if entry.is_file() and now - entry.stat().st_mtime > PURGE_AFTER_SECONDS:
                    entry.unlink()
            except OSError:
                continue


def _lock(name: str) -> threading.Lock:
    with _LOCKS_GUARD:
        return _LOCKS.setdefault(name, threading.Lock())


def current() -> FetchCache | None:
    return _ACTIVE.get()


@contextmanager
def active(cache: FetchCache | None) -> Iterator[FetchCache | None]:
    token = _ACTIVE.set(cache)
    try:
        yield cache
    finally:
        _ACTIVE.reset(token)
