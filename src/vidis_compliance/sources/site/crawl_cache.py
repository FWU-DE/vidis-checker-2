"""Reuse a recent browser crawl of the same site.

Running checks one by one would otherwise crawl the same site again for every
call. A crawl is keyed by URL and page count and kept on disk with its
screenshots and screenshot reviews; jobs within ``max_age`` seconds get a copy.
"""

from __future__ import annotations

import hashlib
import json
import shutil
import time
import uuid
from dataclasses import asdict, fields
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from .crawl import PageCapture

DEFAULT_MAX_AGE_SECONDS = 30 * 60
# Entries older than this are deleted when a new crawl is stored.
PURGE_AFTER_SECONDS = 24 * 60 * 60

_FIELDS = [field.name for field in fields(PageCapture)]


def cache_key(url: str, pages: int) -> str:
    return hashlib.sha256(f"{url.strip()}|{pages}".encode()).hexdigest()[:32]


def _to_dict(capture: Any) -> dict[str, Any]:
    try:
        return asdict(capture)
    except TypeError:
        return {name: getattr(capture, name) for name in _FIELDS if hasattr(capture, name)}


def _from_dict(data: dict[str, Any]) -> PageCapture:
    return PageCapture(**{name: data[name] for name in _FIELDS if name in data})


def load(cache_root: Path, url: str, pages: int, max_age: int, outdir: Path) -> tuple[PageCapture, dict[str, Any]] | None:
    """Return a cached crawl copied into ``outdir``, or ``None``."""
    if max_age <= 0:
        return None
    entry = cache_root / cache_key(url, pages)
    try:
        meta = json.loads((entry / "meta.json").read_text(encoding="utf-8"))
        data = json.loads((entry / "capture.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    age = time.time() - float(meta.get("created", 0))
    if age > max_age or meta.get("url") != url or meta.get("pages") != pages:
        return None
    screenshot_dir = outdir / "screenshots"
    for shot in data.get("screenshots") or []:
        source = entry / "screenshots" / Path(str(shot.get("filename") or "")).name
        if source.is_file():
            screenshot_dir.mkdir(parents=True, exist_ok=True)
            target = screenshot_dir / source.name
            shutil.copy2(source, target)
            shot["path"] = str(target)
    info = {
        "cached": True,
        "crawled_at": meta.get("crawled_at"),
        "age_seconds": int(age),
        "max_age_seconds": max_age,
        "created": float(meta.get("created", 0)),
    }
    if isinstance(meta.get("vision_reviews"), list):
        info["vision_reviews"] = meta["vision_reviews"]
    return _from_dict(data), info


def store(
    cache_root: Path,
    url: str,
    pages: int,
    capture: Any,
    vision_reviews: list[dict] | None = None,
    created: float | None = None,
) -> None:
    """Keep this crawl for later jobs. Failures are ignored; the cache is an optimisation."""
    try:
        cache_root.mkdir(parents=True, exist_ok=True)
        _purge(cache_root)
        data = _to_dict(capture)
        tmp = cache_root / f".tmp-{uuid.uuid4().hex}"
        (tmp / "screenshots").mkdir(parents=True)
        for shot in data.get("screenshots") or []:
            source = Path(str(shot.get("path") or ""))
            if source.is_file():
                shutil.copy2(source, tmp / "screenshots" / source.name)
        (tmp / "capture.json").write_text(json.dumps(data, ensure_ascii=False, default=str), encoding="utf-8")
        meta = {
            "url": url,
            "pages": pages,
            "created": created or time.time(),
            "crawled_at": datetime.now(timezone.utc).isoformat(),
            "vision_reviews": vision_reviews,
        }
        (tmp / "meta.json").write_text(json.dumps(meta, ensure_ascii=False), encoding="utf-8")
        entry = cache_root / cache_key(url, pages)
        if entry.exists():
            shutil.rmtree(entry, ignore_errors=True)
        tmp.rename(entry)
    except OSError:
        return


def _purge(cache_root: Path) -> None:
    now = time.time()
    for entry in cache_root.iterdir():
        try:
            if now - entry.stat().st_mtime > PURGE_AFTER_SECONDS:
                shutil.rmtree(entry, ignore_errors=True)
        except OSError:
            continue


def cached_crawl(
    crawl_fn: Callable[..., Any],
    *,
    url: str,
    pages: int,
    outdir: Path,
    cache_root: Path,
    max_age: int,
) -> tuple[Any, dict[str, Any]]:
    """Crawl ``url`` or reuse a crawl younger than ``max_age`` seconds."""
    hit = load(cache_root, url, pages, max_age, outdir)
    if hit is not None:
        return hit
    try:
        capture = crawl_fn(url, pages=pages, headless=True, screenshot_dir=outdir / "screenshots")
    except TypeError as exc:
        if "screenshot_dir" not in str(exc):
            raise
        capture = crawl_fn(url, pages=pages, headless=True)
    return capture, {
        "cached": False,
        "crawled_at": datetime.now(timezone.utc).isoformat(),
        "max_age_seconds": max_age,
        "created": time.time(),
    }
