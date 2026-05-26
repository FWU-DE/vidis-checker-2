from __future__ import annotations

import random
from collections import deque
from dataclasses import dataclass, field
from html.parser import HTMLParser
from typing import Callable, Dict, Iterable, List, Sequence
from urllib.parse import urldefrag, urljoin, urlparse

from playwright.sync_api import BrowserContext, Page, sync_playwright

JS_LOCAL = """
() => {
  const items = {};
  for (let i = 0; i < localStorage.length; i++) {
    const key = localStorage.key(i);
    items[key] = localStorage.getItem(key);
  }
  return items;
}
""".strip()

JS_SESSION = """
() => {
  const items = {};
  for (let i = 0; i < sessionStorage.length; i++) {
    const key = sessionStorage.key(i);
    items[key] = sessionStorage.getItem(key);
  }
  return items;
}
""".strip()

JS_RESOURCES = """
() => {
  const resources = [];
  const elements = document.querySelectorAll('img, iframe, script, object, embed');
  elements.forEach(el => {
    let src = el.src || el.data;
    if (src) {
      resources.push({
        type: el.tagName.toLowerCase(),
        url: src,
        id: el.id || null,
        className: el.className || null
      });
    }
  });
  return resources;
}
""".strip()

JS_LINKS = """
() => Array.from(document.querySelectorAll('a[href]')).map(a => a.getAttribute('href'))
""".strip()

ConsentHook = Callable[[Page], None]


class _LinkParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.hrefs: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag.lower() != "a":
            return
        for name, value in attrs:
            if name.lower() == "href" and value is not None:
                self.hrefs.append(value)


def _normalize_url(url: str) -> str:
    normalized = url.strip()
    if not normalized.lower().startswith(("http://", "https://")):
        normalized = "https://" + normalized
    return normalized


@dataclass
class PageCapture:
    url: str
    cookies: List[dict]
    local_storage: Dict[str, str]
    session_storage: Dict[str, str]
    scripts: List[str]
    requests: List[str]
    visited_urls: List[str] = field(default_factory=list)


def _clean_internal_url(base_url: str, href: str | None) -> str | None:
    if not href:
        return None
    href = href.strip()
    if not href:
        return None
    parsed_href = urlparse(href)
    if parsed_href.scheme in {"mailto", "tel", "javascript", "data"}:
        return None

    absolute, _fragment = urldefrag(urljoin(base_url, href))
    parsed_base = urlparse(base_url)
    parsed_absolute = urlparse(absolute)
    if parsed_absolute.scheme not in {"http", "https"}:
        return None
    if parsed_absolute.netloc != parsed_base.netloc:
        return None
    return absolute


def discover_internal_links(
    base_url: str, html: str, limit: int | None = None
) -> List[str]:
    """Return deterministic same-origin links discovered in HTML."""
    parser = _LinkParser()
    parser.feed(html)
    links = {
        url
        for url in (
            _clean_internal_url(base_url, href)
            for href in parser.hrefs
        )
        if url is not None
    }
    ordered = sorted(links)
    return ordered if limit is None else ordered[: max(limit, 0)]


def _dedupe_sorted(values: Iterable[str]) -> List[str]:
    return sorted({value for value in values if value})


def _cookie_key(cookie: dict) -> tuple[str, str, str, str]:
    return (
        str(cookie.get("domain") or ""),
        str(cookie.get("path") or ""),
        str(cookie.get("name") or ""),
        str(cookie.get("value") or ""),
    )


def aggregate_captures(captures: Sequence[PageCapture]) -> PageCapture:
    """Aggregate page captures into one deterministic, de-duplicated result."""
    if not captures:
        return PageCapture(
            url="",
            cookies=[],
            local_storage={},
            session_storage={},
            scripts=[],
            requests=[],
            visited_urls=[],
        )

    cookies_by_key: dict[tuple[str, str, str, str], dict] = {}
    local_storage: Dict[str, str] = {}
    session_storage: Dict[str, str] = {}
    scripts: list[str] = []
    requests: list[str] = []
    visited_urls: list[str] = []

    for capture in captures:
        visited_urls.append(capture.url)
        for cookie in capture.cookies:
            cookies_by_key[_cookie_key(cookie)] = cookie
        local_storage.update(capture.local_storage)
        session_storage.update(capture.session_storage)
        scripts.extend(capture.scripts)
        requests.extend(capture.requests)

    return PageCapture(
        url=captures[0].url,
        cookies=[cookies_by_key[key] for key in sorted(cookies_by_key)],
        local_storage=dict(sorted(local_storage.items())),
        session_storage=dict(sorted(session_storage.items())),
        scripts=_dedupe_sorted(scripts),
        requests=_dedupe_sorted(requests),
        visited_urls=list(dict.fromkeys(visited_urls)),
    )


def _default_consent_hook(page: Page) -> None:
    selectors = [
        "button:has-text('Alle akzeptieren')",
        "button:has-text('Akzeptieren')",
        "button:has-text('Accept all')",
        "button:has-text('Accept')",
        "[aria-label*='accept' i]",
        "[aria-label*='akzept' i]",
    ]
    for selector in selectors:
        try:
            locator = page.locator(selector).first
            if locator.count() > 0 and locator.is_visible(timeout=500):
                locator.click(timeout=1000)
                page.wait_for_load_state("networkidle", timeout=3000)
                return
        except Exception:
            continue


def _capture_page(
    page: Page,
    context: BrowserContext,
    url: str,
    requests: list[str],
    consent_hook: ConsentHook | None = None,
    request_start: int = 0,
) -> PageCapture:
    page.goto(url, wait_until="load", timeout=30000)
    try:
        page.wait_for_load_state("networkidle", timeout=5000)
    except Exception:
        pass
    if consent_hook is not None:
        consent_hook(page)

    cookies = context.cookies()
    local_storage = page.evaluate(JS_LOCAL)
    session_storage = page.evaluate(JS_SESSION)
    resources = page.evaluate(JS_RESOURCES)
    scripts = [r["url"] for r in resources if r.get("type") == "script"]
    return PageCapture(
        url=page.url,
        cookies=cookies,
        local_storage=local_storage,
        session_storage=session_storage,
        scripts=scripts,
        requests=list(requests[request_start:]),
    )


def _discover_from_page(page: Page, limit: int | None = None) -> List[str]:
    html_links = discover_internal_links(page.url, page.content(), limit=None)
    try:
        dom_links = {
            url
            for url in (
                _clean_internal_url(page.url, href) for href in page.evaluate(JS_LINKS)
            )
            if url is not None
        }
    except Exception:
        dom_links = set()
    ordered = sorted(set(html_links) | dom_links)
    return ordered if limit is None else ordered[: max(limit, 0)]


def crawl(
    url: str,
    pages: int = 5,
    headless: bool = True,
    seed: int = 0,
    consent_hook: ConsentHook | None = None,
) -> PageCapture:
    """Crawl up to ``pages`` same-origin pages and aggregate browser signals.

    ``seed`` deterministically shuffles newly discovered links while preserving
    repeatable test runs. ``consent_hook`` lets callers inject site-specific
    consent handling; if omitted, a conservative built-in accept hook is tried.
    """
    max_pages = max(1, pages)
    start_url = _normalize_url(url)
    rng = random.Random(seed)
    hook = consent_hook or _default_consent_hook

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=headless)
        context = browser.new_context()
        page = context.new_page()
        request_log: List[str] = []
        page.on("requestfinished", lambda req: request_log.append(req.url))

        captures: list[PageCapture] = []
        queue: deque[str] = deque([start_url])
        seen: set[str] = set()

        try:
            while queue and len(captures) < max_pages:
                current_url = queue.popleft()
                if current_url in seen:
                    continue
                seen.add(current_url)

                request_start = len(request_log)
                capture = _capture_page(
                    page,
                    context,
                    current_url,
                    requests=request_log,
                    consent_hook=hook,
                    request_start=request_start,
                )
                captures.append(capture)

                remaining = max_pages - len(captures)
                if remaining <= 0:
                    continue
                links = [
                    link
                    for link in _discover_from_page(page)
                    if link not in seen and link not in queue
                ]
                rng.shuffle(links)
                queue.extend(links[:remaining])
        finally:
            context.close()
            browser.close()

    return aggregate_captures(captures)

