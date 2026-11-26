from __future__ import annotations

import random
from collections import deque
from dataclasses import dataclass, field
from html.parser import HTMLParser
from pathlib import Path
from typing import Callable, Dict, Iterable, List, Sequence
from urllib.parse import parse_qsl, urlencode, urldefrag, urljoin, urlparse, urlunparse

from playwright.sync_api import BrowserContext, Page, ViewportSize, sync_playwright

from ...net import BrowserGuard, guard_browser_context

# Match the PDF screenshot appendix slot closely: wide enough for readable text,
# tall enough to fill one A4 page without excessive downscaling or side margins.
SCREENSHOT_VIEWPORT = ViewportSize(width=1900, height=2100)

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

JS_RESOURCES = r"""
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
        className: el.className || null,
        selector: el.id ? `${el.tagName.toLowerCase()}#${el.id}` : (el.className ? `${el.tagName.toLowerCase()}.${String(el.className).trim().split(/\s+/).join('.')}` : el.tagName.toLowerCase())
      });
    }
  });
  return resources;
}
""".strip()

JS_LINKS = """
() => Array.from(document.querySelectorAll('a[href]')).map(a => a.getAttribute('href'))
""".strip()

JS_LINK_DETAILS = r"""
() => Array.from(document.querySelectorAll('a[href]')).map(a => ({
  url: a.href,
  text: (a.innerText || a.textContent || '').trim().replace(/\s+/g, ' ').slice(0, 180),
  selector: a.id ? `a#${a.id}` : (a.className ? `a.${String(a.className).trim().split(/\s+/).join('.')}` : 'a')
}))
""".strip()

JS_VISIBLE_TEXT = r"""
() => {
  const text = (document.body && document.body.innerText ? document.body.innerText : '').replace(/\s+/g, ' ').trim();
  if (!text) return [];
  const snippets = [];
  for (let i = 0; i < text.length && snippets.length < 20; i += 220) {
    snippets.push(text.slice(i, i + 220));
  }
  return snippets;
}
""".strip()

JS_BROWSER_SIGNAL_INSTALL = """
(() => {
  if (window.__vidisSignals) return;
  const counts = {fingerprinting: {}, device_storage: {}};
  window.__vidisSignals = counts;
  const bump = (group, api) => { counts[group][api] = (counts[group][api] || 0) + 1; };
  const wrapMethod = (target, name, group, api) => {
    try {
      if (!target || typeof target[name] !== 'function') return;
      const original = target[name];
      if (original.__vidisWrapped) return;
      const wrapped = function(...args) { bump(group, api); return original.apply(this, args); };
      wrapped.__vidisWrapped = true;
      target[name] = wrapped;
    } catch (_) {}
  };
  wrapMethod(window.HTMLCanvasElement && HTMLCanvasElement.prototype, 'toDataURL', 'fingerprinting', 'canvas.toDataURL');
  wrapMethod(window.HTMLCanvasElement && HTMLCanvasElement.prototype, 'getContext', 'fingerprinting', 'canvas.getContext');
  if (window.WebGLRenderingContext) wrapMethod(WebGLRenderingContext.prototype, 'getParameter', 'fingerprinting', 'WebGLRenderingContext.getParameter');
  if (window.AudioContext) wrapMethod(AudioContext.prototype, 'createOscillator', 'fingerprinting', 'AudioContext.createOscillator');
  if (navigator.mediaDevices) wrapMethod(navigator.mediaDevices, 'enumerateDevices', 'fingerprinting', 'navigator.mediaDevices.enumerateDevices');
  if (navigator.userAgentData) wrapMethod(navigator.userAgentData, 'getHighEntropyValues', 'fingerprinting', 'navigator.userAgentData.getHighEntropyValues');
  for (const prop of ['hardwareConcurrency', 'deviceMemory', 'platform', 'plugins', 'languages']) {
    try {
      const proto = Object.getPrototypeOf(navigator);
      const desc = Object.getOwnPropertyDescriptor(proto, prop);
      if (desc && desc.get && !desc.get.__vidisWrapped) {
        const original = desc.get;
        const wrapped = function() { bump('fingerprinting', `navigator.${prop}`); return original.call(this); };
        wrapped.__vidisWrapped = true;
        Object.defineProperty(proto, prop, {...desc, get: wrapped});
      }
    } catch (_) {}
  }
  if (window.indexedDB) wrapMethod(indexedDB, 'open', 'device_storage', 'indexedDB.open');
  if (window.caches) wrapMethod(caches, 'open', 'device_storage', 'caches.open');
  if (navigator.serviceWorker) wrapMethod(navigator.serviceWorker, 'register', 'device_storage', 'serviceWorker.register');
})()
""".strip()

JS_BROWSER_SIGNALS = """
() => {
  const src = window.__vidisSignals || {fingerprinting: {}, device_storage: {}};
  const toItems = obj => Object.entries(obj || {}).map(([api, count]) => ({api, count})).sort((a, b) => a.api.localeCompare(b.api));
  return {fingerprinting: toItems(src.fingerprinting), device_storage: toItems(src.device_storage)};
}
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


_TRACKING_QUERY_PREFIXES = ("utm_",)
_TRACKING_QUERY_KEYS = {
    "fbclid",
    "gclid",
    "mc_cid",
    "mc_eid",
    "msclkid",
}
_INDEX_FILENAMES = {"index.htm", "index.html", "index.php", "default.htm", "default.html"}


def _canonical_page_url(url: str) -> str:
    """Return a stable page identity for crawl/screenshot deduplication."""
    absolute, _fragment = urldefrag(_normalize_url(url))
    parsed = urlparse(absolute)
    scheme = parsed.scheme.lower() or "https"
    netloc = parsed.netloc.lower()
    path = parsed.path or "/"
    if path != "/":
        segments = path.rsplit("/", 1)
        filename = segments[-1].lower()
        if filename in _INDEX_FILENAMES:
            path = (segments[0] or "") + "/"
        elif path.endswith("/"):
            path = path.rstrip("/") or "/"
    query_pairs = [
        (key, value)
        for key, value in parse_qsl(parsed.query, keep_blank_values=True)
        if key.lower() not in _TRACKING_QUERY_KEYS
        and not key.lower().startswith(_TRACKING_QUERY_PREFIXES)
    ]
    query = urlencode(sorted(query_pairs), doseq=True)
    return urlunparse((scheme, netloc, path, "", query, ""))


@dataclass
class PageCapture:
    url: str
    cookies: List[dict]
    local_storage: Dict[str, str]
    session_storage: Dict[str, str]
    scripts: List[str]
    requests: List[str]
    resources: List[dict] = field(default_factory=list)
    links: List[dict] = field(default_factory=list)
    visible_text: List[str] = field(default_factory=list)
    browser_signals: dict[str, list[dict]] = field(default_factory=dict)
    visited_urls: List[str] = field(default_factory=list)
    screenshots: List[dict] = field(default_factory=list)
    vision_reviews: List[dict] = field(default_factory=list)


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


def _dedupe_urls_sorted(values: Iterable[str]) -> List[str]:
    by_key: dict[str, str] = {}
    for value in values:
        if not value:
            continue
        by_key.setdefault(_canonical_page_url(value), value)
    return [by_key[key] for key in sorted(by_key)]


def _dedupe_dicts(values: Iterable[dict], keys: tuple[str, ...]) -> List[dict]:
    by_key: dict[tuple[str, ...], dict] = {}
    for value in values:
        if not isinstance(value, dict):
            continue
        dedupe_key = tuple(str(value.get(key) or "") for key in keys)
        if not any(dedupe_key):
            continue
        by_key[dedupe_key] = value
    return [by_key[key] for key in sorted(by_key)]


def _dedupe_screenshots(values: Iterable[dict]) -> List[dict]:
    by_page: dict[tuple[str, str], dict] = {}
    for value in values:
        if not isinstance(value, dict):
            continue
        url = str(value.get("url") or "")
        filename = str(value.get("filename") or "")
        path = str(value.get("path") or "")
        if url:
            dedupe_key = ("url", _canonical_page_url(url))
        elif filename or path:
            dedupe_key = ("file", filename or path)
        else:
            continue
        by_page.setdefault(dedupe_key, value)
    return [by_page[key] for key in sorted(by_page)]


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
            resources=[],
            links=[],
            visible_text=[],
            browser_signals={},
            visited_urls=[],
            screenshots=[],
            vision_reviews=[],
        )

    cookies_by_key: dict[tuple[str, str, str, str], dict] = {}
    local_storage: Dict[str, str] = {}
    session_storage: Dict[str, str] = {}
    scripts: list[str] = []
    requests: list[str] = []
    resources: list[dict] = []
    links: list[dict] = []
    visible_text: list[str] = []
    browser_signal_counts: dict[str, dict[str, int]] = {
        "fingerprinting": {},
        "device_storage": {},
    }
    visited_urls: list[str] = []
    screenshots: list[dict] = []
    vision_reviews: list[dict] = []

    seen_visited_urls: set[str] = set()

    for capture in captures:
        canonical_capture_url = _canonical_page_url(capture.url)
        if canonical_capture_url not in seen_visited_urls:
            seen_visited_urls.add(canonical_capture_url)
            visited_urls.append(capture.url)
        for cookie in capture.cookies:
            cookies_by_key[_cookie_key(cookie)] = cookie
        local_storage.update(capture.local_storage)
        session_storage.update(capture.session_storage)
        scripts.extend(capture.scripts)
        requests.extend(capture.requests)
        resources.extend(capture.resources)
        links.extend(capture.links)
        visible_text.extend(capture.visible_text)
        screenshots.extend(capture.screenshots)
        vision_reviews.extend(capture.vision_reviews)
        for group, items in (capture.browser_signals or {}).items():
            group_counts = browser_signal_counts.setdefault(group, {})
            for item in items:
                api = str(item.get("api") or "")
                if not api:
                    continue
                group_counts[api] = group_counts.get(api, 0) + int(item.get("count") or 0)

    browser_signals = {
        group: [
            {"api": api, "count": count}
            for api, count in sorted(counts.items())
            if count
        ]
        for group, counts in browser_signal_counts.items()
    }

    return PageCapture(
        url=captures[0].url,
        cookies=[cookies_by_key[key] for key in sorted(cookies_by_key)],
        local_storage=dict(sorted(local_storage.items())),
        session_storage=dict(sorted(session_storage.items())),
        scripts=_dedupe_sorted(scripts),
        requests=_dedupe_urls_sorted(requests),
        resources=_dedupe_dicts(resources, ("type", "url", "selector")),
        links=_dedupe_dicts(links, ("url", "text", "selector")),
        visible_text=_dedupe_sorted(visible_text),
        browser_signals=browser_signals,
        visited_urls=visited_urls,
        screenshots=_dedupe_screenshots(screenshots),
        vision_reviews=_dedupe_dicts(vision_reviews, ("label", "note")),
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
    screenshot_dir: Path | None = None,
    screenshot_index: int | None = None,
    authenticated: bool = False,
    guard: BrowserGuard | None = None,
) -> PageCapture:
    page.add_init_script(JS_BROWSER_SIGNAL_INSTALL)
    page.goto(url, wait_until="load", timeout=30000)
    try:
        page.wait_for_load_state("networkidle", timeout=5000)
    except Exception:
        pass
    if guard is not None:
        guard.assert_safe(page)
    if consent_hook is not None:
        consent_hook(page)
    if guard is not None:
        guard.assert_safe(page)

    cookies = context.cookies()
    local_storage = page.evaluate(JS_LOCAL)
    session_storage = page.evaluate(JS_SESSION)
    resources = page.evaluate(JS_RESOURCES)
    links = page.evaluate(JS_LINK_DETAILS)
    visible_text = page.evaluate(JS_VISIBLE_TEXT)
    browser_signals = page.evaluate(JS_BROWSER_SIGNALS)
    scripts = [r["url"] for r in resources if r.get("type") == "script"]
    screenshots: list[dict] = []
    if screenshot_dir is not None:
        label = f"page-{screenshot_index or 1}"
        filename = f"{label}.png"
        screenshot_dir.mkdir(parents=True, exist_ok=True)
        screenshot_path = screenshot_dir / filename
        if guard is not None:
            guard.assert_safe(page)
        page.screenshot(path=str(screenshot_path), full_page=False)
        viewport = getattr(page, "viewport_size", None) or SCREENSHOT_VIEWPORT
        screenshots.append(
            {
                "label": label,
                "url": page.url,
                "filename": filename,
                "path": str(screenshot_path),
                "authenticated": bool(authenticated),
                "local_only": bool(authenticated),
                "viewport_width": int(viewport.get("width") or SCREENSHOT_VIEWPORT["width"]),
                "viewport_height": int(viewport.get("height") or SCREENSHOT_VIEWPORT["height"]),
            }
        )
    return PageCapture(
        url=page.url,
        cookies=cookies,
        local_storage=local_storage,
        session_storage=session_storage,
        scripts=scripts,
        requests=list(requests[request_start:]),
        resources=resources,
        links=links,
        visible_text=visible_text,
        browser_signals=browser_signals,
        screenshots=screenshots,
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
    screenshot_dir: str | Path | None = None,
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
    screenshot_path = Path(screenshot_dir) if screenshot_dir is not None else None

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=headless)
        context = browser.new_context(viewport=SCREENSHOT_VIEWPORT)
        guard = guard_browser_context(context)
        page = context.new_page()
        request_log: List[str] = []
        page.on("requestfinished", lambda req: request_log.append(req.url))

        captures: list[PageCapture] = []
        queue: deque[str] = deque([start_url])
        seen: set[str] = set()

        try:
            while queue and len(captures) < max_pages:
                current_url = queue.popleft()
                current_key = _canonical_page_url(current_url)
                if current_key in seen:
                    continue
                seen.add(current_key)

                request_start = len(request_log)
                capture = _capture_page(
                    page,
                    context,
                    current_url,
                    requests=request_log,
                    consent_hook=hook,
                    request_start=request_start,
                    screenshot_dir=screenshot_path,
                    screenshot_index=len(captures) + 1,
                    guard=guard,
                )
                final_key = _canonical_page_url(capture.url)
                if final_key != current_key and final_key in seen:
                    continue
                seen.add(final_key)
                captures.append(capture)

                remaining = max_pages - len(captures)
                if remaining <= 0:
                    continue
                queued_keys = {_canonical_page_url(link) for link in queue}
                links = [
                    link
                    for link in _discover_from_page(page)
                    if _canonical_page_url(link) not in seen
                    and _canonical_page_url(link) not in queued_keys
                ]
                rng.shuffle(links)
                queue.extend(links[:remaining])
        finally:
            context.close()
            browser.close()

    return aggregate_captures(captures)

