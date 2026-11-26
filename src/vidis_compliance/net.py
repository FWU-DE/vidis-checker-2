"""Outbound requests to caller-supplied URLs.

Every URL the service fetches on someone else's behalf (documents, legal
pages, browser crawls) must stay on the public internet: the service runs
next to other internal services. ``safe_get`` follows redirects itself and
checks each hop, and caps size and time; ``guard_browser_context`` blocks
browser requests to non-public addresses.

``VIDIS_ALLOW_PRIVATE_TARGETS=1`` lifts the address check for test setups.

Residual risk: the address is checked by resolving the host, and the HTTP
client resolves it again when connecting, so a DNS answer that changes in
between (rebinding) is not caught.
"""

from __future__ import annotations

import ipaddress
import os
import socket
import threading
from dataclasses import dataclass
from urllib.parse import urljoin, urlsplit

import httpx

DEFAULT_MAX_BYTES = 10 * 1024 * 1024
DEFAULT_TIMEOUT = 20.0
MAX_REDIRECTS = 5
USER_AGENT = "vidis-compliance/1 (+https://github.com/FWU-DE/vidis-checker-2)"


class UnsafeTargetError(ValueError):
    """The URL points somewhere the service must not go."""


class ResponseTooLargeError(ValueError):
    """The response exceeded the size limit."""


def private_targets_allowed() -> bool:
    return os.environ.get("VIDIS_ALLOW_PRIVATE_TARGETS", "").strip().lower() in {"1", "true", "yes", "on"}


def _address_is_public(address: str) -> bool:
    ip = ipaddress.ip_address(address.split("%", 1)[0])
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    return ip.is_global


def check_public_host(host: str, *, strict: bool = True) -> None:
    """Raise ``UnsafeTargetError`` unless every address of ``host`` is public.

    With ``strict=False`` a host that does not resolve passes (the caller will
    fail later anyway); outbound fetches use ``strict=True``.
    """
    if private_targets_allowed():
        return
    host = (host or "").strip().lower().rstrip(".")
    if not host or host in {"localhost", "localhost.localdomain"} or host.endswith(".localhost"):
        raise UnsafeTargetError(f"target host is not public: {host or '(empty)'}")
    try:
        infos = socket.getaddrinfo(host, None)
    except (socket.gaierror, UnicodeError) as exc:
        if strict:
            raise UnsafeTargetError(f"target host does not resolve: {host}") from exc
        return
    for info in infos:
        if not _address_is_public(str(info[4][0])):
            raise UnsafeTargetError(f"target host resolves to a non-public address: {host}")


def check_public_url(url: str, *, strict: bool = True) -> None:
    parts = urlsplit(url)
    if parts.scheme not in {"http", "https"}:
        raise UnsafeTargetError(f"only http and https URLs are allowed: {parts.scheme or '(none)'}")
    if parts.username or parts.password:
        raise UnsafeTargetError("URLs with credentials are not allowed")
    check_public_host(parts.hostname or "", strict=strict)


@dataclass
class SafeResponse:
    url: str
    status_code: int
    headers: httpx.Headers
    content: bytes

    @property
    def text(self) -> str:
        charset = httpx.Response(200, headers=self.headers, content=self.content).encoding or "utf-8"
        return self.content.decode(charset, errors="replace")

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            raise httpx.HTTPStatusError(
                f"HTTP {self.status_code} for {self.url}",
                request=httpx.Request("GET", self.url),
                response=httpx.Response(self.status_code),
            )


def safe_get(
    url: str,
    *,
    timeout: float = DEFAULT_TIMEOUT,
    max_bytes: int = DEFAULT_MAX_BYTES,
    max_redirects: int = MAX_REDIRECTS,
    headers: dict[str, str] | None = None,
) -> SafeResponse:
    """GET ``url`` following at most ``max_redirects`` redirects, each checked.

    Raises ``UnsafeTargetError`` for a non-public hop, ``ResponseTooLargeError``
    past ``max_bytes`` and ``httpx.HTTPError`` for transport errors.
    """
    # Uncompressed: some servers label bodies gzip that are not, which made whole sites unreadable.
    request_headers = {"User-Agent": USER_AGENT, "Accept-Encoding": "identity", **(headers or {})}
    current = url
    with httpx.Client(timeout=timeout, follow_redirects=False, headers=request_headers) as client:
        for _hop in range(max_redirects + 1):
            check_public_url(current)
            with client.stream("GET", current) as response:
                if response.is_redirect and response.headers.get("location"):
                    current = urljoin(current, response.headers["location"])
                    continue
                declared = response.headers.get("content-length")
                if declared and declared.isdigit() and int(declared) > max_bytes:
                    raise ResponseTooLargeError(f"response larger than {max_bytes} bytes: {current}")
                chunks: list[bytes] = []
                size = 0
                for chunk in response.iter_bytes():
                    size += len(chunk)
                    if size > max_bytes:
                        raise ResponseTooLargeError(f"response larger than {max_bytes} bytes: {current}")
                    chunks.append(chunk)
                return SafeResponse(url=current, status_code=response.status_code, headers=response.headers, content=b"".join(chunks))
    raise UnsafeTargetError(f"too many redirects (>{max_redirects}): {url}")


class BrowserGuard:
    """Keeps a browser context on public addresses.

    Two layers, because Playwright's request routing only sees the first URL
    of a redirect chain:

    - the route handler aborts direct requests to non-public addresses;
    - every request event, including each redirect hop, is checked and
      recorded, and ``assert_safe`` raises before anything is read from or
      captured on a page once any request went to a non-public address.

    The request to a redirect target has then already been sent (a blind
    GET); its response is never read, captured or shown. Only a network-level
    egress filter can stop the request itself.
    """

    def __init__(self, enabled: bool = True) -> None:
        self.enabled = enabled
        self._decisions: dict[str, bool] = {}
        self._lock = threading.Lock()
        self.blocked: list[str] = []
        self.violations: list[str] = []

    def allowed(self, url: str) -> bool:
        if not self.enabled:
            return True
        parts = urlsplit(url)
        if parts.scheme in {"data", "blob", "about"}:
            return True
        if parts.scheme not in {"http", "https", "ws", "wss"}:
            return False
        host = (parts.hostname or "").lower()
        with self._lock:
            cached = self._decisions.get(host)
        if cached is None:
            try:
                check_public_host(host)
                cached = True
            except UnsafeTargetError:
                cached = False
            with self._lock:
                self._decisions[host] = cached
        return cached

    def __call__(self, route) -> None:
        url = route.request.url
        if self.allowed(url):
            route.continue_()
            return
        if len(self.blocked) < 50:
            self.blocked.append(url[:300])
        route.abort("blockedbyclient")

    def observe(self, request) -> None:
        """Request event handler; also fires for every redirect hop."""
        url = request.url
        if not self.allowed(url) and len(self.violations) < 50:
            self.violations.append(url[:300])

    def websocket(self, ws_route) -> None:
        if self.allowed(ws_route.url):
            ws_route.connect_to_server()
            return
        if len(self.blocked) < 50:
            self.blocked.append(ws_route.url[:300])
        ws_route.close(code=1008, reason="blocked")

    def assert_safe(self, page=None) -> None:
        """Raise ``UnsafeTargetError`` if the browser reached a non-public address."""
        if not self.enabled:
            return
        urls = []
        if page is not None:
            urls.append(str(page.url))
            try:
                urls.extend(str(frame.url) for frame in page.frames)
            except Exception:
                pass
        for url in urls:
            if url and not self.allowed(url) and url not in self.violations:
                self.violations.append(url[:300])
        if self.violations:
            host = urlsplit(self.violations[0]).hostname or self.violations[0]
            raise UnsafeTargetError(f"crawl stopped: the site led the browser to a non-public address ({host})")


def guard_browser_context(context) -> BrowserGuard:
    """Keep ``context`` on public addresses; call ``assert_safe(page)`` before reading a page."""
    guard = BrowserGuard(enabled=not private_targets_allowed())
    if guard.enabled:
        context.route("**/*", guard)
        context.on("request", guard.observe)
        route_web_socket = getattr(context, "route_web_socket", None)
        if route_web_socket is not None:
            route_web_socket("**/*", guard.websocket)
    return guard
