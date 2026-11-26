from __future__ import annotations

import socket

import httpx
import pytest

from vidis_compliance import net
from vidis_compliance.checks.site import ipf
from vidis_compliance.sources.documents import analyze

PUBLIC = "93.184.215.14"
REAL_CLIENT = httpx.Client


@pytest.fixture
def no_private(monkeypatch):
    """Turn the address check on and resolve test hosts without DNS."""
    monkeypatch.delenv("VIDIS_ALLOW_PRIVATE_TARGETS", raising=False)
    table = {
        "public.test": PUBLIC,
        "other.test": PUBLIC,
        "internal.test": "10.1.2.3",
        "mapped.test": "::ffff:127.0.0.1",
        "meta.test": "169.254.169.254",
    }

    def fake_getaddrinfo(host, *args, **kwargs):
        if host not in table:
            raise socket.gaierror("unknown")
        family = socket.AF_INET6 if ":" in table[host] else socket.AF_INET
        return [(family, socket.SOCK_STREAM, 6, "", (table[host], 0))]

    monkeypatch.setattr(net.socket, "getaddrinfo", fake_getaddrinfo)


def _serve(monkeypatch, handler):
    """Route safe_get's client through a mock transport."""
    def client(**kwargs):
        return REAL_CLIENT(transport=httpx.MockTransport(handler), **kwargs)

    monkeypatch.setattr(net.httpx, "Client", client)


@pytest.mark.parametrize(
    "url, message",
    [
        ("https://internal.test/x", "non-public"),
        ("https://mapped.test/x", "non-public"),
        ("https://meta.test/latest/meta-data", "non-public"),
        ("https://localhost/x", "not public"),
        ("https://nowhere.test/x", "does not resolve"),
        ("file:///etc/passwd", "only http and https"),
        ("https://user:pw@public.test/", "credentials"),
    ],
)
def test_check_public_url_refuses(no_private, url: str, message: str) -> None:
    with pytest.raises(net.UnsafeTargetError, match=message):
        net.check_public_url(url)


def test_redirect_to_internal_address_is_refused(no_private, monkeypatch) -> None:
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(str(request.url))
        if request.url.host == "public.test":
            return httpx.Response(302, headers={"Location": "https://internal.test/admin"})
        return httpx.Response(200, text="secret")

    _serve(monkeypatch, handler)
    with pytest.raises(net.UnsafeTargetError, match="non-public"):
        net.safe_get("https://public.test/agb")
    assert seen == ["https://public.test/agb"]


def test_public_redirects_are_followed(no_private, monkeypatch) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/agb":
            return httpx.Response(301, headers={"Location": "https://other.test/terms"})
        return httpx.Response(200, text="AGB Text", headers={"content-type": "text/html; charset=utf-8"})

    _serve(monkeypatch, handler)
    response = net.safe_get("https://public.test/agb")

    assert response.url == "https://other.test/terms"
    assert response.text == "AGB Text"


def test_redirect_loops_stop(no_private, monkeypatch) -> None:
    _serve(monkeypatch, lambda request: httpx.Response(302, headers={"Location": "https://public.test/again"}))

    with pytest.raises(net.UnsafeTargetError, match="too many redirects"):
        net.safe_get("https://public.test/start")


def test_size_limit_applies_with_and_without_content_length(no_private, monkeypatch) -> None:
    _serve(monkeypatch, lambda request: httpx.Response(200, content=b"x" * 2048))
    with pytest.raises(net.ResponseTooLargeError):
        net.safe_get("https://public.test/big", max_bytes=1024)

    def streamed(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, stream=httpx.ByteStream(b"y" * 4096), headers={})

    _serve(monkeypatch, streamed)
    with pytest.raises(net.ResponseTooLargeError):
        net.safe_get("https://public.test/stream", max_bytes=1024)


def test_document_fetch_uses_the_guard(no_private, monkeypatch) -> None:
    _serve(monkeypatch, lambda request: httpx.Response(302, headers={"Location": "http://meta.test/latest/meta-data"}))

    with pytest.raises(net.UnsafeTargetError):
        analyze.fetch_document(analyze.DocumentInput(location="https://public.test/agb", kind="agb"))


def test_legal_page_fetch_uses_the_guard(no_private, monkeypatch) -> None:
    _serve(monkeypatch, lambda request: httpx.Response(302, headers={"Location": "https://internal.test/"}))

    with pytest.raises(net.UnsafeTargetError):
        ipf._default_fetch("https://public.test/impressum")


def test_browser_guard_blocks_internal_and_odd_schemes(no_private) -> None:
    guard = net.BrowserGuard()

    assert guard.allowed("https://public.test/app.js")
    assert guard.allowed("data:image/png;base64,AAAA")
    assert not guard.allowed("http://internal.test/admin")
    assert not guard.allowed("http://meta.test/latest/meta-data")
    assert not guard.allowed("file:///etc/passwd")
    assert not guard.allowed("chrome://settings")


def test_browser_guard_aborts_blocked_routes(no_private) -> None:
    class Route:
        def __init__(self, url: str) -> None:
            self.request = type("R", (), {"url": url})()
            self.result = ""

        def continue_(self) -> None:
            self.result = "continued"

        def abort(self, reason: str) -> None:
            self.result = reason

    guard = net.BrowserGuard()
    ok, bad = Route("https://public.test/"), Route("http://internal.test/")
    guard(ok)
    guard(bad)

    assert ok.result == "continued"
    assert bad.result == "blockedbyclient"
    assert guard.blocked == ["http://internal.test/"]


def test_guard_is_installed_on_browser_contexts(no_private) -> None:
    routes: list = []

    class Context:
        def route(self, pattern, handler) -> None:
            routes.append((pattern, handler))

    net.guard_browser_context(Context())

    assert routes and routes[0][0] == "**/*" and isinstance(routes[0][1], net.BrowserGuard)
