from __future__ import annotations

import socket
from pathlib import Path

import httpx
import pytest
from fastapi.testclient import TestClient

from vidis_compliance import net, server
from vidis_compliance.checks.site import basic_http
from vidis_compliance.report import markdown


@pytest.fixture
def client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> TestClient:
    monkeypatch.setenv("VIDIS_RESULTS_DIR", str(tmp_path / "results"))
    return TestClient(server.app)


def test_internal_errors_are_not_exposed() -> None:
    assert server._public_error(FileNotFoundError("/app/src/vidis_compliance/x.yaml")) == (
        "Interner Fehler (FileNotFoundError); Details stehen im Server-Log."
    )
    assert "Interner Fehler" in server._public_error(ValueError("bad value in /app/.venv/lib/python3.12/x.py"))
    assert server._public_error(ValueError("check site.cookies requires target_url")) == "check site.cookies requires target_url"
    assert "non-public" in server._public_error(net.UnsafeTargetError("target host resolves to a non-public address: x"))


def test_http_errors_name_the_url_without_query() -> None:
    request = httpx.Request("GET", "https://docs.example/agb?token=SECRET")
    error = httpx.HTTPStatusError("x", request=request, response=httpx.Response(404, request=request))

    message = server._public_error(error)

    assert message == "HTTP 404 beim Abruf von https://docs.example/agb"
    assert "SECRET" not in message


def test_manual_ignores_a_forged_host_header(client: TestClient) -> None:
    page = client.get("/manual/", headers={"host": 'evil.example"><script>alert(1)</script>'})

    assert page.status_code in {200, 400}
    assert "<script>alert(1)" not in page.text


def test_manual_escapes_the_configured_url(client: TestClient, monkeypatch) -> None:
    monkeypatch.setenv("VIDIS_PUBLIC_URL", 'https://x.example/"><b>')

    assert '"><b>' not in client.get("/manual/").text


@pytest.mark.parametrize(
    "body",
    [
        {"target_url": "https://app.example.test", "agentic": True, "agent_instructions": ["x" * 501]},
        {"agb_url": "https://app.example.test/agb", "document_paths": [f"/data/inputs/{i}.pdf" for i in range(21)]},
        {"target_url": "https://app.example.test", "agent_username": "u" * 201},
        {"target_url": "https://app.example.test", "agentic": True, "agent_password": "p" * 501},
    ],
)
def test_request_fields_are_bounded(client: TestClient, body: dict) -> None:
    assert client.post("/jobs", json=body).status_code == 422


def test_large_request_bodies_are_refused(client: TestClient) -> None:
    response = client.post("/jobs", content=b"{" + b" " * (300 * 1024) + b"}", headers={"content-type": "application/json"})

    assert response.status_code == 413


def test_local_paths_fail_closed_when_keys_are_set(client: TestClient, monkeypatch) -> None:
    monkeypatch.delenv("VIDIS_AUTH_DISABLED")
    monkeypatch.setenv("VIDIS_API_KEYS", "k")
    monkeypatch.delenv("VIDIS_ALLOWED_PATH_ROOTS", raising=False)

    response = client.post("/jobs", json={"code_path": "/etc"}, headers={"X-API-Key": "k"})

    assert response.status_code == 422 and "local paths are disabled" in response.text


def test_status_counts_are_cached(client: TestClient, monkeypatch) -> None:
    server._COUNTS_CACHE.clear()
    calls: list = []
    original = server._list_metadata

    def counting(*args, **kwargs):
        calls.append(1)
        return original(*args, **kwargs)

    monkeypatch.setattr(server, "_list_metadata", counting)
    client.get("/status")
    client.get("/status")

    assert len(calls) == 1


def test_tls_check_refuses_internal_hosts_at_connect_time(monkeypatch) -> None:
    monkeypatch.delenv("VIDIS_ALLOW_PRIVATE_TARGETS", raising=False)
    monkeypatch.setattr(net.socket, "getaddrinfo", lambda host, *a, **k: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.7", 0))])

    with pytest.raises(net.UnsafeTargetError):
        basic_http.check_site_transport(
            "https://rebound.example:2375/",
            http_get=lambda *a, **k: pytest.fail("must not connect"),
            tls_probe=lambda *a: pytest.fail("must not connect"),
        )


def test_markdown_neutralises_images_and_html_but_keeps_links() -> None:
    text = markdown._md_safe('Siehe ![x](https://evil.example/beacon.png) <img src=x onerror=alert(1)> [Impressum](https://a.example/impressum)')

    assert "![" not in text
    assert "<img" not in text and "&lt;img" in text
    assert "[Impressum](https://a.example/impressum)" in text
    assert markdown._escape_table("a|b\n<c>") == "a\\|b<br>&lt;c&gt;"


def test_discovery_links_use_the_public_url(client: TestClient, monkeypatch) -> None:
    monkeypatch.setenv("VIDIS_PUBLIC_URL", "https://vidis-checker.example")

    links = client.get("/discovery").json()["links"]

    assert links["openapi"] == "https://vidis-checker.example/openapi.json"
    assert links["manual"] == "https://vidis-checker.example/manual/"
