from __future__ import annotations

import hashlib
import hmac
import json
import time
from pathlib import Path

import httpx
import pytest
from fastapi.testclient import TestClient

from vidis_compliance import callbacks, server
from vidis_compliance.checks.site.ipf import IpfSiteAnalysis, LegalPageResult
from vidis_compliance.models import CheckFinding

SECRET = "workshop-secret-0123456789"


@pytest.fixture
def client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> TestClient:
    monkeypatch.setenv("VIDIS_RESULTS_DIR", str(tmp_path / "results"))
    monkeypatch.setattr(
        server.cli_module,
        "check_site_transport",
        lambda url: [CheckFinding(criterion="ITS-ENC-359", status="PASS", note="ok"), CheckFinding(criterion="ITS-ENC-360", status="FAIL", note="no")],
    )
    monkeypatch.setattr(
        server.cli_module,
        "analyze_ipf_site",
        lambda url: IpfSiteAnalysis(source_url=url, visited_urls=[], impressum=LegalPageResult(kind="impressum"), privacy=LegalPageResult(kind="privacy")),
    )
    monkeypatch.setattr(callbacks, "RETRY_DELAYS_SECONDS", (0, 0, 0, 0))
    return TestClient(server.app)


@pytest.fixture
def receiver(monkeypatch) -> list[dict]:
    received: list[dict] = []
    responses: list[int] = []

    def fake_post(url, content, headers, timeout, follow_redirects):
        assert follow_redirects is False
        received.append({"url": url, "body": content, "headers": headers})
        return httpx.Response(responses.pop(0) if responses else 200)

    monkeypatch.setattr(callbacks.httpx, "post", fake_post)
    return received


def _wait_callback(client: TestClient, job_id: str) -> dict:
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        job = client.get(f"/jobs/{job_id}").json()
        callback = job.get("callback") or {}
        if job["status"] in {"completed", "failed"} and callback and not callback.get("pending"):
            return job
        time.sleep(0.05)
    raise AssertionError("callback not finished")


def test_callback_is_posted_and_signed_when_the_job_finishes(client: TestClient, receiver: list, tmp_path: Path) -> None:
    response = client.post(
        "/checks/site.transport",
        json={"target_url": "https://app.example.test", "callback_url": "https://hooks.example.test/vidis", "callback_secret": SECRET},
        headers={"x-forwarded-proto": "https", "host": "vidis.example.test"},
    )
    job = _wait_callback(client, response.json()["id"])

    assert job["callback"]["delivered"] is True and job["callback"]["attempts"] == 1
    sent = receiver[0]
    payload = json.loads(sent["body"])
    assert sent["url"] == "https://hooks.example.test/vidis"
    assert payload["event"] == "job.finished" and payload["status"] == "completed"
    assert payload["job_id"] == job["id"]
    assert payload["checks"] == ["site.transport"]
    assert payload["summary"]["PASS"] == 1 and payload["summary"]["FAIL"] >= 1
    assert payload["links"]["job"] == f"https://vidis.example.test/jobs/{job['id']}"
    assert "findings" not in payload
    expected = hmac.new(SECRET.encode(), sent["headers"]["X-VIDIS-Timestamp"].encode() + b"." + sent["body"], hashlib.sha256).hexdigest()
    assert sent["headers"]["X-VIDIS-Signature"] == f"sha256={expected}"
    assert sent["headers"]["X-VIDIS-Event"] == "job.finished"
    stored = (tmp_path / "results" / job["id"] / "job.json").read_text(encoding="utf-8")
    assert SECRET not in stored
    assert "callback_secret" not in json.loads(stored)["request"]


def test_public_url_setting_wins_for_links(client: TestClient, receiver: list, monkeypatch) -> None:
    monkeypatch.setenv("VIDIS_PUBLIC_URL", "https://vidis-checker.example/")
    job_id = client.post("/jobs", json={"target_url": "https://app.example.test", "checks": ["site.transport"], "callback_url": "https://hooks.example.test/x"}).json()["id"]
    _wait_callback(client, job_id)

    payload = json.loads(receiver[0]["body"])
    assert payload["links"]["archive"] == f"https://vidis-checker.example/jobs/{job_id}/archive.zip"
    assert "X-VIDIS-Signature" not in receiver[0]["headers"]


def test_server_errors_are_retried_then_given_up(monkeypatch) -> None:
    monkeypatch.setattr(callbacks, "RETRY_DELAYS_SECONDS", (0, 0, 0, 0))
    statuses = [500, 502, 503, 500]
    calls: list = []

    def post(url, content, headers, timeout, follow_redirects):
        calls.append(headers["X-VIDIS-Delivery"])
        return httpx.Response(statuses.pop(0))

    record = callbacks.deliver("https://h.example/x", {"a": 1}, secret=None, check_target=lambda url: None, post=post, sleep=lambda s: None)

    assert record["delivered"] is False and record["attempts"] == 4
    assert record["last_error"] == "HTTP 500"
    assert len(set(calls)) == 1  # one delivery id across retries


def test_retry_succeeds_after_a_network_error(monkeypatch) -> None:
    outcomes: list = [httpx.ConnectError("down"), httpx.Response(204)]

    def post(url, content, headers, timeout, follow_redirects):
        outcome = outcomes.pop(0)
        if isinstance(outcome, Exception):
            raise outcome
        return outcome

    record = callbacks.deliver("https://h.example/x", {}, secret=None, check_target=lambda url: None, post=post, sleep=lambda s: None)

    assert record["delivered"] is True and record["attempts"] == 2 and record["last_status"] == 204


def test_client_errors_are_not_retried() -> None:
    calls: list = []

    def post(url, content, headers, timeout, follow_redirects):
        calls.append(1)
        return httpx.Response(410)

    record = callbacks.deliver("https://h.example/x", {}, secret=None, check_target=lambda url: None, post=post, sleep=lambda s: None)

    assert record["attempts"] == 1 and record["delivered"] is False


def test_target_that_turns_private_is_not_contacted() -> None:
    def refuse(url):
        raise ValueError("target host resolves to a non-public address: h.example")

    def post(*args, **kwargs):
        raise AssertionError("must not post")

    record = callbacks.deliver("https://h.example/x", {}, secret=None, check_target=refuse, post=post, sleep=lambda s: None)

    assert record["delivered"] is False and "non-public" in record["last_error"]


@pytest.mark.parametrize(
    "url, message",
    [
        ("http://hooks.example.test/x", "https"),
        ("https://127.0.0.1/x", "non-public"),
        ("https://localhost/x", "not public"),
        ("https://does-not-exist.invalid/x", "does not resolve"),
    ],
)
def test_callback_url_must_be_public_https(client: TestClient, monkeypatch, url: str, message: str) -> None:
    monkeypatch.delenv("VIDIS_ALLOW_PRIVATE_TARGETS")

    response = client.post("/jobs", json={"agb_url": "https://example.com/agb", "callback_url": url})

    assert response.status_code == 422
    assert message in response.text


def test_secret_without_url_is_rejected(client: TestClient) -> None:
    response = client.post("/jobs", json={"target_url": "https://app.example.test", "callback_secret": SECRET})

    assert response.status_code == 422 and "callback_secret requires callback_url" in response.text


def test_discovery_documents_callbacks(client: TestClient) -> None:
    payload = client.get("/discovery").json()["callbacks"]

    assert payload["request_fields"] == ["callback_url", "callback_secret"]
    assert "X-VIDIS-Signature" in payload["headers"]
