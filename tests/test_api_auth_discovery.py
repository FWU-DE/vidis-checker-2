from __future__ import annotations

import json
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from vidis_compliance import server
from vidis_compliance.catalog import CHECKS
from vidis_compliance.checks.site.ipf import IpfSiteAnalysis, LegalPageResult
from vidis_compliance.cli import load_criteria
from vidis_compliance.models import CheckFinding
from vidis_compliance.sources.agentic import AgenticCrawlResult


@pytest.fixture
def client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> TestClient:
    monkeypatch.setenv("VIDIS_RESULTS_DIR", str(tmp_path / "results"))
    return TestClient(server.app)


def _wait(client: TestClient, job_id: str, headers: dict | None = None) -> dict:
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        payload = client.get(f"/jobs/{job_id}", headers=headers or {}).json()
        if payload["status"] in {"completed", "failed"}:
            return payload
        time.sleep(0.05)
    raise AssertionError("job did not finish")


def test_api_refuses_jobs_when_no_key_is_configured(client: TestClient, monkeypatch) -> None:
    monkeypatch.delenv("VIDIS_AUTH_DISABLED")

    assert client.get("/jobs").status_code == 503
    assert client.post("/jobs", json={"code_path": "/tmp"}).status_code == 503
    assert client.get("/health").status_code == 200
    assert client.get("/discovery").status_code == 200


def test_api_accepts_any_configured_key_via_bearer_or_header(client: TestClient, monkeypatch) -> None:
    monkeypatch.delenv("VIDIS_AUTH_DISABLED")
    monkeypatch.setenv("VIDIS_API_KEYS", "key-one, key-two")

    assert client.get("/jobs").status_code == 401
    assert client.get("/jobs", headers={"X-API-Key": "nope"}).status_code == 401
    assert client.get("/jobs", headers={"Authorization": "Bearer key-one"}).status_code == 200
    assert client.get("/jobs", headers={"X-API-Key": "key-two"}).status_code == 200
    assert client.get("/jobs/abc/archive.zip").status_code == 401
    assert client.get("/discovery").status_code == 200


def test_configured_key_wins_over_disabled_flag(client: TestClient, monkeypatch) -> None:
    monkeypatch.setenv("VIDIS_API_KEY", "secret")

    assert client.get("/jobs").status_code == 401


def test_discovery_lists_checks_criteria_and_endpoints(client: TestClient, monkeypatch) -> None:
    monkeypatch.delenv("VIDIS_AUTH_DISABLED")
    monkeypatch.setenv("VIDIS_API_KEYS", "k")

    payload = client.get("/discovery").json()

    check_ids = {check["id"] for check in payload["checks"]}
    assert {"site.cookies", "site.transport", "site.legal_pages", "code.inspection", "documents.analysis", "agentic.persona_crawl"} <= check_ids
    registry = set(load_criteria().items)
    assert {item["code"] for item in payload["criteria"]} == registry
    assert payload["criteria_catalog"]["count"] == len(registry)
    assert payload["authentication"]["required"] is True
    assert any(endpoint["path"] == "/jobs" and endpoint["method"] == "POST" for endpoint in payload["endpoints"])
    transport = next(check for check in payload["checks"] if check["id"] == "site.transport")
    assert transport["criteria"] == ["ITS-ENC-359", "ITS-ENC-360", "ITS-ENC-361"]
    assert transport["requires"] == ["target_url"]
    dso = next(item for item in payload["criteria"] if item["code"] == "RDS-DSO-383")
    assert dso["automated"] is True and "documents.analysis" in dso["checks"]
    assert client.get("/.well-known/vidis-checks").json()["checks"] == payload["checks"]


def test_catalog_only_names_registry_criteria() -> None:
    registry = set(load_criteria().items)
    for check in CHECKS:
        assert set(check.criteria) <= registry, check.id


def test_openapi_documents_both_auth_schemes(client: TestClient) -> None:
    schemes = client.get("/openapi.json").json()["components"]["securitySchemes"]

    assert schemes["HTTPBearer"]["scheme"] == "bearer"
    assert schemes["APIKeyHeader"]["name"] == "X-API-Key"


def test_local_paths_are_limited_to_allowed_roots(client: TestClient, tmp_path: Path, monkeypatch) -> None:
    inputs = tmp_path / "inputs"
    inputs.mkdir()
    monkeypatch.setenv("VIDIS_ALLOWED_PATH_ROOTS", str(inputs))

    outside = client.post("/jobs", json={"code_path": "/etc"})
    escape = client.post("/jobs", json={"document_paths": [str(inputs / ".." / "secret.txt")]})

    assert outside.status_code == 422
    assert "outside the allowed input directories" in outside.text
    assert escape.status_code == 422


def test_local_paths_can_be_disabled(client: TestClient, monkeypatch) -> None:
    monkeypatch.setenv("VIDIS_ALLOWED_PATH_ROOTS", "none")

    assert client.post("/jobs", json={"code_path": "/tmp"}).status_code == 422


@pytest.mark.parametrize("url", ["http://127.0.0.1:8080/", "http://localhost/", "http://10.0.0.5/", "http://[::1]/"])
def test_private_targets_are_refused(client: TestClient, monkeypatch, url: str) -> None:
    monkeypatch.delenv("VIDIS_ALLOW_PRIVATE_TARGETS")

    response = client.post("/jobs", json={"target_url": url})

    assert response.status_code == 422
    assert "public" in response.text


def test_api_job_runs_the_same_site_checks_as_the_cli(client: TestClient, monkeypatch) -> None:
    class FakeCapture:
        url = "https://example.test/"
        cookies: list = []
        scripts: list = []
        requests: list = []
        resources: list = []
        links: list = []
        visible_text = ""
        browser_signals: dict = {}
        local_storage: dict = {}
        session_storage: dict = {}
        visited_urls = ["https://example.test/"]
        screenshots: list = []

    monkeypatch.setattr(server.cli_module, "crawl", lambda *args, **kwargs: FakeCapture())
    monkeypatch.setattr(
        server.cli_module,
        "check_site_transport",
        lambda url: [CheckFinding(criterion="ITS-ENC-359", status="PASS", note="TLS fixture")],
    )
    monkeypatch.setattr(
        server.cli_module,
        "analyze_ipf_site",
        lambda url: IpfSiteAnalysis(
            source_url=url,
            visited_urls=[],
            impressum=LegalPageResult(kind="impressum"),
            privacy=LegalPageResult(kind="privacy"),
        ),
    )

    job_id = client.post("/jobs", json={"target_url": "https://example.test", "pages": 1}).json()["id"]
    completed = _wait(client, job_id)

    assert completed["status"] == "completed", completed.get("error")
    by_code = {finding["criterion"]: finding for finding in completed["result"]["findings"]}
    assert by_code["ITS-ENC-359"]["note"] == "TLS fixture"
    for code in ("RDS-CUC-375", "RDS-CUC-376", "RDS-WER-384", "RDS-VIN-354"):
        assert by_code[code]["note"] != "Not yet implemented", code


def _fake_site(monkeypatch) -> None:
    class FakeCapture:
        url = "https://app.example.test/"
        cookies: list = []
        scripts: list = []
        requests: list = []
        resources: list = []
        links: list = []
        visible_text = ""
        browser_signals: dict = {}
        local_storage: dict = {}
        session_storage: dict = {}
        visited_urls: list = []
        screenshots: list = []

    monkeypatch.setattr(server.cli_module, "crawl", lambda *args, **kwargs: FakeCapture())
    monkeypatch.setattr(server.cli_module, "check_site_transport", lambda url: [])
    monkeypatch.setattr(
        server.cli_module,
        "analyze_ipf_site",
        lambda url: IpfSiteAnalysis(
            source_url=url, visited_urls=[], impressum=LegalPageResult(kind="impressum"), privacy=LegalPageResult(kind="privacy")
        ),
    )


def test_agent_password_reaches_the_runner_but_is_never_stored(client: TestClient, tmp_path: Path, monkeypatch) -> None:
    seen: dict = {}

    class FakeRunner:
        def run(self, **kwargs):
            seen.update(kwargs)
            return AgenticCrawlResult(base_url=kwargs["base_url"], task_types=kwargs["task_types"], persona=kwargs["persona"])

    _fake_site(monkeypatch)
    monkeypatch.setattr(server.cli_module, "DefaultAgenticRunner", lambda: FakeRunner())
    monkeypatch.delenv("VIDIS_AGENT_PASSWORD", raising=False)

    job_id = client.post(
        "/jobs",
        json={
            "target_url": "https://app.example.test",
            "agentic": True,
            "agent_username": "lehrer1",
            "agent_password": "geheim-123",
            "agent_vidis_portal": "Test Landesportal",
            "agent_tasks": ["legal"],
        },
    ).json()["id"]
    completed = _wait(client, job_id)

    assert completed["status"] == "completed", completed.get("error")
    assert seen["password"] == "geheim-123"
    assert seen["vidis_portal"] == "Test Landesportal"
    stored = (tmp_path / "results" / job_id / "job.json").read_text(encoding="utf-8")
    assert "geheim-123" not in stored
    assert "agent_password" not in json.loads(stored)["request"]
