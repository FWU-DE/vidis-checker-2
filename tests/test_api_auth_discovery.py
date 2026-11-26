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


def _counting_site(monkeypatch) -> dict:
    """Fake site sources that count how often the browser crawl runs."""
    calls = {"crawl": 0}
    _fake_site(monkeypatch)
    original = server.cli_module.crawl

    def counting_crawl(*args, **kwargs):
        calls["crawl"] += 1
        return original(*args, **kwargs)

    monkeypatch.setattr(server.cli_module, "crawl", counting_crawl)
    monkeypatch.setattr(
        server.cli_module,
        "check_site_transport",
        lambda url: [CheckFinding(criterion=code, status="PASS", note="TLS fixture") for code in ("ITS-ENC-359", "ITS-ENC-360", "ITS-ENC-361")],
    )
    return calls


def test_job_with_checks_returns_only_their_criteria(client: TestClient, monkeypatch) -> None:
    calls = _counting_site(monkeypatch)

    job_id = client.post("/jobs", json={"target_url": "https://app.example.test", "checks": ["site.cookies", "site.advertising"]}).json()["id"]
    completed = _wait(client, job_id)

    assert completed["status"] == "completed", completed.get("error")
    assert {f["criterion"] for f in completed["result"]["findings"]} == {"RDS-CUC-371", "RDS-CUC-372", "RDS-WER-384"}
    assert completed["request"]["checks"] == ["site.cookies", "site.advertising"]
    assert calls["crawl"] == 1


def test_transport_check_alone_skips_the_browser_crawl(client: TestClient, monkeypatch) -> None:
    calls = _counting_site(monkeypatch)

    job_id = client.post("/jobs", json={"target_url": "https://app.example.test", "checks": ["site.transport"]}).json()["id"]
    completed = _wait(client, job_id)

    assert completed["status"] == "completed", completed.get("error")
    assert {f["criterion"] for f in completed["result"]["findings"]} == {"ITS-ENC-359", "ITS-ENC-360", "ITS-ENC-361"}
    assert calls["crawl"] == 0


def test_single_check_endpoint_runs_one_check(client: TestClient, monkeypatch) -> None:
    calls = _counting_site(monkeypatch)

    response = client.post("/checks/site.legal_pages", json={"target_url": "https://app.example.test"})
    assert response.status_code == 202
    completed = _wait(client, response.json()["id"])

    assert completed["status"] == "completed", completed.get("error")
    assert {f["criterion"] for f in completed["result"]["findings"]} == {"RDS-IPF-364", "RDS-IPF-365", "RDS-IPF-366", "RDS-IPF-367"}
    assert completed["request"]["checks"] == ["site.legal_pages"]
    assert calls["crawl"] == 0


def test_check_selection_is_validated(client: TestClient) -> None:
    unknown = client.post("/jobs", json={"target_url": "https://app.example.test", "checks": ["site.nope"]})
    missing_input = client.post("/jobs", json={"agb_url": "https://app.example.test/agb", "checks": ["site.cookies"]})
    endpoint_unknown = client.post("/checks/site.nope", json={"target_url": "https://app.example.test"})
    endpoint_missing = client.post("/checks/code.inspection", json={"target_url": "https://app.example.test"})
    extra_field = client.post("/checks/site.cookies", json={"target_url": "https://app.example.test", "checks": ["site.transport"]})

    assert unknown.status_code == 422 and "unknown check" in unknown.text
    assert missing_input.status_code == 422 and "requires target_url" in missing_input.text
    assert endpoint_unknown.status_code == 404
    assert endpoint_missing.status_code == 422 and "requires code_path" in endpoint_missing.text
    assert extra_field.status_code == 422


def test_single_check_endpoint_needs_a_key(client: TestClient, monkeypatch) -> None:
    monkeypatch.delenv("VIDIS_AUTH_DISABLED")
    monkeypatch.setenv("VIDIS_API_KEYS", "k")

    assert client.post("/checks/site.transport", json={"target_url": "https://app.example.test"}).status_code == 401
    assert client.get("/checks").status_code == 200
    assert client.get("/checks/site.transport").json()["criteria"] == ["ITS-ENC-359", "ITS-ENC-360", "ITS-ENC-361"]
    assert client.get("/checks/site.nope").status_code == 404


def test_discovery_links_each_check_to_its_run_endpoint(client: TestClient) -> None:
    payload = client.get("/discovery").json()

    for check in payload["checks"]:
        assert check["run"] == {"method": "POST", "path": f"/checks/{check['id']}", "auth": True}
    assert any(endpoint["path"] == "/checks/{check_id}" and endpoint["method"] == "POST" for endpoint in payload["endpoints"])


def test_single_check_endpoint_passes_agent_password(client: TestClient, monkeypatch) -> None:
    seen: dict = {}

    class FakeRunner:
        def run(self, **kwargs):
            seen.update(kwargs)
            return AgenticCrawlResult(base_url=kwargs["base_url"], task_types=kwargs["task_types"], persona=kwargs["persona"])

    _fake_site(monkeypatch)
    monkeypatch.setattr(server.cli_module, "DefaultAgenticRunner", lambda: FakeRunner())

    response = client.post(
        "/checks/agentic.persona_crawl",
        json={"target_url": "https://app.example.test", "agent_username": "lehrer1", "agent_password": "geheim-456", "agent_tasks": ["legal"]},
    )
    completed = _wait(client, response.json()["id"])

    assert completed["status"] == "completed", completed.get("error")
    assert seen["password"] == "geheim-456"
    assert completed["request"]["agentic"] is True


@pytest.mark.parametrize("path", ["/discovery", "/health", "/checks", "/checks/site.transport", "/criteria"])
def test_public_json_is_utf8_and_readable_in_browsers(client: TestClient, path: str) -> None:
    response = client.get(path)

    assert response.headers["content-type"] == "application/json; charset=utf-8"
    assert response.text.startswith("{\n  ")


def test_umlauts_are_sent_as_utf8_not_escaped(client: TestClient) -> None:
    response = client.get("/discovery")

    assert "Prüfkriterien".encode("utf-8") in response.content
    assert b"\\u00fc" not in response.content


def test_error_responses_also_declare_utf8(client: TestClient, monkeypatch) -> None:
    monkeypatch.delenv("VIDIS_AUTH_DISABLED")
    monkeypatch.setenv("VIDIS_API_KEYS", "k")

    unauthorized = client.get("/jobs")
    missing = client.get("/checks/site.nope")
    invalid = client.post("/jobs", headers={"X-API-Key": "k"}, json={"pages": 0})

    for response in (unauthorized, missing, invalid):
        assert response.headers["content-type"] == "application/json; charset=utf-8"
    assert unauthorized.status_code == 401 and unauthorized.headers["www-authenticate"] == "Bearer"
    assert missing.status_code == 404
    assert invalid.status_code == 422 and isinstance(invalid.json()["detail"], list)
