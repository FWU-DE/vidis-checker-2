from __future__ import annotations

import io
import json
import time
import zipfile
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from vidis_compliance import server
from vidis_compliance.checks.site.ipf import IpfSiteAnalysis, LegalPageResult
from vidis_compliance.models import CheckFinding

A = {"X-API-Key": "partner-a-key"}
B = {"X-API-Key": "partner-b-key"}
ADMIN = {"X-API-Key": "operator-admin-key"}


@pytest.fixture
def client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> TestClient:
    monkeypatch.setenv("VIDIS_RESULTS_DIR", str(tmp_path / "results"))
    monkeypatch.delenv("VIDIS_AUTH_DISABLED")
    monkeypatch.setenv("VIDIS_API_KEYS", "partner-a-key,partner-b-key")
    monkeypatch.setenv("VIDIS_ADMIN_KEYS", "operator-admin-key")
    monkeypatch.setattr(server.cli_module, "check_site_transport", lambda url: [CheckFinding(criterion="ITS-ENC-359", status="PASS", note="ok")])
    monkeypatch.setattr(
        server.cli_module,
        "analyze_ipf_site",
        lambda url: IpfSiteAnalysis(source_url=url, visited_urls=[], impressum=LegalPageResult(kind="impressum"), privacy=LegalPageResult(kind="privacy")),
    )
    return TestClient(server.app)


def _job(client: TestClient, headers: dict) -> str:
    job_id = client.post("/checks/site.transport", json={"target_url": "https://app.example.test"}, headers=headers).json()["id"]
    deadline = time.monotonic() + 5
    while client.get(f"/jobs/{job_id}", headers=headers).json()["status"] not in {"completed", "failed"}:
        assert time.monotonic() < deadline
        time.sleep(0.05)
    return job_id


def test_each_key_sees_only_its_own_jobs(client: TestClient) -> None:
    job_a = _job(client, A)
    job_b = _job(client, B)

    assert [item["id"] for item in client.get("/jobs", headers=A).json()["items"]] == [job_a]
    assert [item["id"] for item in client.get("/jobs", headers=B).json()["items"]] == [job_b]
    assert client.get("/jobs", headers=B).json()["total"] == 1


@pytest.mark.parametrize(
    "method, path",
    [
        ("GET", "/jobs/{id}"),
        ("GET", "/jobs/{id}/artifacts/result.json"),
        ("GET", "/jobs/{id}/artifacts/job.json"),
        ("POST", "/jobs/{id}/reports"),
        ("GET", "/jobs/{id}/reports/report.md"),
        ("GET", "/jobs/{id}/archive.zip"),
    ],
)
def test_other_keys_get_404_for_every_job_endpoint(client: TestClient, method: str, path: str) -> None:
    job_a = _job(client, A)
    assert client.post(f"/jobs/{job_a}/reports", json={"format": "md"}, headers=A).status_code == 201

    url = path.format(id=job_a)
    response = client.request(method, url, headers=B, json={"format": "md"} if method == "POST" else None)

    assert response.status_code == 404
    assert client.request(method, url, headers=A, json={"format": "md"} if method == "POST" else None).status_code in {200, 201}


def test_admin_keys_see_every_job(client: TestClient) -> None:
    job_a = _job(client, A)
    job_b = _job(client, B)

    ids = {item["id"] for item in client.get("/jobs", headers=ADMIN).json()["items"]}
    assert ids == {job_a, job_b}
    assert client.get(f"/jobs/{job_a}", headers=ADMIN).status_code == 200


def test_owner_is_never_sent(client: TestClient) -> None:
    job_a = _job(client, A)

    assert "owner" not in client.get(f"/jobs/{job_a}", headers=A).json()
    assert "owner" not in client.get(f"/jobs/{job_a}/artifacts/job.json", headers=A).json()
    archive = zipfile.ZipFile(io.BytesIO(client.get(f"/jobs/{job_a}/archive.zip", headers=A).content))
    assert "owner" not in json.loads(archive.read("job.json"))
    assert "partner-a-key" not in archive.read("job.json").decode()


def test_jobs_without_owner_are_admin_only(client: TestClient, tmp_path: Path) -> None:
    job_a = _job(client, A)
    path = tmp_path / "results" / job_a / "job.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    data.pop("owner")
    path.write_text(json.dumps(data), encoding="utf-8")

    assert client.get(f"/jobs/{job_a}", headers=A).status_code == 404
    assert client.get(f"/jobs/{job_a}", headers=ADMIN).status_code == 200


def test_generic_api_key_variable_is_ignored(client: TestClient, monkeypatch) -> None:
    monkeypatch.setenv("API_KEY", "leaked-from-another-tool")

    assert client.get("/jobs", headers={"X-API-Key": "leaked-from-another-tool"}).status_code == 401


def test_api_reports_leave_out_logged_in_screenshots() -> None:
    raw = {"screenshots": [{"label": "public"}, {"label": "login", "authenticated": True}, {"label": "local", "local_only": True}]}

    assert [shot["label"] for shot in server._without_authenticated_screenshots(raw)["screenshots"]] == ["public"]
