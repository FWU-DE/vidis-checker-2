from __future__ import annotations

import json
import threading
import time
import zipfile
from io import BytesIO
from pathlib import Path

from fastapi.testclient import TestClient

from vidis_compliance import server
from vidis_compliance.models import CheckFinding
from vidis_compliance.sources.documents.analyze import DocumentInput


def _wait_for_completed(client: TestClient, job_id: str) -> dict:
    deadline = time.monotonic() + 5
    payload: dict = {}
    while time.monotonic() < deadline:
        response = client.get(f"/jobs/{job_id}")
        assert response.status_code == 200
        payload = response.json()
        if payload["status"] == "completed":
            return payload
        assert payload["status"] in {"queued", "running"}
        time.sleep(0.05)
    raise AssertionError(f"job did not complete: {payload}")


def test_post_job_runs_code_check_and_exposes_result_artifact_and_reports(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("VIDIS_RESULTS_DIR", str(tmp_path / "results"))

    def fake_inspect_code_path(code_path: str | Path, audience: str):
        return (
            [CheckFinding(criterion="RDS-IPF-364", status="PASS", note="fixture")],
            {"files_scanned": 1, "root": str(code_path), "audience": audience},
        )

    monkeypatch.setattr(server.cli_module, "inspect_code_path", fake_inspect_code_path)
    client = TestClient(server.app)

    created = client.post(
        "/jobs",
        json={"code_path": str(tmp_path), "target_audience": "SuS", "pages": 1},
    )

    assert created.status_code == 202
    job_id = created.json()["id"]
    assert created.json()["status"] in {"queued", "running"}

    completed = _wait_for_completed(client, job_id)
    assert completed["status"] == "completed"
    assert completed["result"]["job_id"] == job_id
    assert completed["artifacts"]["result_json"].endswith(f"/jobs/{job_id}/artifacts/result.json")
    assert completed["artifacts"]["code_capture_json"].endswith(f"/jobs/{job_id}/artifacts/code_capture.json")

    artifact = client.get(f"/jobs/{job_id}/artifacts/result.json")
    assert artifact.status_code == 200
    by_code = {finding["criterion"]: finding for finding in artifact.json()["findings"]}
    assert by_code["RDS-IPF-364"]["status"] == "PASS"

    md_report = client.post(f"/jobs/{job_id}/reports", json={"format": "md"})
    assert md_report.status_code == 201
    assert md_report.json()["download_url"].endswith(f"/jobs/{job_id}/reports/report.md")
    downloaded_md = client.get(f"/jobs/{job_id}/reports/report.md")
    assert downloaded_md.status_code == 200
    assert downloaded_md.text.startswith("# VIDIS Prüfkriterien")

    pdf_report = client.post(f"/jobs/{job_id}/reports", json={"format": "pdf"})
    assert pdf_report.status_code == 201
    downloaded_pdf = client.get(f"/jobs/{job_id}/reports/report.pdf")
    assert downloaded_pdf.status_code == 200
    assert downloaded_pdf.content.startswith(b"%PDF")


def test_post_job_returns_before_slow_scan_finishes(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("VIDIS_RESULTS_DIR", str(tmp_path / "results"))
    release = threading.Event()
    started = threading.Event()

    def slow_inspect_code_path(code_path: str | Path, audience: str):
        started.set()
        assert release.wait(timeout=2)
        return ([CheckFinding(criterion="RDS-IPF-364", status="PASS", note="slow")], None)

    monkeypatch.setattr(server.cli_module, "inspect_code_path", slow_inspect_code_path)
    client = TestClient(server.app)

    created = client.post("/jobs", json={"code_path": str(tmp_path), "pages": 1})

    assert created.status_code == 202
    assert started.wait(timeout=1)
    job_id = created.json()["id"]
    pending = client.get(f"/jobs/{job_id}").json()
    assert pending["status"] in {"queued", "running"}

    release.set()
    assert _wait_for_completed(client, job_id)["status"] == "completed"


def test_jobs_reject_missing_targets_and_path_traversal(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("VIDIS_RESULTS_DIR", str(tmp_path / "results"))
    client = TestClient(server.app)
    document_path = tmp_path / "doc.pdf"
    document_path.write_text("Datenschutzerklärung personenbezogene Daten", encoding="utf-8")

    missing = client.post("/jobs", json={"pages": 1})
    assert missing.status_code == 422

    created = client.post("/jobs", json={"document_path": str(document_path)})
    assert created.status_code == 202
    job_id = created.json()["id"]
    completed = _wait_for_completed(client, job_id)
    assert completed["status"] == "completed"

    bad_artifact = client.get(f"/jobs/{job_id}/artifacts/../result.json")
    assert bad_artifact.status_code in {404, 422}

    bad_report = client.get(f"/jobs/{job_id}/reports/../report.md")
    assert bad_report.status_code in {404, 422}

    unknown_artifact = client.get(f"/jobs/{job_id}/artifacts/secrets.txt")
    assert unknown_artifact.status_code == 404

    metadata_path = tmp_path / "results" / job_id / "job.json"
    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    assert metadata["request"]["document_path"].endswith("doc.pdf")


def test_api_requires_bearer_token_when_configured(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("VIDIS_RESULTS_DIR", str(tmp_path / "results"))
    monkeypatch.setenv("VIDIS_API_KEY", "secret-token")
    client = TestClient(server.app)

    missing = client.get("/criteria")
    wrong = client.get("/criteria", headers={"Authorization": "Bearer wrong"})
    allowed = client.get("/criteria", headers={"Authorization": "Bearer secret-token"})

    assert missing.status_code == 401
    assert wrong.status_code == 401
    assert allowed.status_code == 200


def test_jobs_list_returns_persisted_jobs_with_status_filter_and_no_results(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("VIDIS_RESULTS_DIR", str(tmp_path / "results"))
    client = TestClient(server.app)
    one = tmp_path / "one.pdf"
    two = tmp_path / "two.pdf"
    one.write_text("AGB Datenschutz DSGVO", encoding="utf-8")
    two.write_text("AVV Art. 28 DSGVO", encoding="utf-8")

    first = client.post("/jobs", json={"document_path": str(one)})
    second = client.post("/jobs", json={"document_path": str(two)})
    assert first.status_code == 202
    assert second.status_code == 202
    first_id = first.json()["id"]
    second_id = second.json()["id"]
    assert _wait_for_completed(client, first_id)["status"] == "completed"
    assert _wait_for_completed(client, second_id)["status"] == "completed"

    listed = client.get("/jobs", params={"status": "completed", "limit": 1, "offset": 0})

    assert listed.status_code == 200
    payload = listed.json()
    assert payload["total"] == 2
    assert payload["limit"] == 1
    assert payload["offset"] == 0
    assert len(payload["items"]) == 1
    assert payload["items"][0]["id"] in {first_id, second_id}
    assert payload["items"][0]["status"] == "completed"
    assert "result" not in payload["items"][0]


def test_archive_zip_contains_expected_files_and_excludes_unsafe_artifacts(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("VIDIS_RESULTS_DIR", str(tmp_path / "results"))
    client = TestClient(server.app)
    document_path = tmp_path / "doc.pdf"
    document_path.write_text("AGB Datenschutz DSGVO", encoding="utf-8")

    created = client.post("/jobs", json={"document_path": str(document_path)})
    assert created.status_code == 202
    job_id = created.json()["id"]
    assert _wait_for_completed(client, job_id)["status"] == "completed"
    assert client.post(f"/jobs/{job_id}/reports", json={"format": "md"}).status_code == 201

    job_dir = tmp_path / "results" / job_id
    (job_dir / "secret.txt").write_text("do not export", encoding="utf-8")
    (job_dir / "../escape.txt").write_text("escape", encoding="utf-8")

    response = client.get(f"/jobs/{job_id}/archive.zip")

    assert response.status_code == 200
    assert response.headers["content-type"] == "application/zip"
    with zipfile.ZipFile(BytesIO(response.content)) as archive:
        names = set(archive.namelist())
        assert {"job.json", "result.json", "reports/report.md"}.issubset(names)
        assert "secret.txt" not in names
        assert "../escape.txt" not in names
        assert all(".." not in Path(name).parts for name in names)


def test_post_job_analyzes_remote_document_urls_and_exposes_document_capture(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("VIDIS_RESULTS_DIR", str(tmp_path / "results"))
    captured_inputs: list[DocumentInput] = []

    def fake_analyze_documents(documents):
        captured_inputs.extend(documents)
        return (
            [CheckFinding(criterion="RDS-AGB-369", status="PASS", note="avv fixture")],
            {
                "documents": [
                    {"location": document.location, "kind": document.kind, "content_type": "text/html", "text_length": 42, "snippets": {}}
                    for document in documents
                ],
                "evidence": {"RDS-AGB-369": ["avv fixture"]},
            },
        )

    monkeypatch.setattr(server.cli_module, "analyze_documents", fake_analyze_documents)
    client = TestClient(server.app)

    created = client.post(
        "/jobs",
        json={
            "agb_url": "https://example.com/agb",
            "privacy_url": "https://example.com/datenschutz",
            "avv_url": "https://example.com/avv",
        },
    )

    assert created.status_code == 202
    job_id = created.json()["id"]
    completed = _wait_for_completed(client, job_id)

    assert completed["status"] == "completed"
    assert completed["artifacts"]["document_capture_json"].endswith(f"/jobs/{job_id}/artifacts/document_capture.json")
    assert [(item.kind, item.location) for item in captured_inputs] == [
        ("agb", "https://example.com/agb"),
        ("privacy", "https://example.com/datenschutz"),
        ("avv", "https://example.com/avv"),
    ]
    by_code = {finding["criterion"]: finding for finding in completed["result"]["findings"]}
    assert by_code["RDS-AGB-369"]["status"] == "PASS"

    artifact = client.get(f"/jobs/{job_id}/artifacts/document_capture.json")
    assert artifact.status_code == 200
    assert [document["kind"] for document in artifact.json()["documents"]] == ["agb", "privacy", "avv"]


def test_post_job_accepts_document_path_list_and_rejects_invalid_document_inputs(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("VIDIS_RESULTS_DIR", str(tmp_path / "results"))
    document_a = tmp_path / "agb.txt"
    document_b = tmp_path / "privacy.txt"
    document_a.write_text("AGB Datenschutz DSGVO", encoding="utf-8")
    document_b.write_text("Datenschutzerklärung personenbezogene Daten", encoding="utf-8")
    captured_inputs: list[DocumentInput] = []

    def fake_analyze_documents(documents):
        captured_inputs.extend(documents)
        return ([CheckFinding(criterion="RDS-AGB-368", status="PASS", note="docs fixture")], {"documents": [], "evidence": {}})

    monkeypatch.setattr(server.cli_module, "analyze_documents", fake_analyze_documents)
    client = TestClient(server.app)

    created = client.post("/jobs", json={"document_paths": [str(document_a), str(document_b)]})

    assert created.status_code == 202
    completed = _wait_for_completed(client, created.json()["id"])
    assert completed["status"] == "completed"
    assert [(item.kind, item.location) for item in captured_inputs] == [
        ("document", str(document_a)),
        ("document", str(document_b)),
    ]

    missing_path = client.post("/jobs", json={"document_paths": [str(tmp_path / "missing.pdf")]})
    assert missing_path.status_code == 422

    invalid_url = client.post("/jobs", json={"privacy_url": "file:///etc/passwd"})
    assert invalid_url.status_code == 422
