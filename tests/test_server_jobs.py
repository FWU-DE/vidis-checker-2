from __future__ import annotations

import json
import threading
import time
from pathlib import Path

from fastapi.testclient import TestClient

from vidis_compliance import server
from vidis_compliance.models import CheckFinding


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

    missing = client.post("/jobs", json={"pages": 1})
    assert missing.status_code == 422

    created = client.post("/jobs", json={"document_path": str(tmp_path / "doc.pdf")})
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
